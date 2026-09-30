//! The outbound half of an HTTP-bridging plugin: one request handed to a local
//! service, plus the response handed back.
//!
//! Upstream uses `httputil.ReverseProxy`, which sits on `http.Transport` with
//! its connection pool. This is a single request over a fresh connection to the
//! backend. Functionally equivalent for a local service — the request and
//! response are byte-for-byte the same — and it keeps the connection lifetime
//! obvious, which matters because the response body is *streamed*: the
//! connection has to stay alive until the body is drained.
//!
//! The one place the two differ in a way that shows up on the wire is the
//! request line, and it is easy to get wrong. Go's `Transport` writes
//! `URL.RequestURI()` — the path and query — and uses `URL.Scheme`/`URL.Host`
//! only to pick a socket; a request whose URL is `http://backend/probe` still
//! goes out as `GET /probe HTTP/1.1`. Hyper writes the URI it is given, so the
//! same request would go out as `GET http://backend/probe HTTP/1.1`, which is
//! the absolute form a *proxy* expects and an origin server will misread.
//! [`forward`] therefore reduces the target back to origin-form before sending.

use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::client::conn::http1;
use hyper::header::{HeaderMap, HeaderName, CONNECTION, UPGRADE};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use super::bridge::RespBody;
use super::PluginConn;

/// How long the backend has to accept a connection.
const BACKEND_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Headers that describe this hop rather than the message, from RFC 2616
/// section 13.5.1 as reproduced in Go's `net/http/httputil`.
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Where a bridged request is sent.
#[derive(Clone)]
pub struct Target {
    /// `host:port` of the local service.
    pub addr: String,
    /// `Some` when the backend speaks TLS, which is what `http2https` and
    /// `https2https` select.
    pub client_config: Option<Arc<rustls::ClientConfig>>,
}

impl Target {
    /// Creates the TLS client configuration upstream uses for backend
    /// connections: `InsecureSkipVerify`, because the backend is local.
    pub fn tls_client_config() -> Arc<rustls::ClientConfig> {
        frp_core::transport::build_client_tls_config(&Default::default())
            .expect("the skip-verify TLS client configuration cannot fail")
    }
}

/// Strips the headers that belong to the connection rather than the message.
///
/// The list named in `Connection` is removed first, then the fixed set, which
/// is the order Go uses. An upgrade is re-declared afterwards by
/// [`forward`], exactly as `httputil.ReverseProxy` does; otherwise a WebSocket
/// handshake would arrive at the backend with its `Upgrade` header removed.
pub fn remove_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();
    for name in listed {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}

/// The `Upgrade` value of an inbound request, if it is an upgrade at all.
pub fn upgrade_type(headers: &HeaderMap) -> Option<String> {
    let offers_upgrade = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
    if !offers_upgrade {
        return None;
    }
    let value = headers.get(UPGRADE)?.to_str().ok()?.trim().to_ascii_lowercase();
    if value.is_empty() {
        return None;
    }
    Some(value)
}

/// Sends `req` (already rewritten by the caller) to `target` and returns the
/// response.
///
/// `inbound_upgrade` is the server-side upgrade half of the request this one
/// answers; `upgrade_hint` is that request's `Upgrade` token. A `101` response
/// is special-cased: both halves are spliced together so a WebSocket or any
/// other protocol switch keeps working through the tunnel.
pub async fn forward(
    mut req: Request<BoxBody<Bytes, hyper::Error>>,
    inbound_upgrade: Option<hyper::upgrade::OnUpgrade>,
    target: &Target,
    upgrade_hint: Option<String>,
) -> Result<Response<RespBody>> {
    if let Some(proto) = upgrade_hint {
        req.headers_mut()
            .insert(CONNECTION, hyper::header::HeaderValue::from_static("Upgrade"));
        if let Ok(value) = hyper::header::HeaderValue::from_str(&proto) {
            req.headers_mut().insert(UPGRADE, value);
        }
    }

    let io = dial(target).await?;
    let (mut sender, conn) = http1::handshake(TokioIo::new(io))
        .await
        .context("start an HTTP/1.1 conversation with the local service")?;
    // The connection has to be driven until the response body is drained, so it
    // runs on its own task. Dropping `sender` at the end of this function is
    // what tells hyper the connection can close once the response is complete.
    let connection = tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!(error = %e, "backend connection ended");
        }
    });

    req = origin_form(req);
    let mut response = sender
        .send_request(req)
        .await
        .context("send the request to the local service")?;
    let mut sender = Some(sender);

    // Read the protocol before the hop-by-hop headers go: `Upgrade` is on that
    // list and would be gone by the time it is needed.
    let upgraded_to = (response.status() == hyper::StatusCode::SWITCHING_PROTOCOLS)
        .then(|| {
            response
                .headers()
                .get(UPGRADE)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.trim().to_ascii_lowercase())
        })
        .flatten();

    remove_hop_by_hop(response.headers_mut());

    if let Some(proto) = upgraded_to {
        // `remove_hop_by_hop` took these away; without them hyper will not
        // switch protocols and the peer would hang waiting for a tunnel.
        response
            .headers_mut()
            .insert(CONNECTION, hyper::header::HeaderValue::from_static("Upgrade"));
        if let Ok(value) = hyper::header::HeaderValue::from_str(&proto) {
            response.headers_mut().insert(UPGRADE, value);
        }

        let outbound_upgrade = hyper::upgrade::on(&mut response);
        if let Some(inbound_upgrade) = inbound_upgrade {
            let keep_alive = sender.take();
            tokio::spawn(async move {
                // Held so the client connection is not torn down while the
                // upgraded halves are still being spliced.
                let _sender = keep_alive;
                let (inbound, outbound) = tokio::join!(inbound_upgrade, outbound_upgrade);
                match (inbound, outbound) {
                    (Ok(inbound), Ok(outbound)) => {
                        let inbound = TokioIo::new(inbound);
                        let outbound = TokioIo::new(outbound);
                        crate::proxy::ProxyContext::join(inbound, outbound).await;
                    }
                    (Err(e), _) => debug!(error = %e, "inbound upgrade failed"),
                    (_, Err(e)) => debug!(error = %e, "backend upgrade failed"),
                }
                connection.abort();
            });
        }
    } else if response.status() == hyper::StatusCode::SWITCHING_PROTOCOLS {
        // A 101 without an `Upgrade` token cannot be completed; close it rather
        // than leave the peer waiting.
        debug!("the local service switched protocols without naming one");
    }

    Ok(response.map(|body| body.boxed()))
}

/// Reduces a request target to origin-form, the way `URL.RequestURI()` does.
///
/// Callers build an absolute URI because that is what says which backend to
/// dial, and `Target` carries that separately, so nothing is lost by sending
/// only the path. An empty path becomes `/`, again matching `RequestURI`.
///
/// `CONNECT` is left alone: its target is an authority, not a path, and no
/// caller here routes it through this function — `http_proxy` splices the
/// tunnel itself.
fn origin_form<B>(mut req: Request<B>) -> Request<B> {
    if req.method() == hyper::Method::CONNECT {
        return req;
    }
    let target = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    if let Ok(uri) = target.parse() {
        *req.uri_mut() = uri;
    }
    req
}

/// Dials the backend, wrapping the socket in TLS when the plugin asks for it.
async fn dial(target: &Target) -> Result<PluginConn> {
    let stream = timeout(BACKEND_DIAL_TIMEOUT, TcpStream::connect(&target.addr))
        .await
        .with_context(|| format!("timed out connecting to {}", target.addr))?
        .with_context(|| format!("connect to {}", target.addr))?;
    let _ = stream.set_nodelay(true);

    let Some(config) = target.client_config.as_ref() else {
        return Ok(Box::new(stream));
    };
    let host = target
        .addr
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(&target.addr)
        .to_string();
    let server_name = rustls::pki_types::ServerName::try_from(host)
        .context("the backend address cannot be used as a TLS server name")?;
    let tls = tokio_rustls::TlsConnector::from(config.clone())
        .connect(server_name, stream)
        .await
        .context("TLS handshake with the local service")?;
    Ok(Box::new(tls))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;

    fn request(uri: &str, method: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Full::new(Bytes::new()))
            .unwrap()
    }

    fn target_of(uri: &str, method: &str) -> String {
        origin_form(request(uri, method)).uri().to_string()
    }

    /// The bug this exists for: an absolute URI reached the backend verbatim,
    /// so `http2http` sent `GET http://backend/probe` where upstream sends
    /// `GET /probe`. The backend sees an absolute-form request, which is a
    /// proxy's shape, and every routing decision it makes on the path is wrong.
    #[test]
    fn an_absolute_target_is_reduced_to_its_path() {
        assert_eq!(target_of("http://127.0.0.1:8080/probe", "GET"), "/probe");
        assert_eq!(target_of("https://backend:8443/probe", "GET"), "/probe");
        assert_eq!(
            target_of("http://127.0.0.1:8080/probe?q=1", "GET"),
            "/probe?q=1"
        );
        // The path was already relative: nothing to strip, and stripping must
        // not eat it.
        assert_eq!(target_of("/probe", "GET"), "/probe");
        assert_eq!(target_of("/a/b?c=d", "POST"), "/a/b?c=d");
        // `URL.RequestURI` answers `/` for an empty path, and so does this.
        assert_eq!(target_of("/", "GET"), "/");
    }

    #[test]
    fn connect_keeps_its_authority_target() {
        // A `CONNECT` target is an authority, not a path; rewriting it to
        // origin-form would strip the host the tunnel needs. The address is the
        // one the `http_proxy` scenario actually connects to, because that is
        // the shape whose parsing is known to yield an authority.
        let req = request("127.0.0.1:38000", "CONNECT");
        assert!(req.uri().authority().is_some());
        assert_eq!(origin_form(req).uri().to_string(), "127.0.0.1:38000");
    }
}
