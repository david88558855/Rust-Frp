//! `http_proxy`: speak HTTP proxy to whoever reaches the remote port.
//!
//! Upstream peeks seven bytes for `CONNECT` and either tunnels by hand or hands
//! the connection to a `http.Server`. Hyper routes both through the same code
//! path — a `CONNECT` arrives as a normal request whose method is `CONNECT`, and
//! answering it with a `200` switches the connection into tunnel mode — so the
//! peek is unnecessary here. The observable behaviour is the same: `CONNECT`
//! dials the authority and splices, anything else is a forward proxy request.
//!
//! Credentials come from `Proxy-Authorization`, and a rejected request is a
//! `407` with `Proxy-Authenticate: Basic` and `Connection: close`, exactly as
//! upstream replies.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{
    HeaderMap, HeaderValue, CONNECTION, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION,
};
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::bridge::{full_body, Bridge, Handler, RespBody};
use super::forward::{forward, upgrade_type, Target};
use super::{basic_auth, ConnInfo, Plugin};

/// How long the requested host has to accept a connection.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

pub struct HttpProxyPlugin {
    http_user: String,
    http_password: String,
    cancel: CancellationToken,
    bridge: OnceLock<Arc<Bridge>>,
}

impl HttpProxyPlugin {
    pub fn new(http_user: &str, http_password: &str) -> Arc<Self> {
        let plugin = Arc::new(Self {
            http_user: http_user.to_string(),
            http_password: http_password.to_string(),
            cancel: CancellationToken::new(),
            bridge: OnceLock::new(),
        });

        // The handler needs the plugin and the plugin needs the bridge, so the
        // handler holds a weak reference; an `Arc` here would be a cycle.
        let weak = Arc::downgrade(&plugin);
        let handler: Handler = Arc::new(move |req: Request<Incoming>, _peer: Option<SocketAddr>| {
            let weak = weak.clone();
            Box::pin(async move {
                match weak.upgrade() {
                    Some(plugin) => plugin.serve(req).await,
                    None => proxy_auth_required(),
                }
            })
        });
        let bridge = Bridge::new(handler, None, false, plugin.cancel.clone());
        let _ = plugin.bridge.set(bridge);
        plugin
    }

    fn authorised(&self, headers: &HeaderMap) -> bool {
        basic_auth(
            headers,
            PROXY_AUTHORIZATION,
            &self.http_user,
            &self.http_password,
        )
    }

    async fn serve(&self, req: Request<Incoming>) -> Response<RespBody> {
        if !self.authorised(req.headers()) {
            return proxy_auth_required();
        }
        if req.method() == Method::CONNECT {
            self.connect(req).await
        } else {
            self.forward_proxy(req).await
        }
    }

    /// Dials the authority of a `CONNECT` and splices the two halves.
    async fn connect(&self, req: Request<Incoming>) -> Response<RespBody> {
        let Some(authority) = req.uri().authority().map(|a| a.as_str().to_string()) else {
            return bad_request("CONNECT requires an authority");
        };

        // Taken before the dial so the upgrade cannot be missed; the future is
        // only awaited once the tunnel is ready.
        let inbound_upgrade = hyper::upgrade::on(req);

        let remote = match timeout(DIAL_TIMEOUT, TcpStream::connect(&authority)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                debug!(authority = %authority, error = %e, "http_proxy CONNECT target is unreachable");
                return bad_request("cannot connect to the requested host");
            }
            Err(_) => {
                debug!(authority = %authority, "http_proxy CONNECT dial timed out");
                return bad_request("timed out connecting to the requested host");
            }
        };
        let _ = remote.set_nodelay(true);
        debug!(authority = %authority, "http_proxy tunnel established");

        tokio::spawn(async move {
            match inbound_upgrade.await {
                Ok(upgraded) => {
                    let upgraded = TokioIo::new(upgraded);
                    crate::proxy::ProxyContext::join(upgraded, remote).await;
                }
                Err(e) => debug!(error = %e, "http_proxy upgrade failed"),
            }
        });

        Response::builder()
            .status(StatusCode::OK)
            .body(full_body(""))
            .unwrap_or_else(|_| Response::new(full_body("")))
    }

    /// Forwards an absolute-form proxy request to the host it names.
    async fn forward_proxy(&self, req: Request<Incoming>) -> Response<RespBody> {
        let Some(scheme) = req.uri().scheme_str().map(|s| s.to_ascii_lowercase()) else {
            return bad_request("a proxy request must use an absolute URI");
        };
        let Some(authority) = req.uri().authority().map(|a| a.as_str().to_string()) else {
            return bad_request("a proxy request must name a host");
        };
        if scheme != "http" && scheme != "https" {
            return bad_request("unsupported scheme");
        }

        let upgrade_hint = upgrade_type(req.headers());
        let (mut parts, body) = req.into_parts();
        let inbound_upgrade = parts.extensions.remove::<hyper::upgrade::OnUpgrade>();

        // `removeProxyHeaders`: these describe the proxy hop, not the origin.
        for name in [
            "proxy-connection",
            "connection",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "trailers",
            "transfer-encoding",
            "upgrade",
        ] {
            parts.headers.remove(name);
        }
        // Hyper writes origin-form for the request line, so the absolute URI is
        // fine; only the scheme decides whether the origin is reached over TLS.
        if parts.headers.get(HOST).is_none() {
            if let Ok(value) = HeaderValue::from_str(&authority) {
                parts.headers.insert(HOST, value);
            }
        }
        match format!("{scheme}://{authority}{}", path_and_query(&parts.uri)).parse() {
            Ok(uri) => parts.uri = uri,
            Err(_) => return bad_request("the request target is not usable"),
        }

        let target = Target {
            addr: authority,
            client_config: (scheme == "https").then(verified_tls_client_config),
        };
        let outbound = Request::from_parts(parts, body.boxed());
        match forward(outbound, inbound_upgrade, &target, upgrade_hint).await {
            Ok(response) => response,
            Err(e) => {
                debug!(error = %e, "the proxied request failed");
                bad_gateway()
            }
        }
    }
}

impl Plugin for HttpProxyPlugin {
    fn name(&self) -> &'static str {
        "http_proxy"
    }

    fn handle(&self, info: ConnInfo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let bridge = self.bridge.get().cloned();
        let peer = info.src_addr;
        let conn = info.conn;
        Box::pin(async move {
            match bridge {
                Some(bridge) => bridge.put_conn(conn, peer),
                None => debug!("the http_proxy bridge is not running"),
            }
        })
    }

    fn close(&self) {
        self.cancel.cancel();
    }
}

fn path_and_query(uri: &Uri) -> String {
    uri.path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string())
}

/// A verifying TLS configuration for `https://` proxy requests.
///
/// Unlike the `http2https`/`https2https` plugins, whose backend is a local
/// service, a forward proxy talks to an arbitrary origin server, so the
/// certificate is checked against the public roots.
fn verified_tls_client_config() -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the default protocol versions are valid")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

fn proxy_auth_required() -> Response<RespBody> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(PROXY_AUTHENTICATE, "Basic")
        // Upstream closes the connection after a rejected CONNECT.
        .header(CONNECTION, "close")
        .body(full_body(""))
        .unwrap_or_else(|_| Response::new(full_body("")))
}

fn bad_request(message: &str) -> Response<RespBody> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(CONNECTION, "close")
        .body(full_body(format!("{message}\n")))
        .unwrap_or_else(|_| Response::new(full_body("")))
}

fn bad_gateway() -> Response<RespBody> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header(CONNECTION, "close")
        .body(full_body("cannot reach the requested host\n"))
        .unwrap_or_else(|_| Response::new(full_body("")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_and_query_falls_back_to_the_root() {
        let uri: Uri = "http://example.com".parse().unwrap();
        assert_eq!(path_and_query(&uri), "/");
        let uri: Uri = "http://example.com/a?b=1".parse().unwrap();
        assert_eq!(path_and_query(&uri), "/a?b=1");
    }

    #[test]
    fn a_rejected_request_advertises_basic_and_closes() {
        let response = proxy_auth_required();
        assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert_eq!(
            response.headers().get(PROXY_AUTHENTICATE),
            Some(&HeaderValue::from_static("Basic"))
        );
        assert_eq!(
            response.headers().get(CONNECTION),
            Some(&HeaderValue::from_static("close"))
        );
    }

    #[tokio::test]
    async fn credentials_are_enforced_when_set() {
        let plugin = HttpProxyPlugin::new("u", "p");
        let mut headers = HeaderMap::new();
        assert!(!plugin.authorised(&headers));
        headers.insert(
            PROXY_AUTHORIZATION,
            "Basic dTpw".parse().unwrap(), // "u:p"
        );
        assert!(plugin.authorised(&headers));
        assert!(!HttpProxyPlugin::new("", "").authorised(&HeaderMap::new()));
    }

    #[test]
    fn the_public_root_store_is_populated() {
        assert!(!webpki_roots::TLS_SERVER_ROOTS.is_empty());
        // And the configuration builds from it without a client certificate.
        let _ = verified_tls_client_config();
    }
}
