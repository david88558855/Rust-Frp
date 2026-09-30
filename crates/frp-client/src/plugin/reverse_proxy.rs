//! The four HTTP-bridging plugins: `http2http`, `http2https`, `https2http` and
//! `https2https`.
//!
//! They differ only in two booleans — whether the work connection is wrapped in
//! TLS, and whether the backend speaks TLS — plus the `X-Forwarded-*` policy,
//! which upstream expresses by writing a different `Rewrite` closure for each.
//! Reproducing that faithfully matters more than it looks: `http2http` and
//! `http2https` deliberately differ in whether the inbound `X-Forwarded-*`
//! headers survive.
//!
//! | plugin | inbound | backend | forwarded headers |
//! |---|---|---|---|
//! | `http2http` | plain | plain | per-hop headers dropped before the rewrite, so nothing is re-added |
//! | `http2https` | plain | TLS | the inbound `X-Forwarded-*` copied back verbatim |
//! | `https2http` | TLS | plain | `X-Forwarded-For` appended with the client IP, plus host and proto |
//! | `https2https` | TLS | TLS | same as `https2http` |

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use frp_core::config::common::HeaderOperations;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue, HOST};
use hyper::{Request, Response, StatusCode, Version};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use super::bridge::{full_body, Bridge, Handler, RespBody};
use super::forward::{forward, remove_hop_by_hop, upgrade_type, Target};
use super::tls::{alpn_for, build_acceptor};
use super::{ConnInfo, Plugin};

// The `http` crate has no constants for these, so they are declared here.
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");

/// Which of the four shapes a plugin instance is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Http2Http,
    Http2Https,
    Https2Http,
    Https2Https,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Http2Http => "http2http",
            Kind::Http2Https => "http2https",
            Kind::Https2Http => "https2http",
            Kind::Https2Https => "https2https",
        }
    }

    /// `http` or `https`: what the backend speaks.
    fn backend_scheme(self) -> &'static str {
        match self {
            Kind::Http2Http | Kind::Https2Http => "http",
            Kind::Http2Https | Kind::Https2Https => "https",
        }
    }

    /// Whether the work connection arrives wrapped in TLS.
    fn terminates_tls(self) -> bool {
        matches!(self, Kind::Https2Http | Kind::Https2Https)
    }

    /// Whether the inbound `X-Forwarded-*` are copied back, which is what only
    /// `http2https` does.
    fn copies_x_forwarded(self) -> bool {
        matches!(self, Kind::Http2Https)
    }

    /// Whether `X-Forwarded-*` are rebuilt the way Go's `SetXForwarded` does.
    fn sets_x_forwarded(self) -> bool {
        matches!(self, Kind::Https2Http | Kind::Https2Https)
    }
}

/// The options the four plugins share, in their upstream spelling.
pub struct Options {
    pub local_addr: String,
    pub host_header_rewrite: String,
    pub request_headers: HeaderOperations,
}

pub struct BridgePlugin {
    kind: Kind,
    target: Target,
    local_addr: String,
    host_header_rewrite: String,
    request_headers: HashMap<String, String>,
    cancel: CancellationToken,
    bridge: OnceLock<Arc<Bridge>>,
}

impl BridgePlugin {
    /// Builds the plugin and starts its bridge server.
    pub fn new(
        kind: Kind,
        opts: Options,
        crt_path: &str,
        key_path: &str,
        http2: bool,
    ) -> anyhow::Result<Arc<Self>> {
        let plugin = Arc::new(Self {
            kind,
            target: Target {
                addr: opts.local_addr.clone(),
                client_config: matches!(
                    kind.backend_scheme(),
                    "https"
                )
                .then(Target::tls_client_config),
            },
            local_addr: opts.local_addr,
            host_header_rewrite: opts.host_header_rewrite,
            request_headers: opts.request_headers.set,
            cancel: CancellationToken::new(),
            bridge: OnceLock::new(),
        });

        let acceptor = if kind.terminates_tls() {
            Some(build_acceptor(crt_path, key_path, alpn_for(http2))?)
        } else {
            None
        };

        // The handler needs the plugin, and the plugin needs the bridge, so the
        // handler holds a weak reference: keeping an `Arc` here would form a
        // cycle and pin the plugin in memory for the life of the process.
        let weak = Arc::downgrade(&plugin);
        let handler: Handler = Arc::new(move |req: Request<Incoming>, peer: Option<SocketAddr>| {
            let weak = weak.clone();
            Box::pin(async move {
                match weak.upgrade() {
                    Some(plugin) => plugin.serve(req, peer).await,
                    None => service_unavailable(),
                }
            })
        });
        let bridge = Bridge::new(handler, acceptor, http2, plugin.cancel.clone());
        let _ = plugin.bridge.set(bridge);
        Ok(plugin)
    }

    /// One request, rewritten towards the backend.
    async fn serve(&self, req: Request<Incoming>, peer: Option<SocketAddr>) -> Response<RespBody> {
        let upgrade_hint = upgrade_type(req.headers());
        let inbound_host = req
            .headers()
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());

        let (mut parts, body) = req.into_parts();
        // hyper stores the server-side half of an upgrade here.
        let inbound_upgrade = parts.extensions.remove::<hyper::upgrade::OnUpgrade>();
        let in_headers = std::mem::take(&mut parts.headers);

        let mut out = HeaderMap::new();
        for (name, value) in in_headers.iter() {
            // `httputil.ReverseProxy` strips the forwarding headers before it
            // calls `Rewrite`; only the plugins that put them back keep them.
            if is_forwarded_header(name.as_str()) {
                continue;
            }
            out.append(name.clone(), value.clone());
        }
        if self.kind.copies_x_forwarded() {
            for name in [X_FORWARDED_FOR, X_FORWARDED_HOST, X_FORWARDED_PROTO] {
                for value in in_headers.get_all(name) {
                    out.append(name.clone(), value.clone());
                }
            }
        }
        if self.kind.sets_x_forwarded() {
            self.set_x_forwarded(&mut out, &in_headers, &inbound_host, peer);
        }

        remove_hop_by_hop(&mut out);

        // The Host header is the inbound one unless `hostHeaderRewrite` says
        // otherwise — upstream assigns `URL.Host` for dialing but leaves
        // `Request.Host` alone, so the backend still sees the original domain.
        let host = if self.host_header_rewrite.is_empty() {
            inbound_host
        } else {
            self.host_header_rewrite.clone()
        };
        if !host.is_empty() {
            match HeaderValue::from_str(&host) {
                Ok(value) => {
                    out.insert(HOST, value);
                }
                Err(e) => warn!(host = %host, error = %e, "ignoring an unusable Host header"),
            }
        }

        // Applied last, so an explicit `requestHeaders` entry always wins.
        for (name, value) in &self.request_headers {
            match (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                (Ok(name), Ok(value)) => {
                    out.insert(name, value);
                }
                _ => warn!(header = %name, "ignoring an unusable request header"),
            }
        }

        parts.headers = out;
        // The backend hop is always HTTP/1.1 here, even when the peer reached
        // us over HTTP/2 on a TLS listener.
        parts.version = Version::HTTP_11;

        let uri = format!("{}://{}{}", self.kind.backend_scheme(), self.local_addr, path_and_query);
        match uri.parse() {
            Ok(uri) => parts.uri = uri,
            Err(e) => {
                warn!(uri = %uri, error = %e, "cannot build the backend URI");
                return bad_gateway("invalid request target");
            }
        }

        let outbound = Request::from_parts(parts, body.boxed());
        match forward(outbound, inbound_upgrade, &self.target, upgrade_hint).await {
            Ok(response) => response,
            Err(e) => {
                warn!(backend = %self.local_addr, error = %e, "the local service could not be reached");
                bad_gateway("cannot reach the local service")
            }
        }
    }

    /// Reproduces Go's `ProxyRequest.SetXForwarded`.
    ///
    /// Note the `else` branch: when the client address cannot be determined Go
    /// *deletes* the header rather than leaving a partial one.
    fn set_x_forwarded(
        &self,
        out: &mut HeaderMap,
        in_headers: &HeaderMap,
        inbound_host: &str,
        peer: Option<SocketAddr>,
    ) {
        let prior = in_headers
            .get_all(X_FORWARDED_FOR)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>()
            .join(", ");
        match peer.map(|addr| addr.ip().to_string()) {
            Some(ip) => {
                let value = if prior.is_empty() {
                    ip
                } else {
                    format!("{prior}, {ip}")
                };
                match HeaderValue::from_str(&value) {
                    Ok(value) => {
                        out.insert(X_FORWARDED_FOR, value);
                    }
                    Err(_) => {
                        out.remove(X_FORWARDED_FOR);
                    }
                }
            }
            None => {
                out.remove(X_FORWARDED_FOR);
            }
        }
        if let Ok(value) = HeaderValue::from_str(inbound_host) {
            out.insert(X_FORWARDED_HOST, value);
        }
        // These plugins terminate TLS, so the backend is told the client spoke
        // HTTPS even though the backend hop itself is plain.
        out.insert(X_FORWARDED_PROTO, HeaderValue::from_static("https"));
    }
}

impl Plugin for BridgePlugin {
    fn name(&self) -> &'static str {
        self.kind.name()
    }

    fn handle(&self, info: ConnInfo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let bridge = self.bridge.get().cloned();
        let peer = info.src_addr;
        let conn = info.conn;
        Box::pin(async move {
            match bridge {
                Some(bridge) => bridge.put_conn(conn, peer),
                None => warn!("the plugin bridge is not running"),
            }
        })
    }

    fn close(&self) {
        self.cancel.cancel();
    }
}

fn is_forwarded_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("forwarded")
        || name.eq_ignore_ascii_case("x-forwarded-for")
        || name.eq_ignore_ascii_case("x-forwarded-host")
        || name.eq_ignore_ascii_case("x-forwarded-proto")
}

fn bad_gateway(message: &str) -> Response<RespBody> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_body(format!("{message}\n")))
        .unwrap_or_else(|_| Response::new(full_body("bad gateway\n")))
}

fn service_unavailable() -> Response<RespBody> {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .body(full_body("plugin is closed\n"))
        .unwrap_or_else(|_| Response::new(full_body("")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_kind_selects_the_right_backend_and_xff_policy() {
        assert_eq!(Kind::Http2Http.backend_scheme(), "http");
        assert!(!Kind::Http2Http.terminates_tls());
        assert!(!Kind::Http2Http.copies_x_forwarded());
        assert!(!Kind::Http2Http.sets_x_forwarded());

        assert_eq!(Kind::Http2Https.backend_scheme(), "https");
        assert!(!Kind::Http2Https.terminates_tls());
        // The one difference between http2http and http2https beyond the
        // backend scheme.
        assert!(Kind::Http2Https.copies_x_forwarded());
        assert!(!Kind::Http2Https.sets_x_forwarded());

        assert!(Kind::Https2Http.terminates_tls());
        assert_eq!(Kind::Https2Http.backend_scheme(), "http");
        assert!(Kind::Https2Http.sets_x_forwarded());
        assert!(!Kind::Https2Http.copies_x_forwarded());

        assert!(Kind::Https2Https.terminates_tls());
        assert_eq!(Kind::Https2Https.backend_scheme(), "https");
        assert!(Kind::Https2Https.sets_x_forwarded());
    }

    #[test]
    fn the_names_match_the_upstream_plugin_tags() {
        assert_eq!(Kind::Http2Http.name(), "http2http");
        assert_eq!(Kind::Http2Https.name(), "http2https");
        assert_eq!(Kind::Https2Http.name(), "https2http");
        assert_eq!(Kind::Https2Https.name(), "https2https");
    }

    #[test]
    fn forwarded_headers_are_recognised_case_insensitively() {
        assert!(is_forwarded_header("X-Forwarded-For"));
        assert!(is_forwarded_header("x-forwarded-proto"));
        assert!(is_forwarded_header("Forwarded"));
        assert!(!is_forwarded_header("X-Forwarded-By"));
    }
}
