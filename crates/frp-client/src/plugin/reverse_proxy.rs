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
//!
//! The two TLS-terminating ones also share upstream's misdirected-request
//! guard: when the peer sent an SNI and it does not match the request's Host,
//! the request is refused with `421` rather than being served. It is the only
//! thing standing between a certificate for one name and traffic addressed to
//! another, so it is worth getting the comparison exactly right --
//! [`canonical_host`] is a port of `pkg/util/http.CanonicalHost`.

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
        let handler: Handler =
            Arc::new(
                move |req: Request<Incoming>, peer: Option<SocketAddr>, sni: Option<String>| {
                    let weak = weak.clone();
                    Box::pin(async move {
                        match weak.upgrade() {
                            Some(plugin) => plugin.serve(req, peer, sni).await,
                            None => service_unavailable(),
                        }
                    })
                },
            );
        let bridge = Bridge::new(handler, acceptor, http2, plugin.cancel.clone());
        let _ = plugin.bridge.set(bridge);
        Ok(plugin)
    }

    /// One request, rewritten towards the backend.
    async fn serve(
        &self,
        req: Request<Incoming>,
        peer: Option<SocketAddr>,
        server_name: Option<String>,
    ) -> Response<RespBody> {
        if self.kind.terminates_tls() && is_misdirected(server_name.as_deref(), &request_host(&req))
        {
            return misdirected();
        }

        let upgrade_hint = upgrade_type(req.headers());
        let inbound_host = request_host(&req);
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
            for name in [&X_FORWARDED_FOR, &X_FORWARDED_HOST, &X_FORWARDED_PROTO] {
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

/// The Host a Go `http.Server` would report as `r.Host`.
///
/// For an absolute-form request target the authority from the request line
/// wins over the `Host` header, which is what `net/http`'s request reader does;
/// for the origin-form everyone actually sends they are the same value.
fn request_host(req: &Request<Incoming>) -> String {
    if let Some(authority) = req.uri().authority() {
        return authority.as_str().to_string();
    }
    req.headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// Upstream's `pkg/util/http.CanonicalHost`: lower-cased, port removed, and a
/// trailing dot on a fully qualified name dropped.
///
/// An address it cannot make sense of canonicalises to the empty string. The
/// Go caller ignores the error, so an empty result is not a mismatch -- which
/// is why [`is_misdirected`] tests the SNI for emptiness after canonicalising
/// rather than before.
pub(crate) fn canonical_host(host: &str) -> String {
    let lowered = host.to_ascii_lowercase();
    let without_port = if has_port(&lowered) {
        split_host_port(&lowered).unwrap_or_default()
    } else {
        lowered
    };
    without_port
        .strip_suffix('.')
        .unwrap_or(&without_port)
        .to_string()
}

/// Whether `host` carries a port, matching `net.SplitHostPort`'s idea of one.
/// A bare IPv6 address has several colons but no port; a bracketed one does.
fn has_port(host: &str) -> bool {
    match host.matches(':').count() {
        0 => false,
        1 => true,
        _ => host.starts_with('[') && host.contains("]:"),
    }
}

/// The host half of `host:port`, or `None` when `net.SplitHostPort` would fail.
fn split_host_port(host: &str) -> Option<String> {
    if let Some(rest) = host.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':')?;
        return valid_port(port).then(|| inside.to_string());
    }
    let (name, port) = host.rsplit_once(':')?;
    valid_port(port).then(|| name.to_string())
}

/// `net.validOptionalPort`: empty, or a colon followed by digits.
fn valid_port(port: &str) -> bool {
    port.is_empty() || port.chars().all(|c| c.is_ascii_digit())
}

/// Reproduces `withMisdirectedRequestCheck`.
///
/// Only a non-empty SNI that differs from the request Host is refused: a peer
/// that sent no SNI at all gets served, which is how every plain HTTP client
/// behind a TLS-terminating proxy behaves.
fn is_misdirected(server_name: Option<&str>, host: &str) -> bool {
    let Some(server_name) = server_name else {
        return false;
    };
    let sni = canonical_host(server_name);
    if sni.is_empty() {
        return false;
    }
    sni != canonical_host(host)
}

fn misdirected() -> Response<RespBody> {
    Response::builder()
        .status(StatusCode::MISDIRECTED_REQUEST)
        .body(full_body(""))
        .unwrap_or_else(|_| Response::new(full_body("")))
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

    /// The cases `pkg/util/http.CanonicalHost` documents: lower-cased, port
    /// stripped, trailing dot dropped.
    #[test]
    fn canonical_host_matches_the_upstream_implementation() {
        assert_eq!(canonical_host("Example.COM"), "example.com");
        assert_eq!(canonical_host("example.com:8080"), "example.com");
        // `net.SplitHostPort` accepts an empty port.
        assert_eq!(canonical_host("example.com:"), "example.com");
        assert_eq!(canonical_host("example.com."), "example.com");
        assert_eq!(canonical_host("[::1]:8080"), "::1");
        assert_eq!(canonical_host("127.0.0.1:80"), "127.0.0.1");
        assert_eq!(canonical_host(""), "");
        // `hasPort` only calls a bracketed string a host:port pair when it
        // contains `]:`, so a bare IPv6 literal is left alone either way. The
        // colons in `[::1]` are not a port and the result is *not* empty.
        assert_eq!(canonical_host("::1"), "::1");
        assert_eq!(canonical_host("[::1]"), "[::1]");
        // `hasPort` is false for `a:b:c` too: more than one colon, and it does
        // not start with a bracket.
        assert_eq!(canonical_host("a:b:c"), "a:b:c");
        // These are the shapes that reach `net.SplitHostPort` and fail it. The
        // Go caller ignores the error and keeps the empty string it got back,
        // which is what disables the misdirected check below.
        assert_eq!(canonical_host("host:notaport"), "");
        assert_eq!(canonical_host("[::1]:notaport"), "");
    }

    #[test]
    fn the_misdirected_check_follows_upstream() {
        // A peer that sent no SNI is always served.
        assert!(!is_misdirected(None, "anything.test"));
        // Matching names are served, however they are spelled.
        assert!(!is_misdirected(Some("front.example"), "front.example"));
        assert!(!is_misdirected(Some("Front.Example"), "front.example:443"));
        assert!(!is_misdirected(Some("front.example."), "front.example"));
        assert!(!is_misdirected(Some("[::1]:8080"), "[::1]:443"));
        // The case the guard exists for.
        assert!(is_misdirected(Some("any.sni"), "front.example"));
        assert!(is_misdirected(Some("front.example"), "other.example"));
        // A request with no usable Host is a mismatch as soon as an SNI was
        // sent: upstream compares against the empty string it canonicalised to.
        assert!(is_misdirected(Some("front.example"), ""));
        // Only an SNI that fails to canonicalise disables the check -- an
        // unusual spelling, but the one upstream lets through.
        assert!(!is_misdirected(Some("front.example:notaport"), "anything.test"));
    }

    #[test]
    fn only_the_tls_terminating_kinds_are_guarded() {
        assert!(Kind::Https2Http.terminates_tls());
        assert!(Kind::Https2Https.terminates_tls());
        assert!(!Kind::Http2Http.terminates_tls());
        assert!(!Kind::Http2Https.terminates_tls());
    }
}
