//! Shared HTTP plumbing for the virtual host port and the dashboard.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{HeaderMap, HeaderName, HeaderValue, HOST};
use hyper::{Response, StatusCode};

use crate::context::ServerContext;

/// Body type used by every virtual host response.
pub type RespBody = BoxBody<Bytes, hyper::Error>;

/// Hop-by-hop headers stripped before forwarding, matching Go's reverse proxy.
pub const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Default 404 page, served when `custom404Page` is not configured.
pub const NOT_FOUND_HTML: &str = r#"<!DOCTYPE html>
<html>
<head><title>Not Found</title>
<style>
  body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>404 Not Found</h1>
<p>Sorry, the page you are looking for is currently unavailable.<br/>
Please try again later.</p>
<p>The server is powered by <a href="https://github.com/david88558855/Rust-Frp">Rust-Frp</a>.</p>
</body>
</html>
"#;

/// A body built from a full in-memory payload.
pub fn full_body(data: impl Into<Bytes>) -> RespBody {
    Full::new(data.into())
        .map_err(|never| match never {})
        .boxed()
}

pub fn empty_body() -> RespBody {
    full_body(Bytes::new())
}

/// Reads the configured `custom404Page`, falling back to the built-in page.
pub fn not_found_body(ctx: &ServerContext) -> RespBody {
    if !ctx.cfg.custom404_page.is_empty() {
        match std::fs::read(&ctx.cfg.custom404_page) {
            Ok(data) => return full_body(Bytes::from(data)),
            Err(e) => {
                tracing::warn!(
                    path = %ctx.cfg.custom404_page,
                    error = %e,
                    "unable to read custom404Page, using the built-in page"
                );
            }
        }
    }
    full_body(Bytes::from_static(NOT_FOUND_HTML.as_bytes()))
}

/// Builds the 404 response upstream returns for unroutable requests.
pub fn not_found_response(ctx: &ServerContext) -> Response<RespBody> {
    let mut resp = Response::new(not_found_body(ctx));
    *resp.status_mut() = StatusCode::NOT_FOUND;
    resp.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}

/// 502 for failures inside the tunnel, which upstream reports through its
/// reverse proxy error handler.
pub fn bad_gateway_response() -> Response<RespBody> {
    let text = "502 Bad Gateway: the request could not be forwarded to the client";
    let mut resp = Response::new(full_body(Bytes::from_static(text.as_bytes())));
    *resp.status_mut() = StatusCode::BAD_GATEWAY;
    resp.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

/// 401 / 407 when `httpUser` / `httpPassword` are configured on the route.
pub fn auth_required_response(proxy_mode: bool) -> Response<RespBody> {
    let (status, header, text) = if proxy_mode {
        (
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            HeaderName::from_static("proxy-authenticate"),
            "Proxy Authentication Required",
        )
    } else {
        (
            StatusCode::UNAUTHORIZED,
            HeaderName::from_static("www-authenticate"),
            "Unauthorized",
        )
    };
    let mut resp = Response::new(full_body(Bytes::from_static(text.as_bytes())));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header,
        HeaderValue::from_static("Basic realm=\"Restricted\""),
    );
    resp
}

/// Strips the `:port` suffix from a `Host` header value.
pub fn canonical_host(headers: &HeaderMap) -> String {
    let raw = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    frp_core::vhost::host_without_port(raw).to_ascii_lowercase()
}

/// Username the request is routed by, mirroring upstream `getRequestRouteUser`.
pub fn route_http_user(headers: &HeaderMap, proxy_mode: bool) -> String {
    if proxy_mode {
        if let Some(value) = headers
            .get("proxy-authorization")
            .and_then(|v| v.to_str().ok())
        {
            if let Some((user, _)) = parse_basic(value) {
                return user;
            }
            return String::new();
        }
    }
    match headers.get(hyper::header::AUTHORIZATION) {
        Some(value) => value
            .to_str()
            .ok()
            .and_then(|v| parse_basic(v))
            .map(|(user, _)| user)
            .unwrap_or_default(),
        None => String::new(),
    }
}

/// Validates `httpUser` / `httpPassword` for a route.
pub fn check_route_auth(
    username: &str,
    password: &str,
    headers: &HeaderMap,
    proxy_mode: bool,
) -> bool {
    if username.is_empty() && password.is_empty() {
        return true;
    }
    let header = if proxy_mode {
        headers
            .get("proxy-authorization")
            .and_then(|v| v.to_str().ok())
    } else {
        headers
            .get(hyper::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
    };
    match header.and_then(parse_basic) {
        Some((user, pass)) => {
            constant_time_eq(user.as_bytes(), username.as_bytes())
                && constant_time_eq(pass.as_bytes(), password.as_bytes())
        }
        None => false,
    }
}

fn parse_basic(value: &str) -> Option<(String, String)> {
    let encoded = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    let decoded = B64.decode(encoded.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, pass) = decoded.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;
    use std::sync::Arc;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    fn basic(user: &str, pass: &str) -> String {
        format!("Basic {}", B64.encode(format!("{user}:{pass}")))
    }

    #[test]
    fn canonical_host_strips_ports_and_lowercases() {
        assert_eq!(
            canonical_host(&headers(&[("host", "Example.COM:8080")])),
            "example.com"
        );
        assert_eq!(canonical_host(&headers(&[("host", "a.b")])), "a.b");
        assert_eq!(canonical_host(&headers(&[])), "");
    }

    #[test]
    fn route_user_comes_from_basic_auth() {
        let h = headers(&[("authorization", &basic("bob", "pw"))]);
        assert_eq!(route_http_user(&h, false), "bob");
        assert_eq!(route_http_user(&headers(&[]), false), "");

        // Proxy mode prefers Proxy-Authorization.
        let h = headers(&[
            ("authorization", &basic("bob", "pw")),
            ("proxy-authorization", &basic("alice", "pw")),
        ]);
        assert_eq!(route_http_user(&h, true), "alice");
        assert_eq!(route_http_user(&h, false), "bob");

        // Legacy proxy mode falls back to Authorization so the route still
        // matches and the client gets a 407 instead of a 404.
        let h = headers(&[("authorization", &basic("bob", "pw"))]);
        assert_eq!(route_http_user(&h, true), "bob");
    }

    #[test]
    fn route_auth_accepts_matching_credentials_only() {
        let h = headers(&[("authorization", &basic("u", "p"))]);
        assert!(check_route_auth("u", "p", &h, false));
        assert!(!check_route_auth("u", "x", &h, false));
        assert!(!check_route_auth("other", "p", &h, false));
        assert!(!check_route_auth("u", "p", &headers(&[]), false));
        // No credentials configured means the route is open.
        assert!(check_route_auth("", "", &headers(&[]), false));
    }

    #[test]
    fn auth_required_status_differs_by_mode() {
        assert_eq!(
            auth_required_response(false).status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            auth_required_response(true).status(),
            StatusCode::PROXY_AUTHENTICATION_REQUIRED
        );
    }

    #[test]
    fn not_found_uses_the_builtin_page() {
        let ctx = Arc::new(test_support::context());
        let resp = not_found_response(&ctx);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn not_found_reads_custom_page_when_configured() {
        let dir = std::env::temp_dir().join(format!("frp-404-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let page = dir.join("404.html");
        std::fs::write(&page, b"<h1>custom</h1>").unwrap();

        let mut cfg = frp_core::config::server::ServerConfig::default();
        cfg.complete();
        cfg.custom404_page = page.to_string_lossy().to_string();
        let ctx = Arc::new(test_support::context_with(cfg));
        let resp = not_found_response(&ctx);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn empty_and_full_bodies_carry_their_payload() {
        let empty = empty_body().collect().await.unwrap().to_bytes();
        assert!(empty.is_empty());
        let full = full_body("abcd").collect().await.unwrap().to_bytes();
        assert_eq!(&full[..], b"abcd");
    }
}
