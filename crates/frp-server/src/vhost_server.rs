//! The `vhostHTTPPort` and `vhostHTTPSPort` servers.
//!
//! The HTTP port terminates HTTP, picks a route and hands the request to the
//! owning `http` proxy. The HTTPS port never terminates TLS: it peeks the
//! ClientHello to learn the SNI, picks a route and copies the stream verbatim,
//! so the handshake happens between the browser and the backend.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info};

use crate::context::ServerContext;
use crate::http_util::{
    auth_required_response, canonical_host, check_route_auth, not_found_response, route_http_user,
    RespBody,
};
use crate::proxy::ServerProxy;

/// Serves the plain HTTP virtual host port until the process exits.
pub async fn serve_http(ctx: Arc<ServerContext>) -> Result<()> {
    if ctx.cfg.vhost_http_port <= 0 {
        return Ok(());
    }
    let addr = format!("{}:{}", ctx.cfg.proxy_bind(), ctx.cfg.vhost_http_port);
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind vhost HTTP port on {addr}"))?;
    info!(addr = %addr, "http vhost listening");

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                debug!(error = %e, "vhost http accept failed");
                continue;
            }
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(sock);
            let service = service_fn(move |req: Request<Incoming>| {
                let ctx = ctx.clone();
                async move { handle_http(req, ctx, peer).await }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                debug!(client = %peer, error = %e, "vhost http connection ended");
            }
        });
    }
}

/// Serves the SNI-routed HTTPS virtual host port until the process exits.
pub async fn serve_https(ctx: Arc<ServerContext>) -> Result<()> {
    if ctx.cfg.vhost_https_port <= 0 {
        return Ok(());
    }
    let addr = format!("{}:{}", ctx.cfg.proxy_bind(), ctx.cfg.vhost_https_port);
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind vhost HTTPS port on {addr}"))?;
    info!(addr = %addr, "https vhost listening (SNI routing)");

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                debug!(error = %e, "vhost https accept failed");
                continue;
            }
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            handle_https_connection(&ctx, sock, peer).await;
        });
    }
}

async fn handle_https_connection(ctx: &Arc<ServerContext>, mut sock: TcpStream, peer: SocketAddr) {
    let peeked = match frp_core::tls_sni::peek_client_hello(&mut sock).await {
        Ok(peeked) => peeked,
        Err(e) => {
            debug!(client = %peer, error = %e, "unable to read the TLS ClientHello");
            return;
        }
    };
    let host = peeked.server_name.clone().unwrap_or_default();
    let Some(proxy) = ctx.vhost_https.route(&host, "/", "") else {
        debug!(client = %peer, sni = %host, "no https route for this SNI");
        return;
    };

    // The peeked bytes are replayed so the backend sees the real handshake.
    let stream = frp_core::transport::PrefixedStream::new(sock, peeked.prefix);
    if let Err(e) = proxy.forward_raw(stream, peer).await {
        debug!(client = %peer, sni = %host, error = %e, "https tunnel ended");
    }
}

/// Routes and forwards one HTTP request.
async fn handle_http(
    req: Request<Incoming>,
    ctx: Arc<ServerContext>,
    peer: SocketAddr,
) -> Result<Response<RespBody>, Infallible> {
    let host = canonical_host(req.headers());
    // An absolute-form request URI means the client is talking to us as a proxy.
    let proxy_mode = req.uri().host().is_some();
    let user = route_http_user(req.headers(), proxy_mode);
    let path = req.uri().path().to_string();

    let Some(proxy) = ctx.vhost_http.route(&host, &path, &user) else {
        return Ok(not_found_response(&ctx));
    };

    if !check_route_auth(
        &proxy.spec().http_user,
        &proxy.spec().http_pwd,
        req.headers(),
        proxy_mode,
    ) {
        return Ok(auth_required_response(proxy_mode));
    }

    Ok(proxy.forward(req, peer).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::Control;
    use crate::proxy::http::{start_http, start_https};
    use crate::proxy::{ProxySpec, ServerProxy};
    use base64::Engine as _;
    use frp_core::config::server::ServerConfig;
    use hyper::body::Bytes;
    use hyper::header::HOST;
    use hyper::StatusCode;

    fn ctx_with_vhost() -> Arc<ServerContext> {
        let mut cfg = ServerConfig::default();
        cfg.complete();
        cfg.vhost_http_port = 8080;
        cfg.vhost_https_port = 8443;
        Arc::new(crate::test_support::context_with(cfg))
    }

    fn control(ctx: &Arc<ServerContext>) -> Arc<Control> {
        let (out_tx, _out_rx) = tokio::sync::mpsc::unbounded_channel();
        let (work_req_tx, _work_req_rx) = tokio::sync::mpsc::unbounded_channel();
        let (work_conn_tx, _work_conn_rx) = tokio::sync::mpsc::unbounded_channel();
        Arc::new(Control::new(
            ctx.clone(),
            frp_core::msg::Login::default(),
            "run1".into(),
            "127.0.0.1:1".into(),
            out_tx,
            work_req_tx,
            work_conn_tx,
        ))
    }

    fn head_request(host: &str, path: &str, auth: Option<&str>) -> Request<Bytes> {
        let mut builder = Request::builder().uri(path).header(HOST, host);
        if let Some(auth) = auth {
            builder = builder.header("authorization", auth);
        }
        builder.body(Bytes::new()).unwrap()
    }

    #[test]
    fn unroutable_host_is_404() {
        let ctx = ctx_with_vhost();
        let req = head_request("missing.example.com", "/", None);
        let host = canonical_host(req.headers());
        assert_eq!(host, "missing.example.com");
        assert!(ctx.vhost_http.route(&host, "/", "").is_none());
        assert_eq!(not_found_response(&ctx).status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn host_header_drives_the_lookup_and_port_is_ignored() {
        let ctx = ctx_with_vhost();
        let ctl = control(&ctx);
        let spec = ProxySpec {
            name: "web".into(),
            proxy_type: "http".into(),
            custom_domains: vec!["a.example.com".into()],
            ..Default::default()
        };
        let proxy = start_http(ctx.clone(), &ctl, spec).unwrap();

        let req = head_request("a.example.com:8080", "/", None);
        let host = canonical_host(req.headers());
        let found = ctx.vhost_http.route(&host, "/", "").expect("route");
        assert_eq!(found.name(), "web");
        proxy.close();
    }

    #[test]
    fn route_by_http_user_selects_and_falls_back() {
        let ctx = ctx_with_vhost();
        let ctl = control(&ctx);

        let mut bob_spec = ProxySpec {
            name: "bob".into(),
            proxy_type: "http".into(),
            custom_domains: vec!["a.example.com".into()],
            route_by_http_user: "bob".into(),
            ..Default::default()
        };
        bob_spec.http_user = "bob".into();
        bob_spec.http_pwd = "pw".into();
        let bob = start_http(ctx.clone(), &ctl, bob_spec).unwrap();

        let any_spec = ProxySpec {
            name: "any".into(),
            proxy_type: "http".into(),
            custom_domains: vec!["a.example.com".into()],
            ..Default::default()
        };
        let any = start_http(ctx.clone(), &ctl, any_spec).unwrap();

        let auth = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("bob:pw")
        );
        let bob_req = head_request("a.example.com", "/", Some(&auth));
        let user = route_http_user(bob_req.headers(), false);
        assert_eq!(user, "bob");
        assert_eq!(
            ctx.vhost_http
                .route("a.example.com", "/", &user)
                .unwrap()
                .name(),
            "bob"
        );

        let anon_req = head_request("a.example.com", "/", None);
        let user = route_http_user(anon_req.headers(), false);
        assert_eq!(user, "");
        assert_eq!(
            ctx.vhost_http
                .route("a.example.com", "/", &user)
                .unwrap()
                .name(),
            "any"
        );

        bob.close();
        any.close();
    }

    #[test]
    fn https_routes_are_matched_by_sni() {
        let ctx = ctx_with_vhost();
        let ctl = control(&ctx);
        let spec = ProxySpec {
            name: "secure".into(),
            proxy_type: "https".into(),
            custom_domains: vec!["s.example.com".into()],
            ..Default::default()
        };
        let proxy = start_https(ctx.clone(), &ctl, spec).unwrap();
        assert!(ctx.vhost_https.route("s.example.com", "/", "").is_some());
        assert!(ctx
            .vhost_https
            .route("other.example.com", "/", "")
            .is_none());
        proxy.close();
    }

    #[test]
    fn auth_and_error_statuses() {
        assert_eq!(
            auth_required_response(false).status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            auth_required_response(true).status(),
            StatusCode::PROXY_AUTHENTICATION_REQUIRED
        );
        assert!(!check_route_auth(
            "u",
            "p",
            head_request("h", "/", None).headers(),
            false
        ));
        assert!(check_route_auth(
            "",
            "",
            head_request("h", "/", None).headers(),
            false
        ));
    }
}
