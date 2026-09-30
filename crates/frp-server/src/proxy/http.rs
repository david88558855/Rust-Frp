//! `http` and `https` virtual host proxies.
//!
//! Both types expose no dedicated listener: they register routes in the shared
//! vhost routers that the `vhostHTTPPort` / `vhostHTTPSPort` servers consult.
//!
//! * `http` terminates HTTP, applies the route's rewrite/auth/header policies
//!   and replays the request over a work connection with hyper.
//! * `https` never terminates TLS. The vhost server peeks the ClientHello for
//!   its SNI, routes on it, and the still-encrypted stream is copied verbatim
//!   to the client — the handshake runs end to end against the backend.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};

use anyhow::{anyhow, Result};
use frp_core::crypto::stream::WorkConnStream;
use frp_core::transport::ServerConn;
use frp_core::util::canonical_addr;
use frp_core::vhost::normalize_location;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue, HOST};
use hyper::{Method, Request, Response, StatusCode, Version};
use hyper_util::rt::TokioIo;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::context::ServerContext;
use crate::control::Control;
use crate::http_util::{
    bad_gateway_response, empty_body, full_body, not_found_response, RespBody, HOP_BY_HOP,
};
use crate::proxy::{join_user_stream, start_work_conn_for, ProxySpec, ServerProxy};

/// A route registered in one of the vhost routers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub domain: String,
    pub location: String,
    pub http_user: String,
}

/// `http` proxy: HTTP termination plus routing.
pub struct HttpProxy {
    spec: ProxySpec,
    routes: Mutex<Vec<RouteEntry>>,
    remote_addr: String,
    cancel: CancellationToken,
    ctx: Arc<ServerContext>,
    control: Weak<Control>,
}

impl ServerProxy for HttpProxy {
    fn name(&self) -> &str {
        &self.spec.name
    }

    fn proxy_type(&self) -> &str {
        "http"
    }

    fn spec(&self) -> &ProxySpec {
        &self.spec
    }

    fn remote_addr(&self) -> String {
        self.remote_addr.clone()
    }

    fn close(&self) {
        self.cancel.cancel();
        for route in self.routes.lock().unwrap().drain(..) {
            self.ctx
                .vhost_http
                .del(&route.domain, &route.location, &route.http_user);
        }
    }
}

/// `https` proxy: SNI routing with the TLS stream forwarded untouched.
pub struct HttpsProxy {
    spec: ProxySpec,
    domains: Vec<String>,
    remote_addr: String,
    cancel: CancellationToken,
    ctx: Arc<ServerContext>,
    control: Weak<Control>,
}

impl ServerProxy for HttpsProxy {
    fn name(&self) -> &str {
        &self.spec.name
    }

    fn proxy_type(&self) -> &str {
        "https"
    }

    fn spec(&self) -> &ProxySpec {
        &self.spec
    }

    fn remote_addr(&self) -> String {
        self.remote_addr.clone()
    }

    fn close(&self) {
        self.cancel.cancel();
        for domain in &self.domains {
            self.ctx.vhost_https.del_domain(domain);
        }
    }
}

/// Registers every domain/location pair of an `http` proxy.
pub fn start_http(
    ctx: Arc<ServerContext>,
    ctl: &Arc<Control>,
    spec: ProxySpec,
) -> Result<Arc<HttpProxy>> {
    if ctx.cfg.vhost_http_port <= 0 {
        return Err(anyhow!(
            "vhostHTTPPort is not configured, http proxies cannot be registered"
        ));
    }
    let domains = spec.domains(&ctx.cfg.sub_domain_host);
    if domains.is_empty() {
        return Err(anyhow!(
            "http proxy requires at least one customDomain or a subdomain"
        ));
    }
    let locations = if spec.locations.is_empty() {
        vec![String::new()]
    } else {
        spec.locations
            .iter()
            .map(|l| normalize_location(l))
            .collect()
    };

    let remote_addr = domains
        .iter()
        .map(|d| canonical_addr(d, ctx.cfg.vhost_http_port as u16))
        .collect::<Vec<_>>()
        .join(",");

    let proxy = Arc::new(HttpProxy {
        spec,
        routes: Mutex::new(Vec::new()),
        remote_addr,
        cancel: CancellationToken::new(),
        ctx: ctx.clone(),
        control: Arc::downgrade(ctl),
    });

    let mut registered: Vec<RouteEntry> = Vec::new();
    for domain in &domains {
        for location in &locations {
            let ok = ctx.vhost_http.add(
                domain,
                location,
                &proxy.spec.route_by_http_user,
                proxy.clone(),
            );
            if !ok {
                for route in &registered {
                    ctx.vhost_http
                        .del(&route.domain, &route.location, &route.http_user);
                }
                return Err(anyhow!(
                    "router config conflict for host [{domain}] location [{location}]"
                ));
            }
            registered.push(RouteEntry {
                domain: domain.clone(),
                location: location.clone(),
                http_user: proxy.spec.route_by_http_user.clone(),
            });
            info!(
                proxy = %proxy.spec.name,
                host = %domain,
                location = %location,
                route_by_http_user = %proxy.spec.route_by_http_user,
                "http proxy route registered"
            );
        }
    }
    *proxy.routes.lock().unwrap() = registered;
    Ok(proxy)
}

/// Registers every domain of an `https` proxy.
pub fn start_https(
    ctx: Arc<ServerContext>,
    ctl: &Arc<Control>,
    spec: ProxySpec,
) -> Result<Arc<HttpsProxy>> {
    if ctx.cfg.vhost_https_port <= 0 {
        return Err(anyhow!(
            "vhostHTTPSPort is not configured, https proxies cannot be registered"
        ));
    }
    let domains = spec.domains(&ctx.cfg.sub_domain_host);
    if domains.is_empty() {
        return Err(anyhow!(
            "https proxy requires at least one customDomain or a subdomain"
        ));
    }

    let remote_addr = domains
        .iter()
        .map(|d| canonical_addr(d, ctx.cfg.vhost_https_port as u16))
        .collect::<Vec<_>>()
        .join(",");

    let proxy = Arc::new(HttpsProxy {
        spec,
        domains: domains.clone(),
        remote_addr,
        cancel: CancellationToken::new(),
        ctx: ctx.clone(),
        control: Arc::downgrade(ctl),
    });

    let mut registered: Vec<String> = Vec::new();
    for domain in &domains {
        if !ctx.vhost_https.add(domain, "", "", proxy.clone()) {
            for done in &registered {
                ctx.vhost_https.del_domain(done);
            }
            return Err(anyhow!("router config conflict for host [{domain}]"));
        }
        registered.push(domain.clone());
        info!(
            proxy = %proxy.spec.name,
            host = %domain,
            "https proxy route registered"
        );
    }
    Ok(proxy)
}

impl HttpProxy {
    /// Opens and wraps a work connection for one user request.
    async fn open_work_conn(
        &self,
        peer: Option<&SocketAddr>,
    ) -> Result<WorkConnStream<ServerConn>> {
        let control = self
            .control
            .upgrade()
            .ok_or_else(|| anyhow!("control session is closed"))?;
        let mut work_conn = control.get_work_conn(&self.cancel).await?;
        work_conn
            .start(start_work_conn_for(&self.spec, peer))
            .await?;
        Ok(WorkConnStream::new(
            work_conn.into_stream(),
            &self.ctx.token,
            self.spec.use_encryption,
            self.spec.use_compression,
        ))
    }

    /// Forwards one HTTP request and returns the client's response.
    pub async fn forward(
        self: &Arc<Self>,
        mut req: Request<Incoming>,
        peer: SocketAddr,
    ) -> Response<RespBody> {
        // The remote address travels with the request so `build_outgoing` can
        // append it to X-Forwarded-For.
        req.extensions_mut().insert(peer);

        if req.method() == Method::CONNECT {
            return self.forward_connect(req, peer).await;
        }

        let work = match self.open_work_conn(Some(&peer)).await {
            Ok(work) => work,
            Err(e) => {
                warn!(proxy = %self.spec.name, error = %e, "no work connection for http request");
                return bad_gateway_response();
            }
        };

        self.ctx.metrics.open_connection(&self.spec.name);
        let result = self.forward_inner(work, req).await;
        self.ctx.metrics.close_connection(&self.spec.name);

        match result {
            Ok(resp) => resp,
            Err(e) => {
                warn!(proxy = %self.spec.name, error = %e, "http request failed");
                bad_gateway_response()
            }
        }
    }

    async fn forward_inner(
        &self,
        work: WorkConnStream<ServerConn>,
        req: Request<Incoming>,
    ) -> Result<Response<RespBody>> {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(work))
            .await
            .map_err(|e| anyhow!("http handshake over work connection: {e}"))?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!(error = %e, "work connection http session ended");
            }
        });

        let out = self.build_outgoing(req)?;
        let resp = sender
            .send_request(out)
            .await
            .map_err(|e| anyhow!("send request over work connection: {e}"))?;

        let (parts, body) = resp.into_parts();
        let mut out = Response::new(body.boxed());
        *out.status_mut() = parts.status;
        *out.version_mut() = parts.version;
        for (name, value) in parts.headers.iter() {
            if !is_hop_by_hop(name) {
                out.headers_mut().insert(name, value.clone());
            }
        }
        for (name, value) in &self.spec.response_headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                out.headers_mut().insert(name, value);
            }
        }
        Ok(out)
    }

    /// Applies host rewrite, `X-Forwarded-For` and `requestHeaders` policies.
    fn build_outgoing(&self, req: Request<Incoming>) -> Result<Request<Incoming>> {
        let (parts, body) = req.into_parts();
        let path = match parts.uri.path_and_query() {
            Some(pq) => pq.as_str().to_string(),
            None => "/".to_string(),
        };

        let mut builder = Request::builder()
            .method(parts.method.clone())
            .uri(path)
            .version(Version::HTTP_11);

        for (name, value) in parts.headers.iter() {
            if is_hop_by_hop(name) {
                continue;
            }
            builder = builder.header(name, value);
        }

        // Upstream restores the inbound X-Forwarded-For and then appends the
        // immediate client address.
        let forwarded = parts
            .headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>()
            .join(", ");
        let client_ip = match parts.extensions.get::<SocketAddr>() {
            Some(addr) => addr.ip().to_string(),
            None => parts
                .headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string(),
        };
        if !client_ip.is_empty() {
            let value = if forwarded.is_empty() {
                client_ip
            } else {
                format!("{forwarded}, {client_ip}")
            };
            builder = builder.header("x-forwarded-for", value);
        }

        if !self.spec.host_header_rewrite.is_empty() {
            builder = builder.header(HOST, self.spec.host_header_rewrite.as_str());
        }

        // Route level request headers win, matching upstream ordering.
        for (name, value) in &self.spec.request_headers {
            builder = builder.header(name.as_str(), value.as_str());
        }

        builder
            .body(body)
            .map_err(|e| anyhow!("rebuild request for the work connection: {e}"))
    }

    /// Tunnels a `CONNECT` request, as upstream's hijack handler does.
    async fn forward_connect(
        self: &Arc<Self>,
        req: Request<Incoming>,
        peer: SocketAddr,
    ) -> Response<RespBody> {
        let head = match build_connect_head(&req) {
            Ok(head) => head,
            Err(e) => {
                warn!(proxy = %self.spec.name, error = %e, "invalid CONNECT request");
                return not_found_response(&self.ctx);
            }
        };
        let work = match self.open_work_conn(Some(&peer)).await {
            Ok(work) => work,
            Err(e) => {
                warn!(proxy = %self.spec.name, error = %e, "no work connection for CONNECT");
                return bad_gateway_response();
            }
        };
        let on_upgrade = hyper::upgrade::on(req);
        let name = self.spec.name.clone();
        let metrics = self.ctx.metrics.clone();

        tokio::spawn(async move {
            let mut work = work;
            match on_upgrade.await {
                Ok(upgraded) => {
                    if let Err(e) = work.write_all(head.as_bytes()).await {
                        debug!(proxy = %name, error = %e, "CONNECT request was not delivered");
                        return;
                    }
                    if let Err(e) = work.flush().await {
                        debug!(proxy = %name, error = %e, "CONNECT request flush failed");
                        return;
                    }
                    metrics.open_connection(&name);
                    let (traffic_in, traffic_out) =
                        join_user_stream(work, TokioIo::new(upgraded)).await;
                    metrics.close_connection(&name);
                    metrics.add_traffic_in(&name, traffic_in as i64);
                    metrics.add_traffic_out(&name, traffic_out as i64);
                }
                Err(e) => debug!(proxy = %name, error = %e, "client upgrade failed"),
            }
        });

        let mut resp = Response::new(empty_body());
        *resp.status_mut() = StatusCode::OK;
        resp
    }
}

impl HttpsProxy {
    /// Copies an already-peeked TLS stream to the client's local service.
    pub async fn forward_raw<S>(self: &Arc<Self>, stream: S, peer: SocketAddr) -> Result<(u64, u64)>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let control = self
            .control
            .upgrade()
            .ok_or_else(|| anyhow!("control session is closed"))?;
        let mut work_conn = control.get_work_conn(&self.cancel).await?;
        work_conn
            .start(start_work_conn_for(&self.spec, Some(&peer)))
            .await?;

        let work = WorkConnStream::new(
            work_conn.into_stream(),
            &self.ctx.token,
            self.spec.use_encryption,
            self.spec.use_compression,
        );

        self.ctx.metrics.open_connection(&self.spec.name);
        let (traffic_in, traffic_out) = join_user_stream(work, stream).await;
        self.ctx.metrics.close_connection(&self.spec.name);
        self.ctx
            .metrics
            .add_traffic_in(&self.spec.name, traffic_in as i64);
        self.ctx
            .metrics
            .add_traffic_out(&self.spec.name, traffic_out as i64);
        Ok((traffic_in, traffic_out))
    }
}

/// Renders the request head that a `CONNECT` tunnel must forward verbatim.
pub fn build_connect_head<B>(req: &Request<B>) -> Result<String> {
    let authority = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            req.headers()
                .get(HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .ok_or_else(|| anyhow!("CONNECT without a target authority"))?;

    let mut head = format!("{} {} {:?}\r\n", req.method(), authority, req.version());
    for (name, value) in req.headers() {
        let Ok(value) = value.to_str() else { continue };
        head.push_str(name.as_str());
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    Ok(head)
}

/// Whether a header must not be forwarded, matching Go's reverse proxy.
pub fn is_hop_by_hop(name: &HeaderName) -> bool {
    let name = name.as_str();
    HOP_BY_HOP.contains(&name)
}

/// Response helper used by the vhost server for unroutable requests.
pub fn route_not_found(ctx: &ServerContext) -> Response<RespBody> {
    not_found_response(ctx)
}

/// Wraps a plain payload as the vhost response body.
pub fn text_response(status: StatusCode, text: &str) -> Response<RespBody> {
    let mut resp = Response::new(full_body(text.to_string()));
    *resp.status_mut() = status;
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_detection() {
        assert!(is_hop_by_hop(&HeaderName::from_static("connection")));
        assert!(is_hop_by_hop(&HeaderName::from_static("transfer-encoding")));
        assert!(!is_hop_by_hop(&HeaderName::from_static("content-type")));
        assert!(!is_hop_by_hop(&HeaderName::from_static("host")));
    }

    #[test]
    fn connect_head_uses_authority_then_host_header() {
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri("example.com:443")
            .header(HOST, "example.com:443")
            .header("user-agent", "curl/8")
            .body(())
            .unwrap();
        let head = build_connect_head(&req).unwrap();
        assert!(head.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(head.contains("user-agent: curl/8\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
    }

    #[test]
    fn connect_without_authority_is_rejected() {
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri("/")
            .body(())
            .unwrap();
        assert!(build_connect_head(&req).is_err());
    }

    #[test]
    fn domain_less_proxies_cannot_register() {
        let mut cfg = frp_core::config::server::ServerConfig::default();
        cfg.complete();
        cfg.vhost_http_port = 8080;
        let ctx = Arc::new(crate::test_support::context_with(cfg));

        let (out_tx, _out_rx) = tokio::sync::mpsc::unbounded_channel();
        let (work_req_tx, _work_req_rx) = tokio::sync::mpsc::unbounded_channel();
        let (work_conn_tx, _work_conn_rx) = tokio::sync::mpsc::unbounded_channel();
        let ctl = Arc::new(Control::new(
            ctx.clone(),
            frp_core::msg::Login::default(),
            "run1".into(),
            "127.0.0.1:1".into(),
            out_tx,
            work_req_tx,
            work_conn_tx,
        ));

        let spec = ProxySpec {
            name: "web".into(),
            proxy_type: "http".into(),
            ..Default::default()
        };
        let err = start_http(ctx.clone(), &ctl, spec)
            .err()
            .expect("registering an http proxy without domains must fail");
        assert!(err.to_string().contains("customDomain"));

        // With vhostHTTPPort unset the proxy must be refused outright.
        let mut cfg = frp_core::config::server::ServerConfig::default();
        cfg.complete();
        cfg.vhost_http_port = 0;
        let ctx = Arc::new(crate::test_support::context_with(cfg));
        let spec = ProxySpec {
            name: "web".into(),
            proxy_type: "http".into(),
            custom_domains: vec!["a.example.com".into()],
            ..Default::default()
        };
        let err = start_http(ctx, &ctl, spec)
            .err()
            .expect("registering an http proxy without vhostHTTPPort must fail");
        assert!(err.to_string().contains("vhostHTTPPort"));
    }

    #[test]
    fn http_proxy_registers_and_unregisters_routes() {
        let mut cfg = frp_core::config::server::ServerConfig::default();
        cfg.complete();
        cfg.vhost_http_port = 8080;
        cfg.sub_domain_host = "example.com".into();
        let ctx = Arc::new(crate::test_support::context_with(cfg));

        let (out_tx, _out_rx) = tokio::sync::mpsc::unbounded_channel();
        let (work_req_tx, _work_req_rx) = tokio::sync::mpsc::unbounded_channel();
        let (work_conn_tx, _work_conn_rx) = tokio::sync::mpsc::unbounded_channel();
        let ctl = Arc::new(Control::new(
            ctx.clone(),
            frp_core::msg::Login::default(),
            "run1".into(),
            "127.0.0.1:1".into(),
            out_tx,
            work_req_tx,
            work_conn_tx,
        ));

        let spec = ProxySpec {
            name: "web".into(),
            proxy_type: "http".into(),
            custom_domains: vec!["a.example.com".into()],
            sub_domain: "demo".into(),
            locations: vec!["/api".into(), "/".into()],
            route_by_http_user: String::new(),
            ..Default::default()
        };
        let proxy = start_http(ctx.clone(), &ctl, spec).unwrap();
        assert_eq!(ctx.vhost_http.len(), 4, "2 domains x 2 locations");
        assert!(ctx
            .vhost_http
            .route("a.example.com", "/api/x", "")
            .is_some());
        assert!(ctx.vhost_http.route("demo.example.com", "/", "").is_some());
        assert_eq!(
            proxy.remote_addr(),
            "a.example.com:8080,demo.example.com:8080"
        );

        proxy.close();
        assert!(ctx.vhost_http.is_empty());
    }

    #[test]
    fn duplicate_http_route_is_rejected() {
        let mut cfg = frp_core::config::server::ServerConfig::default();
        cfg.complete();
        cfg.vhost_http_port = 8080;
        let ctx = Arc::new(crate::test_support::context_with(cfg));

        let (out_tx, _out_rx) = tokio::sync::mpsc::unbounded_channel();
        let (work_req_tx, _work_req_rx) = tokio::sync::mpsc::unbounded_channel();
        let (work_conn_tx, _work_conn_rx) = tokio::sync::mpsc::unbounded_channel();
        let ctl = Arc::new(Control::new(
            ctx.clone(),
            frp_core::msg::Login::default(),
            "run1".into(),
            "127.0.0.1:1".into(),
            out_tx,
            work_req_tx,
            work_conn_tx,
        ));

        let spec = ProxySpec {
            name: "web".into(),
            proxy_type: "http".into(),
            custom_domains: vec!["a.example.com".into()],
            ..Default::default()
        };
        let _first = start_http(ctx.clone(), &ctl, spec.clone()).unwrap();
        let err = start_http(ctx.clone(), &ctl, spec)
            .err()
            .expect("a duplicate route must be rejected");
        assert!(err.to_string().contains("conflict"));
        assert_eq!(ctx.vhost_http.len(), 1, "the failed attempt must roll back");
    }

    #[test]
    fn https_proxy_registers_domains() {
        let mut cfg = frp_core::config::server::ServerConfig::default();
        cfg.complete();
        cfg.vhost_https_port = 8443;
        let ctx = Arc::new(crate::test_support::context_with(cfg));

        let (out_tx, _out_rx) = tokio::sync::mpsc::unbounded_channel();
        let (work_req_tx, _work_req_rx) = tokio::sync::mpsc::unbounded_channel();
        let (work_conn_tx, _work_conn_rx) = tokio::sync::mpsc::unbounded_channel();
        let ctl = Arc::new(Control::new(
            ctx.clone(),
            frp_core::msg::Login::default(),
            "run1".into(),
            "127.0.0.1:1".into(),
            out_tx,
            work_req_tx,
            work_conn_tx,
        ));

        let spec = ProxySpec {
            name: "secure".into(),
            proxy_type: "https".into(),
            custom_domains: vec!["s.example.com".into()],
            ..Default::default()
        };
        let proxy = start_https(ctx.clone(), &ctl, spec).unwrap();
        assert!(ctx.vhost_https.route("s.example.com", "/", "").is_some());
        assert_eq!(proxy.remote_addr(), "s.example.com:8443");

        proxy.close();
        assert!(ctx.vhost_https.is_empty());
    }
}
