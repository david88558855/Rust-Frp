//! Server dashboard, admin API and Prometheus endpoint.
//!
//! Implemented directly on hyper rather than through a web framework so the
//! dependency surface of the server stays small. The HTML page is embedded and
//! pulls its data from the same JSON API the CLI can use.

use std::convert::Infallible;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::net::TcpListener;
use tracing::{debug, info};

use crate::context::ServerContext;

/// Serves the dashboard until the process exits.
pub async fn serve(ctx: Arc<ServerContext>) -> Result<()> {
    let Some(addr) = ctx.cfg.web_server.bind_addr() else {
        return Ok(());
    };
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind dashboard on {addr}"))?;
    info!(addr = %addr, "dashboard listening");

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                debug!(error = %e, "dashboard accept failed");
                continue;
            }
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(sock);
            let service = service_fn(move |req| handle(req, ctx.clone()));
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                debug!(client = %peer, error = %e, "dashboard connection ended");
            }
        });
    }
}

#[derive(Serialize)]
struct ServerInfo {
    version: String,
    bind_port: i32,
    vhost_http_port: i32,
    vhost_https_port: i32,
    sub_domain_host: String,
    allow_ports: Vec<String>,
    tcp_mux: bool,
    heartbeat_timeout: i64,
    cur_conns: i64,
    client_counts: usize,
    proxy_counts: usize,
    total_traffic_in: i64,
    total_traffic_out: i64,
}

#[derive(Serialize)]
struct GeneralResponse {
    code: u16,
    msg: String,
}

async fn handle<B>(
    req: Request<B>,
    ctx: Arc<ServerContext>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let resp = match route(req, ctx).await {
        Ok(resp) => resp,
        Err(err) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &GeneralResponse {
                code: 500,
                msg: err.to_string(),
            },
        ),
    };
    Ok(resp)
}

async fn route<B>(req: Request<B>, ctx: Arc<ServerContext>) -> Result<Response<Full<Bytes>>> {
    if !authorized(&req, &ctx) {
        let mut resp = text_response(StatusCode::UNAUTHORIZED, "401 Unauthorized\n");
        // Upstream sets the realm to "Restricted" in HTTPAuthMiddleware
        // (pkg/util/net/http.go), not to the product name.
        resp.headers_mut().insert(
            hyper::header::WWW_AUTHENTICATE,
            hyper::header::HeaderValue::from_static("Basic realm=\"Restricted\""),
        );
        return Ok(resp);
    }

    let path = req.uri().path().to_string();
    let method = req.method().clone();

    match (method, path.as_str()) {
        (Method::GET, "/") | (Method::GET, "/index.html") => {
            Ok(html_response(INDEX_HTML))
        }
        (Method::GET, "/healthz") => Ok(text_response(StatusCode::OK, "ok\n")),
        (Method::GET, "/metrics") => {
            if !ctx.cfg.enable_prometheus {
                return Ok(text_response(
                    StatusCode::NOT_FOUND,
                    "prometheus metrics are disabled\n",
                ));
            }
            Ok(text_response(
                StatusCode::OK,
                &ctx.metrics.render_prometheus(),
            ))
        }
        (Method::GET, "/api/serverinfo") => {
            let snap = ctx.metrics.snapshot();
            Ok(json_response(
                StatusCode::OK,
                &ServerInfo {
                    version: frp_core::FRP_VERSION.to_string(),
                    bind_port: ctx.cfg.bind_port,
                    vhost_http_port: ctx.cfg.vhost_http_port,
                    vhost_https_port: ctx.cfg.vhost_https_port,
                    sub_domain_host: ctx.cfg.sub_domain_host.clone(),
                    allow_ports: ctx
                        .cfg
                        .allow_ports
                        .iter()
                        .filter_map(|r| r.bounds())
                        .map(|(lo, hi)| {
                            if lo == hi {
                                lo.to_string()
                            } else {
                                format!("{lo}-{hi}")
                            }
                        })
                        .collect(),
                    tcp_mux: ctx.cfg.transport.tcp_mux_enabled(),
                    heartbeat_timeout: ctx.cfg.transport.heartbeat_timeout_secs(),
                    cur_conns: snap.cur_conns,
                    client_counts: snap.clients.iter().filter(|c| c.online).count(),
                    proxy_counts: snap.proxies.len(),
                    total_traffic_in: snap.total_traffic_in,
                    total_traffic_out: snap.total_traffic_out,
                },
            ))
        }
        (Method::GET, "/api/clients") => {
            Ok(json_response(StatusCode::OK, &ctx.metrics.snapshot().clients))
        }
        (Method::GET, "/api/proxy") => {
            Ok(json_response(StatusCode::OK, &ctx.metrics.snapshot().proxies))
        }
        (Method::GET, "/api/traffic") => {
            Ok(json_response(StatusCode::OK, &ctx.metrics.snapshot()))
        }
        (Method::GET, "/api/visitors") => Ok(json_response(
            StatusCode::OK,
            &serde_json::json!({ "count": ctx.visitors.len() }),
        )),
        _ => Ok(text_response(StatusCode::NOT_FOUND, "404 not found\n")),
    }
}

fn authorized<B>(req: &Request<B>, ctx: &ServerContext) -> bool {
    let ws = &ctx.cfg.web_server;
    if ws.user.is_empty() {
        return true;
    }
    let Some(value) = req.headers().get(hyper::header::AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Some(encoded) = value.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = B64.decode(encoded.trim()) else {
        return false;
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
        return false;
    };
    let Some((user, pass)) = decoded.split_once(':') else {
        return false;
    };
    !user.is_empty() && user == ws.user && pass == ws.password
}

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = Response::new(Full::new(Bytes::from(body)));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json; charset=utf-8"),
    );
    resp
}

fn text_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from(body.to_string())));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

fn html_response(body: &str) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from(body.to_string())));
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}

/// Embedded dashboard page.
const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rust-Frp Server Dashboard</title>
<style>
  :root { color-scheme: light; }
  body { margin: 0; font: 14px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif;
         background: #f5f6f8; color: #1f2328; }
  header { background: #fff; border-bottom: 1px solid #e3e6ea; padding: 14px 24px;
           display: flex; align-items: baseline; gap: 12px; }
  h1 { font-size: 17px; margin: 0; }
  .muted { color: #6b7280; font-size: 12px; }
  main { padding: 20px 24px; display: grid; gap: 18px; }
  section { background: #fff; border: 1px solid #e3e6ea; border-radius: 8px; padding: 16px; }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .06em;
       color: #6b7280; margin: 0 0 12px; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid #eef0f3; }
  th { color: #6b7280; font-weight: 600; font-size: 12px; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  .cards { display: flex; flex-wrap: wrap; gap: 12px; }
  .card { flex: 1 1 150px; background: #fafbfc; border: 1px solid #eef0f3;
          border-radius: 6px; padding: 12px; }
  .card .v { font-size: 20px; font-weight: 600; }
  .card .k { color: #6b7280; font-size: 12px; }
</style>
</head>
<body>
<header><h1>Rust-Frp Server</h1><span class="muted" id="ver"></span></header>
<main>
  <section>
    <h2>Overview</h2>
    <div class="cards" id="overview"></div>
  </section>
  <section>
    <h2>Proxies</h2>
    <table id="proxies"><thead><tr><th>Name</th><th>Type</th><th>User</th>
      <th class="num">Conns</th><th class="num">In</th><th class="num">Out</th></tr></thead>
      <tbody></tbody></table>
  </section>
  <section>
    <h2>Clients</h2>
    <table id="clients"><thead><tr><th>Client</th><th>User</th><th>Version</th>
      <th>Hostname</th><th>Online</th></tr></thead><tbody></tbody></table>
  </section>
</main>
<script>
const esc = (v) => String(v == null ? '' : v).replace(/[&<>"]/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const human = (n) => n < 1024 ? n + ' B'
  : n < 1048576 ? (n/1024).toFixed(1) + ' KiB'
  : n < 1073741824 ? (n/1048576).toFixed(1) + ' MiB'
  : (n/1073741824).toFixed(2) + ' GiB';

function card(k, v) { return `<div class="card"><div class="v">${esc(v)}</div>
  <div class="k">${esc(k)}</div></div>`; }

async function refresh() {
  const [info, proxies, clients] = await Promise.all([
    fetch('api/serverinfo').then(r => r.json()),
    fetch('api/proxy').then(r => r.json()),
    fetch('api/clients').then(r => r.json()),
  ]);
  document.getElementById('ver').textContent = 'v' + info.version;
  document.getElementById('overview').innerHTML = [
    card('Online clients', info.client_counts),
    card('Proxies', info.proxy_counts),
    card('Connections', info.cur_conns),
    card('Traffic in', human(info.total_traffic_in)),
    card('Traffic out', human(info.total_traffic_out)),
  ].join('');
  document.querySelector('#proxies tbody').innerHTML = proxies.map(p =>
    `<tr><td>${esc(p.name)}</td><td>${esc(p.type)}</td><td>${esc(p.user)}</td>
     <td class="num">${esc(p.cur_conns)}</td>
     <td class="num">${human(p.today_traffic_in)}</td>
     <td class="num">${human(p.today_traffic_out)}</td></tr>`).join('');
  document.querySelector('#clients tbody').innerHTML = clients.map(c =>
    `<tr><td>${esc(c.client_id)}</td><td>${esc(c.user)}</td><td>${esc(c.version)}</td>
     <td>${esc(c.hostname)}</td><td>${c.online ? 'yes' : 'no'}</td></tr>`).join('');
}
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;

    fn request(uri: &str, auth: Option<&str>) -> Request<Full<Bytes>> {
        let mut builder = Request::builder().method("GET").uri(uri);
        if let Some(auth) = auth {
            builder = builder.header("authorization", auth);
        }
        builder.body(Full::new(Bytes::new())).unwrap()
    }

    fn basic(user: &str, pass: &str) -> String {
        format!("Basic {}", B64.encode(format!("{user}:{pass}")))
    }

    #[tokio::test]
    async fn serverinfo_route_reports_configuration() {
        let ctx = Arc::new(test_support::context());
        let resp = route(request("/api/serverinfo", None), ctx.clone())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("\"bind_port\":7000"));
        assert!(text.contains("\"version\":\"0.71.0\""));
    }

    #[tokio::test]
    async fn metrics_are_gated_by_configuration() {
        let ctx = Arc::new(test_support::context());
        let resp = route(request("/metrics", None), ctx.clone()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let mut cfg = frp_core::config::server::ServerConfig::default();
        cfg.complete();
        cfg.enable_prometheus = true;
        let ctx = Arc::new(test_support::context_with(cfg));
        let resp = route(request("/metrics", None), ctx).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn basic_auth_is_enforced_when_configured() {
        let mut cfg = frp_core::config::server::ServerConfig::default();
        cfg.complete();
        cfg.web_server.user = "admin".into();
        cfg.web_server.password = "s3cret".into();
        let ctx = Arc::new(test_support::context_with(cfg));

        let resp = route(request("/api/serverinfo", None), ctx.clone())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = route(
            request("/api/serverinfo", Some(&basic("admin", "s3cret"))),
            ctx.clone(),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = route(
            request("/api/serverinfo", Some(&basic("admin", "wrong"))),
            ctx,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unknown_route_is_404() {
        let ctx = Arc::new(test_support::context());
        let resp = route(request("/nope", None), ctx).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn index_page_is_served() {
        let ctx = Arc::new(test_support::context());
        let resp = route(request("/", None), ctx).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
