//! The client admin HTTP server, matching upstream `client/api_router.go` and
//! `client/http/controller.go`.
//!
//! `[webServer]` binds this server. `/healthz` is unauthenticated; everything
//! else sits behind HTTP basic auth, which is skipped when both `user` and
//! `password` are empty. The observable details that matter and are easy to
//! get wrong:
//!
//! * an error is `{"Code":<code>,"Msg":"..."}` — upstream's `GeneralResponse`
//!   has no JSON tags, so the keys are capitalised;
//! * a handler returning nothing is `200` with an empty body;
//! * `/api/config` returns the raw file contents, not JSON;
//! * `/api/status` groups proxies by type and sorts each group by name.
//!
//! The server only *reads* shared state; mutations go through the store and a
//! recompute that swaps the effective configuration and asks the service to
//! reconnect, which is how a store change reaches the running proxies here.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use bytes::Bytes;
use frp_core::config::{ClientConfig, ProxyConfig, VisitorConfig};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::control::ControlHandle;
use crate::store::{prepare_proxy, prepare_visitor, Store, StoreError};

type RespBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

const PROXY_TYPES: [&str; 8] = [
    "tcp", "udp", "http", "https", "tcpmux", "stcp", "sudp", "xtcp",
];
const VISITOR_TYPES: [&str; 3] = ["stcp", "sudp", "xtcp"];

/// Shared, observable state the admin server reads and the service updates.
pub struct AdminState {
    /// Basic auth credentials from `[webServer]`.
    pub user: String,
    pub password: String,
    /// The config file path, for `/api/config` and `/api/reload`.
    pub config_file: Option<PathBuf>,
    /// The file-derived config, refreshed on `/api/reload`.
    pub base: RwLock<ClientConfig>,
    /// The effective config: `base` merged with the enabled store entries.
    pub current: RwLock<ClientConfig>,
    /// The live control session, for `/api/status`.
    pub live: Mutex<Option<Arc<ControlHandle>>>,
    /// The store, present when `[store] path` is set.
    pub store: Option<Arc<Store>>,
    /// Cancels the whole service, for `/api/stop`.
    pub cancel: CancellationToken,
}

impl AdminState {
    fn is_store_enabled(&self, name: &str) -> bool {
        self.store
            .as_ref()
            .and_then(|s| s.get_proxy(name))
            .map(|p| p.base().is_enabled())
            .unwrap_or(false)
    }

    /// `serverAddr` from the client common config (host only, no port).
    fn server_addr(&self) -> String {
        self.current.read().unwrap().common.server_addr.clone()
    }
}

/// Builds a response body from bytes.
fn body(bytes: impl Into<Bytes>) -> RespBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

fn response(
    status: StatusCode,
    content_type: Option<&'static str>,
    bytes: Bytes,
) -> Response<RespBody> {
    let mut response = Response::new(body(bytes));
    *response.status_mut() = status;
    if let Some(content_type) = content_type {
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    }
    response
}

fn ok_empty() -> Response<RespBody> {
    Response::new(body(Bytes::new()))
}

fn ok_json(value: &Value) -> Response<RespBody> {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    response(StatusCode::OK, Some("application/json"), Bytes::from(bytes))
}

fn ok_text(text: &str) -> Response<RespBody> {
    response(StatusCode::OK, None, Bytes::from(text.to_string()))
}

/// Upstream's error envelope, capitalised keys and all.
fn api_error(code: u16, msg: &str) -> Response<RespBody> {
    let value = json!({ "Code": code, "Msg": msg });
    let bytes = serde_json::to_vec(&value).unwrap_or_default();
    response(
        StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Some("application/json"),
        Bytes::from(bytes),
    )
}

fn auth_required() -> Response<RespBody> {
    let mut response = response(
        StatusCode::UNAUTHORIZED,
        Some("text/plain; charset=utf-8"),
        Bytes::from_static(b"Unauthorized\n"),
    );
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static(r#"Basic realm="Restricted""#),
    );
    response
}

fn not_found() -> Response<RespBody> {
    response(
        StatusCode::NOT_FOUND,
        Some("text/plain; charset=utf-8"),
        Bytes::from_static(b"404 page not found\n"),
    )
}

/// Reproduces `NewHTTPAuthMiddleware`: empty credentials disable the check.
fn authorized(headers: &HeaderMap, user: &str, password: &str) -> bool {
    if user.is_empty() && password.is_empty() {
        return true;
    }
    let Some(value) = headers.get(AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Some(encoded) = value.strip_prefix("Basic ") else {
        return false;
    };
    use base64::Engine as _;
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
        return false;
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
        return false;
    };
    let Some((offered_user, offered_password)) = decoded.split_once(':') else {
        return false;
    };
    frp_core::crypto::auth::constant_time_eq(user, offered_user)
        && frp_core::crypto::auth::constant_time_eq(password, offered_password)
}

/// Binds and serves the admin HTTP server until `state.cancel` is cancelled.
pub async fn run(state: Arc<AdminState>) -> Result<(), anyhow::Error> {
    let bind = {
        let common = &state.current.read().unwrap().common;
        common
            .web_server
            .bind_addr()
            .expect("the admin server only starts when webServer.port is set")
    };
    let listener = TcpListener::bind(&bind)
        .await
        .map_err(|e| anyhow::anyhow!("bind admin server on {bind}: {e}"))?;
    info!(addr = %bind, "admin server listening");

    loop {
        let (stream, peer) = tokio::select! {
            _ = state.cancel.cancelled() => return Ok(()),
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    warn!(error = %e, "admin server accept failed");
                    continue;
                }
            },
        };
        let state = state.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, std::convert::Infallible>(serve(req, state).await) }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                warn!(peer = %peer, error = %e, "admin server connection ended");
            }
        });
    }
}

/// Dispatches one request.
async fn serve(req: Request<Incoming>, state: Arc<AdminState>) -> Response<RespBody> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    if path == "/healthz" {
        return ok_empty();
    }

    if !authorized(req.headers(), &state.user, &state.password) {
        return auth_required();
    }

    if path == "/" {
        let mut response = Response::new(body(Bytes::new()));
        *response.status_mut() = StatusCode::MOVED_PERMANENTLY;
        response.headers_mut().insert(
            hyper::header::LOCATION,
            HeaderValue::from_static("/static/"),
        );
        return response;
    }
    if path.starts_with("/static/") || path == "/favicon.ico" {
        // No web assets are bundled; the JSON API is the supported surface.
        return not_found();
    }

    match (method.as_str(), path.as_str()) {
        ("GET", "/api/reload") => reload(&state),
        ("POST", "/api/stop") => {
            state.cancel.cancel();
            ok_empty()
        }
        ("GET", "/api/status") => status(&state),
        ("GET", "/api/config") => read_config(&state),
        ("PUT", "/api/config") => write_config(&state, req).await,
        _ => dispatch_subroutes(&state, &method, &path, req).await,
    }
}

/// Everything with a `{name}` segment.
async fn dispatch_subroutes(
    state: &Arc<AdminState>,
    method: &Method,
    path: &str,
    req: Request<Incoming>,
) -> Response<RespBody> {
    if let Some(name) = path
        .strip_prefix("/api/proxy/")
        .and_then(|r| r.strip_suffix("/config"))
    {
        return get_proxy_config(state, name);
    }
    if let Some(name) = path
        .strip_prefix("/api/visitor/")
        .and_then(|r| r.strip_suffix("/config"))
    {
        return get_visitor_config(state, name);
    }

    if path == "/api/store/proxies" {
        if *method == Method::GET {
            return list_store_proxies(state);
        }
        if *method == Method::POST {
            return create_store_proxy(state, req).await;
        }
    }
    if path == "/api/store/visitors" {
        if *method == Method::GET {
            return list_store_visitors(state);
        }
        if *method == Method::POST {
            return create_store_visitor(state, req).await;
        }
    }
    if let Some(name) = path.strip_prefix("/api/store/proxies/") {
        return store_proxy_item(state, method, name, req).await;
    }
    if let Some(name) = path.strip_prefix("/api/store/visitors/") {
        return store_visitor_item(state, method, name, req).await;
    }

    not_found()
}

// --- status ---------------------------------------------------------------

fn status(state: &AdminState) -> Response<RespBody> {
    let server_addr = state.server_addr();
    let mut by_type: std::collections::BTreeMap<String, Vec<Value>> =
        std::collections::BTreeMap::new();

    if let Some(handle) = state.live.lock().unwrap().as_ref() {
        for s in handle.proxy_statuses() {
            let remote_addr = if s.err.is_empty() {
                if s.proxy_type == "tcp" || s.proxy_type == "udp" {
                    format!("{server_addr}{}", s.remote_addr)
                } else {
                    s.remote_addr.clone()
                }
            } else {
                String::new()
            };
            let mut entry = serde_json::Map::new();
            entry.insert("name".into(), json!(s.name));
            entry.insert("type".into(), json!(s.proxy_type));
            entry.insert("status".into(), json!(s.phase));
            entry.insert("err".into(), json!(s.err));
            entry.insert(
                "local_addr".into(),
                json!(if s.local_port != 0 {
                    format!("{}:{}", s.local_ip, s.local_port)
                } else {
                    String::new()
                }),
            );
            entry.insert("plugin".into(), json!(s.plugin));
            entry.insert("remote_addr".into(), json!(remote_addr));
            if state.is_store_enabled(&s.name) {
                entry.insert("source".into(), json!("store"));
            }
            by_type
                .entry(s.proxy_type.clone())
                .or_default()
                .push(Value::Object(entry));
        }
    }

    for entries in by_type.values_mut() {
        entries.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    }
    let map: serde_json::Map<String, Value> = by_type
        .into_iter()
        .map(|(kind, entries)| (kind, Value::Array(entries)))
        .collect();
    ok_json(&Value::Object(map))
}

// --- config file ----------------------------------------------------------

fn read_config(state: &AdminState) -> Response<RespBody> {
    let Some(path) = &state.config_file else {
        return api_error(400, "invalid argument: frpc has no config file path");
    };
    match std::fs::read_to_string(path) {
        Ok(content) => ok_text(&content),
        Err(e) => api_error(400, &format!("invalid argument: {e}")),
    }
}

async fn write_config(state: &AdminState, req: Request<Incoming>) -> Response<RespBody> {
    let Some(path) = &state.config_file else {
        return api_error(400, "invalid argument: frpc has no config file path");
    };
    let bytes = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => return api_error(400, &format!("read request body error: {e}")),
    };
    if bytes.is_empty() {
        return api_error(400, "body can't be empty");
    }
    match std::fs::write(path, &bytes) {
        Ok(()) => ok_empty(),
        Err(e) => api_error(500, &format!("{e}")),
    }
}

// --- reload ---------------------------------------------------------------

fn reload(state: &AdminState) -> Response<RespBody> {
    let Some(path) = state.config_file.clone() else {
        return api_error(400, "invalid argument: frpc has no config file path");
    };
    match ClientConfig::load(&path) {
        Ok(mut base) => {
            // The store is opened once at startup; a reload re-reads the file
            // configuration but never re-opens the store.
            base.store = state.base.read().unwrap().store.clone();
            *state.base.write().unwrap() = base;
            apply(state)
        }
        Err(e) => api_error(400, &format!("invalid argument: {e}")),
    }
}

/// Recomputes the effective config and asks the service to reconnect.
fn apply(state: &AdminState) -> Response<RespBody> {
    match recompute(state) {
        Ok(()) => {
            if let Some(handle) = state.live.lock().unwrap().as_ref() {
                handle.stop();
            }
            ok_empty()
        }
        Err(e) => api_error(500, &e),
    }
}

/// Merges the file config with the enabled store entries.
pub(crate) fn recompute(state: &AdminState) -> Result<(), String> {
    let base = state.base.read().unwrap().clone();
    let mut proxies = base.proxies.clone();
    let mut visitors = base.visitors.clone();

    if let Some(store) = &state.store {
        for proxy in store.enabled_proxies() {
            if proxies.iter().any(|p| p.name() == proxy.name()) {
                return Err(format!("proxy name [{}] is duplicated", proxy.name()));
            }
            proxies.push(proxy);
        }
        for visitor in store.enabled_visitors() {
            if visitors.iter().any(|v| v.name() == visitor.name()) {
                return Err(format!("visitor name [{}] is duplicated", visitor.name()));
            }
            visitors.push(visitor);
        }
    }

    let mut current = base;
    current.proxies = proxies;
    current.visitors = visitors;
    *state.current.write().unwrap() = current;
    Ok(())
}

// --- proxy / visitor config ------------------------------------------------

fn get_proxy_config(state: &AdminState, name: &str) -> Response<RespBody> {
    if name.is_empty() {
        return api_error(400, "proxy name is required");
    }
    let current = state.current.read().unwrap();
    match current.proxies.iter().find(|p| p.name() == name) {
        Some(cfg) => ok_json(&proxy_definition(cfg)),
        None => api_error(404, &format!("proxy {name:?} not found")),
    }
}

fn get_visitor_config(state: &AdminState, name: &str) -> Response<RespBody> {
    if name.is_empty() {
        return api_error(400, "visitor name is required");
    }
    let current = state.current.read().unwrap();
    match current.visitors.iter().find(|v| v.name() == name) {
        Some(cfg) => ok_json(&visitor_definition(cfg)),
        None => api_error(404, &format!("visitor {name:?} not found")),
    }
}

// --- store: proxies --------------------------------------------------------

fn store_or_disabled(state: &AdminState) -> Option<&Arc<Store>> {
    state.store.as_ref()
}

fn list_store_proxies(state: &AdminState) -> Response<RespBody> {
    let Some(store) = store_or_disabled(state) else {
        return api_error(404, "store disabled: store API is disabled");
    };
    let mut proxies: Vec<Value> = store.all_proxies().iter().map(proxy_definition).collect();
    proxies.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    ok_json(&json!({ "proxies": proxies }))
}

async fn create_store_proxy(state: &AdminState, req: Request<Incoming>) -> Response<RespBody> {
    let bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => return api_error(400, &format!("read body error: {e}")),
    };
    let cfg = match parse_proxy_definition(&bytes) {
        Ok(c) => c,
        Err(e) => return api_error(400, &e),
    };
    let cfg = match prepare_proxy(cfg) {
        Ok(c) => c,
        Err(e) => return api_error(400, &format!("invalid argument: validation error: {e}")),
    };
    let name = cfg.name().to_string();
    let store = match store_or_disabled(state) {
        Some(store) => store,
        None => return api_error(404, "store disabled: store API is disabled"),
    };
    if let Err(e) = store.add_proxy(cfg.clone()) {
        return store_error(e);
    }
    let created = store.get_proxy(&name).expect("just stored");
    apply(state);
    ok_json(&proxy_definition(&created))
}

async fn store_proxy_item(
    state: &AdminState,
    method: &Method,
    name: &str,
    req: Request<Incoming>,
) -> Response<RespBody> {
    if name.is_empty() {
        return api_error(400, "proxy name is required");
    }
    let store = match store_or_disabled(state) {
        Some(store) => store,
        None => return api_error(404, "store disabled: store API is disabled"),
    };

    match *method {
        Method::GET => match store.get_proxy(name) {
            Some(cfg) => ok_json(&proxy_definition(&cfg)),
            None => api_error(404, &format!("not found: proxy {name:?}")),
        },
        Method::PUT => {
            let bytes = match req.into_body().collect().await {
                Ok(c) => c.to_bytes(),
                Err(e) => return api_error(400, &format!("read body error: {e}")),
            };
            let cfg = match parse_proxy_definition(&bytes) {
                Ok(c) => c,
                Err(e) => return api_error(400, &e),
            };
            if cfg.name() != name {
                return api_error(400, "proxy name in URL must match name in body");
            }
            let cfg = match prepare_proxy(cfg) {
                Ok(c) => c,
                Err(e) => {
                    return api_error(400, &format!("invalid argument: validation error: {e}"))
                }
            };
            if let Err(e) = store.update_proxy(cfg.clone()) {
                return store_error(e);
            }
            let updated = store.get_proxy(name).expect("just updated");
            apply(state);
            ok_json(&proxy_definition(&updated))
        }
        Method::DELETE => match store.remove_proxy(name) {
            Ok(()) => {
                apply(state);
                ok_empty()
            }
            Err(e) => store_error(e),
        },
        _ => not_found(),
    }
}

// --- store: visitors -------------------------------------------------------

fn list_store_visitors(state: &AdminState) -> Response<RespBody> {
    let Some(store) = store_or_disabled(state) else {
        return api_error(404, "store disabled: store API is disabled");
    };
    let mut visitors: Vec<Value> = store
        .all_visitors()
        .iter()
        .map(visitor_definition)
        .collect();
    visitors.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    ok_json(&json!({ "visitors": visitors }))
}

async fn create_store_visitor(state: &AdminState, req: Request<Incoming>) -> Response<RespBody> {
    let bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => return api_error(400, &format!("read body error: {e}")),
    };
    let cfg = match parse_visitor_definition(&bytes) {
        Ok(c) => c,
        Err(e) => return api_error(400, &e),
    };
    let cfg = match prepare_visitor(cfg) {
        Ok(c) => c,
        Err(e) => return api_error(400, &format!("invalid argument: validation error: {e}")),
    };
    let name = cfg.name().to_string();
    let store = match store_or_disabled(state) {
        Some(store) => store,
        None => return api_error(404, "store disabled: store API is disabled"),
    };
    if let Err(e) = store.add_visitor(cfg.clone()) {
        return store_error(e);
    }
    let created = store.get_visitor(&name).expect("just stored");
    apply(state);
    ok_json(&visitor_definition(&created))
}

async fn store_visitor_item(
    state: &AdminState,
    method: &Method,
    name: &str,
    req: Request<Incoming>,
) -> Response<RespBody> {
    if name.is_empty() {
        return api_error(400, "visitor name is required");
    }
    let store = match store_or_disabled(state) {
        Some(store) => store,
        None => return api_error(404, "store disabled: store API is disabled"),
    };

    match *method {
        Method::GET => match store.get_visitor(name) {
            Some(cfg) => ok_json(&visitor_definition(&cfg)),
            None => api_error(404, &format!("not found: visitor {name:?}")),
        },
        Method::PUT => {
            let bytes = match req.into_body().collect().await {
                Ok(c) => c.to_bytes(),
                Err(e) => return api_error(400, &format!("read body error: {e}")),
            };
            let cfg = match parse_visitor_definition(&bytes) {
                Ok(c) => c,
                Err(e) => return api_error(400, &e),
            };
            if cfg.name() != name {
                return api_error(400, "visitor name in URL must match name in body");
            }
            let cfg = match prepare_visitor(cfg) {
                Ok(c) => c,
                Err(e) => {
                    return api_error(400, &format!("invalid argument: validation error: {e}"))
                }
            };
            if let Err(e) = store.update_visitor(cfg.clone()) {
                return store_error(e);
            }
            let updated = store.get_visitor(name).expect("just updated");
            apply(state);
            ok_json(&visitor_definition(&updated))
        }
        Method::DELETE => match store.remove_visitor(name) {
            Ok(()) => {
                apply(state);
                ok_empty()
            }
            Err(e) => store_error(e),
        },
        _ => not_found(),
    }
}

fn store_error(e: StoreError) -> Response<RespBody> {
    match e {
        StoreError::AlreadyExists(kind, name) => {
            api_error(409, &format!("conflict: already exists: {kind} {name:?}"))
        }
        StoreError::NotFound(kind, name) => api_error(404, &format!("not found: {kind} {name:?}")),
        StoreError::Persist(msg) => api_error(500, &msg),
    }
}

// --- models ---------------------------------------------------------------

/// `{"name","type","<type>":{flat config}}`, upstream's `ProxyDefinition`.
fn proxy_definition(cfg: &ProxyConfig) -> Value {
    let typ = cfg.proxy_type();
    let mut map = serde_json::Map::new();
    map.insert("name".into(), json!(cfg.name()));
    map.insert("type".into(), json!(typ));
    map.insert(typ.into(), serde_json::to_value(cfg).unwrap_or(Value::Null));
    Value::Object(map)
}

fn visitor_definition(cfg: &VisitorConfig) -> Value {
    let typ = cfg.visitor_type();
    let mut map = serde_json::Map::new();
    map.insert("name".into(), json!(cfg.name()));
    map.insert("type".into(), json!(typ));
    map.insert(typ.into(), serde_json::to_value(cfg).unwrap_or(Value::Null));
    Value::Object(map)
}

fn parse_proxy_definition(bytes: &[u8]) -> Result<ProxyConfig, String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("parse JSON error: {e}"))?;
    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let typ = value
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if name.is_empty() {
        return Err("proxy name is required".into());
    }
    if !PROXY_TYPES.contains(&typ.as_str()) {
        return Err(format!("invalid proxy type: {typ}"));
    }
    let mut blocks = PROXY_TYPES.iter().filter(|t| value.get(**t).is_some());
    let block_type = blocks
        .next()
        .ok_or("exactly one proxy type block is required")?
        .to_string();
    if blocks.next().is_some() {
        return Err("exactly one proxy type block is required".into());
    }
    if block_type != typ {
        return Err(format!(
            "proxy type block {block_type:?} does not match type {typ:?}"
        ));
    }

    // `ToConfigurer` copies name and type from the top level onto the block.
    let mut block = value.get(&block_type).cloned().unwrap_or(Value::Null);
    if let Some(obj) = block.as_object_mut() {
        obj.insert("type".into(), json!(typ));
        obj.insert("name".into(), json!(name));
    }
    serde_json::from_value(block).map_err(|e| format!("invalid proxy config: {e}"))
}

fn parse_visitor_definition(bytes: &[u8]) -> Result<VisitorConfig, String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("parse JSON error: {e}"))?;
    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let typ = value
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if name.is_empty() {
        return Err("visitor name is required".into());
    }
    if !VISITOR_TYPES.contains(&typ.as_str()) {
        return Err(format!("invalid visitor type: {typ}"));
    }
    let mut blocks = VISITOR_TYPES.iter().filter(|t| value.get(**t).is_some());
    let block_type = blocks
        .next()
        .ok_or("exactly one visitor type block is required")?
        .to_string();
    if blocks.next().is_some() {
        return Err("exactly one visitor type block is required".into());
    }
    if block_type != typ {
        return Err(format!(
            "visitor type block {block_type:?} does not match type {typ:?}"
        ));
    }

    let mut block = value.get(&block_type).cloned().unwrap_or(Value::Null);
    if let Some(obj) = block.as_object_mut() {
        obj.insert("type".into(), json!(typ));
        obj.insert("name".into(), json!(name));
    }
    serde_json::from_value(block).map_err(|e| format!("invalid visitor config: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_is_skipped_when_no_credentials_are_set() {
        let headers = HeaderMap::new();
        assert!(authorized(&headers, "", ""));
    }

    #[test]
    fn auth_requires_matching_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic YWRtaW46cHc="), // admin:pw
        );
        assert!(authorized(&headers, "admin", "pw"));
        assert!(!authorized(&headers, "admin", "wrong"));
        assert!(!authorized(&headers, "bob", "pw"));
    }

    #[test]
    fn a_proxy_definition_round_trips() {
        let cfg: ProxyConfig = serde_json::from_str(
            r#"{"type":"tcp","name":"ssh","localIP":"127.0.0.1","localPort":22,"remotePort":6000}"#,
        )
        .unwrap();
        let def = proxy_definition(&cfg);
        assert_eq!(def["name"], "ssh");
        assert_eq!(def["type"], "tcp");
        assert_eq!(def["tcp"]["name"], "ssh");
        assert_eq!(def["tcp"]["remotePort"], 6000);
    }

    #[test]
    fn a_proxy_definition_is_parsed_back() {
        let body = br#"{"name":"ssh","type":"tcp","tcp":{"localPort":22,"remotePort":6000}}"#;
        let cfg = parse_proxy_definition(body).unwrap();
        assert_eq!(cfg.name(), "ssh");
        assert_eq!(cfg.proxy_type(), "tcp");
        match cfg {
            ProxyConfig::Tcp(c) => assert_eq!(c.remote_port, 6000),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_definition_without_a_matching_block_is_rejected() {
        let body = br#"{"name":"ssh","type":"tcp"}"#;
        assert!(parse_proxy_definition(body).is_err());
        let body = br#"{"name":"ssh","type":"tcp","udp":{}}"#;
        assert!(parse_proxy_definition(body).is_err());
    }
}
