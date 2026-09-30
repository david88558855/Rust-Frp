//! Control sessions: login bookkeeping, work-connection pool and proxy
//! registration.
//!
//! The wire conversation mirrors upstream frp exactly:
//!
//! ```text
//! frpc -> frps   Login                       (plaintext)
//! frps -> frpc   LoginResp                   (plaintext)
//! ---- both sides switch the control connection to AES-128-CFB(token) ----
//! frpc -> frps   NewProxy   ...              frps -> frpc  NewProxyResp
//! frpc -> frps   Ping       ...              frps -> frpc  Pong
//! frps -> frpc   ReqWorkConn
//! frpc -> frps   NewWorkConn                 (on a brand new connection)
//! frps -> frpc   StartWorkConn               (on that connection)
//! ---------------- raw payload ------------------------------------------
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Result};
use frp_core::crypto::stream::EncryptedStream;
use frp_core::crypto::{auth, WorkConnStream};
use frp_core::msg::{
    CloseProxy, Login, Message, NewProxy, NewProxyResp, Ping, Pong, ReqWorkConn,
};
use frp_core::transport::ServerConn;
use frp_core::util;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::context::ServerContext;
use crate::metrics::ProxyStat;
use crate::proxy::{stcp, tcp, udp, ProxySpec, ServerProxy, WorkConn, WorkConnRequest};
use crate::util::{response_error, unix_now};

/// The control connection once it has been switched to the encrypted stream.
pub type ControlStream = EncryptedStream<ServerConn>;

/// Number of extra work connections kept idle beyond `pool_count`.
const POOL_EXTRA: i32 = 1;

/// One logged-in client.
pub struct Control {
    pub run_id: String,
    pub login: Login,
    pub user: String,
    pub client_id: String,
    pub pool_count: i32,
    pub remote_addr: String,
    pub ctx: Arc<ServerContext>,
    out_tx: mpsc::UnboundedSender<Message>,
    work_req_tx: mpsc::UnboundedSender<WorkConnRequest>,
    work_conn_tx: mpsc::UnboundedSender<WorkConn>,
    proxies: Mutex<HashMap<String, Arc<dyn ServerProxy>>>,
    ports_used: AtomicI64,
    last_ping: AtomicI64,
    connected_at: i64,
    shutdown: CancellationToken,
}

impl Control {
    /// Builds a control session plus the channels driving its worker tasks.
    pub fn new(
        ctx: Arc<ServerContext>,
        login: Login,
        run_id: String,
        remote_addr: String,
        out_tx: mpsc::UnboundedSender<Message>,
        work_req_tx: mpsc::UnboundedSender<WorkConnRequest>,
        work_conn_tx: mpsc::UnboundedSender<WorkConn>,
    ) -> Self {
        let user = login.user.clone();
        let client_id = if login.client_id.is_empty() {
            run_id.clone()
        } else {
            login.client_id.clone()
        };
        Self {
            run_id,
            pool_count: login.pool_count.max(0),
            login,
            user,
            client_id,
            remote_addr,
            ctx,
            out_tx,
            work_req_tx,
            work_conn_tx,
            proxies: Mutex::new(HashMap::new()),
            ports_used: AtomicI64::new(0),
            last_ping: AtomicI64::new(unix_now()),
            connected_at: unix_now(),
            shutdown: CancellationToken::new(),
        }
    }

    pub fn connected_at(&self) -> i64 {
        self.connected_at
    }

    pub fn cancelled(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Sends a framed message on the control connection.
    pub fn send(&self, msg: Message) -> Result<()> {
        self.out_tx
            .send(msg)
            .map_err(|_| anyhow!("control connection is closed"))
    }

    /// Proxy names currently registered by this client.
    pub fn proxy_names(&self) -> Vec<String> {
        self.proxies.lock().unwrap().keys().cloned().collect()
    }

    pub fn used_ports_num(&self) -> i64 {
        self.ports_used.load(Ordering::Relaxed)
    }

    /// Takes a work connection, asking the client for more when the pool is
    /// empty. Mirrors upstream `Control.GetWorkConn`.
    pub async fn get_work_conn(&self, cancel: &CancellationToken) -> Result<WorkConn> {
        let (reply, rx) = oneshot::channel();
        self.work_req_tx
            .send(WorkConnRequest { reply })
            .map_err(|_| anyhow!("control is already closed"))?;

        tokio::select! {
            _ = cancel.cancelled() => Err(anyhow!("proxy is closed")),
            _ = self.shutdown.cancelled() => Err(anyhow!("control is closed")),
            received = rx => match received {
                Ok(Some(work_conn)) => Ok(work_conn),
                Ok(None) => Err(anyhow!("timeout trying to get work connection")),
                Err(_) => Err(anyhow!("control is closed")),
            },
        }
    }

    /// Accepts a freshly dialled work connection from the client.
    pub fn register_work_conn(&self, work_conn: WorkConn) -> bool {
        self.work_conn_tx.send(work_conn).is_ok()
    }

    /// Registers a proxy described by a `NewProxy` message.
    pub async fn register_proxy(self: &Arc<Self>, msg: &NewProxy) -> Result<String> {
        let spec = ProxySpec::from_msg(msg);
        if spec.name.is_empty() {
            return Err(anyhow!("proxy name must not be empty"));
        }
        if spec.proxy_type.is_empty() {
            return Err(anyhow!("proxy type must not be empty"));
        }
        if self.proxies.lock().unwrap().contains_key(&spec.name) {
            return Err(anyhow!("proxy [{}] already exists", spec.name));
        }

        let used = used_ports_for(&spec.proxy_type);
        let limit = self.ctx.cfg.max_ports_per_client;
        if limit > 0 {
            let current = self.ports_used.load(Ordering::Relaxed);
            if current + used > limit {
                return Err(anyhow!("exceed the max_ports_per_client"));
            }
        }
        self.ports_used.fetch_add(used, Ordering::Relaxed);

        match self.start_proxy(spec.clone()).await {
            Ok((proxy, remote_addr)) => {
                self.proxies
                    .lock()
                    .unwrap()
                    .insert(spec.name.clone(), proxy);
                self.ctx.metrics.new_proxy(ProxyStat {
                    name: spec.name.clone(),
                    proxy_type: spec.proxy_type.clone(),
                    user: self.user.clone(),
                    client_id: self.client_id.clone(),
                    last_start_time: unix_now(),
                    ..Default::default()
                });
                info!(run_id = %self.run_id, proxy = %spec.name, kind = %spec.proxy_type, "proxy registered");
                Ok(remote_addr)
            }
            Err(e) => {
                self.ports_used.fetch_sub(used, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    async fn start_proxy(
        self: &Arc<Self>,
        spec: ProxySpec,
    ) -> Result<(Arc<dyn ServerProxy>, String)> {
        let ctx = self.ctx.clone();
        let ctl = self.clone();
        match spec.proxy_type.as_str() {
            "tcp" => {
                let proxy = tcp::start(ctx, ctl, spec).await?;
                let addr = proxy.remote_addr();
                Ok((proxy, addr))
            }
            "udp" => {
                let proxy = udp::start(ctx, ctl, spec).await?;
                let addr = proxy.remote_addr();
                Ok((proxy, addr))
            }
            "stcp" => {
                let owner = self.user.clone();
                let proxy = stcp::start_stcp(ctx, ctl, spec, &owner).await?;
                let addr = proxy.remote_addr();
                Ok((proxy, addr))
            }
            "sudp" => {
                let owner = self.user.clone();
                let proxy = stcp::start_sudp(ctx, ctl, spec, &owner).await?;
                let addr = proxy.remote_addr();
                Ok((proxy, addr))
            }
            "http" => {
                let proxy = crate::proxy::http::start_http(ctx, &ctl, spec)?;
                let addr = proxy.remote_addr();
                Ok((proxy, addr))
            }
            "https" => {
                let proxy = crate::proxy::http::start_https(ctx, &ctl, spec)?;
                let addr = proxy.remote_addr();
                Ok((proxy, addr))
            }
            other => Err(anyhow!(
                "proxy type [{other}] is not implemented in this build yet"
            )),
        }
    }

    /// Removes a proxy requested by `CloseProxy`.
    pub fn close_proxy(&self, msg: &CloseProxy) -> bool {
        let proxy = self.proxies.lock().unwrap().remove(&msg.proxy_name);
        let Some(proxy) = proxy else { return false };
        proxy.close();
        self.ports_used
            .fetch_sub(used_ports_for(proxy.proxy_type()), Ordering::Relaxed);
        self.ctx.metrics.close_proxy(&msg.proxy_name);
        info!(run_id = %self.run_id, proxy = %msg.proxy_name, "proxy closed");
        true
    }

    /// Tears the session down; safe to call repeatedly.
    pub fn close(&self) {
        if self.shutdown.is_cancelled() {
            return;
        }
        self.shutdown.cancel();
        let proxies: Vec<Arc<dyn ServerProxy>> =
            self.proxies.lock().unwrap().drain().map(|(_, p)| p).collect();
        for proxy in proxies {
            proxy.close();
            self.ctx.metrics.close_proxy(proxy.name());
        }
        self.ctx.metrics.close_client(&self.client_id);
        info!(run_id = %self.run_id, "control session closed");
    }

    fn handle_ping(&self, ping: &Ping) {
        if self.ctx.cfg.auth.signs_heartbeats()
            && !auth::verify_auth_key(&self.ctx.token_str(), ping.timestamp, &ping.privilege_key)
        {
            warn!(run_id = %self.run_id, "received invalid heartbeat");
            let _ = self.send(Message::Pong(Pong {
                error: response_error(
                    "invalid ping",
                    "token in heartbeat doesn't match token from configuration",
                    self.ctx.cfg.detailed_errors(),
                ),
            }));
            return;
        }
        self.last_ping.store(unix_now(), Ordering::Relaxed);
        debug!(run_id = %self.run_id, "heartbeat received");
        let _ = self.send(Message::Pong(Pong::default()));
    }

    fn handle_new_proxy(self: &Arc<Self>, msg: NewProxy) {
        let name = msg.proxy_name.clone();
        let kind = msg.proxy_type.clone();
        let ctl = self.clone();
        tokio::spawn(async move {
            let resp = match ctl.register_proxy(&msg).await {
                Ok(remote_addr) => NewProxyResp {
                    proxy_name: name.clone(),
                    remote_addr,
                    error: String::new(),
                },
                Err(e) => {
                    warn!(run_id = %ctl.run_id, proxy = %name, kind = %kind, error = %e, "new proxy rejected");
                    NewProxyResp {
                        proxy_name: name.clone(),
                        remote_addr: String::new(),
                        error: response_error(
                            &format!("new proxy [{name}] error"),
                            &e.to_string(),
                            ctl.ctx.cfg.detailed_errors(),
                        ),
                    }
                }
            };
            let _ = ctl.send(Message::NewProxyResp(resp));
        });
    }

    fn handle_close_proxy(&self, msg: &CloseProxy) {
        self.close_proxy(msg);
    }

    async fn run_reader(self: &Arc<Self>, mut reader: tokio::io::ReadHalf<ControlStream>) {
        loop {
            match frp_core::codec::read_msg(&mut reader).await {
                Ok(Message::NewProxy(msg)) => self.handle_new_proxy(msg),
                Ok(Message::Ping(ping)) => self.handle_ping(&ping),
                Ok(Message::CloseProxy(msg)) => self.handle_close_proxy(&msg),
                Ok(other) => {
                    debug!(
                        run_id = %self.run_id,
                        kind = other.msg_type().name(),
                        "unexpected control message"
                    );
                }
                Err(e) => {
                    debug!(run_id = %self.run_id, error = %e, "control read loop ended");
                    break;
                }
            }
        }
        self.close();
    }

    /// Checks that the client keeps sending heartbeats.
    async fn run_heartbeat(self: &Arc<Self>) {
        let timeout = self.ctx.cfg.transport.heartbeat_timeout_secs();
        if timeout <= 0 {
            return;
        }
        let interval = Duration::from_secs(1);
        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                _ = tokio::time::sleep(interval) => {
                    let idle = unix_now() - self.last_ping.load(Ordering::Relaxed);
                    if idle > timeout {
                        warn!(run_id = %self.run_id, idle, "heartbeat timeout");
                        self.close();
                        break;
                    }
                }
            }
        }
    }

    /// Tops the work-connection pool up, matching upstream's initial burst.
    fn request_pool_work_conns(&self) {
        let count = self.pool_count.max(1) + POOL_EXTRA;
        for _ in 0..count {
            let _ = self.send(Message::ReqWorkConn(ReqWorkConn {}));
        }
    }
}

/// Ports consumed by a proxy type.
pub fn used_ports_for(proxy_type: &str) -> i64 {
    match proxy_type {
        "tcp" | "udp" => 1,
        _ => 0,
    }
}

/// Owns the run-id index of live control sessions.
#[derive(Default)]
pub struct ControlManager {
    controls: Mutex<HashMap<String, Arc<Control>>>,
}

impl ControlManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a session, returning the session it replaced (if any).
    pub fn add(&self, control: Arc<Control>) -> Option<Arc<Control>> {
        self.controls
            .lock()
            .unwrap()
            .insert(control.run_id.clone(), control)
    }

    pub fn get(&self, run_id: &str) -> Option<Arc<Control>> {
        self.controls.lock().unwrap().get(run_id).cloned()
    }

    pub fn remove(&self, run_id: &str) -> Option<Arc<Control>> {
        self.controls.lock().unwrap().remove(run_id)
    }

    pub fn len(&self) -> usize {
        self.controls.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn all(&self) -> Vec<Arc<Control>> {
        self.controls.lock().unwrap().values().cloned().collect()
    }
}

/// Drives a fully established control session: writer, reader, heartbeat, work
/// connection pool and the pool refill worker.
pub struct ControlTasks {
    pub control: Arc<Control>,
    _handles: Vec<tokio::task::JoinHandle<()>>,
}

impl ControlTasks {
    /// Spawns every task belonging to a session.
    pub fn spawn(
        control: Arc<Control>,
        reader: tokio::io::ReadHalf<ControlStream>,
        writer: tokio::io::WriteHalf<ControlStream>,
        out_rx: mpsc::UnboundedReceiver<Message>,
        work_req_rx: mpsc::UnboundedReceiver<WorkConnRequest>,
        work_conn_rx: mpsc::UnboundedReceiver<WorkConn>,
    ) -> Self {
        let mut handles = Vec::new();

        let ctl = control.clone();
        handles.push(tokio::spawn(async move {
            let mut writer = writer;
            let mut out_rx = out_rx;
            while let Some(msg) = out_rx.recv().await {
                if frp_core::codec::write_msg(&mut writer, &msg).await.is_err() {
                    break;
                }
            }
            ctl.close();
        }));

        let ctl = control.clone();
        handles.push(tokio::spawn(async move {
            ctl.run_reader(reader).await;
        }));

        let ctl = control.clone();
        handles.push(tokio::spawn(async move {
            ctl.run_heartbeat().await;
        }));

        let ctl = control.clone();
        handles.push(tokio::spawn(async move {
            work_conn_dispatcher(ctl, work_req_rx, work_conn_rx).await;
        }));

        control.request_pool_work_conns();
        Self {
            control,
            _handles: handles,
        }
    }
}

/// Serves `WorkConnRequest`s from a queue of client-supplied work connections.
async fn work_conn_dispatcher(
    ctl: Arc<Control>,
    mut req_rx: mpsc::UnboundedReceiver<WorkConnRequest>,
    mut work_conn_rx: mpsc::UnboundedReceiver<WorkConn>,
) {
    let timeout = Duration::from_secs(ctl.ctx.cfg.user_conn_timeout.max(1) as u64);
    while let Some(req) = req_rx.recv().await {
        let work_conn = match work_conn_rx.try_recv() {
            Ok(work_conn) => Some(work_conn),
            Err(_) => {
                debug!(run_id = %ctl.run_id, "work connection pool empty, requesting more");
                if ctl.send(Message::ReqWorkConn(ReqWorkConn {})).is_err() {
                    None
                } else {
                    match tokio::time::timeout(timeout, work_conn_rx.recv()).await {
                        Ok(received) => received,
                        Err(_) => {
                            warn!(run_id = %ctl.run_id, "timeout waiting for a work connection");
                            None
                        }
                    }
                }
            }
        };

        // Keep the pool warm, matching upstream.
        if work_conn.is_some() {
            let _ = ctl.send(Message::ReqWorkConn(ReqWorkConn {}));
        }
        let _ = req.reply.send(work_conn);
    }
}

/// Builds a `ControlStream` wrapper for a control connection.
pub fn wrap_control_stream(stream: ServerConn, token: &[u8]) -> ControlStream {
    EncryptedStream::new(stream, token)
}

/// Convenience for the service: converts a work connection into the payload
/// stream a proxy will use.
pub fn wrap_work_conn(
    work_conn: WorkConn,
    token: &[u8],
    use_encryption: bool,
    use_compression: bool,
) -> WorkConnStream<ServerConn> {
    WorkConnStream::new(
        work_conn.into_stream(),
        token,
        use_encryption,
        use_compression,
    )
}

/// Generates a fresh run id the way upstream `util.RandID` does.
pub fn new_run_id() -> String {
    util::rand_id_frp(16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn used_ports_per_proxy_type() {
        assert_eq!(used_ports_for("tcp"), 1);
        assert_eq!(used_ports_for("udp"), 1);
        assert_eq!(used_ports_for("http"), 0);
        assert_eq!(used_ports_for("stcp"), 0);
    }

    #[test]
    fn run_ids_are_16_chars_and_unique() {
        let a = new_run_id();
        let b = new_run_id();
        assert_eq!(a.len(), 16);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn control_manager_indexes_by_run_id() {
        let ctx = Arc::new(crate::test_support::context());
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        let (work_req_tx, _work_req_rx) = mpsc::unbounded_channel();
        let (work_conn_tx, _work_conn_rx) = mpsc::unbounded_channel();
        let ctl = Arc::new(Control::new(
            ctx,
            Login::default(),
            "run1".into(),
            "127.0.0.1:1".into(),
            out_tx,
            work_req_tx,
            work_conn_tx,
        ));

        let mgr = ControlManager::new();
        assert!(mgr.add(ctl.clone()).is_none());
        assert_eq!(mgr.len(), 1);
        assert!(mgr.get("run1").is_some());
        assert!(mgr.get("run2").is_none());

        let replacement = mgr.add(ctl.clone()).expect("replaced");
        assert_eq!(replacement.run_id, "run1");
        assert_eq!(mgr.len(), 1);
        assert!(mgr.remove("run1").is_some());
        assert!(mgr.is_empty());
    }

    #[test]
    fn client_id_defaults_to_run_id() {
        let ctx = Arc::new(crate::test_support::context());
        let (out_tx, _) = mpsc::unbounded_channel();
        let (work_req_tx, _) = mpsc::unbounded_channel();
        let (work_conn_tx, _) = mpsc::unbounded_channel();
        let ctl = Control::new(
            ctx,
            Login::default(),
            "run1".into(),
            "127.0.0.1:1".into(),
            out_tx,
            work_req_tx,
            work_conn_tx,
        );
        assert_eq!(ctl.client_id, "run1");
        assert_eq!(ctl.pool_count, 0);
    }

    #[test]
    fn ping_is_accepted_without_extra_scopes() {
        let ctx = Arc::new(crate::test_support::context());
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let (work_req_tx, _) = mpsc::unbounded_channel();
        let (work_conn_tx, _) = mpsc::unbounded_channel();
        let ctl = Control::new(
            ctx,
            Login::default(),
            "run1".into(),
            "127.0.0.1:1".into(),
            out_tx,
            work_req_tx,
            work_conn_tx,
        );
        ctl.handle_ping(&Ping::default());
        match out_rx.try_recv() {
            Ok(Message::Pong(pong)) => assert!(pong.error.is_empty()),
            other => panic!("unexpected {other:?}"),
        }
    }
}
