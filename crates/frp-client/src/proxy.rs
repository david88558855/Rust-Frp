//! Client side proxy wrappers.
//!
//! Upstream registers one `Proxy` implementation per proxy type, but five of
//! the eight types — `tcp`, `http`, `https`, `stcp` and `tcpmux` — all resolve
//! to the same `GeneralTCPProxy`: the client terminates nothing, it simply
//! dials the local service and shuttles bytes. Only `udp` (and its `sudp`
//! sibling, whose difference is entirely server side) needs its own handling.
//!
//! The wrapper around each proxy reproduces the upstream state machine. A
//! proxy is registered with `NewProxy`, waits for `NewProxyResp`, and is
//! re-registered periodically while it has not been confirmed yet. A backing
//! service that fails its health check is withdrawn with `CloseProxy` and
//! re-registered once it recovers.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use frp_core::codec;
use frp_core::config::client::ClientCommonConfig;
use frp_core::config::proxy::ProxyConfig;
use frp_core::crypto::stream::WorkConnStream;
use frp_core::msg::{Message, StartWorkConn, UdpAddrJson, UdpPacket};
use frp_core::transport::ClientConn;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Notify};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::connector::Connector;

/// How often a wrapper re-examines its own state.
const STATUS_CHECK_INTERVAL: Duration = Duration::from_secs(3);
/// A registration that the server never answers is retried after this long.
const WAIT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);
/// A failed registration is retried after this long.
const START_ERR_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the client waits for the local service to accept a connection.
const LOCAL_DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Keepalive cadence on a UDP work connection, matching upstream.
const UDP_WORK_CONN_HEARTBEAT: Duration = Duration::from_secs(30);
/// A UDP peer that goes quiet for this long loses its socket.
const UDP_PEER_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Lifecycle phase of a proxy, with the exact strings upstream reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    New,
    WaitStart,
    StartErr,
    Running,
    CheckFailed,
    Closed,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::New => "new",
            Phase::WaitStart => "wait start",
            Phase::StartErr => "start error",
            Phase::Running => "running",
            Phase::CheckFailed => "check failed",
            Phase::Closed => "closed",
        }
    }
}

/// Everything a proxy needs to talk to the server.
pub struct ProxyContext {
    pub cfg: Arc<ClientCommonConfig>,
    /// Raw `auth.token`, also the work-connection encryption key.
    pub token: String,
    pub run_id: String,
    pub connector: Arc<Connector>,
    pub out_tx: mpsc::UnboundedSender<Message>,
}

impl ProxyContext {
    /// Wraps a work connection in the transport the proxy configured.
    fn wrap_work_conn(
        &self,
        conn: ClientConn,
        use_encryption: bool,
        use_compression: bool,
    ) -> WorkConnStream<ClientConn> {
        WorkConnStream::new(
            conn,
            self.token.as_bytes(),
            use_encryption,
            use_compression,
        )
    }

    /// Joins a local service socket with the (already wrapped) work stream.
    pub(crate) async fn join<A, B>(a: A, b: B) -> (u64, u64)
    where
        A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin,
        B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin,
    {
        let (mut ar, mut aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);
        let up = async {
            let n = tokio::io::copy(&mut ar, &mut bw).await.unwrap_or(0);
            let _ = bw.shutdown().await;
            n
        };
        let down = async {
            let n = tokio::io::copy(&mut br, &mut aw).await.unwrap_or(0);
            let _ = aw.shutdown().await;
            n
        };
        tokio::join!(up, down)
    }
}

struct WrapperState {
    phase: Phase,
    err: String,
    last_send_start: Instant,
    last_start_err: Instant,
}

/// Per-peer UDP socket, kept alive while the peer keeps talking.
struct UdpPeer {
    socket: Arc<UdpSocket>,
    alive: Arc<AtomicBool>,
}

/// The live state of a UDP proxy: one long-lived work connection at a time.
struct UdpSession {
    cancel: CancellationToken,
}

struct UdpInner {
    session: Option<UdpSession>,
}

/// Handles `udp` and `sudp` work connections.
pub struct UdpProxy {
    ctx: Arc<ProxyContext>,
    /// `localIP:localPort` of the service to forward to.
    local_addr: String,
    packet_size: usize,
    use_encryption: bool,
    use_compression: bool,
    inner: Mutex<UdpInner>,
}

impl UdpProxy {
    fn new(ctx: Arc<ProxyContext>, cfg: &ProxyConfig) -> Self {
        let base = cfg.base();
        Self {
            local_addr: format!("{}:{}", base.local_ip, base.local_port),
            packet_size: ctx.cfg.udp_packet_size.max(1) as usize,
            use_encryption: base.transport.use_encryption,
            use_compression: base.transport.use_compression,
            inner: Mutex::new(UdpInner { session: None }),
            ctx,
        }
    }

    fn close_session(&self) {
        let previous = {
            let mut inner = self.inner.lock().unwrap();
            inner.session.take()
        };
        if let Some(session) = previous {
            session.cancel.cancel();
        }
    }

    /// Takes over a fresh work connection, dropping whatever was in use.
    ///
    /// Upstream does exactly this: a UDP proxy always keeps a single work
    /// connection, so a new one replaces the old.
    fn handle_work_conn(&self, conn: ClientConn) {
        self.close_session();

        let remote = self
            .ctx
            .wrap_work_conn(conn, self.use_encryption, self.use_compression);
        let (to_local_tx, mut to_local_rx) = mpsc::unbounded_channel::<UdpPacket>();
        let (to_server_tx, mut to_server_rx) = mpsc::unbounded_channel::<Message>();
        let cancel = CancellationToken::new();

        {
            let mut inner = self.inner.lock().unwrap();
            inner.session = Some(UdpSession {
                cancel: cancel.clone(),
            });
        }

        let (mut reader, mut writer) = tokio::io::split(remote);

        // Server -> local: frames off the work connection.
        let read_cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = read_cancel.cancelled() => break,
                    result = codec::read_msg(&mut reader) => match result {
                        Ok(Message::UdpPacket(packet)) => {
                            if to_local_tx.send(packet).is_err() {
                                break;
                            }
                        }
                        Ok(Message::Ping(_)) => {}
                        Ok(other) => debug!(kind = other.msg_type().name(), "unexpected udp work message"),
                        Err(e) => {
                            debug!(error = %e, "udp work connection reader stopped");
                            break;
                        }
                    },
                }
            }
        });

        // Local -> server: our own frames plus the keepalive.
        let write_cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = write_cancel.cancelled() => break,
                    outgoing = to_server_rx.recv() => match outgoing {
                        Some(msg) => {
                            if codec::write_msg(&mut writer, &msg).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    },
                }
            }
        });

        let heartbeat_cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = heartbeat_cancel.cancelled() => return,
                    _ = tokio::time::sleep(UDP_WORK_CONN_HEARTBEAT) => {}
                }
                // Signed heartbeats are not required on a work connection;
                // upstream sends an empty Ping here.
                if to_server_tx
                    .send(Message::Ping(frp_core::msg::Ping {
                        privilege_key: String::new(),
                        timestamp: 0,
                    }))
                    .is_err()
                {
                    return;
                }
            }
        });

        let this = Arc::new(UdpForwarder {
            local_addr: self.local_addr.clone(),
            packet_size: self.packet_size,
            to_server: to_server_tx,
            peers: Mutex::new(HashMap::new()),
            cancel: cancel.clone(),
        });
        tokio::spawn(async move {
            while let Some(packet) = to_local_rx.recv().await {
                this.deliver(packet).await;
            }
        });
    }
}

/// Moves datagrams between the local service and the work connection.
struct UdpForwarder {
    local_addr: String,
    packet_size: usize,
    to_server: mpsc::UnboundedSender<Message>,
    peers: Mutex<HashMap<std::net::SocketAddr, UdpPeer>>,
    cancel: CancellationToken,
}

impl UdpForwarder {
    /// Sends one datagram to the local service, creating the per-peer socket
    /// on first use and reusing it afterwards so the service sees a stable
    /// source port.
    async fn deliver(&self, packet: UdpPacket) {
        let Some(remote) = packet
            .remote_addr
            .as_ref()
            .and_then(UdpAddrJson::to_socket_addr)
        else {
            debug!("udp packet without a usable remote address dropped");
            return;
        };
        let payload = packet.content;

        let socket = {
            let peers = self.peers.lock().unwrap();
            peers
                .get(&remote)
                .filter(|peer| peer.alive.load(Ordering::SeqCst))
                .map(|peer| peer.socket.clone())
        };
        let socket = match socket {
            Some(socket) => socket,
            None => match self.spawn_peer(remote).await {
                Ok(socket) => socket,
                Err(e) => {
                    warn!(peer = %remote, error = %e, "cannot reach the udp service");
                    return;
                }
            },
        };

        if let Err(e) = socket.send(&payload).await {
            debug!(peer = %remote, error = %e, "udp send to the local service failed");
        }
    }

    async fn spawn_peer(&self, remote: std::net::SocketAddr) -> Result<Arc<UdpSocket>> {
        let bind = if remote.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = UdpSocket::bind(bind)
            .await
            .context("bind the udp forwarding socket")?;
        socket
            .connect(&self.local_addr)
            .await
            .with_context(|| format!("connect to the udp service at {}", self.local_addr))?;
        let socket = Arc::new(socket);

        let alive = Arc::new(AtomicBool::new(true));
        {
            let mut peers = self.peers.lock().unwrap();
            peers.insert(
                remote,
                UdpPeer {
                    socket: socket.clone(),
                    alive: alive.clone(),
                },
            );
        }

        let to_server = self.to_server.clone();
        let cancel = self.cancel.clone();
        let packet_size = self.packet_size;
        let alive_task = alive.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; packet_size.max(512)];
            loop {
                let read = tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = tokio::time::timeout(UDP_PEER_IDLE_TIMEOUT, socket.recv(&mut buf)) => result,
                };
                match read {
                    Err(_) => break,
                    Ok(Err(e)) => {
                        debug!(peer = %remote, error = %e, "udp receive from the local service failed");
                        break;
                    }
                    Ok(Ok(n)) => {
                        let packet = UdpPacket {
                            content: buf[..n].to_vec(),
                            local_addr: None,
                            remote_addr: Some(UdpAddrJson::from_socket_addr(&remote)),
                        };
                        if to_server.send(Message::UdpPacket(packet)).is_err() {
                            break;
                        }
                    }
                }
            }
            alive_task.store(false, Ordering::SeqCst);
        });

        Ok(socket)
    }
}

/// One proxy, as tracked by the manager.
pub struct ProxyWrapper {
    pub name: String,
    /// `{user}.{name}`, the name the server knows this proxy by.
    pub wire_name: String,
    pub proxy_type: String,
    cfg: ProxyConfig,
    ctx: Arc<ProxyContext>,
    remote_addr: Mutex<String>,
    state: Mutex<WrapperState>,
    health_failed: AtomicBool,
    health_notify: Notify,
    cancel: CancellationToken,
    udp: Option<Arc<UdpProxy>>,
}

impl ProxyWrapper {
    fn new(ctx: Arc<ProxyContext>, cfg: ProxyConfig) -> Self {
        let name = cfg.name().to_string();
        let wire_name = crate::add_user_prefix(&ctx.cfg.user, &name);
        let udp = match &cfg {
            ProxyConfig::Udp(_) | ProxyConfig::Sudp(_) => {
                Some(Arc::new(UdpProxy::new(ctx.clone(), &cfg)))
            }
            _ => None,
        };
        // A proxy with a health check starts in the failed state so the first
        // successful probe is what registers it with the server.
        let health_failed = cfg.base().health_check.is_enabled() && cfg.base().local_port > 0;        Self {
            proxy_type: cfg.proxy_type().to_string(),
            name,
            wire_name,
            cfg,
            ctx,
            remote_addr: Mutex::new(String::new()),
            state: Mutex::new(WrapperState {
                phase: Phase::New,
                err: String::new(),
                last_send_start: Instant::now(),
                last_start_err: Instant::now(),
            }),
            health_failed: AtomicBool::new(health_failed),
            health_notify: Notify::new(),
            cancel: CancellationToken::new(),
            udp,
        }
    }

    pub fn phase(&self) -> Phase {
        self.state.lock().unwrap().phase
    }

    pub fn remote_addr(&self) -> String {
        self.remote_addr.lock().unwrap().clone()
    }

    pub fn error(&self) -> String {
        self.state.lock().unwrap().err.clone()
    }

    pub fn config(&self) -> &ProxyConfig {
        &self.cfg
    }

    /// Starts the status worker and, when configured, the health monitor.
    fn start(self: &Arc<Self>) {
        let worker = self.clone();
        tokio::spawn(async move { worker.status_worker().await });

        let base = self.cfg.base();
        if base.health_check.is_enabled() && base.local_port > 0 {
            let addr = format!("{}:{}", base.local_ip, base.local_port);
            let monitor = crate::health::Monitor::new(
                &base.health_check,
                addr,
                self.cancel.clone(),
            );
            let normal = self.clone();
            let failed = self.clone();
            tokio::spawn(async move {
                monitor
                    .run(
                        move || normal.mark_healthy(),
                        move || failed.mark_unhealthy(),
                    )
                    .await;
            });
        }
    }

    fn mark_healthy(&self) {
        self.health_failed.store(false, Ordering::SeqCst);
        self.health_notify.notify_waiters();
    }

    fn mark_unhealthy(&self) {
        self.health_failed.store(true, Ordering::SeqCst);
        self.health_notify.notify_waiters();
    }

    /// Registers, re-registers or withdraws the proxy, exactly as upstream's
    /// `checkWorker` decides.
    async fn status_worker(self: Arc<Self>) {
        loop {
            if self.cancel.is_cancelled() {
                return;
            }
            let now = Instant::now();
            if !self.health_failed.load(Ordering::SeqCst) {
                let due = {
                    let mut state = self.state.lock().unwrap();
                    let due = match state.phase {
                        Phase::New | Phase::CheckFailed => true,
                        Phase::WaitStart => now.duration_since(state.last_send_start) > WAIT_RESPONSE_TIMEOUT,
                        Phase::StartErr => now.duration_since(state.last_start_err) > START_ERR_TIMEOUT,
                        Phase::Running | Phase::Closed => false,
                    };
                    if due {
                        state.phase = Phase::WaitStart;
                        state.last_send_start = now;
                    }
                    due
                };
                if due {
                    let mut msg = self.cfg.to_new_proxy();
                    msg.proxy_name = self.wire_name.clone();
                    debug!(proxy = %self.name, "registering with the server");
                    let _ = self.ctx.out_tx.send(Message::NewProxy(msg));
                }
            } else {
                let withdraw = {
                    let mut state = self.state.lock().unwrap();
                    let withdraw = matches!(state.phase, Phase::Running | Phase::WaitStart);
                    if withdraw {
                        state.phase = Phase::CheckFailed;
                    }
                    withdraw
                };
                if withdraw {
                    warn!(proxy = %self.name, "health check failed, withdrawing the proxy");
                    let _ = self.ctx.out_tx.send(Message::CloseProxy(
                        frp_core::msg::CloseProxy {
                            proxy_name: self.wire_name.clone(),
                        },
                    ));
                }
            }

            tokio::select! {
                _ = self.cancel.cancelled() => return,
                _ = tokio::time::sleep(STATUS_CHECK_INTERVAL) => {}
                _ = self.health_notify.notified() => {}
            }
        }
    }

    /// Applies a `NewProxyResp`.
    fn set_running_status(self: &Arc<Self>, remote_addr: String, resp_err: String) -> Result<()> {
        {
            let mut state = self.state.lock().unwrap();
            if state.phase != Phase::WaitStart {
                return Err(anyhow::anyhow!(
                    "proxy [{}] is not waiting for a start response",
                    self.name
                ));
            }
            *self.remote_addr.lock().unwrap() = remote_addr;
            if !resp_err.is_empty() {
                state.phase = Phase::StartErr;
                state.err = resp_err.clone();
                state.last_start_err = Instant::now();
                return Err(anyhow::anyhow!(resp_err));
            }
            state.phase = Phase::Running;
            state.err = String::new();
        }
        Ok(())
    }

    /// Consumes a work connection the server handed over.
    fn handle_work_conn(self: &Arc<Self>, conn: ClientConn, start: StartWorkConn) {
        if self.phase() != Phase::Running {
            drop(conn);
            return;
        }
        match self.udp.clone() {
            Some(udp) => udp.handle_work_conn(conn),
            None => {
                let this = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = this.forward_tcp(conn, &start).await {
                        debug!(proxy = %this.name, error = %e, "work connection ended");
                    }
                });
            }
        }
    }

    /// The general TCP path shared by `tcp`, `http`, `https`, `stcp` and
    /// `tcpmux`: dial the local service and copy bytes both ways.
    async fn forward_tcp(&self, conn: ClientConn, _start: &StartWorkConn) -> Result<()> {
        let base = self.cfg.base();
        let wrapped = self.ctx.wrap_work_conn(
            conn,
            base.transport.use_encryption,
            base.transport.use_compression,
        );
        let addr = format!("{}:{}", base.local_ip, base.local_port);
        let local = tokio::time::timeout(LOCAL_DIAL_TIMEOUT, TcpStream::connect(&addr))
            .await
            .with_context(|| format!("timed out connecting to the local service at {addr}"))?
            .with_context(|| format!("connect to the local service at {addr}"))?;
        let _ = local.set_nodelay(true);
        debug!(proxy = %self.name, service = %addr, "forwarding a work connection");
        ProxyContext::join(wrapped, local).await;
        Ok(())
    }

    fn stop(&self) {
        self.cancel.cancel();
        if let Some(udp) = &self.udp {
            udp.close_session();
        }
        let mut state = self.state.lock().unwrap();
        state.phase = Phase::Closed;
    }
}

/// Owns every proxy of one control session.
pub struct ProxyManager {
    ctx: Arc<ProxyContext>,
    proxies: Mutex<HashMap<String, Arc<ProxyWrapper>>>,
}

impl ProxyManager {
    pub fn new(ctx: Arc<ProxyContext>, cfgs: &[ProxyConfig]) -> Arc<Self> {
        let manager = Arc::new(Self {
            ctx,
            proxies: Mutex::new(HashMap::new()),
        });
        for cfg in cfgs {
            let wrapper = Arc::new(ProxyWrapper::new(manager.ctx.clone(), cfg.clone()));
            let name = wrapper.name.clone();
            let previous = {
                let mut proxies = manager.proxies.lock().unwrap();
                proxies.insert(name.clone(), wrapper.clone())
            };
            if let Some(previous) = previous {
                previous.stop();
            }
            wrapper.start();
            info!(proxy = %name, kind = %wrapper.proxy_type, "proxy added");
        }
        manager
    }

    /// Applies a `NewProxyResp` from the server.
    pub fn set_running_status(&self, proxy_name: &str, remote_addr: String, resp_err: String) {
        let wrapper = {
            let proxies = self.proxies.lock().unwrap();
            proxies.get(proxy_name).cloned()
        };
        let Some(wrapper) = wrapper else {
            debug!(proxy = %proxy_name, "response for an unknown proxy ignored");
            return;
        };
        match wrapper.set_running_status(remote_addr, resp_err) {
            Ok(()) => info!(proxy = %proxy_name, "proxy started"),
            Err(e) => warn!(proxy = %proxy_name, error = %e, "proxy failed to start"),
        }
    }

    /// Hands a work connection to the proxy it was opened for.
    pub fn handle_work_conn(&self, proxy_name: &str, conn: ClientConn, start: StartWorkConn) {
        let wrapper = {
            let proxies = self.proxies.lock().unwrap();
            proxies.get(proxy_name).cloned()
        };
        match wrapper {
            Some(wrapper) => wrapper.handle_work_conn(conn, start),
            None => {
                debug!(proxy = %proxy_name, "work connection for an unknown proxy dropped");
            }
        }
    }

    /// Snapshot of every proxy, for the admin API and for logging.
    pub fn statuses(&self) -> Vec<(String, String, &'static str, String, String)> {
        let proxies = self.proxies.lock().unwrap();
        proxies
            .values()
            .map(|wrapper| {
                (
                    wrapper.name.clone(),
                    wrapper.proxy_type.clone(),
                    wrapper.phase().as_str(),
                    wrapper.remote_addr(),
                    wrapper.error(),
                )
            })
            .collect()
    }

    pub fn stop(&self) {
        let drained: Vec<Arc<ProxyWrapper>> = {
            let mut proxies = self.proxies.lock().unwrap();
            proxies.drain().map(|(_, v)| v).collect()
        };
        for wrapper in drained {
            wrapper.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frp_core::config::{ClientConfig, ClientConfigFile};

    fn fixture(json: &str) -> (Arc<ClientCommonConfig>, Vec<ProxyConfig>) {
        let parsed: ClientConfigFile = serde_json::from_str(json).unwrap();
        let cfg = ClientConfig::from_parts(parsed.common, parsed.proxies, parsed.visitors, Vec::new())
            .unwrap();
        (Arc::new(cfg.common), cfg.proxies)
    }

    fn manager(json: &str) -> (Arc<ProxyManager>, Arc<Connector>) {
        let (common, proxies) = fixture(json);
        let connector = Arc::new(Connector::new(common.clone()));
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        let ctx = Arc::new(ProxyContext {
            cfg: common,
            token: "tok".into(),
            run_id: "run1".into(),
            connector: connector.clone(),
            out_tx,
        });
        (ProxyManager::new(ctx, &proxies), connector)
    }

    #[test]
    fn phases_use_the_upstream_strings() {
        assert_eq!(Phase::New.as_str(), "new");
        assert_eq!(Phase::WaitStart.as_str(), "wait start");
        assert_eq!(Phase::StartErr.as_str(), "start error");
        assert_eq!(Phase::Running.as_str(), "running");
        assert_eq!(Phase::CheckFailed.as_str(), "check failed");
        assert_eq!(Phase::Closed.as_str(), "closed");
    }

    #[tokio::test]
    async fn every_general_tcp_type_is_tracked() {
        let (manager, _) = manager(
            r#"{"proxies":[
                {"type":"tcp","name":"a","localPort":1},
                {"type":"http","name":"b","localPort":2,"customDomains":["x"]},
                {"type":"https","name":"c","localPort":3,"customDomains":["x"]},
                {"type":"stcp","name":"d","localPort":4,"secretKey":"k"},
                {"type":"tcpmux","name":"e","localPort":5,"customDomains":["x"],"multiplexer":"httpconnect"}
            ]}"#,
        );
        let mut names: Vec<String> = manager
            .statuses()
            .into_iter()
            .map(|(name, kind, _, _, _)| format!("{name}:{kind}"))
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec!["a:tcp", "b:http", "c:https", "d:stcp", "e:tcpmux"]
        );
        manager.stop();
    }

    #[tokio::test]
    async fn registration_is_sent_and_confirmed() {
        let (common, proxies) = fixture(
            r#"{"proxies":[{"type":"tcp","name":"ssh","localPort":22,"remotePort":6000}]}"#,
        );
        let connector = Arc::new(Connector::new(common.clone()));
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let ctx = Arc::new(ProxyContext {
            cfg: common,
            token: "tok".into(),
            run_id: "run1".into(),
            connector,
            out_tx,
        });
        let manager = ProxyManager::new(ctx, &proxies);

        // The status worker registers the proxy on its first pass.
        let first = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("the proxy was never registered")
            .expect("channel closed");
        match first {
            Message::NewProxy(msg) => {
                assert_eq!(msg.proxy_name, "ssh");
                assert_eq!(msg.proxy_type, "tcp");
                assert_eq!(msg.remote_port, 6000);
            }
            other => panic!("unexpected {other:?}"),
        }

        manager.set_running_status("ssh", "0.0.0.0:6000".into(), String::new());
        let statuses = manager.statuses();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].2, "running");
        assert_eq!(statuses[0].3, "0.0.0.0:6000");
        manager.stop();
    }

    #[tokio::test]
    async fn a_user_prefix_is_added_to_the_wire_name() {
        let (common, proxies) = fixture(
            r#"{"user":"alice",
                "proxies":[{"type":"tcp","name":"ssh","localPort":22,"remotePort":6000}]}"#,
        );
        let connector = Arc::new(Connector::new(common.clone()));
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let ctx = Arc::new(ProxyContext {
            cfg: common,
            token: "tok".into(),
            run_id: "run1".into(),
            connector,
            out_tx,
        });
        let manager = ProxyManager::new(ctx, &proxies);
        match tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            Message::NewProxy(msg) => assert_eq!(msg.proxy_name, "alice.ssh"),
            other => panic!("unexpected {other:?}"),
        }
        manager.stop();
    }

    #[tokio::test]
    async fn a_server_error_marks_the_proxy_as_failed() {
        let (manager, _) = manager(
            r#"{"proxies":[{"type":"tcp","name":"ssh","localPort":22,"remotePort":6000}]}"#,
        );
        // Wait for the initial registration to be sent.
        tokio::time::sleep(Duration::from_millis(50)).await;
        manager.set_running_status("ssh", String::new(), "port already used".into());
        let statuses = manager.statuses();
        assert_eq!(statuses[0].2, "start error");
        assert_eq!(statuses[0].4, "port already used");
        manager.stop();
    }

    #[tokio::test]
    async fn an_unhealthy_proxy_starts_in_the_failed_state() {
        let (manager, _) = manager(
            r#"{"proxies":[{"type":"tcp","name":"ssh","localPort":22,"remotePort":6000,
                "healthCheck":{"type":"tcp","intervalSeconds":1,"timeoutSeconds":1}}]}"#,
        );
        let statuses = manager.statuses();
        // No registration may be attempted before the first probe succeeds.
        assert_eq!(statuses[0].2, "new");
        manager.stop();
    }

    #[tokio::test]
    async fn work_connections_for_unknown_proxies_are_dropped() {
        use frp_core::transport::ClientStream;

        let (manager, _) = manager(r#"{"proxies":[{"type":"tcp","name":"ssh","localPort":22}]}"#);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let sock = TcpStream::connect(addr).await.unwrap();
        // Nothing observable happens beyond the connection being closed rather
        // than panicking or being routed to the wrong proxy.
        manager.handle_work_conn(
            "nope",
            ClientConn::Plain(ClientStream::Plain(sock)),
            StartWorkConn::default(),
        );
        manager.stop();
    }

    #[test]
    fn udp_address_conversions_round_trip() {
        let addr: std::net::SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let json = UdpAddrJson::from_socket_addr(&addr);
        assert_eq!(json.to_socket_addr(), Some(addr));
        assert_eq!(json.port, 5353);
    }
}
