//! The client side control session.
//!
//! The conversation with frps mirrors upstream exactly:
//!
//! 1. `Login` travels in plaintext and `LoginResp` comes back in plaintext.
//! 2. From that point the control connection is wrapped in AES-128-CFB keyed
//!    by the raw token, so every later message — `NewProxy`, `Ping`,
//!    `ReqWorkConn`, `CloseProxy` — is encrypted.
//! 3. When the server asks for one, the client dials a new connection, sends
//!    `NewWorkConn` in plaintext, and reads `StartWorkConn` on that same
//!    connection before it becomes a raw byte pipe.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use frp_core::codec;
use frp_core::config::client::{ClientCommonConfig, VisitorConfig};
use frp_core::config::proxy::ProxyConfig;
use frp_core::crypto::stream::EncryptedStream;
use frp_core::msg::{Login, Message};
use frp_core::transport::ClientConn;
use frp_core::util;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::connector::Connector;
use crate::proxy::{ProxyContext, ProxyManager};
use crate::visitor::VisitorManager;
use crate::{add_user_prefix, strip_user_prefix};

/// How long the client waits for `LoginResp`.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the client waits for `StartWorkConn` on a fresh work connection.
const START_WORK_CONN_TIMEOUT: Duration = Duration::from_secs(10);

/// The control connection once it has been switched to the encrypted stream.
pub type ControlStream = EncryptedStream<ClientConn>;

/// A logged in session, split into its two halves.
pub struct SessionHandshake {
    pub run_id: String,
    pub reader: ReadHalf<ControlStream>,
    pub writer: WriteHalf<ControlStream>,
}

/// Builds the `Login` message the way upstream `controlSessionDialer` does.
pub fn build_login(cfg: &ClientCommonConfig, token: &str, previous_run_id: &str) -> Login {
    let timestamp = util::now_unix();
    Login {
        version: frp_core::CLIENT_VERSION.to_string(),
        hostname: util::hostname(),
        os: util::os_name().to_string(),
        arch: util::arch_name().to_string(),
        user: cfg.user.clone(),
        privilege_key: frp_core::crypto::auth::get_auth_key(token, timestamp),
        timestamp,
        run_id: previous_run_id.to_string(),
        client_id: cfg.client_id.clone(),
        metas: cfg.metadatas.clone(),
        client_spec: Default::default(),
        pool_count: cfg.transport.pool_count,
    }
}

/// Dials the server, logs in, and returns the encrypted control connection.
///
/// `previous_run_id` is echoed in the `Login` so the server can replace the
/// stale session instead of leaking it.
pub async fn dial_and_login(
    connector: &Connector,
    cfg: &ClientCommonConfig,
    token: &str,
    previous_run_id: &str,
) -> Result<SessionHandshake> {
    let mut conn = connector
        .connect()
        .await
        .context("open the control connection")?;

    let login = build_login(cfg, token, previous_run_id);
    codec::write_msg(&mut conn, &Message::Login(login))
        .await
        .context("send Login")?;

    let resp = tokio::time::timeout(LOGIN_TIMEOUT, codec::read_msg(&mut conn))
        .await
        .context("timed out waiting for LoginResp")?
        .context("read LoginResp")?;
    let Message::LoginResp(resp) = resp else {
        return Err(anyhow!(
            "expected LoginResp but received {}",
            resp.msg_type().name()
        ));
    };
    if !resp.error.is_empty() {
        return Err(anyhow!("login to the server failed: {}", resp.error));
    }

    let encrypted = EncryptedStream::new(conn, token.as_bytes());
    let (reader, writer) = tokio::io::split(encrypted);
    Ok(SessionHandshake {
        run_id: resp.run_id,
        reader,
        writer,
    })
}

/// A live control session.
pub struct Control {
    pub run_id: String,
    pub proxies: Arc<ProxyManager>,
    cfg: Arc<ClientCommonConfig>,
    token: String,
    connector: Arc<Connector>,
    out_tx: mpsc::UnboundedSender<Message>,
    last_pong: Mutex<Instant>,
    cancelled: CancellationToken,
}

impl Control {
    pub fn send(&self, msg: Message) -> Result<()> {
        self.out_tx
            .send(msg)
            .map_err(|_| anyhow!("the control connection is closed"))
    }

    fn touch_pong(&self) {
        *self.last_pong.lock().unwrap() = Instant::now();
    }

    /// Dials a work connection and completes the `NewWorkConn` handshake.
    ///
    /// `sign` decides whether the message carries a `privilege_key`, matching
    /// the server's `auth.additionalScopes` configuration.
    async fn open_work_conn(&self) -> Result<(ClientConn, frp_core::msg::StartWorkConn)> {
        let mut conn = self
            .connector
            .connect()
            .await
            .context("dial a work connection")?;

        let mut msg = frp_core::msg::NewWorkConn {
            run_id: self.run_id.clone(),
            privilege_key: String::new(),
            timestamp: 0,
        };
        if self.cfg.auth.signs_new_work_conns() {
            msg.timestamp = util::now_unix();
            msg.privilege_key = frp_core::crypto::auth::get_auth_key(&self.token, msg.timestamp);
        }
        codec::write_msg(&mut conn, &Message::NewWorkConn(msg))
            .await
            .context("send NewWorkConn")?;

        // The server replies on the same connection, after which it is a raw
        // byte pipe.
        let resp = tokio::time::timeout(START_WORK_CONN_TIMEOUT, codec::read_msg(&mut conn))
            .await
            .context("timed out waiting for StartWorkConn")?
            .context("read StartWorkConn")?;
        let Message::StartWorkConn(start) = resp else {
            return Err(anyhow!(
                "expected StartWorkConn but received {}",
                resp.msg_type().name()
            ));
        };
        if !start.error.is_empty() {
            return Err(anyhow!(
                "server refused the work connection: {}",
                start.error
            ));
        }
        Ok((conn, start))
    }

    /// Serves one `ReqWorkConn`.
    async fn handle_req_work_conn(self: &Arc<Self>) {
        let (conn, start) = match self.open_work_conn().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "cannot open a work connection");
                return;
            }
        };
        let name = strip_user_prefix(&self.cfg.user, &start.proxy_name).to_string();
        self.proxies.handle_work_conn(&name, conn, start);
    }

    /// Dispatches control messages until the connection dies or the session is
    /// cancelled.
    async fn dispatch(self: Arc<Self>, mut reader: ReadHalf<ControlStream>) {
        loop {
            // Racing the read against cancellation is what makes `stop()`
            // prompt: otherwise the reader would stay parked on a connection
            // that nobody is going to close.
            let msg = tokio::select! {
                _ = self.cancelled.cancelled() => break,
                result = codec::read_msg(&mut reader) => match result {
                    Ok(msg) => msg,
                    Err(e) => {
                        debug!(error = %e, "control connection closed");
                        break;
                    }
                },
            };
            match msg {
                Message::ReqWorkConn(_) => {
                    let ctl = self.clone();
                    tokio::spawn(async move { ctl.handle_req_work_conn().await });
                }
                Message::NewProxyResp(resp) => {
                    let name = strip_user_prefix(&self.cfg.user, &resp.proxy_name).to_string();
                    self.proxies
                        .set_running_status(&name, resp.remote_addr, resp.error);
                }
                Message::Pong(pong) => {
                    if !pong.error.is_empty() {
                        warn!(error = %pong.error, "the server rejected our heartbeat");
                        break;
                    }
                    self.touch_pong();
                    debug!("heartbeat acknowledged");
                }
                other => debug!(kind = other.msg_type().name(), "ignoring control message"),
            }
        }
        self.cancelled.cancel();
    }

    /// Forwards queued messages to the server until the session ends.
    ///
    /// `Receiver::recv` is cancel safe, so losing the race against cancellation
    /// never drops a message that was already dequeued.
    async fn write_loop(
        self: Arc<Self>,
        mut writer: WriteHalf<ControlStream>,
        mut rx: mpsc::UnboundedReceiver<Message>,
    ) {
        loop {
            let msg = tokio::select! {
                _ = self.cancelled.cancelled() => return,
                msg = rx.recv() => match msg {
                    Some(msg) => msg,
                    None => return,
                },
            };
            if let Err(e) = codec::write_msg(&mut writer, &msg).await {
                debug!(error = %e, "control connection write failed");
                break;
            }
        }
        self.cancelled.cancel();
    }

    /// Sends heartbeats and, when configured, watches for a missing reply.
    async fn heartbeat_loop(self: Arc<Self>) {
        let interval = self.cfg.transport.heartbeat_interval;
        let timeout = self.cfg.transport.heartbeat_timeout;

        if timeout > 0 {
            let this = self.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = this.cancelled.cancelled() => return,
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                    }
                    let elapsed = this.last_pong.lock().unwrap().elapsed();
                    if elapsed > Duration::from_secs(timeout as u64) {
                        warn!("heartbeat timeout");
                        this.cancelled.cancel();
                        return;
                    }
                }
            });
        }

        if interval <= 0 {
            return;
        }
        let period = Duration::from_secs(interval as u64);
        loop {
            tokio::select! {
                _ = self.cancelled.cancelled() => return,
                _ = tokio::time::sleep(period) => {}
            }
            let mut ping = frp_core::msg::Ping {
                privilege_key: String::new(),
                timestamp: 0,
            };
            if self.cfg.auth.signs_heartbeats() {
                ping.timestamp = util::now_unix();
                ping.privilege_key =
                    frp_core::crypto::auth::get_auth_key(&self.token, ping.timestamp);
            }
            debug!("sending a heartbeat");
            if self.send(Message::Ping(ping)).is_err() {
                return;
            }
        }
    }
}

/// A handle the service uses to observe and stop a session.
pub struct ControlHandle {
    pub run_id: String,
    pub proxies: Arc<ProxyManager>,
    pub visitors: Arc<VisitorManager>,
    cancelled: CancellationToken,
}

impl ControlHandle {
    /// Resolves when the session ends, whichever side closed it.
    pub async fn wait(&self) {
        self.cancelled.cancelled().await;
    }

    /// Snapshots every proxy's status for logging or the admin API.
    pub fn proxy_statuses(&self) -> Vec<crate::proxy::ProxyStatus> {
        self.proxies.statuses()
    }

    pub fn stop(&self) {
        self.cancelled.cancel();
    }
}

/// Starts a control session over an already logged in connection.
pub async fn start_session(
    cfg: Arc<ClientCommonConfig>,
    token: String,
    connector: Arc<Connector>,
    handshake: SessionHandshake,
    proxy_cfgs: &[ProxyConfig],
    visitor_cfgs: &[VisitorConfig],
) -> Result<ControlHandle> {
    let (out_tx, out_rx) = mpsc::unbounded_channel();

    let ctx = Arc::new(ProxyContext {
        cfg: cfg.clone(),
        token: token.clone(),
        run_id: handshake.run_id.clone(),
        connector: connector.clone(),
        out_tx: out_tx.clone(),
    });

    let proxies = ProxyManager::new(ctx.clone(), proxy_cfgs)?;
    let visitors = VisitorManager::new(ctx.clone(), visitor_cfgs).await?;
    visitors.run();

    let control = Arc::new(Control {
        run_id: handshake.run_id.clone(),
        proxies: proxies.clone(),
        cfg: cfg.clone(),
        token,
        connector,
        out_tx,
        last_pong: Mutex::new(Instant::now()),
        cancelled: CancellationToken::new(),
    });

    info!(
        run_id = %handshake.run_id,
        proxies = proxy_cfgs.len(),
        visitors = visitor_cfgs.len(),
        "control session started"
    );

    // `write_loop` and `dispatch` both hold the session, so cancellation can
    // tear the connection down from either side.
    {
        let ctl = control.clone();
        tokio::spawn(async move { ctl.write_loop(handshake.writer, out_rx).await });
    }
    {
        let ctl = control.clone();
        tokio::spawn(async move { ctl.dispatch(handshake.reader).await });
    }
    {
        let ctl = control.clone();
        tokio::spawn(async move { ctl.heartbeat_loop().await });
    }

    Ok(ControlHandle {
        run_id: handshake.run_id,
        proxies,
        visitors,
        cancelled: control.cancelled.clone(),
    })
}

/// Helper used by the visitor manager to build a server side proxy name.
pub fn target_server_proxy_name(local_user: &str, server_user: &str, server_name: &str) -> String {
    if server_user.is_empty() {
        add_user_prefix(local_user, server_name)
    } else {
        add_user_prefix(server_user, server_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frp_core::config::{ClientConfig, ClientConfigFile};

    fn common(json: &str) -> Arc<ClientCommonConfig> {
        let parsed: ClientConfigFile = serde_json::from_str(json).unwrap();
        let cfg =
            ClientConfig::from_parts(parsed.common, parsed.proxies, parsed.visitors, Vec::new())
                .unwrap();
        Arc::new(cfg.common)
    }

    #[test]
    fn login_carries_the_token_signature_and_run_id() {
        let cfg = common(r#"{"user":"alice","clientID":"c1","transport":{"poolCount":3}}"#);
        let login = build_login(&cfg, "s3cret", "previous-run");
        assert_eq!(login.user, "alice");
        assert_eq!(login.client_id, "c1");
        assert_eq!(login.pool_count, 3);
        assert_eq!(login.run_id, "previous-run");
        assert_eq!(login.version, frp_core::CLIENT_VERSION);
        assert!(frp_core::crypto::auth::verify_auth_key(
            "s3cret",
            login.timestamp,
            &login.privilege_key
        ));
    }

    #[test]
    fn server_proxy_names_follow_the_user_rules() {
        assert_eq!(target_server_proxy_name("", "", "ssh"), "ssh");
        assert_eq!(target_server_proxy_name("alice", "", "ssh"), "alice.ssh");
        assert_eq!(target_server_proxy_name("alice", "bob", "ssh"), "bob.ssh");
    }

    #[test]
    fn user_prefix_helpers_round_trip() {
        assert_eq!(add_user_prefix("alice", "ssh"), "alice.ssh");
        assert_eq!(add_user_prefix("", "ssh"), "ssh");
        assert_eq!(strip_user_prefix("alice", "alice.ssh"), "ssh");
        // A name from a different user is left alone, exactly as upstream.
        assert_eq!(strip_user_prefix("alice", "bob.ssh"), "bob.ssh");
        assert_eq!(strip_user_prefix("", "ssh"), "ssh");
    }
}
