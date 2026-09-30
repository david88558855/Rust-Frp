//! Client side visitors, starting with `stcp`.
//!
//! A visitor is the mirror image of a proxy: instead of publishing a local
//! service, it exposes a local port whose connections are tunnelled to the
//! *server*, which hands them to the proxy registered under the matching
//! `serverName`. The tunnel is authenticated with the proxy's `secretKey`
//! rather than the auth token, and the payload is encrypted with that same
//! secret key — not with the token, unlike work connections.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use frp_core::codec;
use frp_core::config::client::{StcpVisitorConfig, VisitorConfig};
use frp_core::crypto::stream::WorkConnStream;
use frp_core::crypto::auth;
use frp_core::msg::{Message, NewVisitorConn};
use frp_core::util;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::control::target_server_proxy_name;
use crate::proxy::ProxyContext;

/// How long the client waits for `NewVisitorConnResp`.
const VISITOR_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// One `stcp` visitor listening on a local port.
pub struct StcpVisitor {
    ctx: Arc<ProxyContext>,
    cfg: StcpVisitorConfig,
    cancel: CancellationToken,
    listener: Mutex<Option<TcpListener>>,
}

impl StcpVisitor {
    /// Binds the visitor's local port. A `bindPort` of zero disables it, which
    /// upstream allows for visitors that only serve a plugin.
    pub async fn new(ctx: Arc<ProxyContext>, cfg: StcpVisitorConfig) -> Result<Self> {
        let addr = format!("{}:{}", cfg.base.bind_addr, cfg.base.bind_port);
        let listener = if cfg.base.bind_port > 0 {
            Some(
                TcpListener::bind(&addr)
                    .await
                    .with_context(|| format!("bind the visitor port {addr}"))?,
            )
        } else {
            None
        };
        Ok(Self {
            ctx,
            cfg,
            cancel: CancellationToken::new(),
            listener: Mutex::new(listener),
        })
    }

    pub fn name(&self) -> &str {
        &self.cfg.base.name
    }

    /// Accepts local connections until cancelled.
    pub async fn run(self: &Arc<Self>) {
        let listener = {
            let mut slot = self.listener.lock().unwrap();
            slot.take()
        };
        let Some(listener) = listener else {
            warn!(visitor = %self.cfg.base.name, "visitor has no bind port, nothing to serve");
            return;
        };
        info!(
            visitor = %self.cfg.base.name,
            server_proxy = %self.target_name(),
            "visitor listening"
        );

        loop {
            let accepted = tokio::select! {
                _ = self.cancel.cancelled() => return,
                accepted = listener.accept() => accepted,
            };
            match accepted {
                Ok((user_conn, peer)) => {
                    let this = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = this.handle_conn(user_conn).await {
                            debug!(peer = %peer, error = %e, "visitor connection ended");
                        }
                    });
                }
                Err(e) => {
                    warn!(visitor = %self.cfg.base.name, error = %e, "visitor accept failed");
                    return;
                }
            }
        }
    }

    fn target_name(&self) -> String {
        target_server_proxy_name(
            &self.ctx.cfg.user,
            &self.cfg.base.server_user,
            &self.cfg.base.server_name,
        )
    }

    /// Tunnels one accepted connection through a freshly dialled visitor
    /// connection.
    async fn handle_conn(&self, user_conn: TcpStream) -> Result<()> {
        let mut conn = self
            .ctx
            .connector
            .connect()
            .await
            .context("dial a visitor connection")?;

        let timestamp = util::now_unix();
        let msg = NewVisitorConn {
            run_id: self.ctx.run_id.clone(),
            proxy_name: self.target_name(),
            // The visitor authenticates with the proxy's secret key, not the
            // client token.
            sign_key: auth::get_auth_key(&self.cfg.base.secret_key, timestamp),
            timestamp,
            use_encryption: self.cfg.base.transport.use_encryption,
            use_compression: self.cfg.base.transport.use_compression,
        };
        codec::write_msg(&mut conn, &Message::NewVisitorConn(msg))
            .await
            .context("send NewVisitorConn")?;

        let resp = tokio::time::timeout(VISITOR_HANDSHAKE_TIMEOUT, codec::read_msg(&mut conn))
            .await
            .context("timed out waiting for NewVisitorConnResp")?
            .context("read NewVisitorConnResp")?;
        let Message::NewVisitorConnResp(resp) = resp else {
            return Err(anyhow!(
                "expected NewVisitorConnResp but received {}",
                resp.msg_type().name()
            ));
        };
        if !resp.error.is_empty() {
            return Err(anyhow!("the server refused the visitor connection: {}", resp.error));
        }

        // Payload encryption uses the secret key, mirroring upstream
        // `wrapVisitorConn`.
        let wrapped = WorkConnStream::new(
            conn,
            self.cfg.base.secret_key.as_bytes(),
            self.cfg.base.transport.use_encryption,
            self.cfg.base.transport.use_compression,
        );
        debug!(visitor = %self.cfg.base.name, "visitor connection established");
        ProxyContext::join(wrapped, user_conn).await;
        Ok(())
    }

    pub fn stop(&self) {
        self.cancel.cancel();
    }
}

/// Owns every visitor of one control session.
pub struct VisitorManager {
    visitors: Vec<Arc<StcpVisitor>>,
}

impl VisitorManager {
    /// Builds and binds every configured visitor.
    pub async fn new(ctx: Arc<ProxyContext>, cfgs: &[VisitorConfig]) -> Result<Arc<Self>> {
        let mut visitors = Vec::new();
        for cfg in cfgs {
            match cfg {
                VisitorConfig::Stcp(config) => {
                    let visitor = StcpVisitor::new(ctx.clone(), config.clone()).await?;
                    visitors.push(Arc::new(visitor));
                }
                other => warn!(
                    kind = other.visitor_type(),
                    name = other.name(),
                    "visitor type is not implemented yet, skipping"
                ),
            }
        }
        Ok(Arc::new(Self { visitors }))
    }

    /// Starts every visitor's accept loop.
    pub fn run(&self) {
        for visitor in &self.visitors {
            let visitor = visitor.clone();
            tokio::spawn(async move { visitor.run().await });
        }
    }

    pub fn names(&self) -> Vec<&str> {
        self.visitors.iter().map(|v| v.name()).collect()
    }

    pub fn stop(&self) {
        for visitor in &self.visitors {
            visitor.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frp_core::config::{ClientConfig, ClientConfigFile};

    fn ctx(json: &str) -> Arc<ProxyContext> {
        let parsed: ClientConfigFile = serde_json::from_str(json).unwrap();
        let cfg =
            ClientConfig::from_parts(parsed.common, parsed.proxies, parsed.visitors, Vec::new())
                .unwrap();
        let common = Arc::new(cfg.common);
        let connector = Arc::new(crate::connector::Connector::new(common.clone()));
        let (out_tx, _out_rx) = tokio::sync::mpsc::unbounded_channel();
        Arc::new(ProxyContext {
            cfg: common,
            token: "tok".into(),
            run_id: "run1".into(),
            connector,
            out_tx,
        })
    }

    #[tokio::test]
    async fn a_visitor_binds_its_local_port() {
        let ctx = ctx(r#"{"user":"alice"}"#);
        let cfg: StcpVisitorConfig = serde_json::from_str(
            r#"{"type":"stcp","name":"secret","serverName":"ssh","secretKey":"k","bindPort":0}"#,
        )
        .unwrap();
        // Port 0 means "do not listen", which must not be an error.
        let visitor = StcpVisitor::new(ctx, cfg).await.unwrap();
        assert!(visitor.listener.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn the_target_name_honours_server_user_then_local_user() {
        let ctx = ctx(r#"{"user":"alice"}"#);
        let cfg: StcpVisitorConfig = serde_json::from_str(
            r#"{"type":"stcp","name":"secret","serverName":"ssh","secretKey":"k","bindPort":0}"#,
        )
        .unwrap();
        let visitor = StcpVisitor::new(ctx.clone(), cfg).await.unwrap();
        assert_eq!(visitor.target_name(), "alice.ssh");

        let cfg: StcpVisitorConfig = serde_json::from_str(
            r#"{"type":"stcp","name":"secret","serverName":"ssh","serverUser":"bob",
                "secretKey":"k","bindPort":0}"#,
        )
        .unwrap();
        let visitor = StcpVisitor::new(ctx, cfg).await.unwrap();
        assert_eq!(visitor.target_name(), "bob.ssh");
    }

    #[tokio::test]
    async fn unsupported_visitor_types_are_skipped() {
        let ctx = ctx(r#"{}"#);
        let visitors = VisitorManager::new(
            ctx,
            &[serde_json::from_str::<VisitorConfig>(
                r#"{"type":"xtcp","name":"p2p","serverName":"ssh","secretKey":"k"}"#,
            )
            .unwrap()],
        )
        .await
        .unwrap();
        assert!(visitors.names().is_empty());
    }
}
