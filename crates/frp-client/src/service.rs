//! The client service: log in, serve, and reconnect forever.
//!
//! Upstream splits this into `loopLoginUntilSuccess` and
//! `keepControllerWorking`. Both are reproduced here: the first login can be
//! fatal (`loginFailExit`), every later one retries with an exponential
//! backoff capped at twenty seconds, and each successful login replaces the
//! previous session wholesale — proxies and visitors are rebuilt from the
//! configuration, which is why a reconnect picks up the current config.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use frp_core::config::ClientConfig;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::connector::Connector;
use crate::control::{dial_and_login, start_session, ControlHandle};

/// Upper bound for the reconnect delay.
const MAX_RECONNECT_INTERVAL: Duration = Duration::from_secs(20);
/// Upper bound for the first login's retry delay.
const MAX_FIRST_LOGIN_INTERVAL: Duration = Duration::from_secs(10);
/// Where the backoff starts after a failed attempt.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// A loaded client, ready to run.
pub struct Service {
    cfg: Arc<ClientConfig>,
    token: String,
    cancel: CancellationToken,
}

impl Service {
    /// Resolves the token and prepares the service.
    ///
    /// Configuration errors — including an unreadable `tokenSource` — surface
    /// here rather than on the first reconnect attempt.
    pub fn new(cfg: ClientConfig) -> Result<Self> {
        let token = cfg
            .token()
            .context("resolve auth.token for the client")?;
        Ok(Self {
            cfg: Arc::new(cfg),
            token,
            cancel: CancellationToken::new(),
        })
    }

    pub fn config(&self) -> &ClientConfig {
        &self.cfg
    }

    pub fn shutdown_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn shutdown(&self) {
        self.cancel.cancel();
    }

    /// A human readable summary, used by `rust-frp frpc --verify`.
    pub fn describe(&self) -> String {
        let mut lines = vec![format!(
            "server {}:{} (protocol {}, tcpMux {}, tls {})",
            self.cfg.common.server_addr,
            self.cfg.common.server_port,
            self.cfg.common.transport.protocol,
            self.cfg.common.transport.tcp_mux_enabled(),
            self.cfg.common.transport.tls.enabled_for("tcp"),
        )];
        for proxy in &self.cfg.proxies {
            lines.push(format!(
                "proxy  {} [{}] local {}:{}",
                proxy.name(),
                proxy.proxy_type(),
                proxy.base().local_ip,
                proxy.base().local_port
            ));
        }
        for visitor in &self.cfg.visitors {
            lines.push(format!(
                "visitor {} [{}] bind {}:{} -> {}",
                visitor.name(),
                visitor.visitor_type(),
                visitor.base().bind_addr,
                visitor.base().bind_port,
                visitor.base().server_name
            ));
        }
        for file in &self.cfg.included_files {
            lines.push(format!("include {}", file.display()));
        }
        lines.join("\n")
    }

    /// Runs until the shutdown token is cancelled.
    pub async fn run(self) -> Result<()> {
        let mut run_id = String::new();
        let mut first = true;
        let mut backoff = INITIAL_BACKOFF;

        loop {
            if self.cancel.is_cancelled() {
                return Ok(());
            }

            match self.login_once(&run_id).await {
                Ok(handle) => {
                    run_id = handle.run_id.clone();
                    backoff = INITIAL_BACKOFF;
                    first = false;

                    let cancel = self.cancel.clone();
                    tokio::select! {
                        _ = handle.wait() => {
                            warn!(run_id = %run_id, "control session ended, reconnecting");
                        }
                        _ = cancel.cancelled() => {
                            handle.stop();
                        }
                    }
                    handle.proxies.stop();
                    handle.visitors.stop();
                    if self.cancel.is_cancelled() {
                        return Ok(());
                    }
                }
                Err(e) => {
                    if first && self.cfg.common.login_fail_exit_enabled() {
                        return Err(e);
                    }
                    warn!(error = %e, "login attempt failed, retrying");
                }
            }

            let cap = if first {
                MAX_FIRST_LOGIN_INTERVAL
            } else {
                MAX_RECONNECT_INTERVAL
            };
            let delay = backoff.min(cap);
            info!(seconds = delay.as_secs_f32(), "waiting before the next attempt");
            tokio::select! {
                _ = self.cancel.cancelled() => return Ok(()),
                _ = tokio::time::sleep(delay) => {}
            }
            backoff = (backoff * 2).min(cap);
        }
    }

    /// One attempt at establishing a control session.
    async fn login_once(&self, previous_run_id: &str) -> Result<ControlHandle> {
        // A fresh connector per session: with TCPMux on it owns the yamux
        // session, which cannot be reused once it has died.
        let connector = Arc::new(Connector::new(Arc::new(self.cfg.common.clone())));
        info!(
            server = %format!("{}:{}", self.cfg.common.server_addr, self.cfg.common.server_port),
            "connecting to the server"
        );
        connector
            .open()
            .await
            .context("open the connection to the server")?;

        let handshake = match dial_and_login(
            &connector,
            &self.cfg.common,
            &self.token,
            previous_run_id,
        )
        .await
        {
            Ok(handshake) => handshake,
            Err(e) => {
                connector.close();
                return Err(e);
            }
        };

        info!(run_id = %handshake.run_id, "logged in");

        start_session(
            Arc::new(self.cfg.common.clone()),
            self.token.clone(),
            connector,
            handshake,
            &self.cfg.proxies,
            &self.cfg.visitors,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frp_core::config::{ClientConfigFile, ConfigFormat};

    fn load(text: &str, format: ConfigFormat) -> ClientConfig {
        let value = format.parse_value(text).unwrap();
        let parsed: ClientConfigFile = serde_json::from_value(value).unwrap();
        ClientConfig::from_parts(parsed.common, parsed.proxies, parsed.visitors, Vec::new())
            .unwrap()
    }

    #[test]
    fn the_service_describes_its_configuration() {
        let cfg = load(
            r#"
serverAddr = "frps.example.com"
serverPort = 7000

[[proxies]]
name = "ssh"
type = "tcp"
localPort = 22
remotePort = 6000

[[visitors]]
name = "secret"
type = "stcp"
serverName = "ssh"
secretKey = "k"
bindPort = 9000
"#,
            ConfigFormat::Toml,
        );
        let service = Service::new(cfg).unwrap();
        let text = service.describe();
        assert!(text.contains("frps.example.com:7000"));
        assert!(text.contains("tcpMux true"));
        assert!(text.contains("proxy  ssh [tcp] local 127.0.0.1:22"));
        assert!(text.contains("visitor secret [stcp] bind 127.0.0.1:9000 -> ssh"));
    }

    #[test]
    fn a_missing_token_source_is_reported_at_startup() {
        let cfg = load(
            r#"
[ auth ]
method = "token"
[ auth.tokenSource ]
type = "file"
[ auth.tokenSource.file ]
path = "/nonexistent/frp-token"
"#,
            ConfigFormat::Toml,
        );
        assert!(Service::new(cfg).is_err());
    }

    #[test]
    fn a_configured_token_is_used_as_is() {
        let cfg = load(
            r#"
[ auth ]
method = "token"
token = "s3cret"
"#,
            ConfigFormat::Toml,
        );
        let service = Service::new(cfg).unwrap();
        assert_eq!(service.token, "s3cret");
    }
}
