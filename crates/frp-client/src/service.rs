//! The client service: log in, serve, and reconnect forever.
//!
//! Upstream splits this into `loopLoginUntilSuccess` and
//! `keepControllerWorking`. Both are reproduced here: the first login can be
//! fatal (`loginFailExit`), every later one retries with an exponential
//! backoff capped at twenty seconds, and each successful login replaces the
//! previous session wholesale — proxies and visitors are rebuilt from the
//! current configuration, which is why a reconnect picks up the current config.
//!
//! The configuration is not fixed: the admin API and the store mutate the
//! shared [`AdminState`], and a change asks the live session to stop so the
//! loop rebuilds it. This is the reconnect-based equivalent of upstream's
//! hot-swap `UpdateAllConfigurer` — the observable outcome is the same, but
//! here a store mutation takes effect by re-logging in rather than by editing
//! the running session in place.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use frp_core::config::ClientConfig;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::admin::AdminState;
use crate::connector::Connector;
use crate::control::{dial_and_login, start_session, ControlHandle};
use crate::store::Store;

/// Upper bound for the reconnect delay.
const MAX_RECONNECT_INTERVAL: Duration = Duration::from_secs(20);
/// Upper bound for the first login's retry delay.
const MAX_FIRST_LOGIN_INTERVAL: Duration = Duration::from_secs(10);
/// Where the backoff starts after a failed attempt.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// A loaded client, ready to run.
pub struct Service {
    state: Arc<AdminState>,
    token: String,
    cancel: CancellationToken,
}

impl Service {
    /// Resolves the token, opens the store and prepares the shared state.
    ///
    /// Configuration errors — including an unreadable `tokenSource` or a
    /// malformed store file — surface here rather than on the first reconnect
    /// attempt.
    pub fn new(cfg: ClientConfig, config_file: Option<PathBuf>) -> Result<Self> {
        let token = cfg
            .token()
            .context("resolve auth.token for the client")?;

        let store = if cfg.store.is_enabled() {
            Some(Arc::new(Store::open(&cfg.store.path).with_context(|| {
                format!("open the store at {}", cfg.store.path)
            })?))
        } else {
            None
        };

        let user = cfg.common.web_server.user.clone();
        let password = cfg.common.web_server.password.clone();
        let cancel = CancellationToken::new();
        let state = Arc::new(AdminState {
            user,
            password,
            config_file,
            base: RwLock::new(cfg.clone()),
            current: RwLock::new(cfg),
            live: Mutex::new(None),
            store,
            cancel: cancel.clone(),
        });

        // The effective config includes the store from the very first login.
        crate::admin::recompute(&state).map_err(anyhow::Error::msg)?;

        Ok(Self {
            state,
            token,
            cancel,
        })
    }

    /// The effective configuration, for the CLI's `--verify` summary.
    pub fn describe(&self) -> String {
        let cfg = self.state.current.read().unwrap().clone();
        let mut lines = vec![format!(
            "server {}:{} (protocol {}, tcpMux {}, tls {})",
            cfg.common.server_addr,
            cfg.common.server_port,
            cfg.common.transport.protocol,
            cfg.common.transport.tcp_mux_enabled(),
            cfg.common.transport.tls.enabled_for("tcp"),
        )];
        if cfg.store.is_enabled() {
            lines.push(format!("store {}", cfg.store.path));
        }
        for proxy in &cfg.proxies {
            lines.push(format!(
                "proxy  {} [{}] local {}:{}",
                proxy.name(),
                proxy.proxy_type(),
                proxy.base().local_ip,
                proxy.base().local_port
            ));
        }
        for visitor in &cfg.visitors {
            lines.push(format!(
                "visitor {} [{}] bind {}:{} -> {}",
                visitor.name(),
                visitor.visitor_type(),
                visitor.base().bind_addr,
                visitor.base().bind_port,
                visitor.base().server_name
            ));
        }
        for file in &cfg.included_files {
            lines.push(format!("include {}", file.display()));
        }
        lines.join("\n")
    }

    pub fn shutdown_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn shutdown(&self) {
        self.cancel.cancel();
    }

    /// Runs until the shutdown token is cancelled.
    pub async fn run(self) -> Result<()> {
        self.start_admin();

        let mut run_id = String::new();
        let mut first = true;
        let mut backoff = INITIAL_BACKOFF;

        loop {
            if self.cancel.is_cancelled() {
                return Ok(());
            }

            let cfg = self.state.current.read().unwrap().clone();
            match self.login_once(&run_id, &cfg).await {
                Ok(handle) => {
                    let handle = Arc::new(handle);
                    run_id = handle.run_id.clone();
                    backoff = INITIAL_BACKOFF;
                    first = false;
                    *self.state.live.lock().unwrap() = Some(handle.clone());

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
                    if first && self.state.current.read().unwrap().common.login_fail_exit_enabled() {
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

    /// Spawns the admin server when `[webServer]` is configured.
    fn start_admin(&self) {
        let enabled = self
            .state
            .current
            .read()
            .unwrap()
            .common
            .web_server
            .bind_addr()
            .is_some();
        if !enabled {
            return;
        }
        let state = self.state.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::admin::run(state).await {
                warn!(error = %e, "admin server stopped");
            }
        });
    }

    /// One attempt at establishing a control session.
    async fn login_once(&self, previous_run_id: &str, cfg: &ClientConfig) -> Result<ControlHandle> {
        // A fresh connector per session: with TCPMux on it owns the yamux
        // session, which cannot be reused once it has died.
        let connector = Arc::new(Connector::new(Arc::new(cfg.common.clone())));
        info!(
            server = %format!("{}:{}", cfg.common.server_addr, cfg.common.server_port),
            "connecting to the server"
        );
        connector
            .open()
            .await
            .context("open the connection to the server")?;

        let handshake = match dial_and_login(
            &connector,
            &cfg.common,
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
            Arc::new(cfg.common.clone()),
            self.token.clone(),
            connector,
            handshake,
            &cfg.proxies,
            &cfg.visitors,
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
        let service = Service::new(cfg, None).unwrap();
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
        assert!(Service::new(cfg, None).is_err());
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
        let service = Service::new(cfg, None).unwrap();
        assert_eq!(service.token, "s3cret");
    }
}
