//! The `frps` service: control listener, TLS negotiation and session dispatch.

use std::sync::Arc;

use anyhow::{Context as _, Result};
use frp_core::codec::{read_msg, write_msg};
use frp_core::config::server::ServerConfig;
use frp_core::crypto::auth;
use frp_core::crypto::stream::EncryptedStream;
use frp_core::msg::{Login, LoginResp, Message, NewVisitorConnResp};
use frp_core::transport::{accept_server_stream, build_server_tls_config, ServerStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::context::ServerContext;
use crate::control::{new_run_id, Control, ControlManager, ControlTasks};
use crate::dashboard;
use crate::metrics::Metrics;
use crate::ports::PortManager;
use crate::proxy::WorkConn;
use crate::util::{response_error, unix_now};
use crate::visitor::{VisitorConn, VisitorRegistry};

/// A configured, runnable frp server.
pub struct Service {
    ctx: Arc<ServerContext>,
    cfg: Arc<ServerConfig>,
    tls: Option<Arc<rustls::ServerConfig>>,
}

impl Service {
    /// Prepares listeners, port managers and the TLS configuration.
    pub fn new(mut cfg: ServerConfig) -> Result<Self> {
        cfg.complete();
        let token = cfg.resolved_token()?;
        let cfg = Arc::new(cfg);

        let tls = match build_server_tls_config(&cfg.transport.tls) {
            Ok(tls) => Some(tls),
            Err(e) => {
                warn!(error = %e, "TLS could not be initialised, only plaintext clients will be accepted");
                None
            }
        };

        let ctx = Arc::new(ServerContext {
            tcp_ports: Arc::new(PortManager::new(
                "tcp",
                cfg.proxy_bind(),
                cfg.allow_ports.clone(),
            )),
            udp_ports: Arc::new(PortManager::new(
                "udp",
                cfg.proxy_bind(),
                cfg.allow_ports.clone(),
            )),
            metrics: Arc::new(Metrics::new()),
            visitors: Arc::new(VisitorRegistry::new()),
            controls: Arc::new(ControlManager::new()),
            token: token.into_bytes(),
            cfg: cfg.clone(),
            shutdown: CancellationToken::new(),
        });

        Ok(Self { ctx, cfg, tls })
    }

    /// Access to the shared server state, mostly for tests.
    pub fn context(&self) -> Arc<ServerContext> {
        self.ctx.clone()
    }

    /// Runs until the shutdown token is cancelled.
    pub async fn run(self) -> Result<()> {
        let ctx = self.ctx.clone();
        let cfg = self.cfg.clone();

        if cfg.web_server.port > 0 {
            let dashboard_ctx = ctx.clone();
            tokio::spawn(async move {
                if let Err(e) = dashboard::serve(dashboard_ctx).await {
                    warn!(error = %e, "dashboard stopped");
                }
            });
        }

        let sampler = ctx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = sampler.shutdown.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                        sampler.metrics.sample_traffic();
                    }
                }
            }
        });

        let bind = cfg.control_bind_addr();
        let listener = TcpListener::bind(&bind)
            .await
            .with_context(|| format!("bind control port on {bind}"))?;
        info!(
            addr = %bind,
            tls = self.tls.is_some(),
            tls_force = cfg.transport.tls.force,
            "rust-frp server started"
        );

        let tls = self.tls.clone();
        let force = cfg.transport.tls.force;
        loop {
            tokio::select! {
                _ = ctx.shutdown.cancelled() => break,
                accepted = listener.accept() => {
                    match accepted {
                        Ok((sock, peer)) => {
                            let ctx = ctx.clone();
                            let tls = tls.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(ctx, tls, force, sock).await {
                                    debug!(client = %peer, error = %e, "connection closed");
                                }
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "control accept failed");
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
        info!("rust-frp server stopped");
        Ok(())
    }

    pub fn shutdown(&self) -> CancellationToken {
        self.ctx.shutdown.clone()
    }
}

/// Classifies and dispatches a freshly accepted control-port connection.
async fn handle_connection(
    ctx: Arc<ServerContext>,
    tls: Option<Arc<rustls::ServerConfig>>,
    force_tls: bool,
    sock: TcpStream,
) -> Result<()> {
    let remote_addr = sock
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let local_addr = sock.local_addr().ok();

    let mut stream = accept_server_stream(sock, tls, force_tls).await?;
    let first = read_msg(&mut stream).await?;

    match first {
        Message::Login(login) => handle_login(ctx, stream, login, remote_addr).await,
        Message::NewWorkConn(msg) => {
            let (Some(remote), Some(local)) = (parse_addr(&remote_addr), local_addr) else {
                return Ok(());
            };
            handle_new_work_conn(ctx, stream, msg, remote, local).await
        }
        Message::NewVisitorConn(msg) => {
            let remote = parse_addr(&remote_addr).unwrap_or_else(|| {
                std::net::SocketAddr::from(([0, 0, 0, 0], 0))
            });
            handle_new_visitor_conn(ctx, stream, msg, remote).await
        }
        other => {
            warn!(kind = other.msg_type().name(), "unexpected first message");
            Ok(())
        }
    }
}

fn parse_addr(addr: &str) -> Option<std::net::SocketAddr> {
    addr.parse().ok()
}

async fn handle_login(
    ctx: Arc<ServerContext>,
    mut stream: ServerStream<TcpStream>,
    login: Login,
    remote_addr: String,
) -> Result<()> {
    let token = ctx.token_str();
    if !auth::verify_auth_key(&token, login.timestamp, &login.privilege_key) {
        warn!(client = %remote_addr, user = %login.user, "login rejected: token mismatch");
        let resp = LoginResp {
            version: frp_core::FRP_VERSION.to_string(),
            run_id: String::new(),
            error: response_error(
                "login",
                "token in login doesn't match token from configuration",
                ctx.cfg.detailed_errors(),
            ),
        };
        let _ = write_msg(&mut stream, &Message::LoginResp(resp)).await;
        return Ok(());
    }

    let run_id = if login.run_id.is_empty() {
        new_run_id()
    } else {
        login.run_id.clone()
    };

    info!(
        client = %remote_addr,
        run_id = %run_id,
        user = %login.user,
        version = %login.version,
        hostname = %login.hostname,
        os = %login.os,
        arch = %login.arch,
        "client login"
    );

    let (out_tx, out_rx) = mpsc::unbounded_channel();
    let (work_req_tx, work_req_rx) = mpsc::unbounded_channel();
    let (work_conn_tx, work_conn_rx) = mpsc::unbounded_channel();

    let control = Arc::new(Control::new(
        ctx.clone(),
        login,
        run_id.clone(),
        remote_addr,
        out_tx,
        work_req_tx,
        work_conn_tx,
    ));

    if let Some(previous) = ctx.controls.add(control.clone()) {
        info!(run_id = %run_id, "replacing the previous session for this run id");
        previous.close();
    }

    ctx.metrics.new_client(crate::metrics::ClientStat {
        client_id: control.client_id.clone(),
        user: control.user.clone(),
        version: control.login.version.clone(),
        hostname: control.login.hostname.clone(),
        online: true,
        last_online_time: unix_now(),
    });

    let resp = Message::LoginResp(LoginResp {
        version: frp_core::FRP_VERSION.to_string(),
        run_id: run_id.clone(),
        error: String::new(),
    });
    write_msg(&mut stream, &resp).await?;

    // From here on the control connection is encrypted with the raw token.
    let encrypted = EncryptedStream::new(stream, &ctx.token);
    let (reader, writer) = tokio::io::split(encrypted);
    let tasks = ControlTasks::spawn(
        control.clone(),
        reader,
        writer,
        out_rx,
        work_req_rx,
        work_conn_rx,
    );

    control.cancelled().cancelled().await;
    ctx.controls.remove(&run_id);
    drop(tasks);
    Ok(())
}

async fn handle_new_work_conn(
    ctx: Arc<ServerContext>,
    mut stream: ServerStream<TcpStream>,
    msg: frp_core::msg::NewWorkConn,
    remote_addr: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
) -> Result<()> {
    let Some(control) = ctx.controls.get(&msg.run_id) else {
        warn!(run_id = %msg.run_id, "work connection for an unknown run id");
        let resp = Message::StartWorkConn(frp_core::msg::StartWorkConn {
            error: response_error(
                "invalid NewWorkConn",
                &format!("no client control found for run id [{}]", msg.run_id),
                ctx.cfg.detailed_errors(),
            ),
            ..Default::default()
        });
        let _ = write_msg(&mut stream, &resp).await;
        return Ok(());
    };

    if ctx.cfg.auth.signs_new_work_conns()
        && !auth::verify_auth_key(&ctx.token_str(), msg.timestamp, &msg.privilege_key)
    {
        warn!(run_id = %msg.run_id, "invalid work connection signature");
        let resp = Message::StartWorkConn(frp_core::msg::StartWorkConn {
            error: response_error(
                "invalid NewWorkConn",
                "token in NewWorkConn doesn't match token from configuration",
                ctx.cfg.detailed_errors(),
            ),
            ..Default::default()
        });
        let _ = write_msg(&mut stream, &resp).await;
        return Ok(());
    }

    let work_conn = WorkConn {
        stream,
        remote_addr,
        local_addr,
    };
    if !control.register_work_conn(work_conn) {
        debug!(run_id = %msg.run_id, "control closed while registering a work connection");
    }
    Ok(())
}

async fn handle_new_visitor_conn(
    ctx: Arc<ServerContext>,
    mut stream: ServerStream<TcpStream>,
    msg: frp_core::msg::NewVisitorConn,
    remote_addr: std::net::SocketAddr,
) -> Result<()> {
    // An older visitor may omit run_id; in that case the user is unknown.
    let user = if msg.run_id.is_empty() {
        String::new()
    } else {
        ctx.controls
            .get(&msg.run_id)
            .map(|c| c.user.clone())
            .unwrap_or_default()
    };

    if let Err(e) = ctx
        .visitors
        .validate(&msg.proxy_name, &msg.sign_key, &user)
    {
        warn!(proxy = %msg.proxy_name, error = %e, "visitor connection rejected");
        let resp = Message::NewVisitorConnResp(NewVisitorConnResp {
            proxy_name: msg.proxy_name.clone(),
            error: response_error("register visitor conn error", &e.to_string(), ctx.cfg.detailed_errors()),
        });
        let _ = write_msg(&mut stream, &resp).await;
        return Ok(());
    }

    let resp = Message::NewVisitorConnResp(NewVisitorConnResp {
        proxy_name: msg.proxy_name.clone(),
        error: String::new(),
    });
    write_msg(&mut stream, &resp).await?;

    let visitor = VisitorConn {
        stream,
        remote_addr,
        user,
        use_encryption: msg.use_encryption,
        use_compression: msg.use_compression,
    };
    if let Err(e) = ctx.visitors.admit(&msg.proxy_name, visitor, &msg.sign_key) {
        warn!(proxy = %msg.proxy_name, error = %e, "visitor connection dropped");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_builds_with_defaults() {
        let service = Service::new(ServerConfig::default()).expect("service");
        assert_eq!(service.cfg.bind_port, 7000);
        assert!(service.tls.is_some(), "self-signed TLS must be available");
    }

    #[test]
    fn address_parsing() {
        assert!(parse_addr("127.0.0.1:5000").is_some());
        assert!(parse_addr("unknown").is_none());
    }
}
