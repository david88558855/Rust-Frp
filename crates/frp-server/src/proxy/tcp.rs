//! `tcp` proxy: one remote port, one work connection per user connection.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use frp_core::crypto::stream::WorkConnStream;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::context::ServerContext;
use crate::control::Control;
use crate::proxy::{join_user_stream, start_work_conn_for, ProxySpec, ServerProxy};

/// Handle for a listening TCP proxy.
pub struct TcpProxy {
    spec: ProxySpec,
    port: i32,
    remote_addr: String,
    cancel: CancellationToken,
    ctx: Arc<ServerContext>,
}

impl ServerProxy for TcpProxy {
    fn name(&self) -> &str {
        &self.spec.name
    }

    fn proxy_type(&self) -> &str {
        "tcp"
    }

    fn spec(&self) -> &ProxySpec {
        &self.spec
    }

    fn used_ports_num(&self) -> i64 {
        1
    }

    fn remote_addr(&self) -> String {
        self.remote_addr.clone()
    }

    fn close(&self) {
        self.cancel.cancel();
        self.ctx.tcp_ports.release(&self.spec.name, self.port);
    }
}

/// Binds the remote port and starts accepting user connections.
pub async fn start(
    ctx: Arc<ServerContext>,
    ctl: Arc<Control>,
    spec: ProxySpec,
) -> Result<Arc<TcpProxy>> {
    let port = ctx.tcp_ports.acquire(&spec.name, spec.remote_port)?;
    let bind_addr = format!("{}:{}", ctx.cfg.proxy_bind(), port);
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            ctx.tcp_ports.release(&spec.name, port);
            return Err(anyhow!("listen on {bind_addr} failed: {e}"));
        }
    };

    let proxy = Arc::new(TcpProxy {
        remote_addr: format!(":{port}"),
        spec,
        port,
        cancel: CancellationToken::new(),
        ctx,
    });

    let runner = proxy.clone();
    tokio::spawn(async move {
        accept_loop(runner, listener, ctl).await;
    });
    Ok(proxy)
}

async fn accept_loop(proxy: Arc<TcpProxy>, listener: TcpListener, ctl: Arc<Control>) {
    info!(proxy = %proxy.spec.name, port = proxy.port, "tcp proxy listening");
    loop {
        tokio::select! {
            _ = proxy.cancel.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((user_conn, peer)) => {
                        let proxy = proxy.clone();
                        let ctl = ctl.clone();
                        tokio::spawn(async move {
                            handle_user_conn(proxy, ctl, user_conn, peer).await;
                        });
                    }
                    Err(e) => {
                        warn!(proxy = %proxy.spec.name, error = %e, "tcp accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }
    info!(proxy = %proxy.spec.name, "tcp proxy stopped");
}

async fn handle_user_conn(
    proxy: Arc<TcpProxy>,
    ctl: Arc<Control>,
    user_conn: TcpStream,
    peer: SocketAddr,
) {
    let ctx = proxy.ctx.clone();
    let spec = proxy.spec.clone();
    let cancel = proxy.cancel.clone();
    ctx.metrics.open_connection(&spec.name);
    let result = forward(ctx.clone(), ctl, &spec, &cancel, user_conn, peer).await;
    ctx.metrics.close_connection(&spec.name);
    if let Err(e) = result {
        debug!(proxy = %spec.name, error = %e, "tcp user connection ended");
    }
}

async fn forward(
    ctx: Arc<ServerContext>,
    ctl: Arc<Control>,
    spec: &ProxySpec,
    cancel: &CancellationToken,
    user_conn: TcpStream,
    peer: SocketAddr,
) -> Result<()> {
    let mut work_conn = ctl.get_work_conn(cancel).await?;
    work_conn.start(start_work_conn_for(spec, Some(&peer))).await?;

    let raw = work_conn.into_stream();
    let wrapped = WorkConnStream::new(
        raw,
        &ctx.token,
        spec.use_encryption,
        spec.use_compression,
    );

    let (traffic_in, traffic_out) = join_user_stream(wrapped, user_conn).await;
    ctx.metrics.add_traffic_in(&spec.name, traffic_in as i64);
    ctx.metrics.add_traffic_out(&spec.name, traffic_out as i64);
    Ok(())
}
