//! `stcp` / `sudp` proxies: no public listener, visitors are admitted by the
//! secret key and paired with a work connection.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use frp_core::crypto::stream::WorkConnStream;
use frp_core::msg::{Message, UdpPacket};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::context::ServerContext;
use crate::control::Control;
use crate::proxy::{join_user_stream, read_work_msg, start_work_conn_for, ProxySpec, ServerProxy};
use crate::visitor::VisitorConn;

/// Handle for an `stcp` or `sudp` proxy.
pub struct VisitorProxy {
    spec: ProxySpec,
    proxy_type: &'static str,
    cancel: CancellationToken,
    ctx: Arc<ServerContext>,
}

impl ServerProxy for VisitorProxy {
    fn name(&self) -> &str {
        &self.spec.name
    }

    fn proxy_type(&self) -> &str {
        self.proxy_type
    }

    fn spec(&self) -> &ProxySpec {
        &self.spec
    }

    fn remote_addr(&self) -> String {
        // stcp/sudp never expose a public port; upstream reports the proxy name.
        self.spec.name.clone()
    }

    fn close(&self) {
        self.cancel.cancel();
        self.ctx.visitors.unregister(&self.spec.name);
    }
}

/// Starts an `stcp` proxy (raw byte pipe to the visitor).
pub async fn start_stcp(
    ctx: Arc<ServerContext>,
    ctl: Arc<Control>,
    spec: ProxySpec,
    owner_user: &str,
) -> Result<Arc<VisitorProxy>> {
    start(ctx, ctl, spec, owner_user, "stcp", false).await
}

/// Starts a `sudp` proxy (`UDPPacket` messages relayed to the visitor).
pub async fn start_sudp(
    ctx: Arc<ServerContext>,
    ctl: Arc<Control>,
    spec: ProxySpec,
    owner_user: &str,
) -> Result<Arc<VisitorProxy>> {
    start(ctx, ctl, spec, owner_user, "sudp", true).await
}

async fn start(
    ctx: Arc<ServerContext>,
    ctl: Arc<Control>,
    spec: ProxySpec,
    owner_user: &str,
    proxy_type: &'static str,
    datagram: bool,
) -> Result<Arc<VisitorProxy>> {
    let rx = ctx
        .visitors
        .register(&spec.name, &spec.sk, spec.allow_users.clone(), owner_user)?;

    let proxy = Arc::new(VisitorProxy {
        spec,
        proxy_type,
        cancel: CancellationToken::new(),
        ctx,
    });

    let runner = proxy.clone();
    tokio::spawn(async move {
        accept_visitors(runner, rx, ctl, datagram).await;
    });
    Ok(proxy)
}

async fn accept_visitors(
    proxy: Arc<VisitorProxy>,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<VisitorConn>,
    ctl: Arc<Control>,
    datagram: bool,
) {
    info!(
        proxy = %proxy.spec.name,
        kind = proxy.proxy_type,
        "visitor proxy ready"
    );
    loop {
        tokio::select! {
            _ = proxy.cancel.cancelled() => break,
            incoming = rx.recv() => {
                let Some(visitor) = incoming else { break };
                let proxy = proxy.clone();
                let ctl = ctl.clone();
                tokio::spawn(async move {
                    let name = proxy.spec.name.clone();
                    if let Err(e) = proxy.pair(ctl, visitor, datagram).await {
                        debug!(proxy = %name, error = %e, "visitor connection ended");
                    }
                });
            }
        }
    }
    info!(proxy = %proxy.spec.name, "visitor proxy stopped");
}

impl VisitorProxy {
    async fn pair(
        &self,
        ctl: Arc<Control>,
        visitor: VisitorConn,
        datagram: bool,
    ) -> Result<()> {
        let mut work_conn = ctl.get_work_conn(&self.cancel).await?;
        work_conn
            .start(start_work_conn_for(&self.spec, Some(&visitor.remote_addr)))
            .await?;

        let work_raw = work_conn.into_stream();
        let work = WorkConnStream::new(
            work_raw,
            &self.ctx.token,
            self.spec.use_encryption,
            self.spec.use_compression,
        );

        // The visitor payload is encrypted with the proxy secret key.
        let visitor_stream = WorkConnStream::new(
            visitor.stream,
            self.spec.sk.as_bytes(),
            visitor.use_encryption,
            visitor.use_compression,
        );

        let name = self.spec.name.clone();
        let metrics_in = self.ctx.metrics.clone();
        let metrics_out = self.ctx.metrics.clone();
        let name_in = name.clone();
        let name_out = name.clone();

        if datagram {
            let (traffic_in, traffic_out) = relay_datagrams(visitor_stream, work).await;
            metrics_in.add_traffic_in(&name_in, traffic_in as i64);
            metrics_out.add_traffic_out(&name_out, traffic_out as i64);
        } else {
            self.ctx.metrics.open_connection(&name);
            let (traffic_in, traffic_out) = join_user_stream(work, visitor_stream).await;
            self.ctx.metrics.close_connection(&name);
            metrics_in.add_traffic_in(&name_in, traffic_in as i64);
            metrics_out.add_traffic_out(&name_out, traffic_out as i64);
        }
        Ok(())
    }
}

/// Relays `UDPPacket` messages between a visitor and a work connection.
async fn relay_datagrams<V, W>(visitor: V, work: W) -> (u64, u64)
where
    V: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    W: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (mut vr, mut vw) = tokio::io::split(visitor);
    let (mut wr, mut ww) = tokio::io::split(work);

    let to_work = async {
        let mut bytes = 0u64;
        loop {
            match read_work_msg(&mut vr).await {
                Ok(Message::UdpPacket(packet)) => {
                    bytes += packet.content.len() as u64;
                    if frp_core::codec::write_msg(&mut ww, &Message::UdpPacket(packet))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(Message::Ping(_)) => continue,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        let _ = ww.shutdown().await;
        bytes
    };

    let to_visitor = async {
        let mut bytes = 0u64;
        loop {
            match read_work_msg(&mut wr).await {
                Ok(Message::UdpPacket(packet)) => {
                    bytes += packet.content.len() as u64;
                    if frp_core::codec::write_msg(&mut vw, &Message::UdpPacket(packet))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(Message::Ping(_)) => continue,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        let _ = vw.shutdown().await;
        bytes
    };

    let (up, down) = tokio::join!(to_work, to_visitor);
    (up, down)
}

/// Extracts the payload length of a datagram message, used by tests.
pub fn datagram_len(packet: &UdpPacket) -> usize {
    packet.content.len()
}

/// Validates that a proxy name can be used for a visitor listener.
pub fn check_visitor_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("proxy name must not be empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visitor_names_must_not_be_empty() {
        assert!(check_visitor_name("a").is_ok());
        assert!(check_visitor_name("").is_err());
    }

    #[test]
    fn datagram_length_helper() {
        let packet = UdpPacket {
            content: b"abcd".to_vec(),
            ..Default::default()
        };
        assert_eq!(datagram_len(&packet), 4);
    }
}
