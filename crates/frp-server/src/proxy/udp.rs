//! `udp` proxy: one remote UDP port carried over a single long-lived work
//! connection as `UDPPacket` messages, matching upstream `server/proxy/udp.go`.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use frp_core::crypto::stream::WorkConnStream;
use frp_core::msg::{Message, UdpAddrJson, UdpPacket};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::context::ServerContext;
use crate::control::Control;
use crate::proxy::{read_work_msg, ProxySpec, ServerProxy};

/// Handle for a bound UDP proxy.
pub struct UdpProxy {
    spec: ProxySpec,
    port: i32,
    remote_addr: String,
    cancel: CancellationToken,
    ctx: Arc<ServerContext>,
}

impl ServerProxy for UdpProxy {
    fn name(&self) -> &str {
        &self.spec.name
    }

    fn proxy_type(&self) -> &str {
        "udp"
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
        self.ctx.udp_ports.release(&self.spec.name, self.port);
    }
}

/// Binds the remote UDP port and starts the forwarding loop.
pub async fn start(
    ctx: Arc<ServerContext>,
    ctl: Arc<Control>,
    spec: ProxySpec,
) -> Result<Arc<UdpProxy>> {
    let port = ctx.udp_ports.acquire(&spec.name, spec.remote_port)?;
    let bind_addr = format!("{}:{}", ctx.cfg.proxy_bind(), port);
    let socket = match UdpSocket::bind(&bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            ctx.udp_ports.release(&spec.name, port);
            return Err(anyhow!("bind udp {bind_addr} failed: {e}"));
        }
    };

    let proxy = Arc::new(UdpProxy {
        remote_addr: bind_addr.clone(),
        spec,
        port,
        cancel: CancellationToken::new(),
        ctx,
    });

    let runner = proxy.clone();
    tokio::spawn(async move {
        runner.run(socket, ctl).await;
    });
    Ok(proxy)
}

impl UdpProxy {
    async fn run(&self, socket: UdpSocket, ctl: Arc<Control>) {
        let socket = Arc::new(socket);
        info!(
            proxy = %self.spec.name,
            port = self.port,
            "udp proxy listening"
        );

        // Only one work connection is used at a time; when it fails we dial a
        // replacement, exactly like upstream.
        loop {
            if self.cancel.is_cancelled() {
                break;
            }
            match ctl.get_work_conn(&self.cancel).await {
                Ok(mut work_conn) => {
                    let start_msg = crate::proxy::start_work_conn_for(&self.spec, None);
                    if let Err(e) = work_conn.start(start_msg).await {
                        debug!(proxy = %self.spec.name, error = %e, "udp start work conn failed");
                        continue;
                    }
                    let raw = work_conn.into_stream();
                    let wrapped = WorkConnStream::new(
                        raw,
                        &self.ctx.token,
                        self.spec.use_encryption,
                        self.spec.use_compression,
                    );
                    if let Err(e) = self.pump(wrapped, socket.clone()).await {
                        debug!(proxy = %self.spec.name, error = %e, "udp work conn ended");
                    }
                }
                Err(e) => {
                    debug!(proxy = %self.spec.name, error = %e, "no udp work connection");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
        info!(proxy = %self.spec.name, "udp proxy stopped");
    }

    async fn pump<S>(&self, stream: S, socket: Arc<UdpSocket>) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (out_tx, mut out_rx) = mpsc::channel::<Message>(1024);
        let name = self.spec.name.clone();
        let metrics = self.ctx.metrics.clone();

        // Client -> server: decoded packets are written back to the user.
        let writer_task = tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                if frp_core::codec::write_msg(&mut writer, &msg).await.is_err() {
                    break;
                }
            }
        });
        let _ = &writer_task;

        let local_addr = socket.local_addr().ok();
        let mut buf = vec![0u8; self.ctx.cfg.udp_packet_size.max(1500) as usize];
        let result = loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break Ok(()),
                read = socket.recv_from(&mut buf) => {
                    let (n, peer) = match read {
                        Ok(v) => v,
                        Err(e) => break Err(anyhow!("udp recv failed: {e}")),
                    };
                    let packet = Message::UdpPacket(UdpPacket {
                        content: buf[..n].to_vec(),
                        local_addr: local_addr.map(|a| UdpAddrJson::from_socket_addr(&a)),
                        remote_addr: Some(UdpAddrJson::from_socket_addr(&peer)),
                    });
                    metrics.add_traffic_in(&name, n as i64);
                    if out_tx.send(packet).await.is_err() {
                        break Ok(());
                    }
                }
                incoming = read_work_msg(&mut reader) => {
                    match incoming {
                        Ok(Message::UdpPacket(packet)) => {
                            let Some(dest) = packet.remote_addr.as_ref().and_then(|a| a.to_socket_addr()) else {
                                continue;
                            };
                            let sent = socket.send_to(&packet.content, dest).await
                                .map_err(|e| anyhow!("udp send failed: {e}"))?;
                            metrics.add_traffic_out(&name, sent as i64);
                        }
                        Ok(Message::Ping(_)) => continue,
                        Ok(other) => {
                            debug!(proxy = %name, kind = other.msg_type().name(), "unexpected udp work conn message");
                        }
                        Err(e) => break Err(e),
                    }
                }
            }
        };

        drop(out_tx);
        let _ = writer_task.await;
        result
    }
}

/// Resolves the destination for a proxied UDP reply.
pub fn reply_destination(packet: &UdpPacket) -> Option<SocketAddr> {
    packet.remote_addr.as_ref().and_then(|a| a.to_socket_addr())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_destination_comes_from_remote_addr() {
        let packet = UdpPacket {
            content: b"x".to_vec(),
            local_addr: Some(UdpAddrJson::new("127.0.0.1", 4000)),
            remote_addr: Some(UdpAddrJson::new("10.1.2.3", 5555)),
        };
        assert_eq!(
            reply_destination(&packet),
            Some("10.1.2.3:5555".parse().unwrap())
        );
        assert_eq!(reply_destination(&UdpPacket::default()), None);
    }
}
