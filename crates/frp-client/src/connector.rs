//! Dialling the server, with or without TCPMux.
//!
//! Upstream `client/connector.go` keeps a yamux session open when
//! `transport.tcpMux` is set and hands out a stream per connection; otherwise
//! every call opens a real TCP connection. Both behaviours live here so the
//! control session and the work-connection path do not have to care which one
//! is active.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use frp_core::config::ClientCommonConfig;
use frp_core::transport::{self, ClientConn, ClientStream};
use frp_core::yamux;

/// Owns the optional multiplexed session to the server.
pub struct Connector {
    cfg: Arc<ClientCommonConfig>,
    session: Mutex<Option<Arc<yamux::Session>>>,
}

impl Connector {
    pub fn new(cfg: Arc<ClientCommonConfig>) -> Self {
        Self {
            cfg,
            session: Mutex::new(None),
        }
    }

    fn server_addr(&self) -> String {
        format!("{}:{}", self.cfg.server_addr, self.cfg.server_port)
    }

    async fn dial(&self) -> Result<ClientStream> {
        let addr = self.server_addr();
        let timeout = Duration::from_secs(self.cfg.transport.dial_server_timeout.max(1) as u64);
        transport::connect_server_stream(
            &addr,
            &self.cfg.transport.tls,
            &self.cfg.transport.connect_server_local_ip,
            timeout,
        )
        .await
    }

    /// Establishes the shared session. A no-op when TCPMux is off.
    pub async fn open(&self) -> Result<()> {
        if !self.cfg.transport.tcp_mux_enabled() {
            return Ok(());
        }
        let stream = self.dial().await.context("dial the control port")?;
        let keepalive = self.cfg.transport.tcp_mux_keepalive_interval.max(1) as u64;
        let session = yamux::Session::new(
            stream,
            yamux::Mode::Client,
            yamux::Config::for_frp(Duration::from_secs(keepalive)),
        );
        let previous = {
            let mut slot = self.session.lock().unwrap();
            slot.replace(Arc::new(session))
        };
        if let Some(previous) = previous {
            previous.close();
        }
        Ok(())
    }

    /// Returns one logical connection to the server.
    pub async fn connect(&self) -> Result<ClientConn> {
        let session = {
            let slot = self.session.lock().unwrap();
            slot.clone()
        };
        if let Some(session) = session {
            let stream = session.open().await.context("open a mux stream")?;
            return Ok(ClientConn::Mux(stream));
        }
        Ok(ClientConn::Plain(self.dial().await?))
    }

    pub fn close(&self) {
        let session = {
            let mut slot = self.session.lock().unwrap();
            slot.take()
        };
        if let Some(session) = session {
            session.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frp_core::config::{ClientConfig, ClientConfigFile};

    fn client_cfg(json: &str) -> Arc<ClientCommonConfig> {
        let parsed: ClientConfigFile = serde_json::from_str(json).unwrap();
        let cfg =
            ClientConfig::from_parts(parsed.common, Vec::new(), Vec::new(), Vec::new()).unwrap();
        Arc::new(cfg.common)
    }

    #[tokio::test]
    async fn connect_without_tcp_mux_returns_a_plain_stream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut stream = frp_core::transport::accept_server_stream(sock, None, false)
                .await
                .unwrap();
            let mut buf = [0u8; 3];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf)
                .await
                .unwrap();
            buf
        });

        let cfg = client_cfg(&format!(
            r#"{{"serverAddr":"127.0.0.1","serverPort":{},"transport":{{"tcpMux":false}}}}"#,
            addr.port()
        ));
        let connector = Connector::new(cfg);
        connector.open().await.unwrap();
        let mut conn = connector.connect().await.unwrap();
        assert_eq!(conn.kind(), "tcp");
        tokio::io::AsyncWriteExt::write_all(&mut conn, b"hey")
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::flush(&mut conn).await.unwrap();
        assert_eq!(server.await.unwrap(), *b"hey");
    }

    #[tokio::test]
    async fn connect_with_tcp_mux_returns_a_mux_stream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // The peer plays the server side of the yamux session.
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let stream = frp_core::transport::accept_server_stream(sock, None, false)
                .await
                .unwrap();
            let mut session = yamux::Session::new(
                stream,
                yamux::Mode::Server,
                yamux::Config::for_frp(Duration::from_secs(30)),
            );
            let mut stream = session.accept().await.unwrap();
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf)
                .await
                .unwrap();
            buf
        });

        let cfg = client_cfg(&format!(
            r#"{{"serverAddr":"127.0.0.1","serverPort":{}}}"#,
            addr.port()
        ));
        assert!(cfg.transport.tcp_mux_enabled());
        let connector = Connector::new(cfg);
        connector.open().await.unwrap();

        let mut conn = connector.connect().await.unwrap();
        assert_eq!(conn.kind(), "mux");
        tokio::io::AsyncWriteExt::write_all(&mut conn, b"muxed")
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::shutdown(&mut conn).await.unwrap();

        assert_eq!(server.await.unwrap(), b"muxed");
    }
}
