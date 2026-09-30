//! `tls2raw`: terminate TLS from the remote peer and forward the plaintext.
//!
//! Useful for a service that speaks a raw protocol but has to be reached over
//! TLS by an off-the-shelf client, e.g. a database driver that insists on an
//! encrypted connection.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, warn};

use super::tls::build_acceptor;
use super::{ConnInfo, Plugin};

/// How long the backend has to accept a connection.
const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub struct Tls2RawPlugin {
    local_addr: String,
    acceptor: Arc<rustls::ServerConfig>,
}

impl Tls2RawPlugin {
    pub fn new(local_addr: &str, crt_path: &str, key_path: &str) -> anyhow::Result<Self> {
        Ok(Self {
            local_addr: local_addr.to_string(),
            // `tls2raw` is not an HTTP bridge, so it advertises no ALPN.
            acceptor: build_acceptor(crt_path, key_path, Vec::new())?,
        })
    }
}

impl Plugin for Tls2RawPlugin {
    fn name(&self) -> &'static str {
        "tls2raw"
    }

    fn handle(&self, info: ConnInfo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let acceptor = self.acceptor.clone();
        let local_addr = self.local_addr.clone();
        Box::pin(async move {
            let tls = match tokio_rustls::TlsAcceptor::from(acceptor)
                .accept(info.conn)
                .await
            {
                Ok(stream) => stream,
                Err(e) => {
                    warn!(error = %e, "tls2raw handshake failed");
                    return;
                }
            };

            let local = match timeout(DIAL_TIMEOUT, TcpStream::connect(&local_addr)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    warn!(addr = %local_addr, error = %e, "tls2raw cannot reach the local service");
                    return;
                }
                Err(_) => {
                    warn!(addr = %local_addr, "tls2raw timed out dialing the local service");
                    return;
                }
            };
            let _ = local.set_nodelay(true);
            debug!(addr = %local_addr, "tls2raw forwarding a decrypted connection");
            crate::proxy::ProxyContext::join(tls, local).await;
        })
    }

    fn close(&self) {}
}
