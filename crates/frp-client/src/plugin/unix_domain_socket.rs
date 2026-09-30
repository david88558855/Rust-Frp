//! `unix_domain_socket`: forward the work connection to a unix socket.
//!
//! `AF_UNIX` is a unix-only facility. Upstream registers the plugin
//! unconditionally and only fails when a connection is dialled, because Go's
//! `net.DialUnix` reports the error at that point. Refusing at configuration
//! load is more useful — the operator finds out at startup rather than when the
//! first request arrives — so a build without `AF_UNIX` rejects the plugin and
//! says why.

use std::future::Future;
use std::pin::Pin;

use super::{ConnInfo, Plugin};

pub struct UnixDomainSocketPlugin {
    unix_path: String,
}

impl UnixDomainSocketPlugin {
    #[cfg(unix)]
    pub fn new(unix_path: &str) -> anyhow::Result<Self> {
        Ok(Self {
            unix_path: unix_path.to_string(),
        })
    }

    #[cfg(not(unix))]
    pub fn new(_unix_path: &str) -> anyhow::Result<Self> {
        anyhow::bail!(
            "the unix_domain_socket plugin needs AF_UNIX, which this platform does not provide"
        )
    }
}

impl Plugin for UnixDomainSocketPlugin {
    fn name(&self) -> &'static str {
        "unix_domain_socket"
    }

    #[cfg(unix)]
    fn handle(&self, info: ConnInfo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        use tokio::net::UnixStream;
        use tracing::warn;

        let unix_path = self.unix_path.clone();
        Box::pin(async move {
            let local = match UnixStream::connect(&unix_path).await {
                Ok(stream) => stream,
                Err(e) => {
                    warn!(path = %unix_path, error = %e, "cannot connect to the unix socket");
                    return;
                }
            };
            crate::proxy::ProxyContext::join(info.conn, local).await;
        })
    }

    #[cfg(not(unix))]
    fn handle(&self, _info: ConnInfo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        // Unreachable: `new` refused the plugin on this platform.
        let _ = &self.unix_path;
        Box::pin(async {})
    }

    fn close(&self) {}
}
