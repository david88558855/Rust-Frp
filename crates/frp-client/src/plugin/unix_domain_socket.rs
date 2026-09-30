//! `unix_domain_socket`: forward the work connection to a unix socket.

use std::future::Future;
use std::pin::Pin;

use tokio::net::UnixStream;
use tracing::warn;

use super::{ConnInfo, Plugin};

pub struct UnixDomainSocketPlugin {
    unix_path: String,
}

impl UnixDomainSocketPlugin {
    pub fn new(unix_path: &str) -> Self {
        Self {
            unix_path: unix_path.to_string(),
        }
    }
}

impl Plugin for UnixDomainSocketPlugin {
    fn name(&self) -> &'static str {
        "unix_domain_socket"
    }

    fn handle(&self, info: ConnInfo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
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

    fn close(&self) {}
}
