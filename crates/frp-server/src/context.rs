//! Shared server state handed to every control session and proxy.

use std::sync::Arc;

use frp_core::config::server::ServerConfig;

use crate::control::ControlManager;
use crate::metrics::Metrics;
use crate::ports::PortManager;
use crate::visitor::VisitorRegistry;

/// Everything a proxy needs to do its job.
pub struct ServerContext {
    pub cfg: Arc<ServerConfig>,
    /// Raw `auth.token`, also the work-connection encryption key.
    pub token: Vec<u8>,
    pub metrics: Arc<Metrics>,
    pub tcp_ports: Arc<PortManager>,
    pub udp_ports: Arc<PortManager>,
    pub visitors: Arc<VisitorRegistry>,
    pub controls: Arc<ControlManager>,
    pub shutdown: tokio_util::sync::CancellationToken,
}

impl ServerContext {
    pub fn token_str(&self) -> String {
        String::from_utf8_lossy(&self.token).to_string()
    }

    pub fn sub_domain_host(&self) -> &str {
        &self.cfg.sub_domain_host
    }
}
