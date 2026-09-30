//! Test fixtures shared across the server crate.

use std::sync::Arc;

use frp_core::config::server::ServerConfig;
use tokio_util::sync::CancellationToken;

use crate::context::ServerContext;
use crate::control::ControlManager;
use crate::metrics::Metrics;
use crate::ports::PortManager;
use crate::visitor::VisitorRegistry;

/// A server context with upstream defaults.
pub fn context() -> ServerContext {
    context_with(ServerConfig::default())
}

/// A server context built from an explicit configuration.
pub fn context_with(mut cfg: ServerConfig) -> ServerContext {
    cfg.complete();
    let tcp_ports = PortManager::new("tcp", cfg.proxy_bind(), cfg.allow_ports.clone());
    let udp_ports = PortManager::new("udp", cfg.proxy_bind(), cfg.allow_ports.clone());
    ServerContext {
        tcp_ports: Arc::new(tcp_ports),
        udp_ports: Arc::new(udp_ports),
        metrics: Arc::new(Metrics::new()),
        visitors: Arc::new(VisitorRegistry::new()),
        controls: Arc::new(ControlManager::new()),
        token: b"test-token".to_vec(),
        cfg: Arc::new(cfg),
        shutdown: CancellationToken::new(),
    }
}
