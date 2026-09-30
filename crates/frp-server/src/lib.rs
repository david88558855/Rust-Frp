//! # frp-server
//!
//! The `frps` side of Rust-Frp.
//!
//! Implemented in this milestone:
//!
//! * control listener with frp's custom TLS first byte handling and token auth;
//! * `transport.tcpMux` stream multiplexing: the accepted socket carries a
//!   yamux session and every logical connection arrives as a stream of it;
//! * control sessions: run-id replacement, heartbeat supervision, work
//!   connection pool, `NewProxy` / `CloseProxy` handling;
//! * `tcp`, `udp`, `stcp`, `sudp`, `http` and `https` proxies with port
//!   allocation;
//! * `http` / `https` virtual host routing: HTTP is terminated and replayed
//!   over a work connection, HTTPS routes on the SNI of a peeked ClientHello
//!   and forwards the still-encrypted stream;
//! * visitor admission for `stcp` / `sudp`;
//! * dashboard, admin JSON API and Prometheus endpoint.
//!
//! Not implemented yet (tracked in the repository roadmap): `tcpmux`, `xtcp`
//! NAT hole punching, proxy groups, bandwidth limiting and wire protocol v2.

#![forbid(unsafe_code)]

pub mod context;
pub mod control;
pub mod dashboard;
pub mod http_util;
pub mod metrics;
pub mod ports;
pub mod proxy;
pub mod service;
pub mod util;
pub mod vhost_server;
pub mod visitor;

#[cfg(test)]
pub mod test_support;

pub use context::ServerContext;
pub use service::Service;

/// Default control port, matching upstream frp.
pub const DEFAULT_BIND_PORT: u16 = 7000;

/// Default dashboard port, matching upstream frp.
pub const DEFAULT_DASHBOARD_PORT: u16 = 7500;

/// Default heartbeat timeout in seconds.
pub const DEFAULT_HEARTBEAT_TIMEOUT: i64 = 90;
