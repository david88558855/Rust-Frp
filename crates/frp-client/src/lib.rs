//! # frp-client
//!
//! The `frpc` side of Rust-Frp.
//!
//! Implemented in this milestone:
//!
//! * configuration loading with `includes`, the `start` whitelist and
//!   duplicate-name rejection (see [`frp_core::config::client`]);
//! * the connector: TCP with optional TLS, and the yamux session that
//!   `transport.tcpMux` installs (see [`connector`]);
//! * the control session: login in plaintext, then the AES-128-CFB stream,
//!   heartbeats, `NewProxy` registration and the `NewWorkConn` handshake
//!   (see [`control`]);
//! * proxies: `tcp`, `http`, `https`, `stcp` and `tcpmux` all share the general
//!   TCP path, while `udp` and `sudp` use a framed UDP work connection
//!   (see [`proxy`]);
//! * the `stcp` visitor (see [`visitor`]);
//! * local service health checks with the upstream register/withdraw cycle
//!   (see [`health`]);
//! * the reconnect loop with exponential backoff (see [`service`]).
//!
//! Not implemented yet (tracked in the repository roadmap): `xtcp` and `sudp`
//! visitors, proxy plugins, the client store and admin UI, client side
//! bandwidth limiting, the proxy protocol header, and the `websocket` / `wss`,
//! `kcp` and `quic` transports.

#![forbid(unsafe_code)]

pub mod connector;
pub mod control;
pub mod health;
pub mod proxy;
pub mod service;
pub mod visitor;

pub use connector::Connector;
pub use control::{ControlHandle, SessionHandshake};
pub use proxy::{Phase, ProxyManager};
pub use service::Service;

/// Default server port, matching upstream frp.
pub const DEFAULT_SERVER_PORT: u16 = 7000;

/// Default heartbeat interval in seconds, used when TCPMux is disabled.
pub const DEFAULT_HEARTBEAT_INTERVAL: i64 = 30;

/// Prefixes a proxy name with the client's user, upstream `naming.AddUserPrefix`.
pub fn add_user_prefix(user: &str, name: &str) -> String {
    if user.is_empty() {
        name.to_string()
    } else {
        format!("{user}.{name}")
    }
}

/// Removes a user prefix, upstream `naming.StripUserPrefix`.
///
/// A name belonging to a different user is returned untouched, which is how
/// upstream behaves and what lets a client watch proxies it does not own.
pub fn strip_user_prefix<'a>(user: &str, name: &'a str) -> &'a str {
    if user.is_empty() {
        return name;
    }
    let prefix = format!("{user}.");
    name.strip_prefix(prefix.as_str()).unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_prefixes_match_upstream_naming() {
        assert_eq!(add_user_prefix("", "ssh"), "ssh");
        assert_eq!(add_user_prefix("alice", "ssh"), "alice.ssh");
        assert_eq!(strip_user_prefix("", "alice.ssh"), "alice.ssh");
        assert_eq!(strip_user_prefix("alice", "alice.ssh"), "ssh");
        assert_eq!(strip_user_prefix("alice", "bob.ssh"), "bob.ssh");
        assert_eq!(strip_user_prefix("alice", "alice."), "");
    }
}
