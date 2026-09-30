//! # frp-client
//!
//! The `frpc` side of Rust-Frp.
//!
//! This milestone pins the crate skeleton plus the login/heartbeat helpers the
//! control session will use; connector, proxy managers, visitors, health checks,
//! plugins and the admin UI arrive in the next commit.

#![forbid(unsafe_code)]

use frp_core::codec;
use frp_core::crypto::auth;
use frp_core::msg::{Login, Message, NewWorkConn, Ping};
use frp_core::util;

/// Default server port, matching upstream frp.
pub const DEFAULT_SERVER_PORT: u16 = 7000;

/// Default heartbeat interval in seconds.
pub const DEFAULT_HEARTBEAT_INTERVAL: i64 = 30;

/// A `Login` message populated exactly the way upstream `frpc` fills it.
#[derive(Debug, Clone)]
pub struct LoginRequest {
    pub user: String,
    pub client_id: String,
    pub metas: std::collections::HashMap<String, String>,
    pub pool_count: i32,
}

impl Default for LoginRequest {
    fn default() -> Self {
        Self {
            user: String::new(),
            client_id: String::new(),
            metas: std::collections::HashMap::new(),
            pool_count: 0,
        }
    }
}

/// Builds the login message, stamping the timestamp and token signature.
///
/// `token` is the raw `auth.token`; the privilege key is
/// `md5(token || decimal(timestamp))` (see [`crypto::auth`]).
pub fn build_login(req: &LoginRequest, token: &str) -> Login {
    let timestamp = util::now_unix();
    Login {
        version: frp_core::CLIENT_VERSION.to_string(),
        hostname: util::hostname(),
        os: util::os_name().to_string(),
        arch: util::arch_name().to_string(),
        user: req.user.clone(),
        privilege_key: auth::get_auth_key(token, timestamp),
        timestamp,
        run_id: String::new(),
        client_id: req.client_id.clone(),
        metas: req.metas.clone(),
        client_spec: Default::default(),
        pool_count: req.pool_count,
    }
}

/// Builds a heartbeat message; `additional_scopes` decides whether it is signed.
pub fn build_ping(token: &str, sign_heartbeats: bool) -> Message {
    let mut ping = Ping {
        privilege_key: String::new(),
        timestamp: 0,
    };
    if sign_heartbeats {
        ping.timestamp = util::now_unix();
        ping.privilege_key = auth::get_auth_key(token, ping.timestamp);
    }
    Message::Ping(ping)
}

/// Builds a `NewWorkConn` message announcing a freshly dialled work connection.
pub fn build_new_work_conn(run_id: &str, token: &str, sign_new_work_conns: bool) -> Message {
    let mut msg = NewWorkConn {
        run_id: run_id.to_string(),
        privilege_key: String::new(),
        timestamp: 0,
    };
    if sign_new_work_conns {
        msg.timestamp = util::now_unix();
        msg.privilege_key = auth::get_auth_key(token, msg.timestamp);
    }
    Message::NewWorkConn(msg)
}

/// Encodes any message into a wire frame.
pub fn frame(msg: &Message) -> anyhow::Result<Vec<u8>> {
    Ok(codec::pack(msg)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_is_signed_with_the_token() {
        let req = LoginRequest {
            user: "alice".into(),
            pool_count: 5,
            ..Default::default()
        };
        let login = build_login(&req, "s3cret");
        assert_eq!(login.user, "alice");
        assert_eq!(login.pool_count, 5);
        assert_eq!(login.version, "0.71.0");
        assert!(auth::verify_auth_key(
            "s3cret",
            login.timestamp,
            &login.privilege_key
        ));
        assert!(!auth::verify_auth_key(
            "wrong",
            login.timestamp,
            &login.privilege_key
        ));
    }

    #[test]
    fn unsigned_ping_has_no_key() {
        match build_ping("tok", false) {
            Message::Ping(p) => {
                assert!(p.privilege_key.is_empty());
                assert_eq!(p.timestamp, 0);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn signed_ping_verifies() {
        match build_ping("tok", true) {
            Message::Ping(p) => {
                assert!(auth::verify_auth_key("tok", p.timestamp, &p.privilege_key))
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
