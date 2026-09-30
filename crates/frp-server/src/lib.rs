//! # frp-server
//!
//! The `frps` side of Rust-Frp.
//!
//! This milestone only pins the crate skeleton and the shared primitives that
//! the control loop will build on; the listener, control connection handler,
//! port manager, proxy managers, admin API and dashboard arrive in the next
//! commit.

#![forbid(unsafe_code)]

use frp_core::codec;
use frp_core::msg::{Login, LoginResp, Message};

/// Default control port, matching upstream frp.
pub const DEFAULT_BIND_PORT: u16 = 7000;

/// Default dashboard port, matching upstream frp.
pub const DEFAULT_DASHBOARD_PORT: u16 = 7500;

/// Default heartbeat timeout in seconds.
pub const DEFAULT_HEARTBEAT_TIMEOUT: i64 = 90;

/// Builds the response the server sends for a login attempt.
///
/// Kept here (rather than inline in the control loop) so the exact wire shape
/// can be unit tested without a running server.
pub fn build_login_resp(run_id: &str, error: Option<String>) -> Message {
    Message::LoginResp(LoginResp {
        version: frp_core::FRP_VERSION.to_string(),
        run_id: run_id.to_string(),
        error: error.unwrap_or_default(),
    })
}

/// Convenience used by the control loop to encode a login response.
pub fn encode_login_resp(run_id: &str, error: Option<String>) -> anyhow::Result<Vec<u8>> {
    let msg = build_login_resp(run_id, error);
    Ok(codec::pack(&msg)?)
}

/// The server rejects logins whose `run_id` does not match an active session.
pub fn check_run_id(expected: &str, login: &Login) -> Result<(), String> {
    if expected.is_empty() || login.run_id == expected {
        Ok(())
    } else {
        Err(format!(
            "invalid run_id: expected {expected}, got {}",
            login.run_id
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_resp_frame_matches_expected_shape() {
        let frame = encode_login_resp("run1", None).unwrap();
        assert_eq!(frame[0], b'1');
        assert_eq!(&frame[9..], br#"{"version":"0.71.0","run_id":"run1","error":""}"#);
    }

    #[test]
    fn run_id_check() {
        let login = Login {
            run_id: "run1".into(),
            ..Default::default()
        };
        assert!(check_run_id("run1", &login).is_ok());
        assert!(check_run_id("", &login).is_ok());
        assert!(check_run_id("run2", &login).is_err());
    }
}
