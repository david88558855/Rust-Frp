//! Small helpers shared by the server crate.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the UNIX epoch.
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Turns an error into a client facing string, honouring
/// `detailedErrorsToClient`.
pub fn response_error(prefix: &str, err: &str, detailed: bool) -> String {
    if detailed {
        format!("{prefix}: {err}")
    } else {
        prefix.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detailed_errors_can_be_hidden() {
        assert_eq!(
            response_error("new proxy [a] error", "port used", true),
            "new proxy [a] error: port used"
        );
        assert_eq!(
            response_error("new proxy [a] error", "port used", false),
            "new proxy [a] error"
        );
    }

    #[test]
    fn clock_is_plausible() {
        assert!(unix_now() > 1_700_000_000);
    }
}
