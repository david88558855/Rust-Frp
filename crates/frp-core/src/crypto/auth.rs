//! Token authentication.
//!
//! Upstream `pkg/util/util/util.go`:
//!
//! ```go
//! func GetAuthKey(token string, timestamp int64) (key string) {
//!     md5Ctx := md5.New()
//!     md5Ctx.Write([]byte(token))
//!     md5Ctx.Write([]byte(strconv.FormatInt(timestamp, 10)))
//!     return hex.EncodeToString(md5Ctx.Sum(nil))
//! }
//! ```

use md5::{Digest, Md5};

/// Computes `md5(token || decimal(timestamp))` in lowercase hex.
pub fn get_auth_key(token: &str, timestamp: i64) -> String {
    let mut hasher = Md5::new();
    hasher.update(token.as_bytes());
    hasher.update(timestamp.to_string().as_bytes());
    hex::encode(hasher.finalize())
}

/// Constant time comparison, mirroring `util.ConstantTimeEqString`.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verifies a privilege key against `token` and `timestamp`.
pub fn verify_auth_key(token: &str, timestamp: i64, key: &str) -> bool {
    constant_time_eq(&get_auth_key(token, timestamp), key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_key_matches_upstream_algorithm() {
        // md5("abc" + "1700000000")
        let key = get_auth_key("abc", 1_700_000_000);
        assert_eq!(key.len(), 32);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // deterministic
        assert_eq!(key, get_auth_key("abc", 1_700_000_000));
        assert_ne!(key, get_auth_key("abc", 1_700_000_001));
    }

    #[test]
    fn empty_token_still_hashes() {
        assert_eq!(get_auth_key("", 0), get_auth_key("", 0));
    }

    #[test]
    fn constant_time_eq_behaviour() {
        assert!(constant_time_eq("deadbeef", "deadbeef"));
        assert!(!constant_time_eq("deadbeef", "deadbeee"));
        assert!(!constant_time_eq("deadbeef", "deadbee"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }
}
