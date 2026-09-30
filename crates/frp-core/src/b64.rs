//! base64 helpers matching Go's `encoding/json` treatment of `[]byte`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serializer};

pub fn encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(s)
}

/// serde adapter for `Vec<u8>` fields that Go would marshal as a base64 string.
/// Accepts both `null` and an absent field, mirroring `omitempty`.
pub mod opt_stdlib {
    use super::*;

    pub fn serialize<S>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&encode(v))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<String>::deserialize(d)? {
            None => Ok(Vec::new()),
            Some(s) if s.is_empty() => Ok(Vec::new()),
            Some(s) => decode(&s).map_err(D::Error::custom),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        assert_eq!(encode(b"hello"), "aGVsbG8=");
        assert_eq!(decode("aGVsbG8=").unwrap(), b"hello");
    }
}
