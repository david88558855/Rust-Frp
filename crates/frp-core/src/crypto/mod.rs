//! Cryptography primitives shared with upstream frp.

pub mod auth;
pub mod cfb;
pub mod snappy;
pub mod stream;

pub use auth::{constant_time_eq, get_auth_key, verify_auth_key};
pub use cfb::{derive_key, Cfb128};
pub use snappy::{FramedDecoder, FramedEncoder};
pub use stream::{CompressedStream, EncryptedStream, WorkConnStream};

/// Default salt used by `golib/crypto`.
pub const DEFAULT_SALT: &[u8] = b"crypto";

/// Number of PBKDF2 iterations used by `golib/crypto`.
pub const PBKDF2_ROUNDS: u32 = 64;
