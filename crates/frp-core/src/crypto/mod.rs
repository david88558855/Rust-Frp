//! Cryptography primitives shared with upstream frp.

pub mod auth;
pub mod cfb;
pub mod snappy;
pub mod stream;

pub use auth::{constant_time_eq, get_auth_key, verify_auth_key};
pub use cfb::{derive_key, Cfb128};
pub use snappy::{FramedDecoder, FramedEncoder};
pub use stream::{CompressedStream, EncryptedStream, WorkConnStream};

/// Salt used to derive the AES key from the auth token or a visitor secret.
///
/// `golib/crypto` declares `DefaultSalt = "crypto"`, but it is an exported
/// variable and frp **overwrites it at package init** in both binaries:
///
/// ```go
/// // client/service.go and server/service.go
/// func init() { crypto.DefaultSalt = "frp" }
/// ```
///
/// so the salt in force on the wire is `"frp"`. Deriving with the library
/// default produces a key that is self consistent — a Rust client and a Rust
/// server still talk to each other — but matches neither frpc nor frps, and
/// every encrypted path fails at the first read. This was found by capturing a
/// real frpc↔frps session and decrypting it.
pub const DEFAULT_SALT: &[u8] = b"frp";

/// Number of PBKDF2 iterations used by `golib/crypto`.
pub const PBKDF2_ROUNDS: u32 = 64;
