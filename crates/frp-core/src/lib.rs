//! # frp-core
//!
//! Protocol, cryptography, configuration and transport primitives used by the
//! `frps` (server) and `frpc` (client) implementations of **Rust-Frp**.
//!
//! The crate is deliberately written to be *wire compatible* with upstream frp
//! `v0.71.0`:
//!
//! * control messages are framed as `type: u8 || len: i64 (big endian) || json`
//!   with a maximum payload of 10240 bytes (see [`codec`]);
//! * authentication keys are `md5(token || timestamp)` (see [`crypto::auth`]);
//! * the control connection is wrapped in AES-128-CFB keyed by
//!   `PBKDF2-HMAC-SHA1(token, "crypto", 64, 16)` immediately after `LoginResp`,
//!   and work connections use the same cipher behind `transport.useEncryption`
//!   (see [`crypto::stream`]);
//! * `useCompression` wraps a stream in the Snappy framed format
//!   (see [`crypto::snappy`]);
//! * the control port accepts frp's obfuscated TLS first byte `0x17`
//!   (see [`transport`]);
//! * HTTP/HTTPS proxies are routed with the same domain / location / http-user
//!   precedence as upstream (see [`vhost`]).

#![forbid(unsafe_code)]

pub mod b64;
pub mod codec;
pub mod config;
pub mod crypto;
pub mod msg;
pub mod transport;
pub mod util;
pub mod vhost;

pub use codec::{read_msg, unpack, write_msg, CodecError, HEADER_LEN, MAX_MSG_LENGTH};
pub use msg::{Message, MsgType};

/// The upstream frp version this implementation is compatible with.
pub const FRP_VERSION: &str = "0.71.0";

/// Version string reported to the server in `Login`.
pub const CLIENT_VERSION: &str = "0.71.0";
