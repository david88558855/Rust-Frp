//! Control message definitions, byte-for-byte compatible with upstream frp
//! `pkg/msg/msg.go` at `v0.71.0`.
//!
//! Every field carries an explicit `serde(rename)` so the emitted JSON matches
//! the Go `encoding/json` output regardless of Rust naming conventions.
//!
//! Every field in upstream's structs is tagged `json:...,omitempty`, so a zero
//! value is **omitted** from the payload rather than emitted as `""`, `0` or
//! `false`. This module reproduces that with `skip_serializing_if`, using the
//! predicates in [`is_zero`]. The distinction is invisible to Go on decode —
//! `json.Unmarshal` treats an absent key and a zero value identically — but it
//! is what "byte-for-byte compatible" means, and
//! `tests/wire_vectors.rs` asserts it against a corpus captured from upstream.
//!
//! Two fields are deliberately different from their neighbours and are called
//! out where they are declared: `ClientSpec` has no `omitempty` upstream so it
//! is always emitted (as at least `{}`), and `NatHoleResp.DetectBehavior`
//! likewise.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Predicate helpers for `skip_serializing_if`.
///
/// Go's `omitempty` drops the zero value of every type it applies to: the empty
/// string, the number zero, `false`, a nil or empty slice, map or pointer. The
/// functions below mirror that set exactly, so a field is emitted if and only if
/// upstream would emit it.
pub mod is_zero {
    use std::collections::HashMap;

    pub fn string(v: &str) -> bool {
        v.is_empty()
    }

    pub fn i32(v: &i32) -> bool {
        *v == 0
    }

    pub fn i64(v: &i64) -> bool {
        *v == 0
    }

    pub fn u16(v: &u16) -> bool {
        *v == 0
    }

    pub fn bool(v: &bool) -> bool {
        !*v
    }

    /// Serde hands the predicate `&Vec<T>`, not `&[T]`, so this takes the owned
    /// container to avoid a deref coercion that does not apply to a function
    /// pointer.
    pub fn slice<T>(v: &Vec<T>) -> bool {
        v.is_empty()
    }

    pub fn map<K, V>(v: &HashMap<K, V>) -> bool {
        v.is_empty()
    }

    /// `UdpPacket.Content` is a `Vec<u8>` serialised as base64, so it needs its
    /// own predicate rather than sharing the generic `slice`.
    pub fn bytes(v: &Vec<u8>) -> bool {
        v.is_empty()
    }

    pub fn opt<T>(v: &Option<T>) -> bool {
        v.is_none()
    }
}

/// Message type bytes, mirrored from `pkg/msg/msg.go`.
pub mod ty {
    pub const LOGIN: u8 = b'o';
    pub const LOGIN_RESP: u8 = b'1';
    pub const NEW_PROXY: u8 = b'p';
    pub const NEW_PROXY_RESP: u8 = b'2';
    pub const CLOSE_PROXY: u8 = b'c';
    pub const NEW_WORK_CONN: u8 = b'w';
    pub const REQ_WORK_CONN: u8 = b'r';
    pub const START_WORK_CONN: u8 = b's';
    pub const NEW_VISITOR_CONN: u8 = b'v';
    pub const NEW_VISITOR_CONN_RESP: u8 = b'3';
    pub const PING: u8 = b'h';
    pub const PONG: u8 = b'4';
    pub const UDP_PACKET: u8 = b'u';
    pub const NAT_HOLE_VISITOR: u8 = b'i';
    pub const NAT_HOLE_CLIENT: u8 = b'n';
    pub const NAT_HOLE_RESP: u8 = b'm';
    pub const NAT_HOLE_SID: u8 = b'5';
    pub const NAT_HOLE_REPORT: u8 = b'6';
}

/// Typed view over the message type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MsgType {
    Login,
    LoginResp,
    NewProxy,
    NewProxyResp,
    CloseProxy,
    NewWorkConn,
    ReqWorkConn,
    StartWorkConn,
    NewVisitorConn,
    NewVisitorConnResp,
    Ping,
    Pong,
    UdpPacket,
    NatHoleVisitor,
    NatHoleClient,
    NatHoleResp,
    NatHoleSid,
    NatHoleReport,
}

impl MsgType {
    pub const fn to_byte(self) -> u8 {
        match self {
            MsgType::Login => ty::LOGIN,
            MsgType::LoginResp => ty::LOGIN_RESP,
            MsgType::NewProxy => ty::NEW_PROXY,
            MsgType::NewProxyResp => ty::NEW_PROXY_RESP,
            MsgType::CloseProxy => ty::CLOSE_PROXY,
            MsgType::NewWorkConn => ty::NEW_WORK_CONN,
            MsgType::ReqWorkConn => ty::REQ_WORK_CONN,
            MsgType::StartWorkConn => ty::START_WORK_CONN,
            MsgType::NewVisitorConn => ty::NEW_VISITOR_CONN,
            MsgType::NewVisitorConnResp => ty::NEW_VISITOR_CONN_RESP,
            MsgType::Ping => ty::PING,
            MsgType::Pong => ty::PONG,
            MsgType::UdpPacket => ty::UDP_PACKET,
            MsgType::NatHoleVisitor => ty::NAT_HOLE_VISITOR,
            MsgType::NatHoleClient => ty::NAT_HOLE_CLIENT,
            MsgType::NatHoleResp => ty::NAT_HOLE_RESP,
            MsgType::NatHoleSid => ty::NAT_HOLE_SID,
            MsgType::NatHoleReport => ty::NAT_HOLE_REPORT,
        }
    }

    pub const fn from_byte(b: u8) -> Option<MsgType> {
        let t = match b {
            ty::LOGIN => MsgType::Login,
            ty::LOGIN_RESP => MsgType::LoginResp,
            ty::NEW_PROXY => MsgType::NewProxy,
            ty::NEW_PROXY_RESP => MsgType::NewProxyResp,
            ty::CLOSE_PROXY => MsgType::CloseProxy,
            ty::NEW_WORK_CONN => MsgType::NewWorkConn,
            ty::REQ_WORK_CONN => MsgType::ReqWorkConn,
            ty::START_WORK_CONN => MsgType::StartWorkConn,
            ty::NEW_VISITOR_CONN => MsgType::NewVisitorConn,
            ty::NEW_VISITOR_CONN_RESP => MsgType::NewVisitorConnResp,
            ty::PING => MsgType::Ping,
            ty::PONG => MsgType::Pong,
            ty::UDP_PACKET => MsgType::UdpPacket,
            ty::NAT_HOLE_VISITOR => MsgType::NatHoleVisitor,
            ty::NAT_HOLE_CLIENT => MsgType::NatHoleClient,
            ty::NAT_HOLE_RESP => MsgType::NatHoleResp,
            ty::NAT_HOLE_SID => MsgType::NatHoleSid,
            ty::NAT_HOLE_REPORT => MsgType::NatHoleReport,
            _ => return None,
        };
        Some(t)
    }

    /// Go type name, used as the lane key of the client side message registry.
    pub const fn name(self) -> &'static str {
        match self {
            MsgType::Login => "Login",
            MsgType::LoginResp => "LoginResp",
            MsgType::NewProxy => "NewProxy",
            MsgType::NewProxyResp => "NewProxyResp",
            MsgType::CloseProxy => "CloseProxy",
            MsgType::NewWorkConn => "NewWorkConn",
            MsgType::ReqWorkConn => "ReqWorkConn",
            MsgType::StartWorkConn => "StartWorkConn",
            MsgType::NewVisitorConn => "NewVisitorConn",
            MsgType::NewVisitorConnResp => "NewVisitorConnResp",
            MsgType::Ping => "Ping",
            MsgType::Pong => "Pong",
            MsgType::UdpPacket => "UDPPacket",
            MsgType::NatHoleVisitor => "NatHoleVisitor",
            MsgType::NatHoleClient => "NatHoleClient",
            MsgType::NatHoleResp => "NatHoleResp",
            MsgType::NatHoleSid => "NatHoleSid",
            MsgType::NatHoleReport => "NatHoleReport",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientSpec {
    #[serde(rename = "type", default, skip_serializing_if = "is_zero::string")]
    pub client_type: String,
    #[serde(rename = "always_auth_pass", default, skip_serializing_if = "is_zero::bool")]
    pub always_auth_pass: bool,
}

/// Sent by `frpc` right after the transport is established.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Login {
    #[serde(rename = "version", default, skip_serializing_if = "is_zero::string")]
    pub version: String,
    #[serde(rename = "hostname", default, skip_serializing_if = "is_zero::string")]
    pub hostname: String,
    #[serde(rename = "os", default, skip_serializing_if = "is_zero::string")]
    pub os: String,
    #[serde(rename = "arch", default, skip_serializing_if = "is_zero::string")]
    pub arch: String,
    #[serde(rename = "user", default, skip_serializing_if = "is_zero::string")]
    pub user: String,
    #[serde(rename = "privilege_key", default, skip_serializing_if = "is_zero::string")]
    pub privilege_key: String,
    #[serde(rename = "timestamp", default, skip_serializing_if = "is_zero::i64")]
    pub timestamp: i64,
    #[serde(rename = "run_id", default, skip_serializing_if = "is_zero::string")]
    pub run_id: String,
    #[serde(rename = "client_id", default, skip_serializing_if = "is_zero::string")]
    pub client_id: String,
    #[serde(rename = "metas", default, skip_serializing_if = "is_zero::map")]
    pub metas: HashMap<String, String>,
    #[serde(rename = "client_spec", default)]
    pub client_spec: ClientSpec,
    #[serde(rename = "pool_count", default, skip_serializing_if = "is_zero::i32")]
    pub pool_count: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LoginResp {
    #[serde(rename = "version", default, skip_serializing_if = "is_zero::string")]
    pub version: String,
    #[serde(rename = "run_id", default, skip_serializing_if = "is_zero::string")]
    pub run_id: String,
    #[serde(rename = "error", default, skip_serializing_if = "is_zero::string")]
    pub error: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NewProxy {
    #[serde(rename = "proxy_name", default, skip_serializing_if = "is_zero::string")]
    pub proxy_name: String,
    #[serde(rename = "proxy_type", default, skip_serializing_if = "is_zero::string")]
    pub proxy_type: String,
    #[serde(rename = "use_encryption", default, skip_serializing_if = "is_zero::bool")]
    pub use_encryption: bool,
    #[serde(rename = "use_compression", default, skip_serializing_if = "is_zero::bool")]
    pub use_compression: bool,
    #[serde(rename = "bandwidth_limit", default, skip_serializing_if = "is_zero::string")]
    pub bandwidth_limit: String,
    #[serde(rename = "bandwidth_limit_mode", default, skip_serializing_if = "is_zero::string")]
    pub bandwidth_limit_mode: String,
    #[serde(rename = "group", default, skip_serializing_if = "is_zero::string")]
    pub group: String,
    #[serde(rename = "group_key", default, skip_serializing_if = "is_zero::string")]
    pub group_key: String,
    #[serde(rename = "metas", default, skip_serializing_if = "is_zero::map")]
    pub metas: HashMap<String, String>,
    #[serde(rename = "annotations", default, skip_serializing_if = "is_zero::map")]
    pub annotations: HashMap<String, String>,
    #[serde(rename = "remote_port", default, skip_serializing_if = "is_zero::i32")]
    pub remote_port: i32,
    #[serde(rename = "custom_domains", default, skip_serializing_if = "is_zero::slice")]
    pub custom_domains: Vec<String>,
    #[serde(rename = "subdomain", default, skip_serializing_if = "is_zero::string")]
    pub sub_domain: String,
    #[serde(rename = "locations", default, skip_serializing_if = "is_zero::slice")]
    pub locations: Vec<String>,
    #[serde(rename = "http_user", default, skip_serializing_if = "is_zero::string")]
    pub http_user: String,
    #[serde(rename = "http_pwd", default, skip_serializing_if = "is_zero::string")]
    pub http_pwd: String,
    #[serde(rename = "host_header_rewrite", default, skip_serializing_if = "is_zero::string")]
    pub host_header_rewrite: String,
    #[serde(rename = "headers", default, skip_serializing_if = "is_zero::map")]
    pub headers: HashMap<String, String>,
    #[serde(rename = "response_headers", default, skip_serializing_if = "is_zero::map")]
    pub response_headers: HashMap<String, String>,
    #[serde(rename = "route_by_http_user", default, skip_serializing_if = "is_zero::string")]
    pub route_by_http_user: String,
    #[serde(rename = "sk", default, skip_serializing_if = "is_zero::string")]
    pub sk: String,
    #[serde(rename = "allow_users", default, skip_serializing_if = "is_zero::slice")]
    pub allow_users: Vec<String>,
    #[serde(rename = "multiplexer", default, skip_serializing_if = "is_zero::string")]
    pub multiplexer: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NewProxyResp {
    #[serde(rename = "proxy_name", default, skip_serializing_if = "is_zero::string")]
    pub proxy_name: String,
    #[serde(rename = "remote_addr", default, skip_serializing_if = "is_zero::string")]
    pub remote_addr: String,
    #[serde(rename = "error", default, skip_serializing_if = "is_zero::string")]
    pub error: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CloseProxy {
    #[serde(rename = "proxy_name", default, skip_serializing_if = "is_zero::string")]
    pub proxy_name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NewWorkConn {
    #[serde(rename = "run_id", default, skip_serializing_if = "is_zero::string")]
    pub run_id: String,
    #[serde(rename = "privilege_key", default, skip_serializing_if = "is_zero::string")]
    pub privilege_key: String,
    #[serde(rename = "timestamp", default, skip_serializing_if = "is_zero::i64")]
    pub timestamp: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ReqWorkConn {}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StartWorkConn {
    #[serde(rename = "proxy_name", default, skip_serializing_if = "is_zero::string")]
    pub proxy_name: String,
    #[serde(rename = "src_addr", default, skip_serializing_if = "is_zero::string")]
    pub src_addr: String,
    #[serde(rename = "dst_addr", default, skip_serializing_if = "is_zero::string")]
    pub dst_addr: String,
    #[serde(rename = "src_port", default, skip_serializing_if = "is_zero::u16")]
    pub src_port: u16,
    #[serde(rename = "dst_port", default, skip_serializing_if = "is_zero::u16")]
    pub dst_port: u16,
    #[serde(rename = "error", default, skip_serializing_if = "is_zero::string")]
    pub error: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NewVisitorConn {
    #[serde(rename = "run_id", default, skip_serializing_if = "is_zero::string")]
    pub run_id: String,
    #[serde(rename = "proxy_name", default, skip_serializing_if = "is_zero::string")]
    pub proxy_name: String,
    #[serde(rename = "sign_key", default, skip_serializing_if = "is_zero::string")]
    pub sign_key: String,
    #[serde(rename = "timestamp", default, skip_serializing_if = "is_zero::i64")]
    pub timestamp: i64,
    #[serde(rename = "use_encryption", default, skip_serializing_if = "is_zero::bool")]
    pub use_encryption: bool,
    #[serde(rename = "use_compression", default, skip_serializing_if = "is_zero::bool")]
    pub use_compression: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NewVisitorConnResp {
    #[serde(rename = "proxy_name", default, skip_serializing_if = "is_zero::string")]
    pub proxy_name: String,
    #[serde(rename = "error", default, skip_serializing_if = "is_zero::string")]
    pub error: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Ping {
    #[serde(rename = "privilege_key", default, skip_serializing_if = "is_zero::string")]
    pub privilege_key: String,
    #[serde(rename = "timestamp", default, skip_serializing_if = "is_zero::i64")]
    pub timestamp: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Pong {
    #[serde(rename = "error", default, skip_serializing_if = "is_zero::string")]
    pub error: String,
}

/// `net.UDPAddr` serialised by Go as `{"IP":"1.2.3.4","Port":53,"Zone":""}`.
///
/// Unlike every message struct, `net.UDPAddr` carries **no** struct tags at all
/// (`src/net/udpsock.go`), so `encoding/json` falls back to the field names and
/// there is no `omitempty`: all three keys are always present, `Zone` included
/// even when empty. Do not add `skip_serializing_if` here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpAddrJson {
    #[serde(rename = "IP", default)]
    pub ip: String,
    #[serde(rename = "Port", default)]
    pub port: u16,
    #[serde(rename = "Zone", default)]
    pub zone: String,
}

impl UdpAddrJson {
    pub fn new(ip: impl Into<String>, port: u16) -> Self {
        Self {
            ip: ip.into(),
            port,
            zone: String::new(),
        }
    }

    pub fn to_socket_addr(&self) -> Option<std::net::SocketAddr> {
        let ip: std::net::IpAddr = self.ip.parse().ok()?;
        Some(std::net::SocketAddr::new(ip, self.port))
    }

    pub fn from_socket_addr(addr: &std::net::SocketAddr) -> Self {
        Self {
            ip: addr.ip().to_string(),
            port: addr.port(),
            zone: String::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UdpPacket {
    #[serde(rename = "c", default, with = "crate::b64::opt_stdlib", skip_serializing_if = "is_zero::bytes")]
    pub content: Vec<u8>,
    #[serde(rename = "l", default, skip_serializing_if = "is_zero::opt")]
    pub local_addr: Option<UdpAddrJson>,
    #[serde(rename = "r", default, skip_serializing_if = "is_zero::opt")]
    pub remote_addr: Option<UdpAddrJson>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NatHoleVisitor {
    #[serde(rename = "transaction_id", default, skip_serializing_if = "is_zero::string")]
    pub transaction_id: String,
    #[serde(rename = "proxy_name", default, skip_serializing_if = "is_zero::string")]
    pub proxy_name: String,
    #[serde(rename = "pre_check", default, skip_serializing_if = "is_zero::bool")]
    pub pre_check: bool,
    #[serde(rename = "protocol", default, skip_serializing_if = "is_zero::string")]
    pub protocol: String,
    #[serde(rename = "sign_key", default, skip_serializing_if = "is_zero::string")]
    pub sign_key: String,
    #[serde(rename = "timestamp", default, skip_serializing_if = "is_zero::i64")]
    pub timestamp: i64,
    #[serde(rename = "mapped_addrs", default, skip_serializing_if = "is_zero::slice")]
    pub mapped_addrs: Vec<String>,
    #[serde(rename = "assisted_addrs", default, skip_serializing_if = "is_zero::slice")]
    pub assisted_addrs: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NatHoleClient {
    #[serde(rename = "transaction_id", default, skip_serializing_if = "is_zero::string")]
    pub transaction_id: String,
    #[serde(rename = "proxy_name", default, skip_serializing_if = "is_zero::string")]
    pub proxy_name: String,
    #[serde(rename = "sid", default, skip_serializing_if = "is_zero::string")]
    pub sid: String,
    #[serde(rename = "mapped_addrs", default, skip_serializing_if = "is_zero::slice")]
    pub mapped_addrs: Vec<String>,
    #[serde(rename = "assisted_addrs", default, skip_serializing_if = "is_zero::slice")]
    pub assisted_addrs: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PortsRange {
    #[serde(rename = "from", default, skip_serializing_if = "is_zero::i32")]
    pub from: i32,
    #[serde(rename = "to", default, skip_serializing_if = "is_zero::i32")]
    pub to: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NatHoleDetectBehavior {
    #[serde(rename = "role", default, skip_serializing_if = "is_zero::string")]
    pub role: String,
    #[serde(rename = "mode", default, skip_serializing_if = "is_zero::i32")]
    pub mode: i32,
    #[serde(rename = "ttl", default, skip_serializing_if = "is_zero::i32")]
    pub ttl: i32,
    #[serde(rename = "send_delay_ms", default, skip_serializing_if = "is_zero::i32")]
    pub send_delay_ms: i32,
    #[serde(rename = "read_timeout", default, skip_serializing_if = "is_zero::i32")]
    pub read_timeout: i32,
    #[serde(rename = "candidate_ports", default, skip_serializing_if = "is_zero::slice")]
    pub candidate_ports: Vec<PortsRange>,
    #[serde(rename = "send_random_ports", default, skip_serializing_if = "is_zero::i32")]
    pub send_random_ports: i32,
    #[serde(rename = "listen_random_ports", default, skip_serializing_if = "is_zero::i32")]
    pub listen_random_ports: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NatHoleResp {
    #[serde(rename = "transaction_id", default, skip_serializing_if = "is_zero::string")]
    pub transaction_id: String,
    #[serde(rename = "sid", default, skip_serializing_if = "is_zero::string")]
    pub sid: String,
    #[serde(rename = "protocol", default, skip_serializing_if = "is_zero::string")]
    pub protocol: String,
    #[serde(rename = "candidate_addrs", default, skip_serializing_if = "is_zero::slice")]
    pub candidate_addrs: Vec<String>,
    #[serde(rename = "assisted_addrs", default, skip_serializing_if = "is_zero::slice")]
    pub assisted_addrs: Vec<String>,
    #[serde(rename = "detect_behavior", default)]
    pub detect_behavior: NatHoleDetectBehavior,
    #[serde(rename = "error", default, skip_serializing_if = "is_zero::string")]
    pub error: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NatHoleSid {
    #[serde(rename = "transaction_id", default, skip_serializing_if = "is_zero::string")]
    pub transaction_id: String,
    #[serde(rename = "sid", default, skip_serializing_if = "is_zero::string")]
    pub sid: String,
    #[serde(rename = "response", default, skip_serializing_if = "is_zero::bool")]
    pub response: bool,
    #[serde(rename = "nonce", default, skip_serializing_if = "is_zero::string")]
    pub nonce: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NatHoleReport {
    #[serde(rename = "sid", default, skip_serializing_if = "is_zero::string")]
    pub sid: String,
    #[serde(rename = "success", default, skip_serializing_if = "is_zero::bool")]
    pub success: bool,
}

/// Mirrors upstream `msgTypeMap`, plus the wire codec entry points.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Login(Login),
    LoginResp(LoginResp),
    NewProxy(NewProxy),
    NewProxyResp(NewProxyResp),
    CloseProxy(CloseProxy),
    NewWorkConn(NewWorkConn),
    ReqWorkConn(ReqWorkConn),
    StartWorkConn(StartWorkConn),
    NewVisitorConn(NewVisitorConn),
    NewVisitorConnResp(NewVisitorConnResp),
    Ping(Ping),
    Pong(Pong),
    UdpPacket(UdpPacket),
    NatHoleVisitor(NatHoleVisitor),
    NatHoleClient(NatHoleClient),
    NatHoleResp(NatHoleResp),
    NatHoleSid(NatHoleSid),
    NatHoleReport(NatHoleReport),
}

impl Message {
    pub fn msg_type(&self) -> MsgType {
        match self {
            Message::Login(_) => MsgType::Login,
            Message::LoginResp(_) => MsgType::LoginResp,
            Message::NewProxy(_) => MsgType::NewProxy,
            Message::NewProxyResp(_) => MsgType::NewProxyResp,
            Message::CloseProxy(_) => MsgType::CloseProxy,
            Message::NewWorkConn(_) => MsgType::NewWorkConn,
            Message::ReqWorkConn(_) => MsgType::ReqWorkConn,
            Message::StartWorkConn(_) => MsgType::StartWorkConn,
            Message::NewVisitorConn(_) => MsgType::NewVisitorConn,
            Message::NewVisitorConnResp(_) => MsgType::NewVisitorConnResp,
            Message::Ping(_) => MsgType::Ping,
            Message::Pong(_) => MsgType::Pong,
            Message::UdpPacket(_) => MsgType::UdpPacket,
            Message::NatHoleVisitor(_) => MsgType::NatHoleVisitor,
            Message::NatHoleClient(_) => MsgType::NatHoleClient,
            Message::NatHoleResp(_) => MsgType::NatHoleResp,
            Message::NatHoleSid(_) => MsgType::NatHoleSid,
            Message::NatHoleReport(_) => MsgType::NatHoleReport,
        }
    }

    pub fn encode_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        match self {
            Message::Login(m) => serde_json::to_vec(m),
            Message::LoginResp(m) => serde_json::to_vec(m),
            Message::NewProxy(m) => serde_json::to_vec(m),
            Message::NewProxyResp(m) => serde_json::to_vec(m),
            Message::CloseProxy(m) => serde_json::to_vec(m),
            Message::NewWorkConn(m) => serde_json::to_vec(m),
            Message::ReqWorkConn(m) => serde_json::to_vec(m),
            Message::StartWorkConn(m) => serde_json::to_vec(m),
            Message::NewVisitorConn(m) => serde_json::to_vec(m),
            Message::NewVisitorConnResp(m) => serde_json::to_vec(m),
            Message::Ping(m) => serde_json::to_vec(m),
            Message::Pong(m) => serde_json::to_vec(m),
            Message::UdpPacket(m) => serde_json::to_vec(m),
            Message::NatHoleVisitor(m) => serde_json::to_vec(m),
            Message::NatHoleClient(m) => serde_json::to_vec(m),
            Message::NatHoleResp(m) => serde_json::to_vec(m),
            Message::NatHoleSid(m) => serde_json::to_vec(m),
            Message::NatHoleReport(m) => serde_json::to_vec(m),
        }
    }

    pub fn decode_json(type_byte: u8, buf: &[u8]) -> Result<Message, serde_json::Error> {
        use serde::de::Error as _;
        let msg_type = match MsgType::from_byte(type_byte) {
            Some(t) => t,
            None => {
                return Err(serde_json::Error::custom(format!(
                    "unknown message type byte: {type_byte}"
                )))
            }
        };
        Ok(match msg_type {
            MsgType::Login => Message::Login(serde_json::from_slice(buf)?),
            MsgType::LoginResp => Message::LoginResp(serde_json::from_slice(buf)?),
            MsgType::NewProxy => Message::NewProxy(serde_json::from_slice(buf)?),
            MsgType::NewProxyResp => Message::NewProxyResp(serde_json::from_slice(buf)?),
            MsgType::CloseProxy => Message::CloseProxy(serde_json::from_slice(buf)?),
            MsgType::NewWorkConn => Message::NewWorkConn(serde_json::from_slice(buf)?),
            MsgType::ReqWorkConn => Message::ReqWorkConn(serde_json::from_slice(buf)?),
            MsgType::StartWorkConn => Message::StartWorkConn(serde_json::from_slice(buf)?),
            MsgType::NewVisitorConn => Message::NewVisitorConn(serde_json::from_slice(buf)?),
            MsgType::NewVisitorConnResp => {
                Message::NewVisitorConnResp(serde_json::from_slice(buf)?)
            }
            MsgType::Ping => Message::Ping(serde_json::from_slice(buf)?),
            MsgType::Pong => Message::Pong(serde_json::from_slice(buf)?),
            MsgType::UdpPacket => Message::UdpPacket(serde_json::from_slice(buf)?),
            MsgType::NatHoleVisitor => Message::NatHoleVisitor(serde_json::from_slice(buf)?),
            MsgType::NatHoleClient => Message::NatHoleClient(serde_json::from_slice(buf)?),
            MsgType::NatHoleResp => Message::NatHoleResp(serde_json::from_slice(buf)?),
            MsgType::NatHoleSid => Message::NatHoleSid(serde_json::from_slice(buf)?),
            MsgType::NatHoleReport => Message::NatHoleReport(serde_json::from_slice(buf)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_bytes_match_upstream() {
        assert_eq!(MsgType::Login.to_byte(), b'o');
        assert_eq!(MsgType::LoginResp.to_byte(), b'1');
        assert_eq!(MsgType::NewProxy.to_byte(), b'p');
        assert_eq!(MsgType::NewProxyResp.to_byte(), b'2');
        assert_eq!(MsgType::CloseProxy.to_byte(), b'c');
        assert_eq!(MsgType::NewWorkConn.to_byte(), b'w');
        assert_eq!(MsgType::ReqWorkConn.to_byte(), b'r');
        assert_eq!(MsgType::StartWorkConn.to_byte(), b's');
        assert_eq!(MsgType::NewVisitorConn.to_byte(), b'v');
        assert_eq!(MsgType::NewVisitorConnResp.to_byte(), b'3');
        assert_eq!(MsgType::Ping.to_byte(), b'h');
        assert_eq!(MsgType::Pong.to_byte(), b'4');
        assert_eq!(MsgType::UdpPacket.to_byte(), b'u');
        assert_eq!(MsgType::NatHoleVisitor.to_byte(), b'i');
        assert_eq!(MsgType::NatHoleClient.to_byte(), b'n');
        assert_eq!(MsgType::NatHoleResp.to_byte(), b'm');
        assert_eq!(MsgType::NatHoleSid.to_byte(), b'5');
        assert_eq!(MsgType::NatHoleReport.to_byte(), b'6');
    }

    #[test]
    fn login_json_uses_upstream_field_names() {
        let mut login = Login {
            version: "0.71.0".into(),
            timestamp: 1_700_000_000,
            ..Default::default()
        };
        login.metas.insert("k".into(), "v".into());
        let json = Message::Login(login).encode_json().unwrap();
        let text = String::from_utf8(json).unwrap();
        assert!(text.contains("\"version\":\"0.71.0\""));
        assert!(text.contains("\"timestamp\":1700000000"));
        assert!(text.contains("\"metas\":{\"k\":\"v\"}"));
        // client_spec is a struct, so it survives omitempty as {}.
        assert!(text.contains("\"client_spec\":{}"));
        // Zero valued strings are omitted, not sent as "".
        assert!(!text.contains("\"privilege_key\""));
        assert!(!text.contains("\"run_id\""));
        assert!(!text.contains("\"hostname\""));
    }
    }

    #[test]
    fn new_proxy_subdomain_field_name() {
        let m = NewProxy {
            proxy_name: "t".into(),
            proxy_type: "http".into(),
            sub_domain: "demo".into(),
            ..Default::default()
        };
        let text = String::from_utf8(Message::NewProxy(m).encode_json().unwrap()).unwrap();
        assert!(text.contains("\"subdomain\":\"demo\""));
        assert!(text.contains("\"proxy_type\":\"http\""));
    }

    #[test]
    fn udp_packet_roundtrip_base64() {
        let pkt = UdpPacket {
            content: b"hello".to_vec(),
            local_addr: Some(UdpAddrJson::new("127.0.0.1", 53)),
            remote_addr: None,
        };
        let bytes = Message::UdpPacket(pkt).encode_json().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.contains("\"c\":\"aGVsbG8=\""));
        let back = Message::decode_json(ty::UDP_PACKET, &bytes).unwrap();
        match back {
            Message::UdpPacket(p) => {
                assert_eq!(p.content, b"hello");
                assert_eq!(p.local_addr.unwrap().port, 53);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
