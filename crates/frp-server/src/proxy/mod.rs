//! Proxy runtime: specification, lifecycle trait and work-connection plumbing.

pub mod http;
pub mod stcp;
pub mod tcp;
pub mod udp;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use frp_core::codec::write_msg;
use frp_core::msg::{Message, NewProxy, StartWorkConn};
use frp_core::transport::{ServerStream, FRP_TLS_HEAD_BYTE};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

use crate::util::unix_now;

/// A work connection supplied by the client and waiting to be used.
pub struct WorkConn {
    pub stream: ServerStream<TcpStream>,
    pub remote_addr: SocketAddr,
    pub local_addr: SocketAddr,
}

/// Indicates the wire encoding actually in use, for logging.
pub fn stream_kind(stream: &ServerStream<TcpStream>) -> &'static str {
    if stream.is_tls() {
        "tls"
    } else {
        "tcp"
    }
}

/// Marker so the obfuscated-TLS byte is never mistaken for a message type.
pub fn looks_like_frp_tls(byte: u8) -> bool {
    byte == FRP_TLS_HEAD_BYTE
}

impl WorkConn {
    /// Sends `StartWorkConn`, the last framed message on a work connection
    /// before it turns into a raw byte pipe.
    pub async fn start(&mut self, msg: StartWorkConn) -> Result<()> {
        write_msg(&mut self.stream, &Message::StartWorkConn(msg))
            .await
            .map_err(|e| anyhow!("write StartWorkConn: {e}"))?;
        Ok(())
    }

    pub fn into_stream(self) -> ServerStream<TcpStream> {
        self.stream
    }
}

/// A proxy request from a user connection waiting for a work connection.
pub struct WorkConnRequest {
    pub reply: oneshot::Sender<Option<WorkConn>>,
}

/// Static description of a proxy, built from the client's `NewProxy` message.
#[derive(Debug, Clone, Default)]
pub struct ProxySpec {
    pub name: String,
    pub proxy_type: String,
    pub use_encryption: bool,
    pub use_compression: bool,
    pub remote_port: i32,
    pub custom_domains: Vec<String>,
    pub sub_domain: String,
    pub locations: Vec<String>,
    pub http_user: String,
    pub http_pwd: String,
    pub host_header_rewrite: String,
    pub request_headers: Vec<(String, String)>,
    pub response_headers: Vec<(String, String)>,
    pub route_by_http_user: String,
    pub sk: String,
    pub allow_users: Vec<String>,
    pub multiplexer: String,
    pub group: String,
    pub group_key: String,
}

impl ProxySpec {
    pub fn from_msg(msg: &NewProxy) -> Self {
        let mut request_headers: Vec<(String, String)> = msg
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        request_headers.sort();
        let mut response_headers: Vec<(String, String)> = msg
            .response_headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        response_headers.sort();

        Self {
            name: msg.proxy_name.clone(),
            proxy_type: msg.proxy_type.clone(),
            use_encryption: msg.use_encryption,
            use_compression: msg.use_compression,
            remote_port: msg.remote_port,
            custom_domains: msg.custom_domains.clone(),
            sub_domain: msg.sub_domain.clone(),
            locations: msg.locations.clone(),
            http_user: msg.http_user.clone(),
            http_pwd: msg.http_pwd.clone(),
            host_header_rewrite: msg.host_header_rewrite.clone(),
            request_headers,
            response_headers,
            route_by_http_user: msg.route_by_http_user.clone(),
            sk: msg.sk.clone(),
            allow_users: msg.allow_users.clone(),
            multiplexer: msg.multiplexer.clone(),
            group: msg.group.clone(),
            group_key: msg.group_key.clone(),
        }
    }

    /// Domains this proxy answers for, including the configured subdomain.
    pub fn domains(&self, sub_domain_host: &str) -> Vec<String> {
        let mut out: Vec<String> = self
            .custom_domains
            .iter()
            .filter(|d| !d.is_empty())
            .cloned()
            .collect();
        if !self.sub_domain.is_empty() && !sub_domain_host.is_empty() {
            out.push(format!("{}.{}", self.sub_domain, sub_domain_host));
        }
        out
    }
}

/// Lifecycle interface implemented by every proxy type.
pub trait ServerProxy: Send + Sync {
    fn name(&self) -> &str;
    fn proxy_type(&self) -> &str;
    fn spec(&self) -> &ProxySpec;
    /// Number of remote ports this proxy holds.
    fn used_ports_num(&self) -> i64 {
        0
    }
    /// Human readable bind address reported back in `NewProxyResp`.
    fn remote_addr(&self) -> String;
    /// Releases listeners, ports and registrations.
    fn close(&self);
}

/// Bidirectional copy with byte accounting, replacing upstream `libio.Join`.
///
/// `local` is the work connection (or its encryption/compression wrapper) and
/// `user` is the end user's socket. The return value is
/// `(traffic_in, traffic_out)` from the server's point of view, matching
/// upstream's `joinUserConnection`.
pub async fn join_user_stream<L, U>(local: L, user: U) -> (u64, u64)
where
    L: AsyncRead + AsyncWrite + Send + Unpin,
    U: AsyncRead + AsyncWrite + Send + Unpin,
{
    let (mut lr, mut lw) = tokio::io::split(local);
    let (mut ur, mut uw) = tokio::io::split(user);

    let local_to_user = async {
        let n = tokio::io::copy(&mut lr, &mut uw).await.unwrap_or(0);
        let _ = uw.shutdown().await;
        n
    };
    let user_to_local = async {
        let n = tokio::io::copy(&mut ur, &mut lw).await.unwrap_or(0);
        let _ = lw.shutdown().await;
        n
    };
    let (traffic_out, traffic_in) = tokio::join!(local_to_user, user_to_local);
    (traffic_in, traffic_out)
}

/// Reads a framed message from a raw stream, used for UDP work connections.
pub async fn read_work_msg<R>(reader: &mut R) -> Result<Message>
where
    R: AsyncRead + Unpin,
{
    frp_core::codec::read_msg(reader)
        .await
        .map_err(|e| anyhow!("read work conn message: {e}"))
}

/// Builds the `StartWorkConn` payload describing a user connection.
pub fn start_work_conn_for(spec: &ProxySpec, user: Option<&SocketAddr>) -> StartWorkConn {
    let (src_addr, src_port) = match user {
        Some(addr) => (addr.ip().to_string(), addr.port()),
        None => (String::new(), 0),
    };
    StartWorkConn {
        proxy_name: spec.name.clone(),
        src_addr,
        src_port,
        dst_addr: String::new(),
        dst_port: 0,
        error: String::new(),
    }
}

/// Convenience used by logging.
pub fn proxy_log_line(user: &str, spec: &ProxySpec, remote: &str) -> String {
    format!(
        "user={user} name={} type={} remote={remote}",
        spec.name, spec.proxy_type
    )
}

/// Timestamp helper so tests do not depend on the clock implementation.
pub fn now() -> i64 {
    unix_now()
}

/// Truncates a byte slice for trace logging.
pub fn preview(data: &[u8]) -> String {
    String::from_utf8_lossy(&data[..data.len().min(32)]).to_string()
}

/// Reads exactly the requested prefix, returning how many bytes were captured.
pub async fn read_prefix<R>(reader: &mut R, len: usize) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_from_new_proxy_message() {
        let mut msg = NewProxy {
            proxy_name: "web".into(),
            proxy_type: "http".into(),
            use_encryption: true,
            custom_domains: vec!["a.example.com".into()],
            sub_domain: "demo".into(),
            locations: vec!["/api".into()],
            http_user: "u".into(),
            host_header_rewrite: "internal".into(),
            ..Default::default()
        };
        msg.headers.insert("X-B".into(), "2".into());
        msg.headers.insert("X-A".into(), "1".into());

        let spec = ProxySpec::from_msg(&msg);
        assert_eq!(spec.name, "web");
        assert_eq!(spec.proxy_type, "http");
        assert!(spec.use_encryption);
        assert_eq!(
            spec.domains("example.com"),
            vec!["a.example.com", "demo.example.com"]
        );
        assert_eq!(
            spec.request_headers,
            vec![("X-A".to_string(), "1".to_string()), ("X-B".to_string(), "2".to_string())]
        );
    }

    #[test]
    fn subdomain_needs_a_host_suffix() {
        let msg = NewProxy {
            proxy_name: "p".into(),
            sub_domain: "demo".into(),
            ..Default::default()
        };
        let spec = ProxySpec::from_msg(&msg);
        assert!(spec.domains("").is_empty());
        assert_eq!(spec.domains("example.com"), vec!["demo.example.com"]);
    }

    #[test]
    fn start_work_conn_carries_the_client_address() {
        let spec = ProxySpec {
            name: "t".into(),
            ..Default::default()
        };
        let addr: SocketAddr = "10.0.0.1:5555".parse().unwrap();
        let msg = start_work_conn_for(&spec, Some(&addr));
        assert_eq!(msg.proxy_name, "t");
        assert_eq!(msg.src_addr, "10.0.0.1");
        assert_eq!(msg.src_port, 5555);
        assert!(msg.error.is_empty());
    }
}
