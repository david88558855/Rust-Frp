//! `socks5`: speak SOCKS5 to whoever reaches the remote port.
//!
//! Upstream delegates to `armon/go-socks5`, which implements RFC 1928. This is
//! the same protocol by hand, because the crate has no SOCKS5 dependency and
//! the surface needed here is a single `CONNECT` command.
//!
//! Covered: the no-authentication method, username/password authentication
//! (RFC 1929), `CONNECT` over IPv4, IPv6 and domain names, and the reply codes
//! for the failures that can actually happen. Not covered: `BIND` and `UDP
//! ASSOCIATE`, which answer with the "command not supported" reply upstream's
//! handler configuration also produces.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use frp_core::crypto::auth::constant_time_eq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use super::{ConnInfo, Plugin, PluginConn};

const VERSION: u8 = 0x05;
const AUTH_VERSION: u8 = 0x01;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_NETWORK_UNREACHABLE: u8 = 0x03;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// How long the target of a `CONNECT` has to accept.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Socks5Plugin {
    username: String,
    password: String,
}

impl Socks5Plugin {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    /// Credentials are only enforced when at least one of them is set, matching
    /// upstream's `if username != "" || password != ""` guard.
    fn auth_required(&self) -> bool {
        !self.username.is_empty() || !self.password.is_empty()
    }
}

impl Plugin for Socks5Plugin {
    fn name(&self) -> &'static str {
        "socks5"
    }

    fn handle(&self, info: ConnInfo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let username = self.username.clone();
        let password = self.password.clone();
        let auth_required = self.auth_required();
        Box::pin(async move {
            if let Err(e) = serve(info.conn, &username, &password, auth_required).await {
                debug!(error = %e, "socks5 connection ended");
            }
        })
    }

    fn close(&self) {}
}

async fn serve(
    mut conn: PluginConn,
    username: &str,
    password: &str,
    auth_required: bool,
) -> Result<()> {
    negotiate(&mut conn, username, password, auth_required).await?;

    let mut header = [0u8; 4];
    conn.read_exact(&mut header)
        .await
        .context("read the socks5 request")?;
    if header[0] != VERSION {
        bail!("unsupported socks5 version {}", header[0]);
    }
    let command = header[1];
    let address_type = header[3];

    let host = match address_type {
        ATYP_IPV4 => {
            let mut bytes = [0u8; 4];
            conn.read_exact(&mut bytes).await?;
            IpAddr::from(Ipv4Addr::from(bytes)).to_string()
        }
        ATYP_IPV6 => {
            let mut bytes = [0u8; 16];
            conn.read_exact(&mut bytes).await?;
            IpAddr::from(Ipv6Addr::from(bytes)).to_string()
        }
        ATYP_DOMAIN => {
            let mut length = [0u8; 1];
            conn.read_exact(&mut length).await?;
            let mut name = vec![0u8; length[0] as usize];
            conn.read_exact(&mut name).await?;
            String::from_utf8(name).context("the socks5 domain name is not UTF-8")?
        }
        other => {
            reply(&mut conn, REP_ADDRESS_TYPE_NOT_SUPPORTED, None).await?;
            bail!("unsupported address type {other}");
        }
    };
    let mut port = [0u8; 2];
    conn.read_exact(&mut port).await?;
    let target = format!("{host}:{}", u16::from_be_bytes(port));

    if command != CMD_CONNECT {
        reply(&mut conn, REP_COMMAND_NOT_SUPPORTED, None).await?;
        bail!("unsupported command {command}");
    }

    let remote = match timeout(DIAL_TIMEOUT, TcpStream::connect(&target)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            let code = match e.kind() {
                std::io::ErrorKind::ConnectionRefused => REP_CONNECTION_REFUSED,
                // A name that does not resolve is a host the client cannot
                // reach, which is what the reply code means.
                std::io::ErrorKind::NotFound => REP_HOST_UNREACHABLE,
                _ => REP_GENERAL_FAILURE,
            };
            reply(&mut conn, code, None).await?;
            return Err(e).with_context(|| format!("connect to {target}"));
        }
        Err(_) => {
            reply(&mut conn, REP_NETWORK_UNREACHABLE, None).await?;
            bail!("timed out connecting to {target}");
        }
    };
    let _ = remote.set_nodelay(true);
    let bound = remote.local_addr().ok();

    reply(&mut conn, REP_SUCCESS, bound).await?;
    debug!(target = %target, "socks5 tunnel established");
    crate::proxy::ProxyContext::join(conn, remote).await;
    Ok(())
}

/// Runs the method-selection exchange, with the username/password sub-negotiation
/// when it is the chosen method.
async fn negotiate(
    conn: &mut PluginConn,
    username: &str,
    password: &str,
    auth_required: bool,
) -> Result<()> {
    let mut greeting = [0u8; 2];
    conn.read_exact(&mut greeting)
        .await
        .context("read the socks5 greeting")?;
    if greeting[0] != VERSION {
        bail!("unsupported socks5 version {}", greeting[0]);
    }
    let mut methods = vec![0u8; greeting[1] as usize];
    conn.read_exact(&mut methods).await?;

    let method = if auth_required {
        if methods.contains(&METHOD_USER_PASS) {
            METHOD_USER_PASS
        } else {
            METHOD_NONE_ACCEPTABLE
        }
    } else if methods.contains(&METHOD_NO_AUTH) {
        METHOD_NO_AUTH
    } else {
        METHOD_NONE_ACCEPTABLE
    };

    conn.write_all(&[VERSION, method]).await?;
    conn.flush().await?;
    if method == METHOD_NONE_ACCEPTABLE {
        bail!("the client offered no acceptable authentication method");
    }
    if method == METHOD_NO_AUTH {
        return Ok(());
    }

    let mut version = [0u8; 1];
    conn.read_exact(&mut version).await?;
    if version[0] != AUTH_VERSION {
        bail!("unsupported username/password auth version {}", version[0]);
    }
    let mut length = [0u8; 1];
    conn.read_exact(&mut length).await?;
    let mut offered_user = vec![0u8; length[0] as usize];
    conn.read_exact(&mut offered_user).await?;
    conn.read_exact(&mut length).await?;
    let mut offered_password = vec![0u8; length[0] as usize];
    conn.read_exact(&mut offered_password).await?;

    let accepted = constant_time_eq(username, &String::from_utf8_lossy(&offered_user))
        && constant_time_eq(password, &String::from_utf8_lossy(&offered_password));
    conn.write_all(&[AUTH_VERSION, if accepted { 0x00 } else { 0x01 }])
        .await?;
    conn.flush().await?;
    if !accepted {
        bail!("socks5 authentication failed");
    }
    Ok(())
}

/// Writes a reply, echoing the address the outbound socket is bound to.
///
/// The bound address is what a real SOCKS5 server reports; when it is unknown —
/// a failed connection has no local address to report — the unspecified IPv4
/// address is sent, which is what the specification permits.
async fn reply(conn: &mut PluginConn, code: u8, bound: Option<SocketAddr>) -> Result<()> {
    let mut out = Vec::with_capacity(22);
    out.push(VERSION);
    out.push(code);
    out.push(0x00);
    match bound.map(|addr| addr.ip()) {
        Some(IpAddr::V4(ip)) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        Some(IpAddr::V6(ip)) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
        None => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&[0, 0, 0, 0]);
        }
    }
    out.extend_from_slice(&bound.map(|addr| addr.port()).unwrap_or(0).to_be_bytes());
    conn.write_all(&out).await?;
    conn.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_only_required_when_one_is_set() {
        assert!(!Socks5Plugin::new("", "").auth_required());
        assert!(Socks5Plugin::new("u", "").auth_required());
        assert!(Socks5Plugin::new("", "p").auth_required());
        assert!(Socks5Plugin::new("u", "p").auth_required());
    }

    #[tokio::test]
    async fn a_reply_without_a_bound_address_is_the_unspecified_ipv4() {
        let (client, mut server) = tokio::io::duplex(64);
        let mut client = Box::new(client) as PluginConn;
        reply(&mut client, REP_SUCCESS, None).await.unwrap();
        let mut buf = [0u8; 10];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn a_reply_echoes_an_ipv6_bound_address() {
        let (client, mut server) = tokio::io::duplex(64);
        let mut client = Box::new(client) as PluginConn;
        let bound: SocketAddr = "[::1]:8080".parse().unwrap();
        reply(&mut client, REP_SUCCESS, Some(bound)).await.unwrap();
        let mut buf = [0u8; 22];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[0], VERSION);
        assert_eq!(buf[3], ATYP_IPV6);
        assert_eq!(u16::from_be_bytes([buf[20], buf[21]]), 8080);
    }

    #[tokio::test]
    async fn the_greeting_selects_no_auth_when_credentials_are_unset() {
        let (client, server) = tokio::io::duplex(64);
        let mut client = Box::new(client) as PluginConn;
        let mut server = Box::new(server) as PluginConn;

        let negotiate = tokio::spawn(async move { negotiate(&mut server, "", "", false).await });
        client
            .write_all(&[VERSION, 1, METHOD_NO_AUTH])
            .await
            .unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [VERSION, METHOD_NO_AUTH]);
        negotiate.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn the_greeting_refuses_clients_without_the_password_method() {
        let (client, server) = tokio::io::duplex(64);
        let mut client = Box::new(client) as PluginConn;
        let mut server = Box::new(server) as PluginConn;

        let negotiate = tokio::spawn(async move { negotiate(&mut server, "u", "p", true).await });
        client
            .write_all(&[VERSION, 1, METHOD_NO_AUTH])
            .await
            .unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [VERSION, METHOD_NONE_ACCEPTABLE]);
        assert!(negotiate.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn the_password_method_accepts_matching_credentials() {
        let (client, server) = tokio::io::duplex(64);
        let mut client = Box::new(client) as PluginConn;
        let mut server = Box::new(server) as PluginConn;

        let negotiate =
            tokio::spawn(async move { negotiate(&mut server, "alice", "s3cret", true).await });
        client
            .write_all(&[VERSION, 1, METHOD_USER_PASS])
            .await
            .unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [VERSION, METHOD_USER_PASS]);

        let mut auth = vec![AUTH_VERSION, 5];
        auth.extend_from_slice(b"alice");
        auth.push(6);
        auth.extend_from_slice(b"s3cret");
        client.write_all(&auth).await.unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status, [AUTH_VERSION, 0x00]);
        negotiate.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn the_password_method_rejects_a_wrong_password() {
        let (client, server) = tokio::io::duplex(64);
        let mut client = Box::new(client) as PluginConn;
        let mut server = Box::new(server) as PluginConn;

        let negotiate =
            tokio::spawn(async move { negotiate(&mut server, "alice", "s3cret", true).await });
        client
            .write_all(&[VERSION, 1, METHOD_USER_PASS])
            .await
            .unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();

        let mut auth = vec![AUTH_VERSION, 5];
        auth.extend_from_slice(b"alice");
        auth.push(5);
        auth.extend_from_slice(b"wrong");
        client.write_all(&auth).await.unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status, [AUTH_VERSION, 0x01]);
        assert!(negotiate.await.unwrap().is_err());
    }
}
