//! Client plugins.
//!
//! A plugin replaces a proxy's local service. Instead of dialing
//! `localIP:localPort` and shuttling bytes, the proxy hands every work
//! connection to the plugin, which decides what to do with it: terminate TLS,
//! speak SOCKS5, serve files, forward HTTP. Upstream picks the plugin from the
//! `type` key of the proxy's `plugin` block and registers each one behind a
//! `CreatorFn`; [`create`] is the same dispatch.
//!
//! Implemented: `unix_domain_socket`, `static_file`, `socks5`, `http_proxy`,
//! `http2http`, `http2https`, `https2http`, `https2https` and `tls2raw`.
//! `virtual_net` needs the shared virtual network subsystem and is refused at
//! configuration load.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, Result};
use frp_core::config::plugin::PluginConfig;
use hyper::header::{HeaderMap, HeaderName};
use tokio::io::{AsyncRead, AsyncWrite};

pub mod bridge;
pub mod forward;
pub mod http_proxy;
pub mod reverse_proxy;
pub mod socks5;
pub mod static_file;
pub mod tls;
pub mod tls2raw;
pub mod unix_domain_socket;

pub use bridge::{full_body, Bridge, Handler, RespBody};
pub use forward::Target;
pub use reverse_proxy::{BridgePlugin, Kind, Options};

/// The read/write pair every plugin works with.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncReadWrite for T {}

/// A work connection handed to a plugin.
pub type PluginConn = Box<dyn AsyncReadWrite + Send + Unpin>;

/// A work connection plus the addressing the server reported for it.
pub struct ConnInfo {
    pub conn: PluginConn,
    /// The address of the peer that reached the server, present only when the
    /// server sent `src_addr`/`src_port` in `StartWorkConn`. The plugins that
    /// terminate TLS put it in `X-Forwarded-For`.
    pub src_addr: Option<SocketAddr>,
    /// The address the server accepted the connection on, for logging.
    pub dst_addr: Option<SocketAddr>,
}

/// One configured plugin.
pub trait Plugin: Send + Sync + 'static {
    /// The `type` tag, matching upstream's constants.
    fn name(&self) -> &'static str;

    /// Consumes one work connection. The returned future is spawned by the
    /// caller, so a plugin that hands the connection to a server may return
    /// immediately while one that shuttles bytes runs for the life of the
    /// connection.
    fn handle(&self, info: ConnInfo) -> Pin<Box<dyn Future<Output = ()> + Send>>;

    /// Releases anything the plugin started.
    fn close(&self);
}

/// Builds the plugin named by a proxy's `plugin` block.
pub fn create(cfg: &PluginConfig) -> Result<Arc<dyn Plugin>> {
    cfg.validate()
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("plugin [{}] options are invalid", cfg.plugin_type()))?;

    let plugin: Arc<dyn Plugin> = match cfg {
        PluginConfig::UnixDomainSocket { unix_path } => {
            Arc::new(unix_domain_socket::UnixDomainSocketPlugin::new(unix_path)?)
        }
        PluginConfig::StaticFile {
            local_path,
            strip_prefix,
            http_user,
            http_password,
        } => {
            static_file::StaticFilePlugin::new(local_path, strip_prefix, http_user, http_password)?
        }
        PluginConfig::Socks5 { username, password } => {
            Arc::new(socks5::Socks5Plugin::new(username, password))
        }
        PluginConfig::HttpProxy {
            http_user,
            http_password,
        } => http_proxy::HttpProxyPlugin::new(http_user, http_password),
        PluginConfig::Http2Http {
            local_addr,
            host_header_rewrite,
            request_headers,
        } => BridgePlugin::new(
            Kind::Http2Http,
            Options {
                local_addr: local_addr.clone(),
                host_header_rewrite: host_header_rewrite.clone(),
                request_headers: request_headers.clone(),
            },
            "",
            "",
            false,
        )?,
        PluginConfig::Http2Https {
            local_addr,
            host_header_rewrite,
            request_headers,
        } => BridgePlugin::new(
            Kind::Http2Https,
            Options {
                local_addr: local_addr.clone(),
                host_header_rewrite: host_header_rewrite.clone(),
                request_headers: request_headers.clone(),
            },
            "",
            "",
            false,
        )?,
        PluginConfig::Https2Http {
            local_addr,
            host_header_rewrite,
            request_headers,
            crt_path,
            key_path,
            ..
        } => BridgePlugin::new(
            Kind::Https2Http,
            Options {
                local_addr: local_addr.clone(),
                host_header_rewrite: host_header_rewrite.clone(),
                request_headers: request_headers.clone(),
            },
            crt_path,
            key_path,
            cfg.http2_enabled(),
        )?,
        PluginConfig::Https2Https {
            local_addr,
            host_header_rewrite,
            request_headers,
            crt_path,
            key_path,
            ..
        } => BridgePlugin::new(
            Kind::Https2Https,
            Options {
                local_addr: local_addr.clone(),
                host_header_rewrite: host_header_rewrite.clone(),
                request_headers: request_headers.clone(),
            },
            crt_path,
            key_path,
            cfg.http2_enabled(),
        )?,
        PluginConfig::Tls2Raw {
            local_addr,
            crt_path,
            key_path,
        } => Arc::new(tls2raw::Tls2RawPlugin::new(local_addr, crt_path, key_path)?),
        PluginConfig::VirtualNet { .. } => {
            anyhow::bail!("plugin [virtual_net] is not implemented in this build")
        }
    };
    Ok(plugin)
}

/// Checks HTTP basic credentials from `header`, in constant time.
///
/// Both the `Authorization` header of `static_file` and the
/// `Proxy-Authorization` header of `http_proxy` use this shape. An empty user
/// *and* password disables the check, which is what upstream's middlewares do.
pub(crate) fn basic_auth(
    headers: &HeaderMap,
    header: HeaderName,
    user: &str,
    password: &str,
) -> bool {
    if user.is_empty() && password.is_empty() {
        return true;
    }
    let Some(value) = headers.get(header) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Some(encoded) = value.strip_prefix("Basic ") else {
        return false;
    };
    use base64::Engine as _;
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
        return false;
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
        return false;
    };
    let Some((offered_user, offered_password)) = decoded.split_once(':') else {
        return false;
    };
    frp_core::crypto::auth::constant_time_eq(user, offered_user)
        && frp_core::crypto::auth::constant_time_eq(password, offered_password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{AUTHORIZATION, PROXY_AUTHORIZATION};

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, value.parse().unwrap());
        headers
    }

    #[test]
    fn an_empty_credential_pair_disables_the_check() {
        let headers = HeaderMap::new();
        assert!(basic_auth(&headers, AUTHORIZATION, "", ""));
    }

    #[test]
    fn a_correct_pair_is_accepted() {
        let mut headers = HeaderMap::new();
        // "alice:s3cret"
        headers.insert(AUTHORIZATION, "Basic YWxpY2U6czNjcmV0".parse().unwrap());
        assert!(basic_auth(&headers, AUTHORIZATION, "alice", "s3cret"));
        assert!(!basic_auth(&headers, AUTHORIZATION, "alice", "wrong"));
        assert!(!basic_auth(&headers, AUTHORIZATION, "bob", "s3cret"));
    }

    #[test]
    fn the_header_name_is_part_of_the_check() {
        let mut headers = HeaderMap::new();
        headers.insert(
            PROXY_AUTHORIZATION,
            "Basic YWxpY2U6czNjcmV0".parse().unwrap(),
        );
        // `static_file` looks at Authorization, `http_proxy` at
        // Proxy-Authorization: the same value must not satisfy both.
        assert!(basic_auth(&headers, PROXY_AUTHORIZATION, "alice", "s3cret"));
        assert!(!basic_auth(&headers, AUTHORIZATION, "alice", "s3cret"));
    }

    #[test]
    fn malformed_credentials_are_rejected() {
        assert!(!basic_auth(
            &headers("Basic !!!not-base64!!!"),
            AUTHORIZATION,
            "a",
            "b"
        ));
        assert!(!basic_auth(
            &headers("Bearer token"),
            AUTHORIZATION,
            "a",
            "b"
        ));
        // A decoded value without a colon.
        assert!(!basic_auth(
            &headers("Basic YWxpY2U="),
            AUTHORIZATION,
            "a",
            "b"
        ));
    }

    #[tokio::test]
    async fn every_implemented_plugin_can_be_created() {
        let mut cases: Vec<PluginConfig> = vec![
            serde_json::from_str(r#"{"type":"unix_domain_socket","unixPath":"/tmp/x.sock"}"#)
                .unwrap(),
            serde_json::from_str(r#"{"type":"socks5"}"#).unwrap(),
            serde_json::from_str(r#"{"type":"http_proxy"}"#).unwrap(),
            serde_json::from_str(r#"{"type":"http2http","localAddr":"127.0.0.1:8080"}"#).unwrap(),
            serde_json::from_str(r#"{"type":"http2https","localAddr":"127.0.0.1:8443"}"#).unwrap(),
        ];
        if !cfg!(unix) {
            // `unix_domain_socket` is refused without `AF_UNIX`, which is the
            // behaviour the platform test below pins down.
            cases.retain(|cfg| cfg.plugin_type() != "unix_domain_socket");
        }
        for cfg in cases {
            let plugin = create(&cfg).unwrap_or_else(|e| panic!("{}: {e}", cfg.plugin_type()));
            assert_eq!(plugin.name(), cfg.plugin_type());
        }
    }

    #[test]
    fn the_unix_socket_plugin_follows_the_platform() {
        let cfg: PluginConfig =
            serde_json::from_str(r#"{"type":"unix_domain_socket","unixPath":"/tmp/x.sock"}"#)
                .unwrap();
        assert!(cfg.is_implemented());
        if cfg!(unix) {
            assert!(create(&cfg).is_ok());
        } else {
            let err = match create(&cfg) {
                Ok(_) => panic!("AF_UNIX is not available on this platform"),
                Err(e) => e.to_string(),
            };
            assert!(err.contains("AF_UNIX"), "{err}");
        }
    }

    /// `tls2raw` and the `https2*` plugins cannot start without a certificate,
    /// which is what upstream's "crtPath is required" validation guards too.
    #[test]
    fn tls_plugins_need_a_readable_certificate() {
        let cfg: PluginConfig =
            serde_json::from_str(r#"{"type":"tls2raw","localAddr":"127.0.0.1:5432","crtPath":"/nope.crt","keyPath":"/nope.key"}"#)
                .unwrap();
        assert!(create(&cfg).is_err());
    }

    #[test]
    fn virtual_net_is_refused_by_name() {
        let cfg: PluginConfig = serde_json::from_str(r#"{"type":"virtual_net"}"#).unwrap();
        // `unwrap_err` cannot be used: the success type is a trait object
        // without `Debug`.
        let err = match create(&cfg) {
            Ok(_) => panic!("virtual_net must be refused"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("virtual_net"), "{err}");
    }
}
