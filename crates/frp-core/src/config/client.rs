//! Client configuration, mirroring upstream `pkg/config/v1/client.go`,
//! `visitor.go` and `LoadClientConfig` in `pkg/config/load.go`.
//!
//! The loader reproduces upstream's two-stage shape: the main file carries the
//! common configuration together with any inline `[[proxies]]` / `[[visitors]]`,
//! and each entry of `includes` contributes *only* proxies and visitors. Names
//! must stay unique across both, otherwise a proxy from an include silently
//! shadows one from the main file.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::common::{AuthMethod, AuthScope, LogConfig, QUICOptions, ValueSource, WebServerConfig};
use super::load::{expand_includes, load_config, load_config_str, ConfigFormat};
use super::proxy::ProxyConfig;

/// Default control port, matching upstream.
pub const DEFAULT_SERVER_PORT: i32 = 7000;
/// Default UDP packet size, matching upstream.
pub const DEFAULT_UDP_PACKET_SIZE: i64 = 1500;
/// Default pool size for work connections.
pub const DEFAULT_POOL_COUNT: i32 = 1;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AuthClientConfig {
    pub method: AuthMethod,
    pub additional_scopes: Vec<AuthScope>,
    pub token: String,
    pub token_source: Option<ValueSource>,
}

impl AuthClientConfig {
    /// Resolves the token, honouring the external source when configured.
    pub fn resolve_token(&self) -> Result<String> {
        match &self.token_source {
            Some(source) => source.resolve(),
            None => Ok(self.token.clone()),
        }
    }

    pub fn signs_heartbeats(&self) -> bool {
        self.additional_scopes.contains(&AuthScope::HeartBeats)
    }

    pub fn signs_new_work_conns(&self) -> bool {
        self.additional_scopes.contains(&AuthScope::NewWorkConns)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TlsClientConfig {
    /// `None` means per protocol default: off for tcp, on for wss and quic.
    pub enable: Option<bool>,
    pub disable_custom_tls_first_byte: Option<bool>,
    pub cert_file: String,
    pub key_file: String,
    pub trusted_ca_file: String,
    pub server_name: String,
}

impl TlsClientConfig {
    pub fn enabled_for(&self, protocol: &str) -> bool {
        self.enable
            .unwrap_or_else(|| matches!(protocol, "wss" | "quic"))
    }

    /// Upstream writes the obfuscated first byte unless it is explicitly off.
    pub fn custom_tls_first_byte(&self) -> bool {
        !self.disable_custom_tls_first_byte.unwrap_or(false)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ClientTransportConfig {
    /// `tcp`, `kcp`, `quic`, `websocket` or `wss`.
    pub protocol: String,
    /// `v1` or `v2`. Only `v1` is implemented.
    pub wire_protocol: String,
    pub dial_server_timeout: i64,
    pub dial_server_keepalive: i64,
    pub connect_server_local_ip: String,
    pub proxy_url: String,
    pub pool_count: i32,
    pub tcp_mux: Option<bool>,
    pub tcp_mux_keepalive_interval: i64,
    pub quic: QUICOptions,
    pub heartbeat_interval: i64,
    pub heartbeat_timeout: i64,
    pub tls: TlsClientConfig,
}

impl ClientTransportConfig {
    pub fn complete(&mut self) {
        if self.protocol.is_empty() {
            self.protocol = "tcp".into();
        }
        if self.wire_protocol.is_empty() {
            self.wire_protocol = "v1".into();
        }
        if self.dial_server_timeout == 0 {
            self.dial_server_timeout = 10;
        }
        if self.dial_server_keepalive == 0 {
            self.dial_server_keepalive = 7200;
        }
        if self.proxy_url.is_empty() {
            self.proxy_url = std::env::var("http_proxy")
                .or_else(|_| std::env::var("HTTP_PROXY"))
                .unwrap_or_default();
        }
        if self.pool_count == 0 {
            self.pool_count = DEFAULT_POOL_COUNT;
        }
        if self.tcp_mux_keepalive_interval == 0 {
            self.tcp_mux_keepalive_interval = 30;
        }
        // Upstream drops the application level heartbeat when TCPMux is on,
        // because yamux already keeps the transport alive.
        if self.tcp_mux_enabled() {
            if self.heartbeat_interval == 0 {
                self.heartbeat_interval = -1;
            }
            if self.heartbeat_timeout == 0 {
                self.heartbeat_timeout = -1;
            }
        } else {
            if self.heartbeat_interval == 0 {
                self.heartbeat_interval = 30;
            }
            if self.heartbeat_timeout == 0 {
                self.heartbeat_timeout = 90;
            }
        }
    }

    pub fn tcp_mux_enabled(&self) -> bool {
        self.tcp_mux.unwrap_or(true)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ClientCommonConfig {
    pub auth: AuthClientConfig,
    /// Prefix applied to every proxy name, `{user}.{name}`.
    pub user: String,
    #[serde(rename = "clientID")]
    pub client_id: String,
    pub server_addr: String,
    pub server_port: i32,
    pub nat_hole_stun_server: String,
    pub dns_server: String,
    pub login_fail_exit: Option<bool>,
    /// When non-empty, only these proxies are started.
    pub start: Vec<String>,
    pub log: LogConfig,
    pub web_server: WebServerConfig,
    pub transport: ClientTransportConfig,
    pub udp_packet_size: i64,
    pub metadatas: HashMap<String, String>,
    /// Additional config files contributing proxies and visitors.
    pub includes: Vec<String>,
}

impl ClientCommonConfig {
    pub fn complete(&mut self) {
        if self.server_addr.is_empty() {
            self.server_addr = "0.0.0.0".into();
        }
        if self.server_port == 0 {
            self.server_port = DEFAULT_SERVER_PORT;
        }
        if self.login_fail_exit.is_none() {
            self.login_fail_exit = Some(true);
        }
        if self.nat_hole_stun_server.is_empty() {
            self.nat_hole_stun_server = "stun.easyvoip.com:3478".into();
        }
        if self.udp_packet_size == 0 {
            self.udp_packet_size = DEFAULT_UDP_PACKET_SIZE;
        }
        self.transport.complete();
    }

    pub fn login_fail_exit_enabled(&self) -> bool {
        self.login_fail_exit.unwrap_or(true)
    }
}

/// Visitor transport options, upstream `VisitorTransport`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VisitorTransport {
    pub use_encryption: bool,
    pub use_compression: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VisitorBaseConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub visitor_type: String,
    pub enabled: Option<bool>,
    pub transport: VisitorTransport,
    pub secret_key: String,
    /// Prefix of the user owning the server side proxy.
    pub server_user: String,
    pub server_name: String,
    pub bind_addr: String,
    pub bind_port: i32,
}

impl VisitorBaseConfig {
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    pub fn complete(&mut self) {
        if self.bind_addr.is_empty() {
            self.bind_addr = "127.0.0.1".into();
        }
        if self.server_name.is_empty() {
            self.server_name = self.name.clone();
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct StcpVisitorConfig {
    #[serde(flatten)]
    pub base: VisitorBaseConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SudpVisitorConfig {
    #[serde(flatten)]
    pub base: VisitorBaseConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct XtcpVisitorConfig {
    #[serde(flatten)]
    pub base: VisitorBaseConfig,
    pub protocol: String,
    pub keep_tunnel_open: bool,
    pub max_retries_an_hour: i32,
    pub min_retry_interval: i32,
    pub fallback_to: String,
    pub fallback_timeout_ms: i32,
}

/// Internally tagged by `type`, exactly like upstream `TypedVisitorConfig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum VisitorConfig {
    #[serde(rename = "stcp")]
    Stcp(StcpVisitorConfig),
    #[serde(rename = "sudp")]
    Sudp(SudpVisitorConfig),
    #[serde(rename = "xtcp")]
    Xtcp(XtcpVisitorConfig),
}

impl VisitorConfig {
    pub fn name(&self) -> &str {
        match self {
            VisitorConfig::Stcp(c) => &c.base.name,
            VisitorConfig::Sudp(c) => &c.base.name,
            VisitorConfig::Xtcp(c) => &c.base.name,
        }
    }

    pub fn base(&self) -> &VisitorBaseConfig {
        match self {
            VisitorConfig::Stcp(c) => &c.base,
            VisitorConfig::Sudp(c) => &c.base,
            VisitorConfig::Xtcp(c) => &c.base,
        }
    }

    pub fn base_mut(&mut self) -> &mut VisitorBaseConfig {
        match self {
            VisitorConfig::Stcp(c) => &mut c.base,
            VisitorConfig::Sudp(c) => &mut c.base,
            VisitorConfig::Xtcp(c) => &mut c.base,
        }
    }

    pub fn visitor_type(&self) -> &'static str {
        match self {
            VisitorConfig::Stcp(_) => "stcp",
            VisitorConfig::Sudp(_) => "sudp",
            VisitorConfig::Xtcp(_) => "xtcp",
        }
    }
}

/// The shape of a client configuration file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ClientConfigFile {
    #[serde(flatten)]
    pub common: ClientCommonConfig,
    pub proxies: Vec<ProxyConfig>,
    pub visitors: Vec<VisitorConfig>,
}

/// A fully loaded and completed client configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConfig {
    pub common: ClientCommonConfig,
    pub proxies: Vec<ProxyConfig>,
    pub visitors: Vec<VisitorConfig>,
    /// Paths pulled in through `includes`, in load order.
    pub included_files: Vec<std::path::PathBuf>,
}

impl ClientConfig {
    /// Loads a client configuration from disk, expanding `includes`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let main: ClientConfigFile = load_config(path)
            .with_context(|| format!("load client config {}", path.display()))?;

        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        let mut proxies = main.proxies;
        let mut visitors = main.visitors;
        let mut included_files = Vec::new();

        if !main.common.includes.is_empty() {
            let files = expand_includes(base_dir, &main.common.includes)?;
            for file in files {
                let format = ConfigFormat::from_path(&file)?;
                let raw = std::fs::read_to_string(&file)
                    .with_context(|| format!("read include file {}", file.display()))?;
                let rendered = super::load::render_env(&raw)?;
                // Include files carry proxies and visitors only; a common
                // section there would be ignored by upstream, so reject it
                // rather than silently dropping settings.
                let extra: ClientConfigFile = load_config_str(&rendered, format)
                    .with_context(|| format!("load include file {}", file.display()))?;
                proxies.extend(extra.proxies);
                visitors.extend(extra.visitors);
                included_files.push(file);
            }
        }

        Self::from_parts(main.common, proxies, visitors, included_files)
    }

    /// Builds a completed configuration from already parsed parts.
    pub fn from_parts(
        mut common: ClientCommonConfig,
        proxies: Vec<ProxyConfig>,
        visitors: Vec<VisitorConfig>,
        included_files: Vec<std::path::PathBuf>,
    ) -> Result<Self> {
        common.complete();

        if common.transport.wire_protocol != "v1" {
            bail!(
                "transport.wireProtocol = {} is not implemented yet; only v1 is supported",
                common.transport.wire_protocol
            );
        }
        if common.transport.protocol != "tcp" {
            bail!(
                "transport.protocol = {} is not implemented yet; only tcp is supported for now, \
                 with transport.tls.enable for a TLS wrapped control connection",
                common.transport.protocol
            );
        }

        // `start` names the proxies to enable; an empty list means all of them.
        let start = &common.start;
        let mut proxies: Vec<ProxyConfig> = proxies
            .into_iter()
            .filter(|p| {
                p.base().is_enabled() && (start.is_empty() || start.iter().any(|n| n == p.name()))
            })
            .collect();
        let mut visitors: Vec<VisitorConfig> = visitors
            .into_iter()
            .filter(|v| v.base().is_enabled())
            .collect();

        for proxy in &mut proxies {
            proxy.base_mut().complete();
        }
        for visitor in &mut visitors {
            visitor.base_mut().complete();
        }

        // Validation runs on the completed configuration, the same order
        // upstream uses: `Complete()` fills in defaults, then the validator
        // checks the result. A plugin proxy has no `localPort` of its own, so
        // the check has to happen after `complete()` has decided the rule.
        for proxy in &proxies {
            if let Err(e) = proxy.validate() {
                bail!("proxy [{}]: {e}", proxy.name());
            }
        }

        // Upstream also refuses to start with duplicate names, because the
        // second registration would silently replace the first.
        for (index, proxy) in proxies.iter().enumerate() {
            if proxies[..index].iter().any(|p| p.name() == proxy.name()) {
                bail!("proxy name [{}] is duplicated", proxy.name());
            }
        }
        for (index, visitor) in visitors.iter().enumerate() {
            if visitors[..index].iter().any(|v| v.name() == visitor.name()) {
                bail!("visitor name [{}] is duplicated", visitor.name());
            }
        }

        Ok(Self {
            common,
            proxies,
            visitors,
            included_files,
        })
    }

    /// Resolves the auth token, which may live in an external source.
    pub fn token(&self) -> Result<String> {
        self.common.auth.resolve_token()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::proxy::{ProxyBaseConfig, TcpProxyConfig};

    #[test]
    fn transport_defaults_follow_tcp_mux() {
        let mut transport = ClientTransportConfig::default();
        transport.complete();
        assert_eq!(transport.protocol, "tcp");
        assert_eq!(transport.wire_protocol, "v1");
        assert_eq!(transport.pool_count, DEFAULT_POOL_COUNT);
        // TCPMux defaults to on, which disables the application heartbeat.
        assert!(transport.tcp_mux_enabled());
        assert_eq!(transport.heartbeat_interval, -1);
        assert_eq!(transport.heartbeat_timeout, -1);

        let mut transport = ClientTransportConfig {
            tcp_mux: Some(false),
            ..Default::default()
        };
        transport.complete();
        assert_eq!(transport.heartbeat_interval, 30);
        assert_eq!(transport.heartbeat_timeout, 90);
    }

    #[test]
    fn tls_defaults_per_protocol() {
        let tls = TlsClientConfig::default();
        assert!(!tls.enabled_for("tcp"));
        assert!(tls.enabled_for("wss"));
        assert!(tls.enabled_for("quic"));
        assert!(tls.custom_tls_first_byte());
    }

    #[test]
    fn common_defaults() {
        let mut common = ClientCommonConfig::default();
        common.complete();
        assert_eq!(common.server_addr, "0.0.0.0");
        assert_eq!(common.server_port, 7000);
        assert!(common.login_fail_exit_enabled());
        assert_eq!(common.udp_packet_size, 1500);
        assert_eq!(common.nat_hole_stun_server, "stun.easyvoip.com:3478");
    }

    #[test]
    fn legacy_field_names_parse() {
        // `clientID`, `includes` and the flattened common config are the three
        // places where a naive serde mapping gets the name wrong.
        let json = r#"{
            "clientID": "abc",
            "serverAddr": "example.com",
            "includes": ["./confd/*.toml"],
            "proxies": [
                {"type":"tcp","name":"ssh","localPort":22,"remotePort":6000}
            ],
            "visitors": [
                {"type":"stcp","name":"secret","serverName":"ssh","secretKey":"k","bindPort":9000}
            ]
        }"#;
        let parsed: ClientConfigFile = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.common.client_id, "abc");
        assert_eq!(parsed.common.includes, vec!["./confd/*.toml"]);
        assert_eq!(parsed.proxies.len(), 1);
        assert_eq!(parsed.visitors.len(), 1);
        assert_eq!(parsed.visitors[0].visitor_type(), "stcp");
    }

    #[test]
    fn start_filter_selects_named_proxies() {
        let proxies: Vec<ProxyConfig> = serde_json::from_str(
            r#"[{"type":"tcp","name":"a","localPort":1},
                {"type":"tcp","name":"b","localPort":2}]"#,
        )
        .unwrap();
        let mut common = ClientCommonConfig {
            start: vec!["b".into()],
            ..Default::default()
        };
        common.complete();
        let cfg = ClientConfig::from_parts(common, proxies, Vec::new(), Vec::new()).unwrap();
        assert_eq!(cfg.proxies.len(), 1);
        assert_eq!(cfg.proxies[0].name(), "b");
    }

    #[test]
    fn disabled_proxies_are_dropped() {
        let proxies: Vec<ProxyConfig> = serde_json::from_str(
            r#"[{"type":"tcp","name":"a","localPort":1,"enabled":false},
                {"type":"tcp","name":"b","localPort":2}]"#,
        )
        .unwrap();
        let mut common = ClientCommonConfig::default();
        common.complete();
        let cfg = ClientConfig::from_parts(common, proxies, Vec::new(), Vec::new()).unwrap();
        assert_eq!(cfg.proxies.len(), 1);
        assert_eq!(cfg.proxies[0].name(), "b");
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let proxies: Vec<ProxyConfig> = serde_json::from_str(
            r#"[{"type":"tcp","name":"a","localPort":1},
                {"type":"udp","name":"a","localPort":2}]"#,
        )
        .unwrap();
        let mut common = ClientCommonConfig::default();
        common.complete();
        let err = ClientConfig::from_parts(common, proxies, Vec::new(), Vec::new()).unwrap_err();
        assert!(err.to_string().contains("duplicated"));
    }

    #[test]
    fn unsupported_transport_is_refused() {
        for protocol in ["kcp", "quic", "websocket", "wss"] {
            let mut common = ClientCommonConfig::default();
            common.transport.protocol = protocol.into();
            let err = ClientConfig::from_parts(common, Vec::new(), Vec::new(), Vec::new())
                .unwrap_err();
            assert!(err.to_string().contains("not implemented"));
        }
        let mut common = ClientCommonConfig::default();
        common.transport.wire_protocol = "v2".into();
        let err =
            ClientConfig::from_parts(common, Vec::new(), Vec::new(), Vec::new()).unwrap_err();
        assert!(err.to_string().contains("wireProtocol"));
    }

    #[test]
    fn tcp_with_tls_is_accepted() {
        let mut common = ClientCommonConfig::default();
        common.transport.tls.enable = Some(true);
        common.transport.tls.server_name = "frps.example.com".into();
        let cfg = ClientConfig::from_parts(common, Vec::new(), Vec::new(), Vec::new()).unwrap();
        assert!(cfg.common.transport.tls.enabled_for("tcp"));
        assert_eq!(cfg.common.transport.tls.server_name, "frps.example.com");
    }

    /// The plugin block travels inside the flattened base config, so this is
    /// the test that proves the internally tagged enum survives TOML.
    #[test]
    fn a_plugin_survives_the_toml_round_trip() {
        let text = r#"
serverAddr = "127.0.0.1"

[[proxies]]
name = "web"
type = "tcp"
remotePort = 6000

[proxies.plugin]
type = "https2http"
localAddr = "127.0.0.1:8080"
crtPath = "server.crt"
keyPath = "server.key"
hostHeaderRewrite = "rewritten"

[proxies.plugin.requestHeaders.set]
X-From = "frpc"
"#;
        let file: ClientConfigFile =
            crate::config::load_config_str(text, crate::config::ConfigFormat::Toml).unwrap();
        let proxy = &file.proxies[0];
        let Some(crate::config::PluginConfig::Https2Http {
            local_addr,
            host_header_rewrite,
            request_headers,
            crt_path,
            key_path,
            ..
        }) = proxy.plugin()
        else {
            panic!("plugin was not decoded: {:?}", proxy.plugin());
        };
        assert_eq!(local_addr, "127.0.0.1:8080");
        assert_eq!(host_header_rewrite, "rewritten");
        assert_eq!(crt_path, "server.crt");
        assert_eq!(key_path, "server.key");
        assert_eq!(request_headers.set.get("X-From").map(String::as_str), Some("frpc"));
    }

    /// A plugin replaces the local service, so `localPort` must not be required.
    #[test]
    fn a_plugin_proxy_needs_no_local_port() {
        let text = r#"
[[proxies]]
name = "sh"
type = "tcp"
remotePort = 6001

[proxies.plugin]
type = "unix_domain_socket"
unixPath = "/run/app.sock"
"#;
        let file: ClientConfigFile =
            crate::config::load_config_str(text, crate::config::ConfigFormat::Toml).unwrap();
        assert_eq!(file.proxies[0].base().local_port, 0);
        let cfg = ClientConfig::from_parts(
            ClientCommonConfig::default(),
            file.proxies,
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(cfg.proxies[0].plugin().unwrap().plugin_type(), "unix_domain_socket");
    }

    #[test]
    fn a_missing_local_port_is_still_refused_without_a_plugin() {
        let proxy = ProxyConfig::Tcp(TcpProxyConfig {
            base: ProxyBaseConfig {
                name: "sh".into(),
                proxy_type: "tcp".into(),
                ..Default::default()
            },
            remote_port: 6001,
        });
        let err = ClientConfig::from_parts(
            ClientCommonConfig::default(),
            vec![proxy],
            Vec::new(),
            Vec::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("localPort"), "{err}");
    }

    #[test]
    fn the_unimplemented_virtual_net_plugin_is_refused_by_name() {
        let text = r#"
[[proxies]]
name = "vnet"
type = "tcp"
remotePort = 6002

[proxies.plugin]
type = "virtual_net"
"#;
        let file: ClientConfigFile =
            crate::config::load_config_str(text, crate::config::ConfigFormat::Toml).unwrap();
        let err = ClientConfig::from_parts(
            ClientCommonConfig::default(),
            file.proxies,
            Vec::new(),
            Vec::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("virtual_net"), "{err}");
    }

    #[test]
    fn a_plugin_missing_a_required_field_names_the_plugin() {
        let text = r#"
[[proxies]]
name = "web"
type = "tcp"
remotePort = 6003

[proxies.plugin]
type = "static_file"
"#;
        let file: ClientConfigFile =
            crate::config::load_config_str(text, crate::config::ConfigFormat::Toml).unwrap();
        let err = ClientConfig::from_parts(
            ClientCommonConfig::default(),
            file.proxies,
            Vec::new(),
            Vec::new(),
        )
        .unwrap_err();
        let err = err.to_string();
        assert!(err.contains("static_file"), "{err}");
        assert!(err.contains("localPath"), "{err}");
    }
}
