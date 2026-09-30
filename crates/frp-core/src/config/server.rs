//! `frps` configuration, mirroring upstream `pkg/config/v1/server.go`.

use serde::{Deserialize, Serialize};

use super::common::{
    AuthMethod, AuthScope, HttpPluginOptions, LogConfig, QUICOptions, ValueSource, WebServerConfig,
};
use super::proxy::PortsRange;

pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0";
pub const DEFAULT_BIND_PORT: i32 = 7000;
pub const DEFAULT_VHOST_HTTP_TIMEOUT: i64 = 60;
pub const DEFAULT_USER_CONN_TIMEOUT: i64 = 10;
pub const DEFAULT_UDP_PACKET_SIZE: i64 = 1500;
pub const DEFAULT_MAX_POOL_COUNT: i64 = 5;
pub const DEFAULT_HEARTBEAT_TIMEOUT: i64 = 90;
pub const DEFAULT_TCP_MUX_KEEPALIVE_INTERVAL: i64 = 60;
pub const DEFAULT_NATHOLE_RESERVE_HOURS: i64 = 7 * 24;
pub const DEFAULT_DASHBOARD_PORT: i32 = 7500;

/// The full `frps.toml` document.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ServerConfig {
    pub auth: AuthServerConfig,
    pub bind_addr: String,
    pub bind_port: i32,
    pub kcp_bind_port: i32,
    pub quic_bind_port: i32,
    pub proxy_bind_addr: String,
    #[serde(rename = "vhostHTTPPort")]
    pub vhost_http_port: i32,
    #[serde(rename = "vhostHTTPTimeout")]
    pub vhost_http_timeout: i64,
    #[serde(rename = "vhostHTTPSPort")]
    pub vhost_https_port: i32,
    #[serde(rename = "tcpmuxHTTPConnectPort")]
    pub tcpmux_http_connect_port: i32,
    pub tcpmux_passthrough: bool,
    pub sub_domain_host: String,
    pub custom404_page: String,
    pub ssh_tunnel_gateway: SshTunnelGateway,
    pub web_server: WebServerConfig,
    pub enable_prometheus: bool,
    pub log: LogConfig,
    pub transport: ServerTransportConfig,
    pub detailed_errors_to_client: Option<bool>,
    pub max_ports_per_client: i64,
    pub user_conn_timeout: i64,
    pub udp_packet_size: i64,
    #[serde(rename = "natholeAnalysisDataReserveHours")]
    pub nathole_analysis_data_reserve_hours: i64,
    pub allow_ports: Vec<PortsRange>,
    pub http_plugins: Vec<HttpPluginOptions>,
}

impl ServerConfig {
    /// Fills in the same defaults as upstream `ServerConfig.Complete`.
    pub fn complete(&mut self) {
        if self.bind_addr.is_empty() {
            self.bind_addr = DEFAULT_BIND_ADDR.to_string();
        }
        if self.bind_port == 0 {
            self.bind_port = DEFAULT_BIND_PORT;
        }
        if self.proxy_bind_addr.is_empty() {
            self.proxy_bind_addr = self.bind_addr.clone();
        }
        if self.web_server.port > 0 && self.web_server.addr.is_empty() {
            self.web_server.addr = DEFAULT_BIND_ADDR.to_string();
        }
        if self.vhost_http_timeout == 0 {
            self.vhost_http_timeout = DEFAULT_VHOST_HTTP_TIMEOUT;
        }
        if self.detailed_errors_to_client.is_none() {
            self.detailed_errors_to_client = Some(true);
        }
        if self.user_conn_timeout == 0 {
            self.user_conn_timeout = DEFAULT_USER_CONN_TIMEOUT;
        }
        if self.udp_packet_size == 0 {
            self.udp_packet_size = DEFAULT_UDP_PACKET_SIZE;
        }
        if self.nathole_analysis_data_reserve_hours == 0 {
            self.nathole_analysis_data_reserve_hours = DEFAULT_NATHOLE_RESERVE_HOURS;
        }
        self.transport.complete();
    }

    pub fn detailed_errors(&self) -> bool {
        self.detailed_errors_to_client.unwrap_or(true)
    }

    /// `bind_port` listener address.
    pub fn control_bind_addr(&self) -> String {
        format!("{}:{}", self.bind_addr, self.bind_port)
    }

    /// Address proxy listeners bind to.
    pub fn proxy_bind(&self) -> &str {
        if self.proxy_bind_addr.is_empty() {
            &self.bind_addr
        } else {
            &self.proxy_bind_addr
        }
    }

    /// Resolved auth token, honouring `auth.tokenSource`.
    pub fn resolved_token(&self) -> anyhow::Result<String> {
        self.auth.resolved_token()
    }

    /// Whether `port` may be claimed by a client.
    pub fn is_port_allowed(&self, port: i32) -> bool {
        if self.allow_ports.is_empty() {
            return true;
        }
        self.allow_ports.iter().any(|r| r.contains(port))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AuthServerConfig {
    pub method: AuthMethod,
    pub additional_scopes: Vec<AuthScope>,
    pub token: String,
    pub token_source: Option<ValueSource>,
    pub oidc: AuthOidcServerConfig,
}

impl AuthServerConfig {
    pub fn resolved_token(&self) -> anyhow::Result<String> {
        if let Some(src) = &self.token_source {
            return src.resolve();
        }
        Ok(self.token.clone())
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
pub struct AuthOidcServerConfig {
    pub issuer: String,
    pub audience: String,
    pub skip_expiry_check: bool,
    pub skip_issuer_check: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ServerTransportConfig {
    pub tcp_mux: Option<bool>,
    pub tcp_mux_keepalive_interval: i64,
    pub tcp_keepalive: i64,
    /// `0` falls back to [`DEFAULT_MAX_POOL_COUNT`].
    pub max_pool_count: i64,
    /// `0` falls back to [`DEFAULT_HEARTBEAT_TIMEOUT`]; negative disables.
    pub heartbeat_timeout: i64,
    pub quic: QUICOptions,
    pub tls: TlsServerConfig,
}

impl Default for ServerTransportConfig {
    fn default() -> Self {
        Self {
            tcp_mux: None,
            tcp_mux_keepalive_interval: DEFAULT_TCP_MUX_KEEPALIVE_INTERVAL,
            tcp_keepalive: 7200,
            max_pool_count: DEFAULT_MAX_POOL_COUNT,
            heartbeat_timeout: DEFAULT_HEARTBEAT_TIMEOUT,
            quic: QUICOptions::default(),
            tls: TlsServerConfig::default(),
        }
    }
}

impl ServerTransportConfig {
    fn complete(&mut self) {
        if self.max_pool_count == 0 {
            self.max_pool_count = DEFAULT_MAX_POOL_COUNT;
        }
        if self.tcp_mux_keepalive_interval == 0 {
            self.tcp_mux_keepalive_interval = DEFAULT_TCP_MUX_KEEPALIVE_INTERVAL;
        }
        if self.heartbeat_timeout == 0 {
            self.heartbeat_timeout = DEFAULT_HEARTBEAT_TIMEOUT;
        }
    }

    pub fn tcp_mux_enabled(&self) -> bool {
        self.tcp_mux.unwrap_or(true)
    }

    pub fn heartbeat_timeout_secs(&self) -> i64 {
        if self.heartbeat_timeout == 0 {
            DEFAULT_HEARTBEAT_TIMEOUT
        } else {
            self.heartbeat_timeout
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TlsServerConfig {
    /// Reject plaintext connections on the control port.
    pub force: bool,
    pub cert_file: String,
    pub key_file: String,
    pub trusted_ca_file: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SshTunnelGateway {
    pub bind_port: i32,
    pub private_key_file: String,
    pub auto_gen_private_key_path: String,
    pub authorized_keys_file: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_upstream() {
        let mut cfg = ServerConfig::default();
        cfg.complete();
        assert_eq!(cfg.bind_addr, "0.0.0.0");
        assert_eq!(cfg.bind_port, 7000);
        assert_eq!(cfg.proxy_bind_addr, "0.0.0.0");
        assert_eq!(cfg.vhost_http_timeout, 60);
        assert_eq!(cfg.user_conn_timeout, 10);
        assert_eq!(cfg.udp_packet_size, 1500);
        assert_eq!(cfg.nathole_analysis_data_reserve_hours, 168);
        assert!(cfg.detailed_errors());
        assert_eq!(cfg.transport.max_pool_count, 5);
        assert_eq!(cfg.transport.heartbeat_timeout_secs(), 90);
        assert!(cfg.transport.tcp_mux_enabled());
        assert_eq!(cfg.control_bind_addr(), "0.0.0.0:7000");
    }

    #[test]
    fn upstream_camel_case_field_names_round_trip() {
        let json = r#"{
            "bindAddr": "127.0.0.1",
            "bindPort": 7000,
            "vhostHTTPPort": 8080,
            "vhostHTTPTimeout": 30,
            "vhostHTTPSPort": 8443,
            "tcpmuxHTTPConnectPort": 1337,
            "subDomainHost": "example.com",
            "enablePrometheus": true,
            "natholeAnalysisDataReserveHours": 24,
            "userConnTimeout": 5,
            "udpPacketSize": 2000,
            "maxPortsPerClient": 10,
            "allowPorts": [{"start": 6000, "end": 6010}, {"single": 7000}],
            "transport": {"tcpMux": false, "maxPoolCount": 3, "heartbeatTimeout": 30},
            "webServer": {"addr": "0.0.0.0", "port": 7500, "user": "admin", "password": "pw"}
        }"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.bind_addr, "127.0.0.1");
        assert_eq!(cfg.vhost_http_port, 8080);
        assert_eq!(cfg.vhost_http_timeout, 30);
        assert_eq!(cfg.vhost_https_port, 8443);
        assert_eq!(cfg.tcpmux_http_connect_port, 1337);
        assert_eq!(cfg.sub_domain_host, "example.com");
        assert!(cfg.enable_prometheus);
        assert_eq!(cfg.nathole_analysis_data_reserve_hours, 24);
        assert_eq!(cfg.user_conn_timeout, 5);
        assert_eq!(cfg.udp_packet_size, 2000);
        assert_eq!(cfg.max_ports_per_client, 10);
        assert_eq!(cfg.allow_ports.len(), 2);
        assert!(!cfg.transport.tcp_mux_enabled());
        assert_eq!(cfg.transport.max_pool_count, 3);
        assert_eq!(cfg.web_server.user, "admin");
        assert_eq!(cfg.web_server.bind_addr().as_deref(), Some("0.0.0.0:7500"));
    }

    #[test]
    fn allow_ports_gate() {
        let mut cfg = ServerConfig::default();
        assert!(cfg.is_port_allowed(1));
        cfg.allow_ports = vec![PortsRange {
            start: 6000,
            end: 6010,
            single: 0,
        }];
        assert!(cfg.is_port_allowed(6005));
        assert!(!cfg.is_port_allowed(5999));
    }

    #[test]
    fn auth_scopes_gate_signing() {
        let mut auth = AuthServerConfig::default();
        assert!(!auth.signs_heartbeats());
        auth.additional_scopes = vec![AuthScope::HeartBeats, AuthScope::NewWorkConns];
        assert!(auth.signs_heartbeats());
        assert!(auth.signs_new_work_conns());
    }
}
