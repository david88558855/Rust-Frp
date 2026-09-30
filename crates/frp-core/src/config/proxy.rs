//! Proxy configuration schema, mirroring upstream `pkg/config/v1/proxy.go`.
//!
//! Parsing goes through `serde_json::Value` (see [`crate::config::load`]) so the
//! internally tagged `type` discriminator and `flatten`ed base config behave the
//! same for TOML, YAML and JSON.

use serde::{Deserialize, Serialize};

use super::common::{HeaderOperations, HttpHeader};

/// A port or port range from `allowPorts`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PortsRange {
    pub start: i32,
    pub end: i32,
    /// A single port; upstream accepts `single = 6000` shorthand.
    pub single: i32,
}

impl PortsRange {
    /// Expands to inclusive `[start, end]`, or `single..=single`.
    pub fn bounds(&self) -> Option<(i32, i32)> {
        if self.single > 0 {
            return Some((self.single, self.single));
        }
        if self.start > 0 && self.end >= self.start {
            return Some((self.start, self.end));
        }
        None
    }

    pub fn contains(&self, port: i32) -> bool {
        self.bounds()
            .map(|(lo, hi)| port >= lo && port <= hi)
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProxyTransport {
    pub use_encryption: bool,
    pub use_compression: bool,
    /// Bandwidth limit string such as `1MB`; upstream keeps it as a quantity.
    pub bandwidth_limit: String,
    /// `client` (default) or `server`.
    pub bandwidth_limit_mode: String,
    /// `v1` or `v2`; empty means disabled.
    pub proxy_protocol_version: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LoadBalancerConfig {
    pub group: String,
    pub group_key: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HealthCheckConfig {
    /// `tcp` or `http`.
    #[serde(rename = "type")]
    pub check_type: String,
    pub timeout_seconds: i64,
    pub max_failed: i64,
    pub interval_seconds: i64,
    pub path: String,
    pub http_headers: Vec<HttpHeader>,
}

impl HealthCheckConfig {
    /// Applies the upstream defaults.
    ///
    /// `check_type` is deliberately *not* defaulted: upstream documents an
    /// empty type as "no health check", and the wrapper uses that to decide
    /// whether to start a monitor at all.
    pub fn complete(&mut self) {
        if self.timeout_seconds == 0 {
            self.timeout_seconds = 3;
        }
        if self.max_failed == 0 {
            self.max_failed = 1;
        }
        if self.interval_seconds == 0 {
            self.interval_seconds = 10;
        }
    }

    /// Whether a monitor should run for this proxy.
    pub fn is_enabled(&self) -> bool {
        !self.check_type.is_empty()
    }
}

/// Fields common to every proxy type.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProxyBaseConfig {
    pub name: String,
    /// Discriminator, also mirrored as the enum tag.
    #[serde(rename = "type")]
    pub proxy_type: String,
    pub enabled: Option<bool>,
    pub annotations: std::collections::HashMap<String, String>,
    pub transport: ProxyTransport,
    pub metadatas: std::collections::HashMap<String, String>,
    pub load_balancer: LoadBalancerConfig,
    pub health_check: HealthCheckConfig,
    #[serde(rename = "localIP")]
    pub local_ip: String,
    pub local_port: i32,
}

impl ProxyBaseConfig {
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    pub fn complete(&mut self) {
        if self.local_ip.is_empty() {
            self.local_ip = "127.0.0.1".into();
        }
        if self.transport.bandwidth_limit_mode.is_empty() {
            self.transport.bandwidth_limit_mode = "client".into();
        }
        self.health_check.complete();
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TcpProxyConfig {
    #[serde(flatten)]
    pub base: ProxyBaseConfig,
    pub remote_port: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UdpProxyConfig {
    #[serde(flatten)]
    pub base: ProxyBaseConfig,
    pub remote_port: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HttpProxyConfig {
    #[serde(flatten)]
    pub base: ProxyBaseConfig,
    pub custom_domains: Vec<String>,
    pub subdomain: String,
    pub locations: Vec<String>,
    pub http_user: String,
    pub http_password: String,
    pub host_header_rewrite: String,
    pub request_headers: HeaderOperations,
    pub response_headers: HeaderOperations,
    #[serde(rename = "routeByHTTPUser")]
    pub route_by_http_user: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HttpsProxyConfig {
    #[serde(flatten)]
    pub base: ProxyBaseConfig,
    pub custom_domains: Vec<String>,
    pub subdomain: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TcpmuxProxyConfig {
    #[serde(flatten)]
    pub base: ProxyBaseConfig,
    pub custom_domains: Vec<String>,
    pub subdomain: String,
    pub http_user: String,
    pub http_password: String,
    #[serde(rename = "routeByHTTPUser")]
    pub route_by_http_user: String,
    pub multiplexer: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct StcpProxyConfig {
    #[serde(flatten)]
    pub base: ProxyBaseConfig,
    pub secret_key: String,
    pub allow_users: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SudpProxyConfig {
    #[serde(flatten)]
    pub base: ProxyBaseConfig,
    pub secret_key: String,
    pub allow_users: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct XtcpProxyConfig {
    #[serde(flatten)]
    pub base: ProxyBaseConfig,
    pub secret_key: String,
    pub allow_users: Vec<String>,
}

/// Internally tagged by the `type` field, exactly like upstream `TypedProxyConfig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProxyConfig {
    #[serde(rename = "tcp")]
    Tcp(TcpProxyConfig),
    #[serde(rename = "udp")]
    Udp(UdpProxyConfig),
    #[serde(rename = "http")]
    Http(HttpProxyConfig),
    #[serde(rename = "https")]
    Https(HttpsProxyConfig),
    #[serde(rename = "tcpmux")]
    Tcpmux(TcpmuxProxyConfig),
    #[serde(rename = "stcp")]
    Stcp(StcpProxyConfig),
    #[serde(rename = "sudp")]
    Sudp(SudpProxyConfig),
    #[serde(rename = "xtcp")]
    Xtcp(XtcpProxyConfig),
}

impl ProxyConfig {
    pub fn name(&self) -> &str {
        match self {
            ProxyConfig::Tcp(c) => &c.base.name,
            ProxyConfig::Udp(c) => &c.base.name,
            ProxyConfig::Http(c) => &c.base.name,
            ProxyConfig::Https(c) => &c.base.name,
            ProxyConfig::Tcpmux(c) => &c.base.name,
            ProxyConfig::Stcp(c) => &c.base.name,
            ProxyConfig::Sudp(c) => &c.base.name,
            ProxyConfig::Xtcp(c) => &c.base.name,
        }
    }

    pub fn base(&self) -> &ProxyBaseConfig {
        match self {
            ProxyConfig::Tcp(c) => &c.base,
            ProxyConfig::Udp(c) => &c.base,
            ProxyConfig::Http(c) => &c.base,
            ProxyConfig::Https(c) => &c.base,
            ProxyConfig::Tcpmux(c) => &c.base,
            ProxyConfig::Stcp(c) => &c.base,
            ProxyConfig::Sudp(c) => &c.base,
            ProxyConfig::Xtcp(c) => &c.base,
        }
    }

    pub fn base_mut(&mut self) -> &mut ProxyBaseConfig {
        match self {
            ProxyConfig::Tcp(c) => &mut c.base,
            ProxyConfig::Udp(c) => &mut c.base,
            ProxyConfig::Http(c) => &mut c.base,
            ProxyConfig::Https(c) => &mut c.base,
            ProxyConfig::Tcpmux(c) => &mut c.base,
            ProxyConfig::Stcp(c) => &mut c.base,
            ProxyConfig::Sudp(c) => &mut c.base,
            ProxyConfig::Xtcp(c) => &mut c.base,
        }
    }

    /// Builds the `NewProxy` message the client sends to register itself.
    ///
    /// The field selection mirrors upstream `ProxyBaseConfig.MarshalToMsg`
    /// plus each concrete `MarshalToMsg`: only the keys that belong to the
    /// proxy type are populated, which keeps the JSON identical to the Go
    /// implementation's `omitempty` output.
    pub fn to_new_proxy(&self) -> crate::msg::NewProxy {
        let mut msg = crate::msg::NewProxy {
            proxy_name: self.name().to_string(),
            proxy_type: self.proxy_type().to_string(),
            ..Default::default()
        };
        let base = self.base();
        msg.use_encryption = base.transport.use_encryption;
        msg.use_compression = base.transport.use_compression;
        msg.bandwidth_limit = base.transport.bandwidth_limit.clone();
        // Upstream leaves the mode empty when it is the default, to save bytes.
        if base.transport.bandwidth_limit_mode != "client" {
            msg.bandwidth_limit_mode = base.transport.bandwidth_limit_mode.clone();
        }
        msg.group = base.load_balancer.group.clone();
        msg.group_key = base.load_balancer.group_key.clone();
        msg.metas = base.metadatas.clone();
        msg.annotations = base.annotations.clone();

        match self {
            ProxyConfig::Tcp(c) => msg.remote_port = c.remote_port,
            ProxyConfig::Udp(c) => msg.remote_port = c.remote_port,
            ProxyConfig::Http(c) => {
                msg.custom_domains = c.custom_domains.clone();
                msg.sub_domain = c.subdomain.clone();
                msg.locations = c.locations.clone();
                msg.host_header_rewrite = c.host_header_rewrite.clone();
                msg.http_user = c.http_user.clone();
                msg.http_pwd = c.http_password.clone();
                msg.headers = c.request_headers.set.clone();
                msg.response_headers = c.response_headers.set.clone();
                msg.route_by_http_user = c.route_by_http_user.clone();
            }
            ProxyConfig::Https(c) => {
                msg.custom_domains = c.custom_domains.clone();
                msg.sub_domain = c.subdomain.clone();
            }
            ProxyConfig::Tcpmux(c) => {
                msg.custom_domains = c.custom_domains.clone();
                msg.sub_domain = c.subdomain.clone();
                msg.http_user = c.http_user.clone();
                msg.http_pwd = c.http_password.clone();
                msg.route_by_http_user = c.route_by_http_user.clone();
                msg.multiplexer = c.multiplexer.clone();
            }
            ProxyConfig::Stcp(c) => {
                msg.sk = c.secret_key.clone();
                msg.allow_users = c.allow_users.clone();
            }
            ProxyConfig::Sudp(c) => {
                msg.sk = c.secret_key.clone();
                msg.allow_users = c.allow_users.clone();
            }
            ProxyConfig::Xtcp(c) => {
                msg.sk = c.secret_key.clone();
                msg.allow_users = c.allow_users.clone();
            }
        }
        msg
    }

    pub fn proxy_type(&self) -> &'static str {
        match self {
            ProxyConfig::Tcp(_) => "tcp",
            ProxyConfig::Udp(_) => "udp",
            ProxyConfig::Http(_) => "http",
            ProxyConfig::Https(_) => "https",
            ProxyConfig::Tcpmux(_) => "tcpmux",
            ProxyConfig::Stcp(_) => "stcp",
            ProxyConfig::Sudp(_) => "sudp",
            ProxyConfig::Xtcp(_) => "xtcp",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> ProxyConfig {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn tcp_proxy_roundtrip() {
        let p = parse(
            r#"{"type":"tcp","name":"ssh","localIP":"127.0.0.1","localPort":22,
                "remotePort":6000,"transport":{"useEncryption":true}}"#,
        );
        match &p {
            ProxyConfig::Tcp(c) => {
                assert_eq!(c.base.name, "ssh");
                assert_eq!(c.base.local_port, 22);
                assert_eq!(c.remote_port, 6000);
                assert!(c.base.transport.use_encryption);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(p.proxy_type(), "tcp");
        assert_eq!(p.name(), "ssh");
    }

    #[test]
    fn http_proxy_upstream_field_names() {
        let p = parse(
            r#"{"type":"http","name":"web","localPort":8080,
                "customDomains":["a.example.com"],"subdomain":"demo",
                "locations":["/api"],"httpUser":"u","httpPassword":"p",
                "hostHeaderRewrite":"internal","routeByHTTPUser":"bob",
                "requestHeaders":{"set":{"X-A":"1"}}}"#,
        );
        match &p {
            ProxyConfig::Http(c) => {
                assert_eq!(c.custom_domains, vec!["a.example.com"]);
                assert_eq!(c.subdomain, "demo");
                assert_eq!(c.locations, vec!["/api"]);
                assert_eq!(c.http_user, "u");
                assert_eq!(c.host_header_rewrite, "internal");
                assert_eq!(c.route_by_http_user, "bob");
                assert_eq!(c.request_headers.set.get("X-A").map(String::as_str), Some("1"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn every_proxy_type_is_accepted() {
        for t in [
            "tcp", "udp", "http", "https", "tcpmux", "stcp", "sudp", "xtcp",
        ] {
            let json = format!(r#"{{"type":"{t}","name":"n","localPort":1}}"#);
            let p = parse(&json);
            assert_eq!(p.proxy_type(), t);
        }
    }

    #[test]
    fn unknown_proxy_type_is_rejected() {
        let err = serde_json::from_str::<ProxyConfig>(r#"{"type":"nope","name":"n"}"#);
        assert!(err.is_err());
    }

    #[test]
    fn ports_range_bounds() {
        let r = PortsRange {
            start: 6000,
            end: 6010,
            single: 0,
        };
        assert_eq!(r.bounds(), Some((6000, 6010)));
        assert!(r.contains(6005));
        assert!(!r.contains(6011));

        let s = PortsRange {
            single: 7000,
            ..Default::default()
        };
        assert_eq!(s.bounds(), Some((7000, 7000)));

        assert_eq!(PortsRange::default().bounds(), None);
    }

    #[test]
    fn base_config_defaults() {
        let mut base = ProxyBaseConfig::default();
        base.complete();
        assert_eq!(base.local_ip, "127.0.0.1");
        assert_eq!(base.transport.bandwidth_limit_mode, "client");
        assert_eq!(base.health_check.interval_seconds, 10);
        assert!(base.is_enabled());
    }

    #[test]
    fn an_absent_health_check_stays_disabled() {
        let mut base = ProxyBaseConfig::default();
        base.complete();
        // Upstream treats an empty type as "no health check", so completion
        // must not fill it in.
        assert!(!base.health_check.is_enabled());
        assert_eq!(base.health_check.check_type, "");

        let mut enabled: HealthCheckConfig = serde_json::from_str(r#"{"type":"http"}"#).unwrap();
        enabled.complete();
        assert!(enabled.is_enabled());
        assert_eq!(enabled.timeout_seconds, 3);
        assert_eq!(enabled.max_failed, 1);
    }
}
