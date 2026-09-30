//! Configuration model mirroring upstream `pkg/config/v1`.
//!
//! Field names follow the TOML/YAML/JSON schema of frp `v0.52.0` and later
//! (camelCase). A handful of upstream tags are *not* the camelCase form of the
//! Go field name — `vhostHTTPPort`, `tcpmuxHTTPConnectPort`,
//! `natholeAnalysisDataReserveHours`, `clientID` and friends — so those carry an
//! explicit `serde(rename)` to avoid silently dropping user configuration.

pub mod client;
pub mod common;
pub mod load;
pub mod proxy;
pub mod server;

pub use client::{
    AuthClientConfig, ClientCommonConfig, ClientConfig, ClientConfigFile, ClientTransportConfig,
    StcpVisitorConfig, SudpVisitorConfig, TlsClientConfig, VisitorBaseConfig, VisitorConfig,
    VisitorTransport, XtcpVisitorConfig,
};
pub use common::{
    AuthMethod, AuthScope, HeaderOperations, HttpHeader, HttpPluginOptions, LogConfig, QUICOptions,
    TlsConfig, ValueSource, WebServerConfig,
};
pub use load::{load_config, load_config_str, ConfigFormat};
pub use proxy::{
    HttpProxyConfig, HttpsProxyConfig, PortsRange, ProxyBaseConfig, ProxyConfig, ProxyTransport,
    StcpProxyConfig, SudpProxyConfig, TcpProxyConfig, TcpmuxProxyConfig, UdpProxyConfig,
    XtcpProxyConfig,
};
pub use server::{
    AuthServerConfig, ServerConfig, ServerTransportConfig, SshTunnelGateway, TlsServerConfig,
};
