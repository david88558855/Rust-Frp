//! Client plugin options.
//!
//! Upstream models these as `TypedClientPluginOptions`, an interface whose
//! concrete type is selected by the `type` key, so every plugin's options are
//! decoded into one Go struct with `json.Unmarshal`. An internally tagged enum
//! expresses the same thing in Rust: the `type` key selects the variant and the
//! remaining keys are the variant's fields.
//!
//! A plugin replaces the proxy's `localIP`/`localPort`: rather than dialing a
//! plain TCP service, the proxy hands the work connection to the plugin, which
//! decides what to do with it.

use serde::{Deserialize, Serialize};

use super::common::HeaderOperations;

/// One entry of [`PluginConfig`], keyed by `type`.
///
/// Every field carries `default` because Go leaves an absent key zero-valued
/// and only validates the result afterwards; a missing `unixPath` has to decode
/// and then fail validation with the upstream message rather than fail to
/// decode at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PluginConfig {
    /// Forward the connection to a unix domain socket.
    #[serde(rename = "unix_domain_socket")]
    UnixDomainSocket {
        #[serde(rename = "unixPath", default)]
        unix_path: String,
    },
    /// Serve a local directory over HTTP.
    #[serde(rename = "static_file")]
    StaticFile {
        #[serde(rename = "localPath", default)]
        local_path: String,
        #[serde(rename = "stripPrefix", default)]
        strip_prefix: String,
        #[serde(rename = "httpUser", default)]
        http_user: String,
        #[serde(rename = "httpPassword", default)]
        http_password: String,
    },
    /// Speak SOCKS5 to the remote peer.
    #[serde(rename = "socks5")]
    Socks5 {
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
    },
    /// Speak HTTP proxy (including `CONNECT`) to the remote peer.
    #[serde(rename = "http_proxy")]
    HttpProxy {
        #[serde(rename = "httpUser", default)]
        http_user: String,
        #[serde(rename = "httpPassword", default)]
        http_password: String,
    },
    /// Terminate HTTP from the work connection and speak HTTP to the backend.
    #[serde(rename = "http2http")]
    Http2Http {
        #[serde(rename = "localAddr", default)]
        local_addr: String,
        #[serde(rename = "hostHeaderRewrite", default)]
        host_header_rewrite: String,
        #[serde(rename = "requestHeaders", default)]
        request_headers: HeaderOperations,
    },
    /// Terminate HTTP from the work connection and speak HTTPS to the backend.
    #[serde(rename = "http2https")]
    Http2Https {
        #[serde(rename = "localAddr", default)]
        local_addr: String,
        #[serde(rename = "hostHeaderRewrite", default)]
        host_header_rewrite: String,
        #[serde(rename = "requestHeaders", default)]
        request_headers: HeaderOperations,
    },
    /// Terminate TLS from the work connection and speak HTTP to the backend.
    #[serde(rename = "https2http")]
    Https2Http {
        #[serde(rename = "localAddr", default)]
        local_addr: String,
        #[serde(rename = "hostHeaderRewrite", default)]
        host_header_rewrite: String,
        #[serde(rename = "requestHeaders", default)]
        request_headers: HeaderOperations,
        #[serde(rename = "enableHTTP2", default)]
        enable_http2: Option<bool>,
        #[serde(rename = "crtPath", default)]
        crt_path: String,
        #[serde(rename = "keyPath", default)]
        key_path: String,
    },
    /// Terminate TLS from the work connection and speak HTTPS to the backend.
    #[serde(rename = "https2https")]
    Https2Https {
        #[serde(rename = "localAddr", default)]
        local_addr: String,
        #[serde(rename = "hostHeaderRewrite", default)]
        host_header_rewrite: String,
        #[serde(rename = "requestHeaders", default)]
        request_headers: HeaderOperations,
        #[serde(rename = "enableHTTP2", default)]
        enable_http2: Option<bool>,
        #[serde(rename = "crtPath", default)]
        crt_path: String,
        #[serde(rename = "keyPath", default)]
        key_path: String,
    },
    /// Terminate TLS from the work connection and forward the plaintext.
    #[serde(rename = "tls2raw")]
    Tls2Raw {
        #[serde(rename = "localAddr", default)]
        local_addr: String,
        #[serde(rename = "crtPath", default)]
        crt_path: String,
        #[serde(rename = "keyPath", default)]
        key_path: String,
    },
    /// The virtual network plugin. Recognised so the error names the plugin
    /// rather than the whole configuration.
    #[serde(rename = "virtual_net")]
    VirtualNet {},
}

impl PluginConfig {
    /// The `type` value, matching upstream's constants.
    pub fn plugin_type(&self) -> &'static str {
        match self {
            PluginConfig::UnixDomainSocket { .. } => "unix_domain_socket",
            PluginConfig::StaticFile { .. } => "static_file",
            PluginConfig::Socks5 { .. } => "socks5",
            PluginConfig::HttpProxy { .. } => "http_proxy",
            PluginConfig::Http2Http { .. } => "http2http",
            PluginConfig::Http2Https { .. } => "http2https",
            PluginConfig::Https2Http { .. } => "https2http",
            PluginConfig::Https2Https { .. } => "https2https",
            PluginConfig::Tls2Raw { .. } => "tls2raw",
            PluginConfig::VirtualNet { .. } => "virtual_net",
        }
    }

    /// Applies the defaults upstream applies in `Complete()`.
    pub fn complete(&mut self) {
        match self {
            PluginConfig::Https2Http { enable_http2, .. }
            | PluginConfig::Https2Https { enable_http2, .. } => {
                // Upstream: `util.EmptyOr(enableHTTP2, lo.ToPtr(true))`.
                enable_http2.get_or_insert(true);
            }
            _ => {}
        }
    }

    /// Whether HTTP/2 should be offered on the TLS listener.
    pub fn http2_enabled(&self) -> bool {
        match self {
            PluginConfig::Https2Http { enable_http2, .. }
            | PluginConfig::Https2Https { enable_http2, .. } => enable_http2.unwrap_or(true),
            _ => false,
        }
    }

    /// Whether this build can run the plugin.
    ///
    /// `virtual_net` needs the virtual network subsystem (a userspace TCP/IP
    /// stack shared across the client's proxies), which is not implemented, so
    /// it is rejected at configuration load rather than silently doing nothing.
    pub fn is_implemented(&self) -> bool {
        !matches!(self, PluginConfig::VirtualNet { .. })
    }

    /// Checks the fields upstream's `ValidateClientPluginOptions` requires.
    pub fn validate(&self) -> Result<(), String> {
        if !self.is_implemented() {
            return Err(format!(
                "plugin [{}] is not implemented in this build",
                self.plugin_type()
            ));
        }
        match self {
            PluginConfig::UnixDomainSocket { unix_path } => {
                if unix_path.is_empty() {
                    return Err("unixPath is required".into());
                }
            }
            PluginConfig::StaticFile { local_path, .. } => {
                if local_path.is_empty() {
                    return Err("localPath is required".into());
                }
            }
            PluginConfig::Http2Http { local_addr, .. }
            | PluginConfig::Http2Https { local_addr, .. }
            | PluginConfig::Https2Http { local_addr, .. }
            | PluginConfig::Https2Https { local_addr, .. }
            | PluginConfig::Tls2Raw { local_addr, .. } => {
                if local_addr.is_empty() {
                    return Err("localAddr is required".into());
                }
            }
            PluginConfig::Socks5 { .. }
            | PluginConfig::HttpProxy { .. }
            | PluginConfig::VirtualNet { .. } => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> PluginConfig {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn the_type_key_selects_the_variant() {
        assert_eq!(
            parse(r#"{"type":"unix_domain_socket","unixPath":"/run/x.sock"}"#),
            PluginConfig::UnixDomainSocket {
                unix_path: "/run/x.sock".into()
            }
        );
        assert_eq!(
            parse(r#"{"type":"socks5","username":"u","password":"p"}"#),
            PluginConfig::Socks5 {
                username: "u".into(),
                password: "p".into()
            }
        );
    }

    /// Every tag upstream registers must round trip, which is what makes the
    /// enum usable in place of the Go interface.
    #[test]
    fn every_upstream_tag_round_trips() {
        for tag in [
            "unix_domain_socket",
            "static_file",
            "socks5",
            "http_proxy",
            "http2http",
            "http2https",
            "https2http",
            "https2https",
            "tls2raw",
            "virtual_net",
        ] {
            let json = format!(r#"{{"type":"{tag}"}}"#);
            let parsed: PluginConfig = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.plugin_type(), tag);
            let back = serde_json::to_string(&parsed).unwrap();
            assert!(
                back.contains(&format!(r#""type":"{tag}""#)),
                "{} lost its tag",
                tag
            );
        }
    }

    #[test]
    fn http_bridge_fields_use_the_upstream_names() {
        let parsed = parse(
            r#"{"type":"https2http","localAddr":"127.0.0.1:8080",
                "hostHeaderRewrite":"rewritten","crtPath":"/a.crt","keyPath":"/a.key",
                "enableHTTP2":false,"requestHeaders":{"set":{"X-A":"1"}}}"#,
        );
        let PluginConfig::Https2Http {
            local_addr,
            host_header_rewrite,
            request_headers,
            enable_http2,
            crt_path,
            key_path,
        } = parsed
        else {
            panic!("wrong variant");
        };
        assert_eq!(local_addr, "127.0.0.1:8080");
        assert_eq!(host_header_rewrite, "rewritten");
        assert_eq!(request_headers.set.get("X-A").map(String::as_str), Some("1"));
        assert_eq!(enable_http2, Some(false));
        assert_eq!(crt_path, "/a.crt");
        assert_eq!(key_path, "/a.key");
    }

    #[test]
    fn http2_defaults_to_enabled_for_the_tls_variants() {
        let mut cfg = parse(r#"{"type":"https2https","localAddr":"127.0.0.1:8443"}"#);
        assert!(cfg.http2_enabled());
        cfg.complete();
        assert!(cfg.http2_enabled());

        let mut cfg =
            parse(r#"{"type":"https2https","localAddr":"127.0.0.1:8443","enableHTTP2":false}"#);
        cfg.complete();
        assert!(!cfg.http2_enabled());
    }

    #[test]
    fn validation_matches_the_upstream_requirements() {
        assert!(parse(r#"{"type":"unix_domain_socket"}"#).validate().is_err());
        assert!(parse(r#"{"type":"static_file"}"#).validate().is_err());
        assert!(parse(r#"{"type":"tls2raw"}"#).validate().is_err());
        // socks5 and http_proxy have no required field.
        assert!(parse(r#"{"type":"socks5"}"#).validate().is_ok());
        assert!(parse(r#"{"type":"http_proxy"}"#).validate().is_ok());
        assert_eq!(
            parse(r#"{"type":"http2https"}"#).validate().unwrap_err(),
            "localAddr is required"
        );
    }
}
