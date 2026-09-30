//! Configuration shared by the server and the client.

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// Authentication method, upstream `AuthMethod`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum AuthMethod {
    #[default]
    Token,
    Oidc,
}

/// Extra moments at which the token is verified, upstream `AuthScope`.
///
/// The wire values are PascalCase, not camelCase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthScope {
    #[serde(rename = "HeartBeats")]
    HeartBeats,
    #[serde(rename = "NewWorkConns")]
    NewWorkConns,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct QUICOptions {
    pub keepalive_period: i32,
    pub max_idle_timeout: i32,
    pub max_incoming_streams: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct WebServerConfig {
    pub addr: String,
    pub port: i32,
    pub user: String,
    pub password: String,
    pub assets_dir: String,
    pub pprof_enable: bool,
    pub tls: Option<TlsConfig>,
}

impl WebServerConfig {
    /// Address the dashboard binds to, or `None` when disabled.
    pub fn bind_addr(&self) -> Option<String> {
        if self.port <= 0 {
            return None;
        }
        let addr = if self.addr.is_empty() {
            "0.0.0.0"
        } else {
            self.addr.as_str()
        };
        Some(format!("{addr}:{}", self.port))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TlsConfig {
    pub cert_file: String,
    pub key_file: String,
    pub trusted_ca_file: String,
    pub server_name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LogConfig {
    /// `console`, `file` or a file path. Empty means console.
    pub to: String,
    /// `trace`, `debug`, `info`, `warn`, `error`.
    pub level: String,
    pub max_days: i64,
    pub disable_print_color: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HttpPluginOptions {
    pub name: String,
    pub addr: String,
    pub path: String,
    pub ops: Vec<String>,
    pub tls_verify: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HeaderOperations {
    pub set: HashMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

/// External source for a secret such as the auth token.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ValueSource {
    #[serde(rename = "type")]
    pub source_type: String,
    pub file: ValueSourceFile,
    pub env: ValueSourceEnv,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ValueSourceFile {
    pub path: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ValueSourceEnv {
    pub name: String,
}

impl ValueSource {
    /// Reads the secret from its backing store.
    pub fn resolve(&self) -> Result<String> {
        match self.source_type.as_str() {
            "file" => {
                let path = &self.file.path;
                let raw = std::fs::read_to_string(path)
                    .with_context(|| format!("read token source file {path}"))?;
                Ok(raw.trim().to_string())
            }
            "env" => std::env::var(&self.env.name)
                .with_context(|| format!("read token source env {}", self.env.name)),
            other => Err(anyhow!("unsupported value source type: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_method_wire_values() {
        assert_eq!(serde_json::to_string(&AuthMethod::Token).unwrap(), "\"token\"");
        assert_eq!(serde_json::to_string(&AuthMethod::Oidc).unwrap(), "\"oidc\"");
    }

    #[test]
    fn auth_scope_wire_values_are_pascal_case() {
        assert_eq!(
            serde_json::to_string(&AuthScope::HeartBeats).unwrap(),
            "\"HeartBeats\""
        );
        assert_eq!(
            serde_json::to_string(&AuthScope::NewWorkConns).unwrap(),
            "\"NewWorkConns\""
        );
        let parsed: AuthScope = serde_json::from_str("\"HeartBeats\"").unwrap();
        assert_eq!(parsed, AuthScope::HeartBeats);
    }

    #[test]
    fn web_server_bind_addr() {
        let mut ws = WebServerConfig::default();
        assert!(ws.bind_addr().is_none());
        ws.port = 7500;
        assert_eq!(ws.bind_addr().as_deref(), Some("0.0.0.0:7500"));
        ws.addr = "127.0.0.1".into();
        assert_eq!(ws.bind_addr().as_deref(), Some("127.0.0.1:7500"));
    }

    #[test]
    fn value_source_env() {
        std::env::set_var("FRP_TEST_TOKEN_SRC", "s3cret");
        let src = ValueSource {
            source_type: "env".into(),
            env: ValueSourceEnv {
                name: "FRP_TEST_TOKEN_SRC".into(),
            },
            ..Default::default()
        };
        assert_eq!(src.resolve().unwrap(), "s3cret");
        std::env::remove_var("FRP_TEST_TOKEN_SRC");
    }
}
