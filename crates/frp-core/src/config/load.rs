//! Configuration loading: format detection, Go-template environment
//! substitution and `includes` expansion.
//!
//! Every format is first normalised to a [`serde_json::Value`]. Beyond keeping
//! TOML, YAML and JSON behaviourally identical, this makes the internally tagged
//! `type` discriminator used by proxies reliable: `toml` has long-standing
//! quirks around `flatten` with internal tagging, while `serde_json` does not.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::de::DeserializeOwned;

/// Supported configuration encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Toml,
    Yaml,
    Json,
}

impl ConfigFormat {
    /// Infers the format from a file extension, mirroring upstream frp.
    pub fn from_path(path: &Path) -> Result<Self> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase());
        match ext.as_deref() {
            Some("toml") => Ok(ConfigFormat::Toml),
            Some("yml") | Some("yaml") => Ok(ConfigFormat::Yaml),
            Some("json") => Ok(ConfigFormat::Json),
            other => Err(anyhow!(
                "unsupported config file extension {:?} for {}",
                other.unwrap_or("<none>"),
                path.display()
            )),
        }
    }

    /// Parses rendered text into a format agnostic value tree.
    pub fn parse_value(self, text: &str) -> Result<serde_json::Value> {
        match self {
            ConfigFormat::Toml => {
                let value: toml::Value = toml::from_str(text).context("parse TOML config")?;
                serde_json::to_value(value).context("normalise TOML config")
            }
            ConfigFormat::Yaml => {
                let value: serde_yaml::Value = serde_yaml::from_str(text)
                    .context("parse YAML config")?;
                serde_json::to_value(value).context("normalise YAML config")
            }
            ConfigFormat::Json => {
                serde_json::from_str(text).context("parse JSON config")
            }
        }
    }
}

/// Substitutes `{{ .Envs.NAME }}` occurrences with environment variables,
/// mirroring the small subset of Go templates that frp uses in practice.
pub fn render_env(text: &str) -> Result<String> {
    const OPEN: &str = "{{";
    const CLOSE: &str = "}}";

    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(OPEN) {
        out.push_str(&rest[..start]);
        let after = &rest[start + OPEN.len()..];
        let end = match after.find(CLOSE) {
            Some(e) => e,
            None => {
                // Unterminated action: emit verbatim and stop scanning.
                out.push_str(OPEN);
                rest = after;
                continue;
            }
        };
        let action = after[..end].trim();
        out.push_str(&resolve_action(action)?);
        rest = &after[end + CLOSE.len()..];
    }
    out.push_str(rest);
    Ok(out)
}

fn resolve_action(action: &str) -> Result<String> {
    if let Some(name) = action.strip_prefix(".Envs.") {
        let name = name.trim();
        return std::env::var(name)
            .with_context(|| format!("environment variable {name} referenced by config is unset"));
    }
    Err(anyhow!("unsupported config template action: {{{{{action}}}}}"))
}

/// Parses already rendered configuration text.
pub fn load_config_str<T: DeserializeOwned>(text: &str, format: ConfigFormat) -> Result<T> {
    let value = format.parse_value(text)?;
    serde_json::from_value(value).context("deserialize config")
}

/// Reads, renders and parses a configuration file.
pub fn load_config<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<T> {
    let path = path.as_ref();
    let format = ConfigFormat::from_path(path)?;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read config file {}", path.display()))?;
    let rendered = render_env(&raw)?;
    load_config_str(&rendered, format)
        .with_context(|| format!("load config file {}", path.display()))
}

/// Expands the `includes` glob list of a client config.
///
/// Only `*` and `?` wildcards inside the final path component group are
/// supported, which covers the `./confd/*.toml` pattern used by frp.
pub fn expand_includes(base_dir: &Path, patterns: &[String]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for pattern in patterns {
        let candidate = if Path::new(pattern).is_absolute() {
            PathBuf::from(pattern)
        } else {
            base_dir.join(pattern)
        };
        let matches = glob_path(&candidate)?;
        if matches.is_empty() {
            return Err(anyhow!(
                "include pattern {} matched no files",
                candidate.display()
            ));
        }
        out.extend(matches);
    }
    Ok(out)
}

fn glob_path(pattern: &Path) -> Result<Vec<PathBuf>> {
    let dir = pattern.parent().unwrap_or_else(|| Path::new("."));
    let file_pattern = pattern
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or_else(|| anyhow!("invalid include pattern {}", pattern.display()))?;

    if !file_pattern.contains('*') && !file_pattern.contains('?') {
        return Ok(if pattern.is_file() {
            vec![pattern.to_path_buf()]
        } else {
            Vec::new()
        });
    }

    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("read include directory {}", dir.display()))?;
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if wildcard_match(file_pattern, name) && entry.path().is_file() {
            out.push(entry.path());
        }
    }
    out.sort();
    Ok(out)
}

/// Minimal `*`/`?` glob matcher.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::server::ServerConfig;

    const TOML_SAMPLE: &str = r#"
bindAddr = "0.0.0.0"
bindPort = 7000
vhostHTTPPort = 8080
subDomainHost = "example.com"
allowPorts = [{ start = 6000, end = 6010 }]

[auth]
method = "token"
token = "s3cret"

[transport]
tcpMux = false
maxPoolCount = 3

[webServer]
addr = "0.0.0.0"
port = 7500
"#;

    #[test]
    fn toml_and_json_agree() {
        let from_toml: ServerConfig =
            load_config_str(TOML_SAMPLE, ConfigFormat::Toml).unwrap();
        let json = serde_json::to_string(&from_toml).unwrap();
        let from_json: ServerConfig = load_config_str(&json, ConfigFormat::Json).unwrap();
        assert_eq!(from_toml, from_json);
        assert_eq!(from_toml.vhost_http_port, 8080);
        assert_eq!(from_toml.auth.token, "s3cret");
        assert_eq!(from_toml.allow_ports.len(), 1);
        assert!(!from_toml.transport.tcp_mux_enabled());
    }

    #[test]
    fn yaml_matches_toml() {
        let yaml = r#"
bindAddr: 0.0.0.0
bindPort: 7000
vhostHTTPPort: 8080
subDomainHost: example.com
allowPorts:
  - start: 6000
    end: 6010
auth:
  method: token
  token: s3cret
transport:
  tcpMux: false
  maxPoolCount: 3
webServer:
  addr: 0.0.0.0
  port: 7500
"#;
        let from_yaml: ServerConfig = load_config_str(yaml, ConfigFormat::Yaml).unwrap();
        let from_toml: ServerConfig =
            load_config_str(TOML_SAMPLE, ConfigFormat::Toml).unwrap();
        assert_eq!(from_yaml, from_toml);
    }

    #[test]
    fn format_detection() {
        assert_eq!(
            ConfigFormat::from_path(Path::new("a/frps.toml")).unwrap(),
            ConfigFormat::Toml
        );
        assert_eq!(
            ConfigFormat::from_path(Path::new("frps.yaml")).unwrap(),
            ConfigFormat::Yaml
        );
        assert_eq!(
            ConfigFormat::from_path(Path::new("frps.json")).unwrap(),
            ConfigFormat::Json
        );
        assert!(ConfigFormat::from_path(Path::new("frps.ini")).is_err());
    }

    #[test]
    fn env_rendering() {
        std::env::set_var("FRP_TEST_BIND", "127.0.0.1");
        let rendered = render_env("bindAddr = \"{{ .Envs.FRP_TEST_BIND }}\"").unwrap();
        assert_eq!(rendered, "bindAddr = \"127.0.0.1\"");
        std::env::remove_var("FRP_TEST_BIND");

        let plain = render_env("bindPort = 7000").unwrap();
        assert_eq!(plain, "bindPort = 7000");

        assert!(render_env("{{ .Envs.FRP_TEST_MISSING }}").is_err());
        assert!(render_env("{{ .Other }}").is_err());
    }

    #[test]
    fn wildcard_matching() {
        assert!(wildcard_match("*.toml", "a.toml"));
        assert!(!wildcard_match("*.toml", "a.yaml"));
        assert!(wildcard_match("frp-?.toml", "frp-1.toml"));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("a*c", "abc"));
        assert!(!wildcard_match("a*c", "abd"));
    }

    #[test]
    fn include_expansion() {
        let dir = std::env::temp_dir().join(format!("frp-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("confd")).unwrap();
        std::fs::write(dir.join("confd/a.toml"), "a = 1").unwrap();
        std::fs::write(dir.join("confd/b.toml"), "b = 2").unwrap();
        std::fs::write(dir.join("confd/c.yaml"), "c: 3").unwrap();

        let files = expand_includes(&dir, &["./confd/*.toml".to_string()]).unwrap();
        assert_eq!(files.len(), 2);
        assert!(files[0].to_string_lossy().ends_with("a.toml"));

        assert!(expand_includes(&dir, &["./confd/*.ini".to_string()]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
