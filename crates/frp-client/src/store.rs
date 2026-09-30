//! The built-in persistent store, matching upstream `pkg/config/source/store.go`.
//!
//! `[store] path = "db.json"` turns the client into a mutable one: proxies and
//! visitors added through the admin API are persisted here and merged into the
//! running configuration on every reload. The file is a plain JSON object —
//! `{"proxies": [...], "visitors": [...]}` with each entry in the flat,
//! `type`-tagged shape — written atomically (temp file + rename) so a crash
//! mid-save cannot truncate the previous contents.
//!
//! Validation is deliberately *not* here: upstream splits it too. The API
//! layer completes and validates an entry before calling into the store, which
//! only worries about uniqueness, persistence, and rollback.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use frp_core::config::{ProxyConfig, VisitorConfig};
use serde::{Deserialize, Serialize};

/// The kind of a store entry, used only to phrase errors like upstream.
const KIND_PROXY: &str = "proxy";
const KIND_VISITOR: &str = "visitor";

/// A mutation that cannot be satisfied, mapped to an HTTP status by the admin
/// server.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("already exists: {0} {1}")]
    AlreadyExists(&'static str, String),
    #[error("not found: {0} {1}")]
    NotFound(&'static str, String),
    #[error("{0}")]
    Persist(String),
}

/// The file layout. `omitempty` on both slices means a fully emptied store
/// writes `{}`, exactly like upstream's `storeData`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreFile {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    proxies: Vec<ProxyConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    visitors: Vec<VisitorConfig>,
}

/// A JSON file holding proxies and visitors.
pub struct Store {
    path: PathBuf,
    proxies: Mutex<HashMap<String, ProxyConfig>>,
    visitors: Mutex<HashMap<String, VisitorConfig>>,
}

impl Store {
    /// Opens the store, loading any existing contents. A missing file is not
    /// an error; a malformed one is.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let store = Self {
            path: path.as_ref().to_path_buf(),
            proxies: Mutex::new(HashMap::new()),
            visitors: Mutex::new(HashMap::new()),
        };
        store.load()?;
        Ok(store)
    }

    fn load(&self) -> Result<()> {
        let raw = match std::fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).context("read store file"),
        };
        let parsed: StoreFile = serde_json::from_str(&raw).context("parse store JSON")?;

        let mut proxies = self.proxies.lock().unwrap();
        let mut visitors = self.visitors.lock().unwrap();
        for proxy in parsed.proxies {
            let name = proxy.name().to_string();
            if name.is_empty() {
                bail!("proxy name cannot be empty");
            }
            proxies.insert(name, proxy);
        }
        for visitor in parsed.visitors {
            let name = visitor.name().to_string();
            if name.is_empty() {
                bail!("visitor name cannot be empty");
            }
            visitors.insert(name, visitor);
        }
        Ok(())
    }

    /// Writes the current contents atomically, sorted by name for a stable file.
    fn save(&self) -> Result<()> {
        let mut proxy_list: Vec<ProxyConfig> =
            self.proxies.lock().unwrap().values().cloned().collect();
        let mut visitor_list: Vec<VisitorConfig> =
            self.visitors.lock().unwrap().values().cloned().collect();
        proxy_list.sort_by(|a, b| a.name().cmp(b.name()));
        visitor_list.sort_by(|a, b| a.name().cmp(b.name()));

        let data = serde_json::to_string_pretty(&StoreFile {
            proxies: proxy_list,
            visitors: visitor_list,
        })
        .context("marshal store JSON")?;

        let dir = self.path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(dir).context("create the store directory")?;
        let tmp = PathBuf::from(format!("{}.tmp", self.path.display()));
        std::fs::write(&tmp, data.as_bytes()).context("write the store temp file")?;
        std::fs::rename(&tmp, &self.path).context("commit the store file")?;
        Ok(())
    }

    // --- proxies ---------------------------------------------------------

    pub fn add_proxy(&self, proxy: ProxyConfig) -> Result<(), StoreError> {
        let name = proxy.name().to_string();
        {
            let mut proxies = self.proxies.lock().unwrap();
            if proxies.contains_key(&name) {
                return Err(StoreError::AlreadyExists(KIND_PROXY, name));
            }
            proxies.insert(name.clone(), proxy);
        }
        if let Err(e) = self.save() {
            self.proxies.lock().unwrap().remove(&name);
            return Err(StoreError::Persist(e.to_string()));
        }
        Ok(())
    }

    pub fn update_proxy(&self, proxy: ProxyConfig) -> Result<(), StoreError> {
        let name = proxy.name().to_string();
        let previous = {
            let proxies = self.proxies.lock().unwrap();
            proxies
                .get(&name)
                .cloned()
                .ok_or_else(|| StoreError::NotFound(KIND_PROXY, name.clone()))?
        };
        self.proxies.lock().unwrap().insert(name.clone(), proxy);
        if let Err(e) = self.save() {
            self.proxies.lock().unwrap().insert(name, previous);
            return Err(StoreError::Persist(e.to_string()));
        }
        Ok(())
    }

    pub fn remove_proxy(&self, name: &str) -> Result<(), StoreError> {
        let previous = self
            .proxies
            .lock()
            .unwrap()
            .remove(name)
            .ok_or_else(|| StoreError::NotFound(KIND_PROXY, name.to_string()))?;
        if let Err(e) = self.save() {
            self.proxies
                .lock()
                .unwrap()
                .insert(name.to_string(), previous);
            return Err(StoreError::Persist(e.to_string()));
        }
        Ok(())
    }

    pub fn get_proxy(&self, name: &str) -> Option<ProxyConfig> {
        self.proxies.lock().unwrap().get(name).cloned()
    }

    pub fn all_proxies(&self) -> Vec<ProxyConfig> {
        self.proxies.lock().unwrap().values().cloned().collect()
    }

    /// The proxies that should actually run: a disabled entry stays stored but
    /// does not reach the control session.
    pub fn enabled_proxies(&self) -> Vec<ProxyConfig> {
        self.proxies
            .lock()
            .unwrap()
            .values()
            .filter(|p| p.base().is_enabled())
            .cloned()
            .collect()
    }

    // --- visitors --------------------------------------------------------

    pub fn add_visitor(&self, visitor: VisitorConfig) -> Result<(), StoreError> {
        let name = visitor.name().to_string();
        {
            let mut visitors = self.visitors.lock().unwrap();
            if visitors.contains_key(&name) {
                return Err(StoreError::AlreadyExists(KIND_VISITOR, name));
            }
            visitors.insert(name.clone(), visitor);
        }
        if let Err(e) = self.save() {
            self.visitors.lock().unwrap().remove(&name);
            return Err(StoreError::Persist(e.to_string()));
        }
        Ok(())
    }

    pub fn update_visitor(&self, visitor: VisitorConfig) -> Result<(), StoreError> {
        let name = visitor.name().to_string();
        let previous = {
            let visitors = self.visitors.lock().unwrap();
            visitors
                .get(&name)
                .cloned()
                .ok_or_else(|| StoreError::NotFound(KIND_VISITOR, name.clone()))?
        };
        self.visitors.lock().unwrap().insert(name.clone(), visitor);
        if let Err(e) = self.save() {
            self.visitors.lock().unwrap().insert(name, previous);
            return Err(StoreError::Persist(e.to_string()));
        }
        Ok(())
    }

    pub fn remove_visitor(&self, name: &str) -> Result<(), StoreError> {
        let previous = self
            .visitors
            .lock()
            .unwrap()
            .remove(name)
            .ok_or_else(|| StoreError::NotFound(KIND_VISITOR, name.to_string()))?;
        if let Err(e) = self.save() {
            self.visitors
                .lock()
                .unwrap()
                .insert(name.to_string(), previous);
            return Err(StoreError::Persist(e.to_string()));
        }
        Ok(())
    }

    pub fn get_visitor(&self, name: &str) -> Option<VisitorConfig> {
        self.visitors.lock().unwrap().get(name).cloned()
    }

    pub fn all_visitors(&self) -> Vec<VisitorConfig> {
        self.visitors.lock().unwrap().values().cloned().collect()
    }

    pub fn enabled_visitors(&self) -> Vec<VisitorConfig> {
        self.visitors
            .lock()
            .unwrap()
            .values()
            .filter(|v| v.base().is_enabled())
            .cloned()
            .collect()
    }
}

/// Completes defaults and validates one store proxy, the way upstream's
/// `validateStoreProxyConfigurer` does before the store ever sees it.
pub fn prepare_proxy(mut proxy: ProxyConfig) -> Result<ProxyConfig, String> {
    proxy.base_mut().complete();
    proxy.validate()?;
    Ok(proxy)
}

/// Completes defaults and validates one store visitor.
pub fn prepare_visitor(mut visitor: VisitorConfig) -> Result<VisitorConfig, String> {
    visitor.base_mut().complete();
    visitor.validate()?;
    Ok(visitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frp_core::config::ProxyBaseConfig;

    fn tmp_store(name: &str) -> Store {
        let dir =
            std::env::temp_dir().join(format!("rust-frp-store-{}-{}", name, std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Store::open(dir.join("db.json")).unwrap()
    }

    fn proxy(name: &str, remote_port: i32) -> ProxyConfig {
        let mut cfg = ProxyConfig::Tcp(frp_core::config::TcpProxyConfig {
            base: ProxyBaseConfig {
                name: name.to_string(),
                local_ip: "127.0.0.1".into(),
                local_port: 22,
                ..Default::default()
            },
            remote_port,
        });
        cfg.base_mut().complete();
        cfg
    }

    #[test]
    fn add_update_remove_round_trips() {
        let store = tmp_store("crud");
        store.add_proxy(proxy("ssh", 6000)).unwrap();
        assert_eq!(store.get_proxy("ssh").unwrap().name(), "ssh");

        store.update_proxy(proxy("ssh", 7000)).unwrap();
        assert_eq!(
            match store.get_proxy("ssh").unwrap() {
                ProxyConfig::Tcp(c) => c.remote_port,
                _ => unreachable!(),
            },
            7000
        );

        store.remove_proxy("ssh").unwrap();
        assert!(store.get_proxy("ssh").is_none());
    }

    #[test]
    fn duplicates_and_missing_entries_are_reported() {
        let store = tmp_store("errors");
        store.add_proxy(proxy("ssh", 6000)).unwrap();
        assert!(matches!(
            store.add_proxy(proxy("ssh", 6001)),
            Err(StoreError::AlreadyExists("proxy", _))
        ));
        assert!(matches!(
            store.remove_proxy("nope"),
            Err(StoreError::NotFound("proxy", _))
        ));
        assert!(matches!(
            store.update_proxy(proxy("nope", 1)),
            Err(StoreError::NotFound("proxy", _))
        ));
    }

    #[test]
    fn a_store_survives_a_reopen() {
        let dir =
            std::env::temp_dir().join(format!("rust-frp-store-reopen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db.json");

        let store = Store::open(&path).unwrap();
        store.add_proxy(proxy("ssh", 6000)).unwrap();
        drop(store);

        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.get_proxy("ssh").unwrap().name(), "ssh");
        // The file is the flat, type-tagged JSON the reference implementation
        // writes, with a single `type` key.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"type\": \"tcp\""));
        assert!(raw.contains("\"name\": \"ssh\""));
        let _ = dir;
    }

    #[test]
    fn disabled_entries_stay_stored_but_do_not_run() {
        let store = tmp_store("enabled");
        store.add_proxy(proxy("off", 6000)).unwrap();
        let mut disabled = proxy("off", 6000);
        disabled.base_mut().enabled = Some(false);
        store.update_proxy(disabled).unwrap();

        assert_eq!(store.all_proxies().len(), 1);
        assert!(store.enabled_proxies().is_empty());
    }
}
