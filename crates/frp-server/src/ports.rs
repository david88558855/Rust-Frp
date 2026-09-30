//! Port allocation for TCP and UDP proxies.
//!
//! Behaviour mirrors upstream `server/ports/ports.go`: a requested port is
//! honoured when it is inside `allowPorts` and not already taken, `0` means
//! "pick any free port", and a released port becomes briefly reserved so that a
//! restarting proxy is likely to get the same one back.

use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use frp_core::config::proxy::PortsRange;

/// How long a released port stays reserved for its previous owner.
const RELEASE_RESERVE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
struct Reservation {
    owner: String,
    released_at: Instant,
}

/// Allocates remote ports for one transport (`tcp` or `udp`).
pub struct PortManager {
    transport: &'static str,
    bind_addr: String,
    allow_ports: Vec<PortsRange>,
    used: Mutex<HashMap<i32, String>>,
    reserved: Mutex<HashMap<i32, Reservation>>,
}

impl PortManager {
    pub fn new(
        transport: &'static str,
        bind_addr: impl Into<String>,
        allow_ports: Vec<PortsRange>,
    ) -> Self {
        Self {
            transport,
            bind_addr: bind_addr.into(),
            allow_ports,
            used: Mutex::new(HashMap::new()),
            reserved: Mutex::new(HashMap::new()),
        }
    }

    pub fn transport(&self) -> &'static str {
        self.transport
    }

    /// Claims `port` for `owner`; `0` picks an arbitrary allowed free port.
    pub fn acquire(&self, owner: &str, requested: i32) -> Result<i32> {
        if requested < 0 {
            return Err(anyhow!("invalid port: {requested}"));
        }
        self.prune_reservations();

        if requested > 0 {
            if !self.is_allowed(requested) {
                return Err(anyhow!(
                    "port {requested} is not in the allowed port range"
                ));
            }
            let mut used = self.used.lock().unwrap();
            if used.contains_key(&requested) {
                return Err(anyhow!("port {requested} is already used"));
            }
            if let Some(res) = self.reserved.lock().unwrap().get(&requested) {
                if res.owner == owner {
                    used.insert(requested, owner.to_string());
                    self.reserved.lock().unwrap().remove(&requested);
                    return Ok(requested);
                }
                return Err(anyhow!("port {requested} is reserved"));
            }
            used.insert(requested, owner.to_string());
            return Ok(requested);
        }

        let candidate = self.pick_random_port()?;
        let mut used = self.used.lock().unwrap();
        used.insert(candidate, owner.to_string());
        Ok(candidate)
    }

    /// Returns a port and keeps it reserved for the previous owner.
    pub fn release(&self, owner: &str, port: i32) {
        if port <= 0 {
            return;
        }
        let mut used = self.used.lock().unwrap();
        if used.get(&port).map(String::as_str) == Some(owner) {
            used.remove(&port);
            self.reserved.lock().unwrap().insert(
                port,
                Reservation {
                    owner: owner.to_string(),
                    released_at: Instant::now(),
                },
            );
        }
    }

    /// Whether `port` is inside the configured `allowPorts`.
    pub fn is_allowed(&self, port: i32) -> bool {
        if self.allow_ports.is_empty() {
            return true;
        }
        self.allow_ports.iter().any(|r| r.contains(port))
    }

    pub fn is_used(&self, port: i32) -> bool {
        self.used.lock().unwrap().contains_key(&port)
    }

    /// Number of ports currently handed out.
    pub fn used_count(&self) -> usize {
        self.used.lock().unwrap().len()
    }

    fn prune_reservations(&self) {
        let mut reserved = self.reserved.lock().unwrap();
        reserved.retain(|_, r| r.released_at.elapsed() < RELEASE_RESERVE);
    }

    fn pick_random_port(&self) -> Result<i32> {
        if self.allow_ports.is_empty() {
            // Walk the ephemeral-ish range and take the first bindable port so
            // we never hand out something the OS already owns.
            for port in 10000..=65535 {
                if !self.is_used(port) && self.can_bind(port) {
                    return Ok(port);
                }
            }
            return Err(anyhow!("no free {} port available", self.transport));
        }

        // A single candidate range is the common case; pick a random offset in
        // each range and fall back to a linear scan.
        let mut candidates: Vec<i32> = Vec::new();
        for range in &self.allow_ports {
            let Some((lo, hi)) = range.bounds() else {
                continue;
            };
            if hi - lo > 65_536 {
                return Err(anyhow!("port range too large: {lo}-{hi}"));
            }
            for port in lo..=hi {
                if !self.is_used(port) {
                    candidates.push(port);
                }
            }
        }
        if candidates.is_empty() {
            return Err(anyhow!("no free {} port in the allowed range", self.transport));
        }
        let idx = fastrand_index(candidates.len());
        let chosen = candidates[idx];
        if self.can_bind(chosen) {
            return Ok(chosen);
        }
        for port in candidates {
            if self.can_bind(port) {
                return Ok(port);
            }
        }
        Err(anyhow!("no bindable {} port in the allowed range", self.transport))
    }

    fn can_bind(&self, port: i32) -> bool {
        if self.transport == "udp" {
            return std::net::UdpSocket::bind((self.bind_addr.as_str(), port as u16)).is_ok();
        }
        TcpListener::bind((self.bind_addr.as_str(), port as u16)).is_ok()
    }
}

/// Cheap random index for picking a free port from a candidate range.
fn fastrand_index(len: usize) -> usize {
    rand::random::<usize>() % len
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager(allow: Vec<PortsRange>) -> PortManager {
        PortManager::new("tcp", "127.0.0.1", allow)
    }

    #[test]
    fn explicit_port_acquire_and_release() {
        let pm = manager(vec![]);
        assert_eq!(pm.acquire("p1", 40000).unwrap(), 40000);
        assert!(pm.acquire("p2", 40000).is_err());
        pm.release("p1", 40000);
        assert!(!pm.is_used(40000));
        // Reserved for the previous owner for a while.
        assert!(pm.acquire("p2", 40000).is_err());
        assert_eq!(pm.acquire("p1", 40000).unwrap(), 40000);
    }

    #[test]
    fn allow_ports_is_enforced() {
        let pm = manager(vec![PortsRange {
            start: 40000,
            end: 40010,
            single: 0,
        }]);
        assert_eq!(pm.acquire("p", 40005).unwrap(), 40005);
        assert!(pm.acquire("p", 39999).is_err());
    }

    #[test]
    fn random_port_comes_from_the_allowed_range() {
        let pm = manager(vec![PortsRange {
            single: 40021,
            ..Default::default()
        }]);
        assert_eq!(pm.acquire("p", 0).unwrap(), 40021);
        assert!(pm.acquire("q", 0).is_err());
    }

    #[test]
    fn invalid_requests() {
        let pm = manager(vec![]);
        assert!(pm.acquire("p", -1).is_err());
    }

    #[test]
    fn release_of_foreign_port_is_ignored() {
        let pm = manager(vec![]);
        pm.acquire("p1", 40030).unwrap();
        pm.release("p2", 40030);
        assert!(pm.is_used(40030));
    }
}
