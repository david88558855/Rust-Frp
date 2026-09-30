//! Virtual host routing for the `http` / `https` proxy types.
//!
//! Mirrors upstream `pkg/util/vhost/router.go`, including the exact lookup
//! order, which matters for compatibility:
//!
//! 1. exact host + exact `routeByHTTPUser`, then the same host with an empty
//!    http user (the "match all users" entry);
//! 2. wildcard walk: for `a.b.example.com` try `*.b.example.com`, then
//!    `*.example.com`; two-label hosts never match `*.com`;
//! 3. the catch-all domain `*`.
//!
//! Within one domain/user bucket the routes are kept sorted by descending
//! location length, so the first prefix match is the longest one.

use std::collections::HashMap;
use std::sync::RwLock;

/// Marker domain matching every host.
pub const CATCH_ALL_DOMAIN: &str = "*";

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct RouteKey {
    pub domain: String,
    pub location: String,
    pub http_user: String,
}

struct Route<T> {
    location: String,
    payload: T,
}

/// Thread safe domain -> http user -> routes index.
pub struct VhostRouter<T> {
    index: RwLock<HashMap<String, HashMap<String, Vec<Route<T>>>>>,
}

impl<T> Default for VhostRouter<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> VhostRouter<T> {
    pub fn new() -> Self {
        Self {
            index: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a route. Returns `false` when the (domain, location, user)
    /// triple is already taken, matching upstream `ErrRouterConfigConflict`.
    pub fn add(&self, domain: &str, location: &str, http_user: &str, payload: T) -> bool {
        let domain = domain.to_ascii_lowercase();
        let location = normalize_location(location);
        let mut index = self.index.write().unwrap();

        let by_user = index.entry(domain).or_default();
        let routes = by_user.entry(http_user.to_string()).or_default();
        if routes.iter().any(|r| r.location == location) {
            return false;
        }
        routes.push(Route { location, payload });
        // Longest location first so prefix matching naturally prefers it.
        routes.sort_by(|a, b| b.location.len().cmp(&a.location.len()));
        true
    }

    /// Removes a route; returns whether anything was removed.
    pub fn del(&self, domain: &str, location: &str, http_user: &str) -> bool {
        let domain = domain.to_ascii_lowercase();
        let location = normalize_location(location);
        let mut index = self.index.write().unwrap();
        let Some(by_user) = index.get_mut(&domain) else {
            return false;
        };
        let Some(routes) = by_user.get_mut(http_user) else {
            return false;
        };
        let before = routes.len();
        routes.retain(|r| r.location != location);
        let removed = routes.len() != before;
        if routes.is_empty() {
            by_user.remove(http_user);
        }
        if by_user.is_empty() {
            index.remove(&domain);
        }
        removed
    }

    /// Removes every route belonging to a domain.
    pub fn del_domain(&self, domain: &str) {
        let domain = domain.to_ascii_lowercase();
        self.index.write().unwrap().remove(&domain);
    }

    /// Resolves `(host, path, http_user)` to the registered payload.
    ///
    /// The payload is cloned out of the index, so callers never hold a lock —
    /// store an `Arc` in the router when the payload is expensive.
    pub fn route(&self, host: &str, path: &str, http_user: &str) -> Option<T>
    where
        T: Clone,
    {
        let host = host.to_ascii_lowercase();
        let index = self.index.read().unwrap();

        if let Some(found) = lookup(&index, &host, path, http_user) {
            return Some(found.clone());
        }

        let labels: Vec<&str> = host.split('.').collect();
        let mut start = 0usize;
        while labels.len() - start >= 3 {
            let mut wildcard: Vec<&str> = labels[start..].to_vec();
            wildcard[0] = CATCH_ALL_DOMAIN;
            let candidate = wildcard.join(".");
            if let Some(found) = lookup(&index, &candidate, path, http_user) {
                return Some(found.clone());
            }
            start += 1;
        }

        lookup(&index, CATCH_ALL_DOMAIN, path, http_user).cloned()
    }

    /// Number of registered routes.
    pub fn len(&self) -> usize {
        self.index
            .read()
            .unwrap()
            .values()
            .map(|by_user| by_user.values().map(Vec::len).sum::<usize>())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// All registered domains.
    pub fn domains(&self) -> Vec<String> {
        self.index.read().unwrap().keys().cloned().collect()
    }
}

/// Exact-host lookup with the all-users fallback.
fn lookup<'a, T>(
    index: &'a HashMap<String, HashMap<String, Vec<Route<T>>>>,
    host: &str,
    path: &str,
    http_user: &str,
) -> Option<&'a T> {
    if let Some(found) = lookup_exact(index, host, path, http_user) {
        return Some(found);
    }
    if http_user.is_empty() {
        return None;
    }
    lookup_exact(index, host, path, "")
}

fn lookup_exact<'a, T>(
    index: &'a HashMap<String, HashMap<String, Vec<Route<T>>>>,
    host: &str,
    path: &str,
    http_user: &str,
) -> Option<&'a T> {
    let by_user = index.get(host)?;
    let routes = by_user.get(http_user)?;
    routes
        .iter()
        .find(|r| path.starts_with(&r.location))
        .map(|r| &r.payload)
}

/// A missing or `/` location is stored as the empty prefix, like upstream.
pub fn normalize_location(location: &str) -> String {
    if location == "/" {
        String::new()
    } else {
        location.to_string()
    }
}

/// Strips the `:port` suffix from an HTTP `Host` header.
pub fn host_without_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match host.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_domain_and_longest_location() {
        let r = VhostRouter::new();
        assert!(r.add("a.example.com", "/", "", "root"));
        assert!(r.add("a.example.com", "/api", "", "api"));
        assert_eq!(r.route("a.example.com", "/x", ""), Some("root"));
        assert_eq!(r.route("a.example.com", "/api/v1", ""), Some("api"));
        assert_eq!(r.route("A.EXAMPLE.COM", "/api", ""), Some("api"));
        assert_eq!(r.route("b.example.com", "/", ""), None);
    }

    #[test]
    fn duplicate_registration_is_rejected() {
        let r = VhostRouter::new();
        assert!(r.add("a.example.com", "/", "", 1));
        assert!(!r.add("a.example.com", "/", "", 2));
        assert!(r.add("a.example.com", "/", "bob", 2));
    }

    #[test]
    fn wildcard_domains() {
        let r = VhostRouter::new();
        r.add("*.example.com", "/", "", "wild");
        assert_eq!(r.route("a.example.com", "/", ""), Some("wild"));
        assert_eq!(r.route("a.b.example.com", "/", ""), Some("wild"));
        // two-label host must not match *.com
        assert_eq!(r.route("example.com", "/", ""), None);
    }

    #[test]
    fn catch_all_domain() {
        let r = VhostRouter::new();
        r.add("*", "/", "", "any");
        assert_eq!(r.route("whatever.test", "/", ""), Some("any"));
        assert_eq!(r.route("a.b.c.d", "/", ""), Some("any"));
    }

    #[test]
    fn http_user_routing_with_all_users_fallback() {
        let r = VhostRouter::new();
        r.add("a.example.com", "/", "bob", "bob-route");
        r.add("a.example.com", "/", "", "any-route");
        assert_eq!(r.route("a.example.com", "/", "bob"), Some("bob-route"));
        assert_eq!(r.route("a.example.com", "/", "alice"), Some("any-route"));

        let r2 = VhostRouter::new();
        r2.add("a.example.com", "/", "bob", "bob-route");
        assert_eq!(r2.route("a.example.com", "/", "alice"), None);
    }

    #[test]
    fn deletion() {
        let r = VhostRouter::new();
        r.add("a.example.com", "/", "", 1);
        assert_eq!(r.len(), 1);
        assert!(r.del("a.example.com", "/", ""));
        assert_eq!(r.route("a.example.com", "/", ""), None);
        assert!(!r.del("a.example.com", "/", ""));
        assert!(r.is_empty());
    }

    #[test]
    fn host_header_port_stripping() {
        assert_eq!(host_without_port("a.example.com:8080"), "a.example.com");
        assert_eq!(host_without_port("a.example.com"), "a.example.com");
        assert_eq!(host_without_port("[::1]:8080"), "::1");
    }

    #[test]
    fn root_location_is_normalized() {
        assert_eq!(normalize_location("/"), "");
        assert_eq!(normalize_location("/api"), "/api");
    }
}
