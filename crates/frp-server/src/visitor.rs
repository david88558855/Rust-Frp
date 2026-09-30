//! Visitor admission for the `stcp` and `sudp` proxy types.
//!
//! A visitor is a client that connects to `frps` with a `NewVisitorConn`
//! message instead of a `Login`, proving knowledge of the proxy's `secretKey`.
//! Once admitted, the connection is handed to the owning proxy, which pairs it
//! with a work connection on the serving side.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;

use anyhow::{anyhow, Result};
use frp_core::crypto::auth;
use frp_core::crypto::auth::constant_time_eq;
use frp_core::transport::ServerConn;
use tokio::sync::mpsc;

/// An admitted visitor connection.
pub struct VisitorConn {
    pub stream: ServerConn,
    pub remote_addr: SocketAddr,
    pub user: String,
    /// Wrap the payload with the proxy secret key when set.
    pub use_encryption: bool,
    pub use_compression: bool,
}

struct Listener {
    secret_key: String,
    allow_users: Vec<String>,
    sender: mpsc::UnboundedSender<VisitorConn>,
}

/// Registry of pending visitor listeners, keyed by proxy name.
#[derive(Default)]
pub struct VisitorRegistry {
    listeners: Mutex<HashMap<String, Listener>>,
}

impl VisitorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a listener for `proxy_name`; the returned receiver yields
    /// admitted visitor connections.
    pub fn register(
        &self,
        proxy_name: &str,
        secret_key: &str,
        allow_users: Vec<String>,
        owner_user: &str,
    ) -> Result<mpsc::UnboundedReceiver<VisitorConn>> {
        let mut listeners = self.listeners.lock().unwrap();
        if listeners.contains_key(proxy_name) {
            return Err(anyhow!("visitor listener for {proxy_name} already exists"));
        }
        let (tx, rx) = mpsc::unbounded_channel();
        listeners.insert(
            proxy_name.to_string(),
            Listener {
                secret_key: secret_key.to_string(),
                // An empty allowUsers list means "only the proxy owner",
                // upstream `startVisitorListener`.
                allow_users: if allow_users.is_empty() {
                    vec![owner_user.to_string()]
                } else {
                    allow_users.to_vec()
                },
                sender: tx,
            },
        );
        Ok(rx)
    }

    pub fn unregister(&self, proxy_name: &str) {
        self.listeners.lock().unwrap().remove(proxy_name);
    }

    pub fn exists(&self, proxy_name: &str) -> bool {
        self.listeners.lock().unwrap().contains_key(proxy_name)
    }

    /// Validates a `NewVisitorConn` request without consuming the connection.
    ///
    /// The response must be written *before* the connection is handed to the
    /// proxy, so validation and queueing are separate steps.
    ///
    /// The visitor proves knowledge of the proxy's secret key by sending
    /// `md5(secretKey || timestamp)`, the same construction the token uses.
    /// Comparing the signature to the secret key itself would never match — and
    /// is what this did until the STCP end to end run caught it.
    pub fn validate(
        &self,
        proxy_name: &str,
        sign_key: &str,
        timestamp: i64,
        user: &str,
    ) -> Result<()> {
        let listeners = self.listeners.lock().unwrap();
        let listener = listeners
            .get(proxy_name)
            .ok_or_else(|| anyhow!("no visitor listener for proxy [{proxy_name}]"))?;

        let expected = auth::get_auth_key(&listener.secret_key, timestamp);
        if !constant_time_eq(&expected, sign_key) {
            return Err(anyhow!(
                "visitor connection of [{proxy_name}] auth failed"
            ));
        }
        // `*` allows any user, matching upstream.
        if !listener.allow_users.iter().any(|u| u == user)
            && !listener.allow_users.iter().any(|u| u == "*")
        {
            return Err(anyhow!(
                "visitor connection of [{proxy_name}] user [{user}] not allowed"
            ));
        }
        Ok(())
    }

    /// Queues an already validated connection for the proxy to pick up.
    pub fn enqueue(&self, proxy_name: &str, conn: VisitorConn) -> Result<()> {
        let listeners = self.listeners.lock().unwrap();
        let listener = listeners
            .get(proxy_name)
            .ok_or_else(|| anyhow!("no visitor listener for proxy [{proxy_name}]"))?;
        listener
            .sender
            .send(conn)
            .map_err(|_| anyhow!("proxy [{proxy_name}] is closed"))
    }

    pub fn len(&self) -> usize {
        self.listeners.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frp_core::transport::{PrefixedStream, ServerStream};
    use tokio::net::TcpStream;

    /// Builds a `VisitorConn` around a real loopback socket pair, inside the
    /// test runtime so the stream can register with the reactor.
    async fn dummy_conn(user: &str) -> VisitorConn {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (_server, _) = listener.accept().await.unwrap();
        VisitorConn {
            stream: ServerConn::Direct(Box::new(ServerStream::Plain(
                PrefixedStream::new(client, Vec::new()),
            ))),
            remote_addr: addr,
            user: user.to_string(),
            use_encryption: false,
            use_compression: false,
        }
    }

    #[tokio::test]
    async fn register_then_admit() {
        let reg = VisitorRegistry::new();
        let mut rx = reg.register("p1", "sk", vec![], "owner").unwrap();
        assert!(reg.exists("p1"));
        let timestamp = 1_700_000_000;
        let sign_key = auth::get_auth_key("sk", timestamp);
        reg.validate("p1", &sign_key, timestamp, "owner").unwrap();
        reg.enqueue("p1", dummy_conn("owner").await).unwrap();
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn duplicate_registration_is_rejected() {
        let reg = VisitorRegistry::new();
        let _rx = reg.register("p1", "sk", vec![], "owner").unwrap();
        assert!(reg.register("p1", "sk", vec![], "owner").is_err());
        reg.unregister("p1");
        assert!(!reg.exists("p1"));
    }

    #[tokio::test]
    async fn a_wrong_secret_key_is_rejected() {
        let reg = VisitorRegistry::new();
        let _rx = reg.register("p1", "sk", vec![], "owner").unwrap();
        let timestamp = 1_700_000_000;
        // Signed with a different secret, so the key itself would match if the
        // server compared it directly.
        let forged = auth::get_auth_key("other", timestamp);
        let err = reg
            .validate("p1", &forged, timestamp, "owner")
            .unwrap_err();
        assert!(err.to_string().contains("auth failed"));
    }

    #[tokio::test]
    async fn the_secret_key_itself_is_not_accepted_as_the_signature() {
        let reg = VisitorRegistry::new();
        let _rx = reg.register("p1", "sk", vec![], "owner").unwrap();
        let err = reg.validate("p1", "sk", 1_700_000_000, "owner").unwrap_err();
        assert!(err.to_string().contains("auth failed"));
    }

    #[tokio::test]
    async fn allow_users_defaults_to_the_owner() {
        let reg = VisitorRegistry::new();
        let _rx = reg.register("p1", "sk", vec![], "owner").unwrap();
        let timestamp = 1_700_000_000;
        let sign_key = auth::get_auth_key("sk", timestamp);
        assert!(reg.validate("p1", &sign_key, timestamp, "owner").is_ok());
        let err = reg
            .validate("p1", &sign_key, timestamp, "intruder")
            .unwrap_err();
        assert!(err.to_string().contains("not allowed"));
    }

    #[tokio::test]
    async fn explicit_allow_users_is_honoured() {
        let reg = VisitorRegistry::new();
        let _rx = reg
            .register("p1", "sk", vec!["alice".into()], "owner")
            .unwrap();
        let timestamp = 1_700_000_000;
        let sign_key = auth::get_auth_key("sk", timestamp);
        assert!(reg.validate("p1", &sign_key, timestamp, "alice").is_ok());
        assert!(reg
            .validate("p1", &sign_key, timestamp, "owner")
            .is_err());
    }

    #[tokio::test]
    async fn a_wildcard_allows_any_user() {
        let reg = VisitorRegistry::new();
        let _rx = reg.register("p1", "sk", vec!["*".into()], "owner").unwrap();
        let timestamp = 1_700_000_000;
        let sign_key = auth::get_auth_key("sk", timestamp);
        assert!(reg.validate("p1", &sign_key, timestamp, "anyone").is_ok());
        assert!(reg.validate("p1", &sign_key, timestamp, "").is_ok());
    }

    #[tokio::test]
    async fn unknown_proxy_is_rejected() {
        let reg = VisitorRegistry::new();
        let err = reg
            .validate("missing", "sig", 1, "u")
            .unwrap_err();
        assert!(err.to_string().contains("no visitor listener"));
    }
}
