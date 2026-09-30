//! An HTTP server fed by work connections instead of a listening socket.
//!
//! Upstream's plugins do this with `client.NewProxyListener()`, a `net.Listener`
//! whose `Accept` blocks on a channel that `Handle` pushes connections into, and
//! then hand it to `http.Server.Serve`. The Rust equivalent keeps the same
//! shape: the accept loop is a task reading a channel, and every connection is
//! served by hyper.
//!
//! Two variants matter, and they differ in ways upstream cares about:
//!
//! * a plain bridge serves HTTP/1.1 only, exactly like a Go `http.Server` on a
//!   non-TLS listener (h2c is never enabled);
//! * a TLS bridge runs the handshake first and can then negotiate HTTP/2, which
//!   is what `enableHTTP2` controls on the `https2http` and `https2https`
//!   plugins.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::PluginConn;

/// The body type every plugin handler returns.
///
/// `Incoming` carries `hyper::Error`, so fixing the error type here lets one
/// handler return either a forwarded body or a locally built one without
/// boxing twice.
pub type RespBody = BoxBody<Bytes, hyper::Error>;

/// Builds a response body from bytes.
pub fn full_body(body: impl Into<Bytes>) -> RespBody {
    Full::new(body.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Handles one inbound request. `peer` is the address the server reported for
/// the work connection, which the TLS-terminating plugins put in
/// `X-Forwarded-For`.
pub type Handler = Arc<
    dyn Fn(
            Request<Incoming>,
            Option<SocketAddr>,
        ) -> Pin<Box<dyn Future<Output = Response<RespBody>> + Send>>
        + Send
        + Sync,
>;

/// A channel-fed HTTP server.
pub struct Bridge {
    tx: mpsc::UnboundedSender<(PluginConn, Option<SocketAddr>)>,
}

impl Bridge {
    /// Starts the accept loop.
    pub fn new(
        handler: Handler,
        acceptor: Option<Arc<rustls::ServerConfig>>,
        http2: bool,
        cancel: CancellationToken,
    ) -> Arc<Self> {
        let (tx, mut rx) = mpsc::unbounded_channel::<(PluginConn, Option<SocketAddr>)>();
        let bridge = Arc::new(Self { tx });

        tokio::spawn(async move {
            loop {
                let (conn, peer) = tokio::select! {
                    _ = cancel.cancelled() => return,
                    got = rx.recv() => match got {
                        Some(item) => item,
                        None => return,
                    },
                };
                let handler = handler.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve(conn, handler, acceptor, http2, peer).await {
                        debug!(error = %e, "plugin bridge connection ended");
                    }
                });
            }
        });

        bridge
    }

    /// Feeds a work connection to the server.
    pub fn put_conn(&self, conn: PluginConn, peer: Option<SocketAddr>) {
        if self.tx.send((conn, peer)).is_err() {
            debug!("plugin bridge is closed, dropping a work connection");
        }
    }
}

async fn serve(
    conn: PluginConn,
    handler: Handler,
    acceptor: Option<Arc<rustls::ServerConfig>>,
    http2: bool,
    peer: Option<SocketAddr>,
) -> Result<()> {
    let io: PluginConn = match acceptor {
        Some(config) => {
            let tls = tokio_rustls::TlsAcceptor::from(config)
                .accept(conn)
                .await
                .context("plugin TLS handshake")?;
            Box::new(tls)
        }
        None => conn,
    };

    let service = service_fn(move |req: Request<Incoming>| {
        let handler = handler.clone();
        async move { Ok::<_, Infallible>(handler(req, peer).await) }
    });

    if http2 {
        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
            .serve_connection_with_upgrades(TokioIo::new(io), service)
            .await
            // hyper reports a boxed error here, which `anyhow::Context` will not
            // take directly.
            .map_err(|e| anyhow!("serve a plugin connection: {e}"))?;
    } else {
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(io), service)
            .with_upgrades()
            .await
            .map_err(|e| anyhow!("serve a plugin connection: {e}"))?;
    }
    Ok(())
}
