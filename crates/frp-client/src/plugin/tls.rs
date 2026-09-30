//! TLS termination for the plugins that need it.
//!
//! `tls2raw`, `https2http` and `https2https` all present a certificate to the
//! remote peer; the certificate comes from `crtPath`/`keyPath` rather than
//! being generated, because the peer has to trust it.

use std::sync::Arc;

use anyhow::{Context, Result};

/// Builds a rustls server configuration from a PEM certificate chain and key.
///
/// `alpn` advertises the application protocols. Upstream advertises `h2` only
/// when `enableHTTP2` is set, and always advertises `http/1.1`; a peer that
/// offers neither falls back to HTTP/1.1 because rustls advertises the list
/// verbatim and hyper then speaks whatever was negotiated.
pub fn build_acceptor(
    crt_path: &str,
    key_path: &str,
    alpn: Vec<Vec<u8>>,
) -> Result<Arc<rustls::ServerConfig>> {
    let certs = frp_core::transport::load_certs(crt_path)?;
    let key = frp_core::transport::load_private_key(key_path)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("select TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .with_context(|| format!("install the certificate from {crt_path}"))?;
    config.alpn_protocols = alpn;
    Ok(Arc::new(config))
}

/// The ALPN list a TLS-terminating plugin advertises.
///
/// Go's `http.Server` installs `h2` when `TLSNextProto` is left alone and
/// removes it when the map is set to empty, which is exactly what
/// `enableHTTP2` toggles.
pub fn alpn_for(http2: bool) -> Vec<Vec<u8>> {
    if http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    }
}
