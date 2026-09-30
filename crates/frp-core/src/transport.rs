//! TLS aware stream handling for the frp control port.
//!
//! Upstream `pkg/util/net/tls.go` distinguishes a real TLS ClientHello from
//! frp's obfuscated TLS by peeking the first byte:
//!
//! * `0x17` ([`FRP_TLS_HEAD_BYTE`]) — the client wrote a fake TLS record byte
//!   before starting an ordinary TLS handshake. The byte is discarded and the
//!   handshake runs on the raw stream.
//! * `0x16` ([`TLS_HANDSHAKE_BYTE`]) — a genuine TLS ClientHello. The byte is
//!   replayed into the handshake.
//! * anything else — plaintext; with `transport.tls.force` this is a hard error.
//!
//! [`PrefixedStream`] keeps a peeked byte pending for the reader, so both cases
//! — and the plaintext case — share a single code path.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Context as _, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::config::server::TlsServerConfig;

/// First byte written by frpc when `disableCustomTLSFirstByte` is false.
pub const FRP_TLS_HEAD_BYTE: u8 = 0x17;
/// First byte of a genuine TLS handshake record.
pub const TLS_HANDSHAKE_BYTE: u8 = 0x16;
/// How long the server waits for the peer to send its first byte.
pub const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(5);

/// A stream whose reader first yields a peeked byte that was consumed already.
pub struct PrefixedStream<S> {
    inner: S,
    prefix: Vec<u8>,
    pos: usize,
}

impl<S> PrefixedStream<S> {
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            pos: 0,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let n = (this.prefix.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.prefix[this.pos..this.pos + n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// A control-port connection after optional TLS negotiation.
pub enum ServerStream<S> {
    Plain(PrefixedStream<S>),
    Tls(Box<tokio_rustls::server::TlsStream<PrefixedStream<S>>>),
}

impl<S> ServerStream<S> {
    pub fn is_tls(&self) -> bool {
        matches!(self, ServerStream::Tls(_))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ServerStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ServerStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            ServerStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ServerStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ServerStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            ServerStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ServerStream::Plain(s) => Pin::new(s).poll_flush(cx),
            ServerStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ServerStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            ServerStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Outcome of inspecting the first byte of a control connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstByte {
    /// frp's obfuscated TLS marker; a TLS handshake follows on the raw stream.
    FrpTls,
    /// A genuine TLS ClientHello whose first byte must be replayed.
    RealTls,
    /// Plaintext frp framing.
    Plain,
}

/// Classifies a peeked first byte the way upstream frp does.
pub fn classify_first_byte(byte: u8) -> FirstByte {
    match byte {
        FRP_TLS_HEAD_BYTE => FirstByte::FrpTls,
        TLS_HANDSHAKE_BYTE => FirstByte::RealTls,
        _ => FirstByte::Plain,
    }
}

/// Performs TLS negotiation on a freshly accepted control connection.
pub async fn accept_server_stream(
    mut sock: TcpStream,
    tls: Option<Arc<rustls::ServerConfig>>,
    force_tls: bool,
) -> Result<ServerStream<TcpStream>> {
    let mut first = [0u8; 1];
    let n = tokio::time::timeout(FIRST_BYTE_TIMEOUT, sock.read(&mut first))
        .await
        .map_err(|_| anyhow!("timed out waiting for the first byte of a connection"))?
        .context("read first byte of control connection")?;
    if n == 0 {
        return Err(anyhow!("connection closed before the first byte"));
    }

    match classify_first_byte(first[0]) {
        FirstByte::FrpTls | FirstByte::RealTls => {
            let Some(tls) = tls else {
                return Err(anyhow!("received a TLS connection while TLS is disabled"));
            };
            let prefix = if first[0] == TLS_HANDSHAKE_BYTE {
                vec![TLS_HANDSHAKE_BYTE]
            } else {
                Vec::new()
            };
            let acceptor = TlsAcceptor::from(tls);
            let stream = acceptor
                .accept(PrefixedStream::new(sock, prefix))
                .await
                .context("complete TLS handshake")?;
            Ok(ServerStream::Tls(Box::new(stream)))
        }
        FirstByte::Plain => {
            if force_tls {
                return Err(anyhow!(
                    "non-TLS connection received on a TlsOnly server"
                ));
            }
            Ok(ServerStream::Plain(PrefixedStream::new(
                sock,
                vec![first[0]],
            )))
        }
    }
}

/// Loads a certificate chain from a PEM file.
pub fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("open certificate file {path}"))?;
    let mut reader = std::io::BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parse certificate file {path}"))?;
    if certs.is_empty() {
        return Err(anyhow!("no certificate found in {path}"));
    }
    Ok(certs)
}

/// Loads a private key from a PEM file.
pub fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("open private key file {path}"))?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parse private key file {path}"))?
        .ok_or_else(|| anyhow!("no private key found in {path}"))
}

/// Generates a self-signed certificate, matching upstream behaviour when no
/// certificate is configured.
pub fn generate_self_signed() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let names = vec!["localhost".to_string(), "frp".to_string()];
    let certified = rcgen::generate_simple_self_signed(names)
        .context("generate self-signed certificate")?;
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()),
    );
    Ok((vec![cert], key))
}

/// Builds a rustls server configuration from frp's `transport.tls` settings.
pub fn build_server_tls_config(tls: &TlsServerConfig) -> Result<Arc<rustls::ServerConfig>> {
    let (certs, key) = if tls.cert_file.is_empty() || tls.key_file.is_empty() {
        generate_self_signed()?
    } else {
        (
            load_certs(&tls.cert_file)?,
            load_private_key(&tls.key_file)?,
        )
    };

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("select TLS protocol versions")?;

    let config = if tls.trusted_ca_file.is_empty() {
        builder.with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        for cert in load_certs(&tls.trusted_ca_file)? {
            roots.add(cert).context("add trusted CA certificate")?;
        }
        let verifier =
            rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .context("build client certificate verifier")?;
        builder.with_client_cert_verifier(verifier)
    };

    let config = config
        .with_single_cert(certs, key)
        .context("install server certificate")?;
    Ok(Arc::new(config))
}

/// A stream the server hands to a control or work connection handler.
///
/// With `transport.tcpMux` enabled — the default on both sides — every logical
/// connection arrives as a yamux stream on a single accepted socket, so the
/// server deals with two shapes of stream behind one type.
pub enum ServerConn {
    /// A direct connection, optionally wrapped in TLS.
    Direct(Box<ServerStream<TcpStream>>),
    /// A stream of a yamux session opened by the client.
    Mux(crate::yamux::Stream),
}

impl ServerConn {
    /// Indicates the wire encoding in use, for logging.
    pub fn kind(&self) -> &'static str {
        match self {
            ServerConn::Direct(stream) => {
                if stream.is_tls() {
                    "tls"
                } else {
                    "tcp"
                }
            }
            ServerConn::Mux(_) => "mux",
        }
    }
}

impl AsyncRead for ServerConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ServerConn::Direct(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
            ServerConn::Mux(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ServerConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ServerConn::Direct(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
            ServerConn::Mux(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ServerConn::Direct(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
            ServerConn::Mux(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ServerConn::Direct(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
            ServerConn::Mux(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn can_generate_tls() -> bool {
        generate_self_signed().is_ok()
    }

    #[test]
    fn first_byte_classification() {
        assert_eq!(classify_first_byte(0x17), FirstByte::FrpTls);
        assert_eq!(classify_first_byte(0x16), FirstByte::RealTls);
        assert_eq!(classify_first_byte(b'o'), FirstByte::Plain);
        assert_eq!(classify_first_byte(0x00), FirstByte::Plain);
    }

    #[tokio::test]
    async fn prefixed_stream_replays_bytes() {
        let (a, mut b) = tokio::io::duplex(64);
        b.write_all(b"world").await.unwrap();
        b.shutdown().await.unwrap();
        let mut stream = PrefixedStream::new(a, b"hello ".to_vec());
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello world");
    }

    #[tokio::test]
    async fn plain_connection_round_trips_without_tls() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            let mut sock = TcpStream::connect(addr).await.unwrap();
            sock.write_all(b"plain-payload").await.unwrap();
            sock.shutdown().await.unwrap();
        });

        let (sock, _) = listener.accept().await.unwrap();
        let stream = accept_server_stream(sock, None, false).await.unwrap();
        assert!(!stream.is_tls());

        let mut stream = stream;
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"plain-payload");
        client.await.unwrap();
    }

    #[tokio::test]
    async fn plain_connection_rejected_when_tls_is_forced() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let mut sock = TcpStream::connect(addr).await.unwrap();
            let _ = sock.write_all(b"x").await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let (sock, _) = listener.accept().await.unwrap();
        let err = accept_server_stream(sock, None, true).await;
        assert!(err.is_err());
    }

    #[test]
    fn self_signed_server_config_builds() {
        let tls = TlsServerConfig::default();
        match build_server_tls_config(&tls) {
            Ok(_) => {}
            Err(e) => panic!("self-signed TLS config failed: {e}"),
        }
        assert!(can_generate_tls());
    }
}
