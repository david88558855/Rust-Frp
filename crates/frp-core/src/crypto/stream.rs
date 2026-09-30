//! Async stream adapters mirroring `golib/io`.
//!
//! frp applies the wrappers in this order (see `client/proxy.BaseProxy.wrapWorkConn`):
//!
//! ```text
//! plain conn
//!   -> EncryptedStream   (useEncryption)
//!   -> CompressedStream  (useCompression)
//! ```
//!
//! so compression is the *outer* layer: bytes are snappy-framed first and the
//! resulting byte stream is then AES-128-CFB encrypted.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::cfb::{derive_key, Cfb128};
use super::snappy::{FramedDecoder, FramedEncoder};

const IV_LEN: usize = 16;
const READ_CHUNK: usize = 16 * 1024;

fn write_zero() -> io::Error {
    io::Error::new(io::ErrorKind::WriteZero, "failed to write whole buffer")
}

fn premature_eof(what: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        format!("unexpected eof while reading {what}"),
    )
}

/// `useEncryption` wrapper: prepends a random IV on the first write and consumes
/// the peer's IV on the first read.
pub struct EncryptedStream<S> {
    inner: S,
    key: [u8; 16],
    enc: Option<Cfb128>,
    dec: Option<Cfb128>,
    iv_out: [u8; IV_LEN],
    iv_out_written: usize,
    iv_in: [u8; IV_LEN],
    iv_in_read: usize,
    /// Ciphertext produced by a `poll_write` that the peer has not fully taken.
    pending: Vec<u8>,
    /// Decrypted bytes that the caller's `ReadBuf` had no room for yet.
    plain: Vec<u8>,
    plain_pos: usize,
}

impl<S> EncryptedStream<S> {
    /// `token` is the raw `auth.token`; upstream uses it verbatim as the KDF input.
    pub fn new(inner: S, token: &[u8]) -> Self {
        let mut iv_out = [0u8; IV_LEN];
        rand::thread_rng().fill_bytes(&mut iv_out);
        Self {
            inner,
            key: derive_key(token),
            enc: None,
            dec: None,
            iv_out,
            iv_out_written: 0,
            iv_in: [0u8; IV_LEN],
            iv_in_read: 0,
            pending: Vec::new(),
            plain: Vec::new(),
            plain_pos: 0,
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            // Hand out anything already decrypted and not yet delivered.
            if this.plain_pos < this.plain.len() {
                let n = (this.plain.len() - this.plain_pos).min(buf.remaining());
                buf.put_slice(&this.plain[this.plain_pos..this.plain_pos + n]);
                this.plain_pos += n;
                if this.plain_pos == this.plain.len() {
                    this.plain.clear();
                    this.plain_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            while this.iv_in_read < IV_LEN {
                let start = this.iv_in_read;
                let mut rb = ReadBuf::new(&mut this.iv_in[start..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(premature_eof("stream iv")));
                        }
                        this.iv_in_read += n;
                    }
                }
            }
            if this.dec.is_none() {
                this.dec = Some(Cfb128::new(&this.key, &this.iv_in));
            }

            let mut tmp = [0u8; READ_CHUNK];
            let mut rb = ReadBuf::new(&mut tmp);
            match ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb)) {
                Ok(()) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
            let n = rb.filled().len();
            if n == 0 {
                return Poll::Ready(Ok(()));
            }
            if let Some(dec) = this.dec.as_mut() {
                dec.decrypt(&mut tmp[..n]);
            }
            this.plain.extend_from_slice(&tmp[..n]);
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        while this.iv_out_written < IV_LEN {
            let start = this.iv_out_written;
            let n = match ready!(Pin::new(&mut this.inner).poll_write(cx, &this.iv_out[start..])) {
                Ok(n) => n,
                Err(e) => return Poll::Ready(Err(e)),
            };
            if n == 0 {
                return Poll::Ready(Err(write_zero()));
            }
            this.iv_out_written += n;
        }
        if this.enc.is_none() {
            this.enc = Some(Cfb128::new(&this.key, &this.iv_out));
        }

        // Flush leftovers from a previous partial write before encrypting more,
        // otherwise the cipher state would advance past bytes that are dropped.
        while !this.pending.is_empty() {
            let n = match ready!(Pin::new(&mut this.inner).poll_write(cx, &this.pending)) {
                Ok(n) => n,
                Err(e) => return Poll::Ready(Err(e)),
            };
            if n == 0 {
                return Poll::Ready(Err(write_zero()));
            }
            this.pending.drain(..n);
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        this.pending.clear();
        this.pending.extend_from_slice(buf);
        if let Some(enc) = this.enc.as_mut() {
            enc.encrypt(&mut this.pending);
        }

        let n = match ready!(Pin::new(&mut this.inner).poll_write(cx, &this.pending)) {
            Ok(n) => n,
            Err(e) => return Poll::Ready(Err(e)),
        };
        if n == 0 {
            return Poll::Ready(Err(write_zero()));
        }
        this.pending.drain(..n);

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.pending.is_empty() {
            let n = match ready!(Pin::new(&mut this.inner).poll_write(cx, &this.pending)) {
                Ok(n) => n,
                Err(e) => return Poll::Ready(Err(e)),
            };
            if n == 0 {
                return Poll::Ready(Err(write_zero()));
            }
            this.pending.drain(..n);
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.pending.is_empty() {
            let n = match ready!(Pin::new(&mut this.inner).poll_write(cx, &this.pending)) {
                Ok(n) => n,
                Err(e) => return Poll::Ready(Err(e)),
            };
            if n == 0 {
                return Poll::Ready(Err(write_zero()));
            }
            this.pending.drain(..n);
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// `useCompression` wrapper using the Snappy framed format.
pub struct CompressedStream<S> {
    inner: S,
    encoder: FramedEncoder,
    decoder: FramedDecoder,
    pending: Vec<u8>,
}

impl<S> CompressedStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            encoder: FramedEncoder::new(),
            decoder: FramedDecoder::new(),
            pending: Vec::new(),
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CompressedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            let available = this.decoder.pending().len();
            if available > 0 {
                let n = available.min(buf.remaining());
                buf.put_slice(&this.decoder.pending()[..n]);
                this.decoder.advance(n);
                return Poll::Ready(Ok(()));
            }

            let mut tmp = [0u8; READ_CHUNK];
            let mut rb = ReadBuf::new(&mut tmp);
            match ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb)) {
                Ok(()) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
            let n = rb.filled().len();
            if n == 0 {
                return Poll::Ready(Ok(()));
            }
            if let Err(e) = this.decoder.push(&tmp[..n]) {
                return Poll::Ready(Err(e));
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CompressedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        while !this.pending.is_empty() {
            let n = match ready!(Pin::new(&mut this.inner).poll_write(cx, &this.pending)) {
                Ok(n) => n,
                Err(e) => return Poll::Ready(Err(e)),
            };
            if n == 0 {
                return Poll::Ready(Err(write_zero()));
            }
            this.pending.drain(..n);
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        this.pending.clear();
        this.encoder.encode(buf, &mut this.pending);

        let n = match ready!(Pin::new(&mut this.inner).poll_write(cx, &this.pending)) {
            Ok(n) => n,
            Err(e) => return Poll::Ready(Err(e)),
        };
        if n == 0 {
            return Poll::Ready(Err(write_zero()));
        }
        this.pending.drain(..n);

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.pending.is_empty() {
            let n = match ready!(Pin::new(&mut this.inner).poll_write(cx, &this.pending)) {
                Ok(n) => n,
                Err(e) => return Poll::Ready(Err(e)),
            };
            if n == 0 {
                return Poll::Ready(Err(write_zero()));
            }
            this.pending.drain(..n);
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.pending.is_empty() {
            let n = match ready!(Pin::new(&mut this.inner).poll_write(cx, &this.pending)) {
                Ok(n) => n,
                Err(e) => return Poll::Ready(Err(e)),
            };
            if n == 0 {
                return Poll::Ready(Err(write_zero()));
            }
            this.pending.drain(..n);
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Concrete wrapper stack for a work connection, avoiding trait objects so the
/// whole chain stays monomorphised and `Unpin`.
pub enum WorkConnStream<S> {
    /// No encryption, no compression.
    Plain(S),
    /// `useEncryption` only.
    Encrypted(EncryptedStream<S>),
    /// `useCompression` only.
    Compressed(CompressedStream<S>),
    /// Both, in the upstream order: compress(encrypt(conn)).
    EncryptedCompressed(CompressedStream<EncryptedStream<S>>),
}

impl<S> WorkConnStream<S> {
    /// Applies the same wrapping order as upstream frp.
    pub fn new(conn: S, token: &[u8], use_encryption: bool, use_compression: bool) -> Self {
        match (use_encryption, use_compression) {
            (false, false) => WorkConnStream::Plain(conn),
            (true, false) => WorkConnStream::Encrypted(EncryptedStream::new(conn, token)),
            (false, true) => WorkConnStream::Compressed(CompressedStream::new(conn)),
            (true, true) => WorkConnStream::EncryptedCompressed(CompressedStream::new(
                EncryptedStream::new(conn, token),
            )),
        }
    }

    pub fn uses_encryption(&self) -> bool {
        matches!(
            self,
            WorkConnStream::Encrypted(_) | WorkConnStream::EncryptedCompressed(_)
        )
    }

    pub fn uses_compression(&self) -> bool {
        matches!(
            self,
            WorkConnStream::Compressed(_) | WorkConnStream::EncryptedCompressed(_)
        )
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WorkConnStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            WorkConnStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            WorkConnStream::Encrypted(s) => Pin::new(s).poll_read(cx, buf),
            WorkConnStream::Compressed(s) => Pin::new(s).poll_read(cx, buf),
            WorkConnStream::EncryptedCompressed(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WorkConnStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            WorkConnStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            WorkConnStream::Encrypted(s) => Pin::new(s).poll_write(cx, buf),
            WorkConnStream::Compressed(s) => Pin::new(s).poll_write(cx, buf),
            WorkConnStream::EncryptedCompressed(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            WorkConnStream::Plain(s) => Pin::new(s).poll_flush(cx),
            WorkConnStream::Encrypted(s) => Pin::new(s).poll_flush(cx),
            WorkConnStream::Compressed(s) => Pin::new(s).poll_flush(cx),
            WorkConnStream::EncryptedCompressed(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            WorkConnStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            WorkConnStream::Encrypted(s) => Pin::new(s).poll_shutdown(cx),
            WorkConnStream::Compressed(s) => Pin::new(s).poll_shutdown(cx),
            WorkConnStream::EncryptedCompressed(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn encrypted_roundtrip() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut client = EncryptedStream::new(a, b"token");
        let mut server = EncryptedStream::new(b, b"token");

        let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();
        });

        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn compressed_roundtrip() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut client = CompressedStream::new(a);
        let mut server = CompressedStream::new(b);

        let payload = b"rust-frp snappy framed compression payload".repeat(500);
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();
        });

        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn encryption_then_compression_matches_upstream_order() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut client = CompressedStream::new(EncryptedStream::new(a, b"secret"));
        let mut server = CompressedStream::new(EncryptedStream::new(b, b"secret"));

        let payload = b"frp interop payload ".repeat(1000);
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();
        });

        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, expected);
    }
}
