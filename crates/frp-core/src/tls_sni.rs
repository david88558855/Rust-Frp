//! TLS ClientHello peeking for the `https` virtual host port.
//!
//! Upstream frps does *not* terminate TLS on `vhostHTTPSPort`. It reads the
//! ClientHello, extracts the SNI server name, routes on it and then forwards the
//! still-encrypted byte stream to the client's local service, so the TLS
//! handshake happens end to end between the browser and the backend.
//!
//! Reproducing that requires reading exactly the ClientHello bytes from the
//! socket — no more — so the rest of the handshake can be replayed to the peer.
//! [`peek_client_hello`] therefore reads record by record, never buffering past
//! the end of the handshake message.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

const RECORD_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXTENSION_SERVER_NAME: u16 = 0x0000;
const NAME_TYPE_HOST_NAME: u8 = 0x00;

/// Refuse absurd lengths early; a real ClientHello is far smaller.
const MAX_HELLO_SIZE: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum SniError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("not a TLS handshake record: 0x{0:02x}")]
    NotHandshakeRecord(u8),
    #[error("not a ClientHello handshake: 0x{0:02x}")]
    NotClientHello(u8),
    #[error("malformed ClientHello")]
    Malformed,
    #[error("ClientHello exceeds {MAX_HELLO_SIZE} bytes")]
    TooLarge,
}

/// The bytes consumed while peeking, together with the SNI name if present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeekedHello {
    /// SNI server name; `None` when the client did not send one.
    pub server_name: Option<String>,
    /// Everything read from the socket, to be replayed to the peer verbatim.
    pub prefix: Vec<u8>,
}

/// Reads a TLS ClientHello from `stream`, consuming only its bytes.
pub async fn peek_client_hello<S>(stream: &mut S) -> Result<PeekedHello, SniError>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut prefix = Vec::with_capacity(517);
    let mut handshake: Vec<u8> = Vec::with_capacity(512);
    let mut handshake_len: Option<usize> = None;

    loop {
        // Records may split the handshake message, so keep reading until the
        // announced handshake length has been captured.
        if let Some(len) = handshake_len {
            if handshake.len() >= len {
                break;
            }
        }

        let mut header = [0u8; 5];
        stream.read_exact(&mut header).await?;
        prefix.extend_from_slice(&header);

        if header[0] != RECORD_HANDSHAKE {
            return Err(SniError::NotHandshakeRecord(header[0]));
        }
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if prefix.len() + record_len > MAX_HELLO_SIZE {
            return Err(SniError::TooLarge);
        }

        let mut payload = vec![0u8; record_len];
        stream.read_exact(&mut payload).await?;
        prefix.extend_from_slice(&payload);
        handshake.extend_from_slice(&payload);

        if handshake_len.is_none() {
            if handshake.len() < 4 {
                continue;
            }
            if handshake[0] != HANDSHAKE_CLIENT_HELLO {
                return Err(SniError::NotClientHello(handshake[0]));
            }
            let body_len = u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
            if body_len > MAX_HELLO_SIZE {
                return Err(SniError::TooLarge);
            }
            // Track the total length so the loop condition matches what has
            // actually been buffered, header included.
            handshake_len = Some(body_len + 4);
        }
    }

    let total = handshake_len.ok_or(SniError::Malformed)?;
    let body_len = total - 4;
    let body = &handshake[4..4 + body_len];
    let server_name = parse_server_name(body)?;
    Ok(PeekedHello {
        server_name,
        prefix,
    })
}

/// Extracts the SNI host name from a ClientHello body (without the handshake
/// header).
pub fn parse_server_name(body: &[u8]) -> Result<Option<String>, SniError> {
    let mut cursor = Cursor::new(body);

    cursor.skip(2)?; // legacy_version
    cursor.skip(32)?; // random

    let session_id_len = cursor.u8()? as usize;
    cursor.skip(session_id_len)?;

    let cipher_suites_len = cursor.u16()? as usize;
    cursor.skip(cipher_suites_len)?;

    let compression_len = cursor.u8()? as usize;
    cursor.skip(compression_len)?;

    // Extensions are optional in theory; a modern client always sends them.
    if cursor.remaining() < 2 {
        return Ok(None);
    }
    let extensions_len = cursor.u16()? as usize;
    let extensions = cursor.take(extensions_len)?;

    let mut ext = Cursor::new(extensions);
    while ext.remaining() >= 4 {
        let ext_type = ext.u16()?;
        let ext_len = ext.u16()? as usize;
        let ext_data = ext.take(ext_len)?;
        if ext_type == EXTENSION_SERVER_NAME {
            return parse_server_name_list(ext_data);
        }
    }
    Ok(None)
}

fn parse_server_name_list(data: &[u8]) -> Result<Option<String>, SniError> {
    let mut cursor = Cursor::new(data);
    let list_len = cursor.u16()? as usize;
    let list = cursor.take(list_len)?;

    let mut entry = Cursor::new(list);
    while entry.remaining() >= 3 {
        let name_type = entry.u8()?;
        let name_len = entry.u16()? as usize;
        let name = entry.take(name_len)?;
        if name_type == NAME_TYPE_HOST_NAME {
            let host = std::str::from_utf8(name)
                .map_err(|_| SniError::Malformed)?
                .to_ascii_lowercase();
            if host.is_empty() {
                return Ok(None);
            }
            return Ok(Some(host));
        }
    }
    Ok(None)
}

/// Minimal bounds-checked reader over the handshake bytes.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn u8(&mut self) -> Result<u8, SniError> {
        if self.remaining() < 1 {
            return Err(SniError::Malformed);
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, SniError> {
        if self.remaining() < 2 {
            return Err(SniError::Malformed);
        }
        let value = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(value)
    }

    fn skip(&mut self, len: usize) -> Result<(), SniError> {
        if self.remaining() < len {
            return Err(SniError::Malformed);
        }
        self.pos += len;
        Ok(())
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], SniError> {
        if self.remaining() < len {
            return Err(SniError::Malformed);
        }
        let out = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    fn client_config() -> Arc<ClientConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Arc::new(
            ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        )
    }

    /// Captures a genuine ClientHello produced by rustls.
    async fn real_client_hello(host: &str) -> Vec<u8> {
        let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let connector = TlsConnector::from(client_config());
        let name = ServerName::try_from(host.to_string()).unwrap();
        tokio::spawn(async move {
            // The handshake never completes; we only need the ClientHello.
            let _ = connector.connect(name, client_side).await;
        });

        let mut buf = vec![0u8; 4096];
        let n = server_side.read(&mut buf).await.unwrap();
        buf.truncate(n);
        buf
    }

    #[tokio::test]
    async fn extracts_sni_from_a_real_client_hello() {
        let hello = real_client_hello("demo.example.com").await;
        let mut reader = hello.as_slice();
        let peeked = peek_client_hello(&mut reader).await.unwrap();
        assert_eq!(peeked.server_name.as_deref(), Some("demo.example.com"));
        assert_eq!(peeked.prefix, hello, "every peeked byte must be replayed");
    }

    #[tokio::test]
    async fn sni_is_lowercased() {
        let hello = real_client_hello("MiXeD.Example.COM").await;
        let mut reader = hello.as_slice();
        let peeked = peek_client_hello(&mut reader).await.unwrap();
        assert_eq!(peeked.server_name.as_deref(), Some("mixed.example.com"));
    }

    #[tokio::test]
    async fn does_not_consume_bytes_after_the_client_hello() {
        let hello = real_client_hello("a.example.com").await;
        let trailer = b"APPLICATION-DATA";
        let mut stream = hello.clone();
        stream.extend_from_slice(trailer);

        let mut reader = stream.as_slice();
        let peeked = peek_client_hello(&mut reader).await.unwrap();
        assert_eq!(peeked.prefix.len(), hello.len());
        // Anything after the ClientHello must still be readable by the caller.
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, trailer);
    }

    #[tokio::test]
    async fn rejects_non_tls_input() {
        let mut stream: &[u8] = b"GET / HTTP/1.1\r\n\r\n";
        let err = peek_client_hello(&mut stream).await.unwrap_err();
        assert!(matches!(err, SniError::NotHandshakeRecord(b'G')));
    }

    #[tokio::test]
    async fn truncated_hello_is_an_error() {
        let hello = real_client_hello("a.example.com").await;
        let truncated = &hello[..hello.len() - 5];
        let mut reader = truncated;
        assert!(peek_client_hello(&mut reader).await.is_err());
    }

    #[test]
    fn malformed_body_is_rejected() {
        assert!(parse_server_name(&[0x03, 0x03]).is_err());
        assert!(parse_server_name(&[]).is_err());
    }

    #[test]
    fn hello_without_extensions_has_no_sni() {
        // legacy_version(2) random(32) session_id(1) cipher_suites(2)
        // compression(1)
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // no session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        body.push(0x01); // one compression method
        body.push(0x00);
        assert_eq!(parse_server_name(&body).unwrap(), None);
    }
}
