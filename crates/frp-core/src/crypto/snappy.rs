//! Snappy *framed* stream format, as produced by `github.com/golang/snappy`.
//!
//! frp wraps work connections with `snappy.NewReader` / `snappy.NewWriter`, so
//! interoperating requires the framing format rather than the raw block format:
//!
//! ```text
//! stream identifier : ff 06 00 00 's' 'N' 'a' 'P' 'p' 'Y'
//! chunk             : type:u8 | length:u24 LE | payload
//!   0x00 compressed data   -> crc32c(uncompressed):u32 LE | block data
//!   0x01 uncompressed data -> crc32c(uncompressed):u32 LE | raw data
//!   0x80..=0xfe skippable
//!   0x02..=0x7f reserved unskippable (treated as corruption)
//! ```
//!
//! The checksum is the CRC-32C (Castagnoli) of the *uncompressed* data, masked
//! with Go's `crc` helper: `rotate_right(15) + 0xa282ead8`.

use std::io;

const MAGIC: &[u8] = b"\xff\x06\x00\x00sNaPpY";
const MAX_BLOCK_SIZE: usize = 65536;

/// Masked CRC-32C used by golang/snappy framed chunks.
pub fn chunk_crc(data: &[u8]) -> u32 {
    crc32c::crc32c(data)
        .rotate_right(15)
        .wrapping_add(0xa282_ead8)
}

fn corrupt(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Incremental framed encoder.
#[derive(Debug, Default)]
pub struct FramedEncoder {
    wrote_stream_id: bool,
}

impl FramedEncoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends the framed representation of `input` to `out`.
    pub fn encode(&mut self, input: &[u8], out: &mut Vec<u8>) {
        if !self.wrote_stream_id {
            out.extend_from_slice(MAGIC);
            self.wrote_stream_id = true;
        }
        if input.is_empty() {
            return;
        }
        for chunk in input.chunks(MAX_BLOCK_SIZE) {
            let mut encoder = snap::raw::Encoder::new();
            let compressed = encoder.compress_vec(chunk).ok();
            match compressed {
                Some(body) if body.len() < chunk.len() => {
                    out.push(0x00);
                    write_u24(out, (body.len() + 4) as u32);
                    out.extend_from_slice(&chunk_crc(chunk).to_le_bytes());
                    out.extend_from_slice(&body);
                }
                _ => {
                    out.push(0x01);
                    write_u24(out, (chunk.len() + 4) as u32);
                    out.extend_from_slice(&chunk_crc(chunk).to_le_bytes());
                    out.extend_from_slice(chunk);
                }
            }
        }
    }
}

fn write_u24(out: &mut Vec<u8>, value: u32) {
    let b = value.to_le_bytes();
    out.extend_from_slice(&b[..3]);
}

/// Incremental framed decoder.
#[derive(Debug, Default)]
pub struct FramedDecoder {
    inbuf: Vec<u8>,
    decoded: Vec<u8>,
    delivered: usize,
}

impl FramedDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds raw bytes from the wire; complete chunks are decoded eagerly.
    pub fn push(&mut self, data: &[u8]) -> io::Result<()> {
        if self.delivered > 0 {
            self.decoded.drain(..self.delivered);
            self.delivered = 0;
        }
        self.inbuf.extend_from_slice(data);
        self.decode_available()
    }

    fn decode_available(&mut self) -> io::Result<()> {
        loop {
            if self.inbuf.len() < 4 {
                return Ok(());
            }
            let chunk_type = self.inbuf[0];
            let len = u32::from_le_bytes([self.inbuf[1], self.inbuf[2], self.inbuf[3], 0]) as usize;
            if self.inbuf.len() < 4 + len {
                return Ok(());
            }
            let payload: Vec<u8> = self.inbuf[4..4 + len].to_vec();
            self.inbuf.drain(..4 + len);

            match chunk_type {
                0x00 | 0x01 => {
                    if payload.len() < 4 {
                        return Err(corrupt("snappy chunk too short"));
                    }
                    let want = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    let body = &payload[4..];
                    let data = if chunk_type == 0x00 {
                        snap::raw::Decoder::new()
                            .decompress_vec(body)
                            .map_err(|_| corrupt("snappy block decode failed"))?
                    } else {
                        body.to_vec()
                    };
                    if chunk_crc(&data) != want {
                        return Err(corrupt("snappy chunk checksum mismatch"));
                    }
                    self.decoded.extend_from_slice(&data);
                }
                0x02..=0x7f => return Err(corrupt("unsupported unskippable snappy chunk")),
                _ => { /* 0x80..=0xfe skippable, 0xff stream identifier */ }
            }
        }
    }

    /// Bytes decoded but not yet consumed by the reader.
    pub fn pending(&self) -> &[u8] {
        &self.decoded[self.delivered..]
    }

    pub fn advance(&mut self, n: usize) {
        self.delivered = (self.delivered + n).min(self.decoded.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_masking_matches_go() {
        let data = b"hello world";
        let raw = crc32c::crc32c(data);
        assert_eq!(
            chunk_crc(data),
            raw.rotate_right(15).wrapping_add(0xa282_ead8)
        );
    }

    #[test]
    fn roundtrip_small_and_large() {
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).collect();
        let mut encoder = FramedEncoder::new();
        let mut wire = Vec::new();
        for part in payload.chunks(9973) {
            encoder.encode(part, &mut wire);
        }
        assert_eq!(&wire[..10], MAGIC);

        let mut decoder = FramedDecoder::new();
        let mut out = Vec::new();
        for part in wire.chunks(1_331) {
            decoder.push(part).unwrap();
            out.extend_from_slice(decoder.pending());
            decoder.advance(decoder.pending().len());
        }
        assert_eq!(out, payload);
    }

    #[test]
    fn rejects_corrupted_checksum() {
        let mut encoder = FramedEncoder::new();
        let mut wire = Vec::new();
        encoder.encode(b"payload", &mut wire);
        let last = wire.len() - 1;
        wire[last] ^= 0xff;
        let mut decoder = FramedDecoder::new();
        assert!(decoder.push(&wire).is_err());
    }
}
