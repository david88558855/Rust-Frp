//! Control message framing.
//!
//! Upstream frp serialises every control message as:
//!
//! ```text
//! +--------+----------------------+------------------+
//! | type   | length (i64, BE)     | json payload     |
//! | 1 byte | 8 bytes              | `length` bytes   |
//! +--------+----------------------+------------------+
//! ```
//!
//! The default maximum payload accepted by the Go implementation is 10240
//! bytes (`golib/msg/json.defaultMaxMsgLength`); frp never raises it, so a
//! faithful port must reject anything larger.

use std::io;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::msg::{Message, MsgType};

/// Maximum accepted payload length, matching `golib/msg/json`.
pub const MAX_MSG_LENGTH: i64 = 10240;

/// Size of the fixed frame header: one type byte plus a big endian i64.
pub const HEADER_LEN: usize = 9;

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("message length {0} exceeds the limit")]
    TooLong(i64),
    #[error("invalid message length {0}")]
    BadLength(i64),
    #[error("unknown message type byte: 0x{0:02x}")]
    UnknownType(u8),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Serialises a message into a raw frame (header included).
pub fn pack(msg: &Message) -> Result<Vec<u8>, CodecError> {
    let body = msg.encode_json()?;
    let mut frame = Vec::with_capacity(HEADER_LEN + body.len());
    frame.push(msg.msg_type().to_byte());
    frame.extend_from_slice(&(body.len() as i64).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Parses a frame previously produced by [`pack`].
pub fn unpack(frame: &[u8]) -> Result<Message, CodecError> {
    if frame.len() < HEADER_LEN {
        return Err(CodecError::BadLength(frame.len() as i64));
    }
    let type_byte = frame[0];
    if MsgType::from_byte(type_byte).is_none() {
        return Err(CodecError::UnknownType(type_byte));
    }
    let mut len = [0u8; 8];
    len.copy_from_slice(&frame[1..HEADER_LEN]);
    let length = i64::from_be_bytes(len);
    if length < 0 {
        return Err(CodecError::BadLength(length));
    }
    if length > MAX_MSG_LENGTH {
        return Err(CodecError::TooLong(length));
    }
    let body = &frame[HEADER_LEN..];
    if body.len() as i64 != length {
        return Err(CodecError::BadLength(body.len() as i64));
    }
    Ok(Message::decode_json(type_byte, body)?)
}

/// Reads a single control message from `r`.
pub async fn read_msg<R>(r: &mut R) -> Result<Message, CodecError>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut header = [0u8; HEADER_LEN];
    r.read_exact(&mut header).await?;

    let type_byte = header[0];
    if MsgType::from_byte(type_byte).is_none() {
        return Err(CodecError::UnknownType(type_byte));
    }

    let mut len = [0u8; 8];
    len.copy_from_slice(&header[1..HEADER_LEN]);
    let length = i64::from_be_bytes(len);

    if length > MAX_MSG_LENGTH {
        return Err(CodecError::TooLong(length));
    }
    if length < 0 {
        return Err(CodecError::BadLength(length));
    }

    let mut buf = vec![0u8; length as usize];
    r.read_exact(&mut buf).await?;
    Ok(Message::decode_json(type_byte, &buf)?)
}

/// Writes a single control message to `w`.
pub async fn write_msg<W>(w: &mut W, msg: &Message) -> Result<(), CodecError>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let frame = pack(msg)?;
    w.write_all(&frame).await?;
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::{ty, LoginResp};

    #[test]
    fn frame_layout_is_type_then_be_length() {
        let msg = Message::LoginResp(LoginResp {
            version: "0.71.0".into(),
            run_id: "abc".into(),
            error: String::new(),
        });
        let frame = pack(&msg).unwrap();
        assert_eq!(frame[0], ty::LOGIN_RESP);
        let mut len = [0u8; 8];
        len.copy_from_slice(&frame[1..9]);
        assert_eq!(i64::from_be_bytes(len) as usize, frame.len() - 9);
        assert_eq!(&frame[9..], br#"{"version":"0.71.0","run_id":"abc","error":""}"#);
    }

    #[test]
    fn roundtrip_unpack() {
        let msg = Message::Ping(crate::msg::Ping {
            privilege_key: "k".into(),
            timestamp: 42,
        });
        let frame = pack(&msg).unwrap();
        assert_eq!(unpack(&frame).unwrap(), msg);
    }

    #[test]
    fn rejects_oversized_payload() {
        let mut frame = vec![ty::PING];
        frame.extend_from_slice(&(MAX_MSG_LENGTH + 1).to_be_bytes());
        assert!(matches!(unpack(&frame), Err(CodecError::TooLong(_))));
    }

    #[test]
    fn rejects_unknown_type() {
        let mut frame = vec![b'Z'];
        frame.extend_from_slice(&0i64.to_be_bytes());
        assert!(matches!(unpack(&frame), Err(CodecError::UnknownType(b'Z'))));
    }

    #[tokio::test]
    async fn async_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let msg = Message::ReqWorkConn(crate::msg::ReqWorkConn {});
        write_msg(&mut a, &msg).await.unwrap();
        let got = read_msg(&mut b).await.unwrap();
        assert_eq!(got, msg);
    }
}
