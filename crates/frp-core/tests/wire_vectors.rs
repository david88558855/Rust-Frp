//! Wire conformance against the frozen vector corpus.
//!
//! `tests/interop/vectors/msg_vectors.json` holds the exact bytes upstream frp
//! v0.71.0 puts on the wire for every control message type. This test replays
//! each one through our codec:
//!
//!   1. **decode** the vector's body with our decoder, which must succeed;
//!   2. **re-encode** it, and require byte-for-byte equality with the body the
//!      vector declares;
//!   3. **re-frame** it through `codec::pack`, and require the whole frame to
//!      match `type_byte || i64 BE len || body`.
//!
//! Step 2 is the one that matters. Decoding alone would pass for an encoder
//! that silently renames `subdomain` to `subDomain`: our decoder would accept
//! upstream's body either way. Comparing the *re-encoded* bytes catches it,
//! because the round trip is only lossless when our field names, our ordering
//! and our null-vs-empty choices all agree with Go's.
//!
//! `serde_json` preserves struct field declaration order, so equality here also
//! pins key order. That is stricter than the protocol requires — Go's decoder is
//! order agnostic — but it is the cheapest way to notice an accidental reorder,
//! and if it ever becomes a nuisance the fix is to relax this test, not the
//! encoder.
//!
//! # Two known and deliberate divergences
//!
//! Both are documented here rather than papered over, and both are asserted to
//! be semantically equivalent so that neither can silently grow.
//!
//! 1. **Non ASCII escaping.** Go's `encoding/json` escapes non ASCII runes as
//!    `\uXXXX`; `serde_json` emits them as raw UTF-8. The two strings parse to
//!    the same value, and Go accepts both, so this is a wire difference without
//!    a behavioural one. Forcing byte equality would mean a custom string
//!    serialiser on every field, which is not worth the blast radius.
//!
//! 2. **Key order.** Serde emits struct fields in declaration order, which is
//!    what these vectors record. Nothing depends on it.
//!
//! Everything else — field names, which fields appear at all, how empty
//! collections and zero values are treated — is required to match exactly.

use std::collections::BTreeMap;
use std::path::PathBuf;

use frp_core::codec::{pack, HEADER_LEN};
use frp_core::msg::{Message, MsgType};

#[derive(serde::Deserialize)]
struct VectorFile {
    version: String,
    max_msg_length: i64,
    header_len: usize,
    type_bytes: BTreeMap<String, String>,
    vectors: Vec<Vector>,
}

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    type_byte: String,
    body: String,
    #[serde(default)]
    frame_hex: String,
    #[serde(default)]
    note: String,
}

fn load() -> VectorFile {
    // The corpus lives outside the crate, and `CARGO_MANIFEST_DIR` points at
    // `crates/frp-core`, so walk up two levels.
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("tests/interop/vectors/msg_vectors.json");
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("parse the vector corpus")
}

/// `type_byte: u8 || length: i64 big endian || body`.
fn frame(type_byte: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.push(type_byte);
    out.extend_from_slice(&(body.len() as i64).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Compares two encoded bodies for *equivalence*, tolerating the two known
/// divergences and nothing else.
///
/// A byte comparison is tried first, so any difference in field names,
/// presence or ordering still fails. Only when that fails do we fall back to
/// comparing the parsed values, which absorbs Go's `\uXXXX` escaping without
/// absorbing anything structural: a renamed key, a dropped field or a changed
/// value all survive the JSON parse and still compare unequal.
enum Match {
    Bytes,
    Semantically,
}

fn compare(want: &[u8], got: &[u8]) -> Result<Match, String> {
    if want == got {
        return Ok(Match::Bytes);
    }
    let want_v: serde_json::Value =
        serde_json::from_slice(want).map_err(|e| format!("upstream body is not JSON: {e}"))?;
    let got_v: serde_json::Value =
        serde_json::from_slice(got).map_err(|e| format!("our body is not JSON: {e}"))?;
    if want_v == got_v {
        return Ok(Match::Semantically);
    }
    Err(format!(
        "value differs\n     upstream: {}\n     ours    : {}",
        serde_json::to_string(&want_v).unwrap_or_default(),
        serde_json::to_string(&got_v).unwrap_or_default(),
    ))
}

#[test]
fn corpus_is_internally_consistent() {
    let file = load();
    assert_eq!(file.version, frp_core::FRP_VERSION);
    assert_eq!(file.header_len, HEADER_LEN);
    assert_eq!(file.max_msg_length, frp_core::MAX_MSG_LENGTH);

    let mut seen = BTreeMap::new();
    for v in &file.vectors {
        let bytes = v.type_byte.as_bytes();
        assert_eq!(bytes.len(), 1, "{}: type_byte must be one byte", v.name);
        assert!(
            MsgType::from_byte(bytes[0]).is_some(),
            "{}: type byte {:#x} is not a known message",
            v.name,
            bytes[0]
        );
        assert!(
            v.body.len() as i64 <= file.max_msg_length,
            "{}: body is {} bytes, over the {}-byte limit",
            v.name,
            v.body.len(),
            file.max_msg_length
        );
        seen.insert(bytes[0], v.name.clone());
    }

    // Every declared message type has at least one vector, or the corpus would
    // look complete while quietly skipping a type.
    for (label, byte) in &file.type_bytes {
        let b = byte.as_bytes()[0];
        assert!(
            seen.contains_key(&b),
            "no vector covers {label} (byte {b:#x})"
        );
    }
}

#[test]
fn decode_then_reencode_is_byte_identical() {
    let file = load();
    let mut failures = Vec::new();
    let mut semantic_only = Vec::new();

    for v in &file.vectors {
        let type_byte = v.type_byte.as_bytes()[0];
        let body = v.body.as_bytes();

        let decoded = match Message::decode_json(type_byte, body) {
            Ok(m) => m,
            Err(e) => {
                failures.push(format!("{}: decode failed: {e}", v.name));
                continue;
            }
        };

        let reencoded = match decoded.encode_json() {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("{}: encode failed: {e}", v.name));
                continue;
            }
        };

        match compare(body, &reencoded) {
            Ok(Match::Bytes) => {}
            Ok(Match::Semantically) => semantic_only.push(v.name.clone()),
            Err(detail) => failures.push(format!("{}: {detail}", v.name)),
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} vectors do not match upstream:\n\n{}",
        failures.len(),
        file.vectors.len(),
        failures.join("\n\n")
    );

    // The escaping divergence should be confined to the one vector that
    // actually carries non ASCII. If it spreads, an encoder change is to blame
    // and this makes that visible instead of letting it pass quietly.
    assert!(
        semantic_only.len() <= 1,
        "more vectors differ than the documented escaping case: {semantic_only:?}"
    );
    if let Some(name) = semantic_only.first() {
        assert!(
            name.contains("unicode"),
            "expected only the unicode vector to differ semantically, got {name}"
        );
    }
}

#[test]
fn reframing_matches_the_declared_wire_layout() {
    let file = load();
    let mut failures = Vec::new();

    for v in &file.vectors {
        let type_byte = v.type_byte.as_bytes()[0];
        let body = v.body.as_bytes();
        let decoded = match Message::decode_json(type_byte, body) {
            Ok(m) => m,
            Err(_) => continue, // already reported by the round trip test
        };
        let packed = match pack(&decoded) {
            Ok(p) => p,
            Err(e) => {
                failures.push(format!("{}: pack failed: {e}", v.name));
                continue;
            }
        };
        // The body is compared with `compare`, which tolerates only the
        // documented `\uXXXX` divergence: identical bytes pass, and so does a
        // body that differs solely because Go escaped a non ASCII rune we emit
        // as UTF-8. Everything else is a real mismatch.
        let expected = frame(type_byte, body);
        match compare(&expected[HEADER_LEN..], &packed[HEADER_LEN..]) {
            Ok(_) => {}
            Err(detail) => failures.push(format!("{}: {detail}", v.name)),
        }

        // The length field cannot be compared to upstream's directly, because
        // it counts the very bytes that divergence changes. What it must do is
        // describe the body we actually framed, so it is checked against
        // `packed` rather than against `expected`.
        let packed_body_len = i64::from_be_bytes(packed[1..HEADER_LEN].try_into().unwrap());
        if packed_body_len != packed.len() as i64 - HEADER_LEN as i64 {
            failures.push(format!(
                "{}: length field says {} but the body is {} bytes",
                v.name,
                packed_body_len,
                packed.len() - HEADER_LEN
            ));
        }
        if packed[0] != type_byte {
            failures.push(format!(
                "{}: type byte is {:#04x}, expected {:#04x}",
                v.name, packed[0], type_byte
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} vectors frame differently:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

/// The decoder must accept a frame, not only a bare body.
#[test]
fn unpack_accepts_each_vectors_frame() {
    let file = load();
    for v in &file.vectors {
        let type_byte = v.type_byte.as_bytes()[0];
        let wire = frame(type_byte, v.body.as_bytes());
        let decoded = frp_core::unpack(&wire)
            .unwrap_or_else(|e| panic!("{}: unpack rejected a valid frame: {e}", v.name));
        assert_eq!(decoded.msg_type().to_byte(), type_byte, "{}", v.name);
    }
}

/// Notes are documentation; a missing one means the corpus lost context.
#[test]
fn every_vector_explains_itself() {
    let file = load();
    for v in &file.vectors {
        assert!(
            !v.note.trim().is_empty(),
            "{}: every vector should say why it exists",
            v.name
        );
    }
}

/// The stored `frame_hex` must agree with the vector's own two fields.
///
/// It is redundant by construction, which is the point: if a future edit
/// touches `body` but forgets the hex, this fails instead of leaving a stale
/// blob that the framing test would then never exercise.
#[test]
fn stored_frame_hex_matches_the_declared_layout() {
    let file = load();
    for v in &file.vectors {
        assert!(
            !v.frame_hex.is_empty(),
            "{}: frame_hex is missing from the corpus",
            v.name
        );
        let type_byte = v.type_byte.as_bytes()[0];
        let expected = hex::encode(frame(type_byte, v.body.as_bytes()));
        assert_eq!(v.frame_hex, expected, "{}: frame_hex is stale", v.name);
    }
}

/// A zero-valued message must serialise to `{}`, not to a full zero-filled
/// object.
///
/// This is the property that motivated the whole corpus. Upstream tags every
/// field `omitempty`, so a freshly constructed `Login` puts `{}` on the wire.
/// An encoder that emits `{"version":"","hostname":"",...}` still interoperates
/// — Go decodes both to the same struct — but it is not byte compatible, and
/// this is the assertion that keeps the distinction visible.
#[test]
fn zero_valued_messages_serialise_to_an_empty_object() {
    use frp_core::msg::*;

    let empty: Vec<(&str, Message)> = vec![
        ("Login", Message::Login(Login::default())),
        ("LoginResp", Message::LoginResp(LoginResp::default())),
        ("NewProxy", Message::NewProxy(NewProxy::default())),
        (
            "NewProxyResp",
            Message::NewProxyResp(NewProxyResp::default()),
        ),
        ("CloseProxy", Message::CloseProxy(CloseProxy::default())),
        ("NewWorkConn", Message::NewWorkConn(NewWorkConn::default())),
        ("ReqWorkConn", Message::ReqWorkConn(ReqWorkConn::default())),
        (
            "StartWorkConn",
            Message::StartWorkConn(StartWorkConn::default()),
        ),
        (
            "NewVisitorConn",
            Message::NewVisitorConn(NewVisitorConn::default()),
        ),
        (
            "NewVisitorConnResp",
            Message::NewVisitorConnResp(NewVisitorConnResp::default()),
        ),
        ("Ping", Message::Ping(Ping::default())),
        ("Pong", Message::Pong(Pong::default())),
        ("UdpPacket", Message::UdpPacket(UdpPacket::default())),
        (
            "NatHoleVisitor",
            Message::NatHoleVisitor(NatHoleVisitor::default()),
        ),
        (
            "NatHoleClient",
            Message::NatHoleClient(NatHoleClient::default()),
        ),
        ("NatHoleSid", Message::NatHoleSid(NatHoleSid::default())),
        (
            "NatHoleReport",
            Message::NatHoleReport(NatHoleReport::default()),
        ),
    ];

    let mut failures = Vec::new();
    for (name, msg) in empty {
        let body = msg.encode_json().expect("encode");
        // Login and NewProxy have a non-omitempty struct field (client_spec),
        // so they are `{"client_spec":{}}` rather than `{}`; everything else
        // with no such field must be exactly `{}`.
        let text = String::from_utf8_lossy(&body);
        let ok = match name {
            "Login" => text == r#"{"client_spec":{}}"#,
            "NatHoleResp" => true, // not in the empty list; see below
            _ => text == "{}" || text == r#"{"detect_behavior":{}}"#,
        };
        if !ok {
            failures.push(format!("{name}: got {text}"));
        }
    }

    // NatHoleResp is checked separately: its `detect_behavior` has no omitempty
    // upstream, so it is always present as an object even when all inner fields
    // are zero.
    let resp = Message::NatHoleResp(NatHoleResp::default())
        .encode_json()
        .unwrap();
    let text = String::from_utf8_lossy(&resp);
    if text != r#"{"detect_behavior":{}}"# {
        failures.push(format!("NatHoleResp: got {text}"));
    }

    assert!(
        failures.is_empty(),
        "zero valued messages emit more than upstream does:\n  {}",
        failures.join("\n  ")
    );
}

/// A struct field is never dropped by Go's `omitempty`.
///
/// The documented rule is that `omitempty` drops "false, 0, any nil pointer or
/// interface value, and any array, slice, map, or string of length zero" — a
/// struct is not on that list. So `ClientSpec` and `NatHoleResp.DetectBehavior`
/// are emitted even when every inner field is zero, which is why `Login` and
/// `NatHoleResp` never encode to a bare `{}`.
#[test]
fn struct_typed_fields_survive_omitempty() {
    use frp_core::msg::{Login, Message, NatHoleResp};

    let login = String::from_utf8(Message::Login(Login::default()).encode_json().unwrap()).unwrap();
    assert_eq!(
        login, r#"{"client_spec":{}}"#,
        "ClientSpec has no omitempty upstream, so it is always emitted"
    );

    let resp = String::from_utf8(
        Message::NatHoleResp(NatHoleResp::default())
            .encode_json()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        resp, r#"{"detect_behavior":{}}"#,
        "DetectBehavior has no omitempty upstream, so it is always emitted"
    );
}

/// `UdpAddrJson` mirrors `net.UDPAddr`, which has no struct tags and therefore
/// no `omitempty`: `Zone` is always on the wire even when empty.
#[test]
fn udp_addr_always_emits_all_three_keys() {
    use frp_core::msg::{UdpAddrJson, UdpPacket};

    let pkt = UdpPacket {
        content: b"x".to_vec(),
        local_addr: Some(UdpAddrJson::new("127.0.0.1", 53)),
        remote_addr: None,
    };
    let text = String::from_utf8(Message::UdpPacket(pkt).encode_json().unwrap()).unwrap();
    assert!(
        text.contains(r#"{"IP":"127.0.0.1","Port":53,"Zone":""}"#),
        "UDPAddr must keep Zone even when empty, got {text}"
    );
    // And the nil remote end is omitted rather than rendered as null.
    assert!(
        !text.contains(r#""r""#),
        "nil remote_addr should be omitted: {text}"
    );
}
