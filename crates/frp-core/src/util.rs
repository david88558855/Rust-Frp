//! Small shared helpers.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::distributions::Alphanumeric;
use rand::Rng;

use crate::codec::CodecError;

const ID_ALPHABET_LEN: u8 = 62;

/// Seconds since the UNIX epoch.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A random alphanumeric identifier, used for `run_id` and transaction ids.
pub fn rand_id(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

/// Random identifier whose alphabet matches upstream `util.RandID`.
pub fn rand_id_frp(len: usize) -> String {
    const CHARSET: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len() as u8) % ID_ALPHABET_LEN;
            CHARSET[idx as usize] as char
        })
        .collect()
}

/// `util.CanonicalAddr`: omits the port for 80 and 443.
pub fn canonical_addr(host: &str, port: u16) -> String {
    if port == 80 || port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// Parses a quantity such as `1MB`, `512KB`, `1048576`, `1MBps`.
///
/// Mirrors `types.BandwidthQuantity` from upstream, which accepts `KB`/`MB`
/// suffixes and a bare byte count.
pub fn parse_bandwidth(s: &str) -> Result<i64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    let lowered = s.to_ascii_lowercase();
    let (num_part, multiplier) = if let Some(v) = lowered.strip_suffix("mb") {
        (v, 1024 * 1024)
    } else if let Some(v) = lowered.strip_suffix("kb") {
        (v, 1024)
    } else if let Some(v) = lowered.strip_suffix('m') {
        (v, 1024 * 1024)
    } else if let Some(v) = lowered.strip_suffix('k') {
        (v, 1024)
    } else if let Some(v) = lowered.strip_suffix("b") {
        (v, 1)
    } else {
        (lowered.as_str(), 1)
    };
    let num_part = num_part.trim();
    let value: f64 = num_part
        .parse()
        .map_err(|_| format!("invalid bandwidth limit: {s}"))?;
    Ok((value * multiplier as f64) as i64)
}

/// Parses `1000-2000,2001,3000-4000` into an explicit list, mirroring
/// `util.ParseRangeNumbers`.
pub fn parse_range_numbers(range_str: &str) -> Result<Vec<i64>, String> {
    let mut out = Vec::new();
    for part in range_str.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let start: i64 = a
                .trim()
                .parse()
                .map_err(|_| format!("invalid range number: {part}"))?;
            let end: i64 = b
                .trim()
                .parse()
                .map_err(|_| format!("invalid range number: {part}"))?;
            if end < start {
                return Err(format!("invalid range number: {part}"));
            }
            out.extend(start..=end);
        } else {
            out.push(
                part.parse()
                    .map_err(|_| format!("invalid range number: {part}"))?,
            );
        }
    }
    Ok(out)
}

/// Best effort local hostname; frp falls back to `unknown` too.
pub fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Go's `runtime.GOOS` spelling of the current platform.
pub fn os_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

/// Go's `runtime.GOARCH` spelling of the current platform.
pub fn arch_name() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "x86" => "386",
        "aarch64" => "arm64",
        other => other,
    }
}

/// Formats a socket address the way Go's `net.Addr.String()` does.
pub fn socket_addr_to_string(addr: &SocketAddr) -> String {
    addr.to_string()
}

/// Splits a `host:port` string, tolerating IPv6 literals in brackets.
pub fn split_host_port(addr: &str) -> Option<(String, u16)> {
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?.parse().ok()?;
        return Some((host.to_string(), port));
    }
    let (host, port) = addr.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

/// Converts a codec error into an `anyhow` error preserving the message.
pub fn codec_err(e: CodecError) -> anyhow::Error {
    anyhow::anyhow!(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bandwidth_parsing() {
        assert_eq!(parse_bandwidth("1MB").unwrap(), 1024 * 1024);
        assert_eq!(parse_bandwidth("512KB").unwrap(), 512 * 1024);
        assert_eq!(parse_bandwidth("1024").unwrap(), 1024);
        assert_eq!(parse_bandwidth("1536KB").unwrap(), 1536 * 1024);
        assert_eq!(parse_bandwidth("").unwrap(), 0);
        assert!(parse_bandwidth("abc").is_err());
    }

    #[test]
    fn range_number_parsing() {
        assert_eq!(
            parse_range_numbers("1000-1003,2000").unwrap(),
            vec![1000, 1001, 1002, 1003, 2000]
        );
        assert!(parse_range_numbers("1003-1000").is_err());
    }

    #[test]
    fn canonical_addr_omits_default_ports() {
        assert_eq!(canonical_addr("example.com", 80), "example.com");
        assert_eq!(canonical_addr("example.com", 443), "example.com");
        assert_eq!(canonical_addr("example.com", 8080), "example.com:8080");
    }

    #[test]
    fn host_port_splitting() {
        assert_eq!(
            split_host_port("1.2.3.4:7500"),
            Some(("1.2.3.4".to_string(), 7500))
        );
        assert_eq!(split_host_port("[::1]:7500"), Some(("::1".to_string(), 7500)));
        assert_eq!(split_host_port("nope"), None);
    }

    #[test]
    fn ids_are_unique_enough() {
        let a = rand_id(16);
        let b = rand_id(16);
        assert_eq!(a.len(), 16);
        assert_ne!(a, b);
    }
}
