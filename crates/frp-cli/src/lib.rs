//! `frp-cli` support library.
//!
//! The crate is a single binary whose job is argument parsing and process
//! lifecycle. Everything that can be decided without touching the console or
//! the network lives here, behind plain functions that return values, so the
//! binary in `main.rs` stays a thin shell and the behaviour is testable.
//!
//! The split matters because the binary previously formatted its output with
//! `println!` inline and asserted inside `run_selftest`, which left nothing to
//! call from a test: the strings were written straight to the process stdout
//! and the checks aborted rather than returning.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use frp_core::config::server::ServerConfig;
use frp_core::crypto::auth;
use frp_core::msg::{Login, Message, ReqWorkConn};
use frp_core::{codec, FRP_VERSION};

/// The command line surface.
///
/// It lives in the library rather than in `main.rs` so that tests exercise the
/// definition the binary actually uses. A copy in the test module would drift
/// from the real one the first time a flag is added.
#[derive(Parser, Debug)]
#[command(
    name = "rust-frp",
    version,
    about = "Rust reimplementation of frp (fast reverse proxy), wire compatible with frp v0.71",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the frp server (frps).
    Frps {
        /// Path to the server configuration file (TOML/YAML/JSON).
        #[arg(short = 'c', long = "config", default_value = "./frps.toml")]
        config: String,
        /// Validate the configuration and exit.
        #[arg(long = "verify")]
        verify: bool,
    },
    /// Run the frp client (frpc).
    Frpc {
        /// Path to the client configuration file (TOML/YAML/JSON).
        #[arg(short = 'c', long = "config", default_value = "./frpc.toml")]
        config: String,
        /// Validate the configuration and exit.
        #[arg(long = "verify")]
        verify: bool,
    },
    /// Print build and wire compatibility information.
    Info,
    /// Run offline protocol self tests (framing, token auth, crypto stream).
    Selftest,
}

/// The compatibility summary printed by `rust-frp info`.
///
/// Returned as lines rather than printed so that the content can be asserted.
/// Each entry is `label` padded to a fixed column followed by `value`, which is
/// what keeps the output aligned in a terminal.
pub fn info_lines() -> Vec<String> {
    vec![
        format!("rust-frp {FRP_VERSION}"),
        format!(
            "wire protocol  : v1 (type:u8 | len:i64 BE | json), max payload {} bytes",
            codec::MAX_MSG_LENGTH
        ),
        "auth           : md5(token || timestamp)".to_string(),
        "control crypto : aes-128-cfb, pbkdf2-hmac-sha1(token, \"frp\", 64, 16)".to_string(),
        "work crypto    : same cipher, enabled per proxy by transport.useEncryption".to_string(),
        "compression    : snappy framed stream (crc32c masked)".to_string(),
        "tls            : custom first byte 0x17, real ClientHello 0x16".to_string(),
        "tcpMux         : yamux session over the control socket (both peers default to on)"
            .to_string(),
        "server proxies : tcp, udp, stcp, sudp, http, https".to_string(),
        "client proxies : tcp, udp, http, https, stcp, sudp, tcpmux".to_string(),
        "client visitors: stcp".to_string(),
        "client plugins : unix_domain_socket, static_file, socks5, http_proxy, http2http, \
         http2https, https2http, https2https, tls2raw"
            .to_string(),
        "message types  : login/login_resp/new_proxy/new_proxy_resp/close_proxy/new_work_conn/\
         req_work_conn/start_work_conn/new_visitor_conn/new_visitor_conn_resp/ping/pong/\
         udp_packet/nat_hole_*"
            .to_string(),
    ]
}

/// The one line summary `frps --verify` prints for a valid configuration.
///
/// `complete` is applied to a clone so that the reported values are the ones
/// the server would actually bind, including any default that only exists after
/// completion.
pub fn describe_server(cfg: &ServerConfig) -> String {
    let mut checked = cfg.clone();
    checked.complete();
    format!(
        "configuration is valid: bind {}:{} ({} allowPorts entries)",
        checked.bind_addr,
        checked.bind_port,
        checked.allow_ports.len()
    )
}

/// Runs the offline protocol checks and returns the report.
///
/// Each entry corresponds to one check that passed. Returning the lines instead
/// of printing them means a failure surfaces as an `Err` from this function
/// rather than as a panic from an assertion buried in the middle of it, and a
/// test can assert on both the count and the wording.
pub fn selftest_checks() -> Result<Vec<String>> {
    let mut lines = Vec::new();

    // 1. framing round trip against a hard coded expected frame
    let msg = Message::Login(Login {
        version: FRP_VERSION.to_string(),
        privilege_key: auth::get_auth_key("token", 1),
        timestamp: 1,
        ..Default::default()
    });
    let frame = codec::pack(&msg).context("pack login")?;
    if frame[0] != b'o' {
        anyhow::bail!("login type byte is {:#x}, expected 0x6f", frame[0]);
    }
    let decoded = codec::unpack(&frame).context("unpack login")?;
    if decoded != msg {
        anyhow::bail!("framing round trip lost information");
    }
    lines.push(format!("[ok] message framing ({} byte frame)", frame.len()));

    // 2. token auth
    let key = auth::get_auth_key("s3cret", 1_700_000_000);
    if !auth::verify_auth_key("s3cret", 1_700_000_000, &key) {
        anyhow::bail!("token auth rejected the correct key");
    }
    if auth::verify_auth_key("other", 1_700_000_000, &key) {
        anyhow::bail!("token auth accepted the wrong token");
    }
    lines.push("[ok] token auth md5(token||timestamp)".to_string());

    // 3. empty message shape
    let empty = codec::pack(&Message::ReqWorkConn(ReqWorkConn {})).context("pack req_work_conn")?;
    if &empty[9..] != b"{}" {
        anyhow::bail!("req_work_conn body is {:?}, expected {{}}", &empty[9..]);
    }
    lines.push("[ok] req_work_conn encodes as {}".to_string());

    // 4. crypto round trip (AES-128-CFB + snappy framing)
    let bytes = stream_crypto_roundtrip(b"token")?;
    lines.push(format!(
        "[ok] encrypted+compressed stream round trip ({bytes} bytes)"
    ));

    Ok(lines)
}

/// Exercises the exact wrapping order used for work connections.
///
/// Returns the number of bytes that made the round trip, or an error naming the
/// step that failed.
pub fn stream_crypto_roundtrip(token: &[u8]) -> Result<usize> {
    use frp_core::crypto::{CompressedStream, EncryptedStream};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;

    runtime.block_on(async move {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut client = CompressedStream::new(EncryptedStream::new(a, token));
        let mut server = CompressedStream::new(EncryptedStream::new(b, token));

        let payload = b"rust-frp work connection payload ".repeat(400);
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&payload).await?;
            client.shutdown().await?;
            Ok::<_, std::io::Error>(())
        });

        let mut got = Vec::new();
        server.read_to_end(&mut got).await.context("read")?;
        writer.await.context("join writer")?.context("write")?;
        if got != expected {
            anyhow::bail!(
                "crypto round trip returned {} bytes, expected {}",
                got.len(),
                expected.len()
            );
        }
        Ok(got.len())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The argument surface is what `main` dispatches on, and clap's derive is
    // easy to get subtly wrong (a default that is not applied, a subcommand
    // name that drifts from the one in the docs). Parsing known argv vectors
    // covers it without spawning the binary. `Cli` is the real definition, so
    // these tests cannot pass against a stale copy.

    #[test]
    fn frps_defaults_to_the_conventional_config_path() {
        let cli = Cli::try_parse_from(["rust-frp", "frps"]).expect("parse");
        match cli.command {
            Command::Frps { config, verify } => {
                assert_eq!(config, "./frps.toml");
                assert!(!verify, "verify must default to false");
            }
            other => panic!("expected frps, got {other:?}"),
        }
    }

    #[test]
    fn frpc_defaults_to_its_own_config_path() {
        // The two subcommands are easy to give the same default by accident;
        // this pins that frpc keeps its own.
        let cli = Cli::try_parse_from(["rust-frp", "frpc"]).expect("parse");
        match cli.command {
            Command::Frpc { config, verify } => {
                assert_eq!(config, "./frpc.toml");
                assert!(!verify);
            }
            other => panic!("expected frpc, got {other:?}"),
        }
    }

    #[test]
    fn long_and_short_config_flags_agree() {
        let long = Cli::try_parse_from(["rust-frp", "frps", "--config", "/etc/frps.toml"])
            .expect("parse long");
        let short =
            Cli::try_parse_from(["rust-frp", "frps", "-c", "/etc/frps.toml"]).expect("parse short");
        for cli in [long, short] {
            match cli.command {
                Command::Frps { config, .. } => assert_eq!(config, "/etc/frps.toml"),
                other => panic!("expected frps, got {other:?}"),
            }
        }
    }

    #[test]
    fn verify_is_accepted_on_both_servers() {
        let s = Cli::try_parse_from(["rust-frp", "frps", "--verify"]).expect("parse frps");
        assert!(matches!(s.command, Command::Frps { verify: true, .. }));
        let c = Cli::try_parse_from(["rust-frp", "frpc", "--verify"]).expect("parse frpc");
        assert!(matches!(c.command, Command::Frpc { verify: true, .. }));
    }

    #[test]
    fn info_and_selftest_take_no_arguments() {
        assert!(matches!(
            Cli::try_parse_from(["rust-frp", "info"]).expect("parse").command,
            Command::Info
        ));
        assert!(matches!(
            Cli::try_parse_from(["rust-frp", "selftest"])
                .expect("parse")
                .command,
            Command::Selftest
        ));
    }

    #[test]
    fn an_unknown_subcommand_is_rejected() {
        assert!(
            Cli::try_parse_from(["rust-frp", "not-a-command"]).is_err(),
            "an unknown subcommand must not parse"
        );
    }

    #[test]
    fn a_missing_subcommand_is_rejected() {
        assert!(
            Cli::try_parse_from(["rust-frp"]).is_err(),
            "the subcommand is required"
        );
    }

    #[test]
    fn info_reports_the_crate_version_first() {
        let lines = info_lines();
        assert_eq!(
            lines[0],
            format!("rust-frp {FRP_VERSION}"),
            "the first line names the binary and the wire version"
        );
    }

    #[test]
    fn info_labels_are_padded_to_a_common_column() {
        // The alignment is the whole point of the padded labels, and it is easy
        // to break by adding a line with a shorter or longer label.
        let lines = info_lines();
        let labels: Vec<usize> = lines[1..]
            .iter()
            .map(|l| l.find(':').expect("every entry has a label"))
            .collect();
        assert!(
            labels.windows(2).all(|w| w[0] == w[1]),
            "labels sit at different columns: {labels:?}"
        );
    }

    #[test]
    fn info_mentions_the_payload_limit_and_the_message_set() {
        let joined = info_lines().join("\n");
        assert!(joined.contains(&codec::MAX_MSG_LENGTH.to_string()));
        assert!(joined.contains("yamux"), "tcpMux is documented");
        assert!(joined.contains("0x17"), "the TLS first byte is documented");
    }

    #[test]
    fn selftest_passes_and_reports_every_check() {
        let lines = selftest_checks().expect("selftest must pass on a healthy build");
        assert_eq!(lines.len(), 4, "one line per check: {lines:#?}");
        assert!(lines.iter().all(|l| l.starts_with("[ok]")));
    }

    #[test]
    fn crypto_roundtrip_preserves_the_payload() {
        let bytes = stream_crypto_roundtrip(b"token").expect("round trip");
        // 32 bytes per repetition, 400 repetitions.
        assert_eq!(bytes, 32 * 400);
    }

    #[test]
    fn crypto_roundtrip_survives_a_different_key() {
        // The key only has to agree between the two ends; length is what is
        // asserted, so a shorter token must still work.
        assert_eq!(
            stream_crypto_roundtrip(b"a").expect("round trip"),
            32 * 400
        );
    }

    #[test]
    fn describe_server_reads_the_binding_and_the_port_range() {
        let mut cfg = ServerConfig::default();
        cfg.bind_addr = "127.0.0.1".to_string();
        cfg.bind_port = 7000;
        cfg.complete();
        let described = describe_server(&cfg);
        assert!(described.starts_with("configuration is valid: bind 127.0.0.1:7000"));
        assert!(described.contains("allowPorts entries"));
    }
}
