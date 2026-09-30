//! `rust-frp` - unified command line entrypoint hosting both `frps` and `frpc`.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use frp_core::config::server::ServerConfig;
use frp_core::crypto::auth;
use frp_core::msg::{Login, Message, ReqWorkConn};
use frp_core::{codec, FRP_VERSION};

#[derive(Parser, Debug)]
#[command(
    name = "rust-frp",
    version,
    about = "Rust reimplementation of frp (fast reverse proxy), wire compatible with frp v0.71",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
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

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().command {
        Command::Info => print_info(),
        Command::Selftest => run_selftest()?,
        Command::Frps { config, verify } => run_frps(&config, verify)?,
        Command::Frpc { config, verify } => run_frpc(&config, verify)?,
    }
    Ok(())
}

fn print_info() {
    println!("rust-frp {FRP_VERSION}");
    println!(
        "wire protocol  : v1 (type:u8 | len:i64 BE | json), max payload {} bytes",
        codec::MAX_MSG_LENGTH
    );
    println!("auth           : md5(token || timestamp)");
    println!("control crypto : aes-128-cfb, pbkdf2-hmac-sha1(token, \"crypto\", 64, 16)");
    println!("work crypto    : same cipher, enabled per proxy by transport.useEncryption");
    println!("compression    : snappy framed stream (crc32c masked)");
    println!("tls            : custom first byte 0x17, real ClientHello 0x16");
    println!("server proxies : tcp, udp, stcp, sudp");
    println!("message types  : login/login_resp/new_proxy/new_proxy_resp/close_proxy/new_work_conn/req_work_conn/start_work_conn/new_visitor_conn/new_visitor_conn_resp/ping/pong/udp_packet/nat_hole_*");
}

fn run_frps(config: &str, verify: bool) -> Result<()> {
    let cfg: ServerConfig =
        frp_core::config::load_config(config).with_context(|| format!("load {config}"))?;

    if verify {
        let mut checked = cfg.clone();
        checked.complete();
        println!(
            "configuration is valid: bind {}:{} ({} allowPorts entries)",
            checked.bind_addr,
            checked.bind_port,
            checked.allow_ports.len()
        );
        return Ok(());
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    runtime.block_on(async move {
        let service = frp_server::Service::new(cfg)?;
        let shutdown = service.shutdown();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                println!("shutting down");
                shutdown.cancel();
            }
        });
        service.run().await
    })
}

fn run_frpc(config: &str, verify: bool) -> Result<()> {
    if verify {
        println!("frpc configuration verification arrives with the client milestone: {config}");
        return Ok(());
    }
    anyhow::bail!("frpc is not implemented yet; see the roadmap in README.md");
}

fn run_selftest() -> Result<()> {
    // 1. framing round trip against a hard coded expected frame
    let msg = Message::Login(Login {
        version: FRP_VERSION.to_string(),
        privilege_key: auth::get_auth_key("token", 1),
        timestamp: 1,
        ..Default::default()
    });
    let frame = codec::pack(&msg)?;
    assert_eq!(frame[0], b'o', "login type byte");
    let decoded = codec::unpack(&frame)?;
    assert_eq!(decoded, msg, "framing round trip");
    println!("[ok] message framing ({} byte frame)", frame.len());

    // 2. token auth
    let key = auth::get_auth_key("s3cret", 1_700_000_000);
    assert!(auth::verify_auth_key("s3cret", 1_700_000_000, &key));
    assert!(!auth::verify_auth_key("other", 1_700_000_000, &key));
    println!("[ok] token auth md5(token||timestamp)");

    // 3. empty message shape
    let empty = codec::pack(&Message::ReqWorkConn(ReqWorkConn {}))?;
    assert_eq!(&empty[9..], b"{}");
    println!("[ok] req_work_conn encodes as {{}}");

    // 4. crypto round trip (AES-128-CFB + snappy framing)
    let bytes = stream_crypto_roundtrip(b"token");
    println!("[ok] encrypted+compressed stream round trip ({bytes} bytes)");

    println!("rust-frp selftest: all checks passed");
    Ok(())
}

/// Exercises the exact wrapping order used for work connections.
fn stream_crypto_roundtrip(token: &[u8]) -> usize {
    use frp_core::crypto::{CompressedStream, EncryptedStream};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    runtime.block_on(async move {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut client = CompressedStream::new(EncryptedStream::new(a, token));
        let mut server = CompressedStream::new(EncryptedStream::new(b, token));

        let payload = b"rust-frp work connection payload ".repeat(400);
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&payload).await.expect("write");
            client.shutdown().await.expect("shutdown");
        });

        let mut got = Vec::new();
        server.read_to_end(&mut got).await.expect("read");
        writer.await.expect("join");
        assert_eq!(got, expected, "crypto stream round trip");
        got.len()
    })
}
