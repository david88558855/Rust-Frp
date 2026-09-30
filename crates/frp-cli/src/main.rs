//! `rust-frp` - unified command line entrypoint hosting both `frps` and `frpc`.
//!
//! Everything decidable without touching the console or the network lives in
//! the `frp_cli` library next to this file; what remains here is process
//! lifecycle: parse, dispatch, install the signal handler, own the runtime.

use anyhow::{Context, Result};
use clap::Parser;
use frp_cli::{describe_server, info_lines, selftest_checks, Cli, Command};
use frp_core::config::server::ServerConfig;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().command {
        Command::Info => {
            for line in info_lines() {
                println!("{line}");
            }
        }
        Command::Selftest => {
            for line in selftest_checks()? {
                println!("{line}");
            }
            println!("rust-frp selftest: all checks passed");
        }
        Command::Frps { config, verify } => run_frps(&config, verify)?,
        Command::Frpc { config, verify } => run_frpc(&config, verify)?,
    }
    Ok(())
}

fn run_frps(config: &str, verify: bool) -> Result<()> {
    let cfg: ServerConfig =
        frp_core::config::load_config(config).with_context(|| format!("load {config}"))?;

    if verify {
        println!("{}", describe_server(&cfg));
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
    let cfg =
        frp_core::config::ClientConfig::load(config).with_context(|| format!("load {config}"))?;
    let service = frp_client::Service::new(cfg, Some(std::path::PathBuf::from(config)))?;

    if verify {
        println!("configuration is valid:\n{}", service.describe());
        return Ok(());
    }

    let shutdown = service.shutdown_token();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    runtime.block_on(async move {
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                println!("shutting down");
                shutdown.cancel();
            }
        });
        service.run().await
    })
}
