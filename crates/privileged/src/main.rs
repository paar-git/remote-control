//! The privileged helper process.
//!
//! Installed as a Windows service running as `LocalSystem`, or as a systemd unit
//! running as root. It listens on loopback, answers a closed set of operations, and
//! does nothing else.
//!
//! # Deliberately small
//!
//! This is the only part of the system that runs elevated. Everything it can be asked
//! to do is enumerated in [`rc_privileged::PrivilegedOperation`], and every request is
//! re-validated here rather than being trusted from the agent. Keeping it small is the
//! point: it is the piece whose compromise matters most, so there is as little of it as
//! possible.

#![forbid(unsafe_code)]

use anyhow::Context as _;
use clap::Parser;
use rc_privileged::{HelperServer, Token};

/// Command-line interface.
#[derive(Debug, Parser)]
#[command(
    name = "rc-privileged-helper",
    version,
    about = "Performs allowlisted privileged operations for the remote-control agent"
)]
struct Cli {
    /// Loopback port to listen on.
    #[arg(long, default_value_t = rc_protocol::DEFAULT_PRIVILEGED_PORT)]
    port: u16,

    /// Directory to publish the control token into.
    ///
    /// Must be readable by the agent's account and by nobody else. The installer sets
    /// this up; see `docs/privileged-operations.md`.
    #[arg(long, value_name = "DIR")]
    data_dir: std::path::PathBuf,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    anyhow::ensure!(
        cli.data_dir.is_dir(),
        "the data directory {} does not exist; the installer creates it with the right \
         permissions",
        cli.data_dir.display()
    );

    // A fresh token every start, so a copy taken from a previous run is useless.
    let token = Token::generate();
    let token_path = rc_privileged::client::token_path(&cli.data_dir);

    token.write_to(&token_path).with_context(|| {
        format!(
            "could not publish the control token to {}",
            token_path.display()
        )
    })?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        elevated = rc_platform::is_elevated(),
        port = cli.port,
        "privileged helper starting"
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        // One thread is plenty: this process answers a handful of requests a day and
        // spends the rest of its life parked on `accept`.
        .enable_all()
        .build()
        .context("could not start the async runtime")?;

    let result = runtime.block_on(async {
        let server = std::sync::Arc::new(HelperServer::new(token));
        server.serve(cli.port, wait_for_shutdown()).await
    });

    // The token is removed on the way out so a stale file cannot be presented to a
    // future helper that has already generated a different one.
    if let Err(err) = std::fs::remove_file(&token_path) {
        tracing::debug!(%err, "could not remove the control token");
    }

    result.context("the privileged helper stopped unexpectedly")?;
    tracing::info!("privileged helper stopped cleanly");
    Ok(())
}

/// Block until the operating system asks the process to stop.
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let Ok(mut term) = signal(SignalKind::terminate()) else {
            let _ = tokio::signal::ctrl_c().await;
            return;
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
