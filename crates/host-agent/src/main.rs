//! Host agent entry point.
//!
//! The agent runs as a system service on the machine being controlled. It performs the
//! full startup sequence — configuration, logging, directories, database, host
//! inventory, health check — then binds its QUIC listener and serves authenticated
//! sessions until it is asked to stop.
//!
//! Subcommands:
//!
//! * `run` — start the agent (the default).
//! * `check` — validate configuration and exit. Used by the installer and by
//!   `ExecStartPre` in the systemd unit, so a bad config fails at deploy time rather
//!   than leaving a service in a crash loop.
//! * `print-config` — write the effective configuration, including defaults, to
//!   stdout so it can be seeded into a file.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod config;
mod file_service;
mod health;
mod identity;
mod logging;
mod metrics_service;
mod server;
mod sessions;

use std::path::PathBuf;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use config::AgentConfig;
use rc_platform::{AppPaths, HostInfo};

/// Command-line interface.
#[derive(Debug, Parser)]
#[command(name = "rc-agent", version, about = "Remote-control host agent")]
struct Cli {
    /// Path to the configuration file. Defaults to the platform config directory.
    #[arg(long, value_name = "FILE", env = "RC_AGENT_CONFIG")]
    config: Option<PathBuf>,

    /// Override the root under which config, data and logs live. Intended for
    /// development and testing; production installs use the platform defaults.
    #[arg(long, value_name = "DIR", env = "RC_AGENT_ROOT")]
    root: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

/// Agent subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Start the agent.
    Run,
    /// Validate the configuration and exit.
    Check,
    /// Print the effective configuration as TOML.
    PrintConfig,
    /// Write the effective configuration to the config file. Used by the installer
    /// to seed a commented starting point without overwriting an existing file.
    WriteConfig {
        /// Overwrite an existing configuration file.
        #[arg(long)]
        force: bool,
    },
    /// Print this agent's device identity and fingerprints.
    Identity,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let paths = match &cli.root {
        Some(root) => AppPaths::with_root(root),
        None => AppPaths::for_agent().context("could not resolve agent directories")?,
    };
    // An explicit `--config` must exist: pointing at a missing file and silently
    // getting defaults could disable a restriction the operator meant to apply.
    let explicit_config = cli.config.is_some();
    let config_path = cli
        .config
        .clone()
        .unwrap_or_else(|| paths.config_dir().join("agent.toml"));

    let load = || -> anyhow::Result<AgentConfig> {
        let config = if explicit_config {
            AgentConfig::load(&config_path)
        } else {
            AgentConfig::load_or_default(&config_path)
        };
        config.with_context(|| format!("invalid configuration at {}", config_path.display()))
    };

    match cli.command.unwrap_or(Command::Run) {
        Command::Check => {
            let config = load()?;
            println!("configuration is valid: {}", config.device_name);
            Ok(())
        }
        Command::PrintConfig => {
            print!("{}", load()?.to_toml()?);
            Ok(())
        }
        Command::WriteConfig { force } => {
            if config_path.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite",
                    config_path.display()
                );
            }
            let config = load()?;
            config.save(&config_path)?;
            println!("wrote {}", config_path.display());
            Ok(())
        }
        Command::Identity => {
            let config = load()?;
            paths
                .create_all()
                .context("could not create agent directories")?;
            let (device_identity, _origin) = identity::load_identity(&paths, &config)?;
            identity::print_identity(&device_identity);
            Ok(())
        }
        Command::Run => run(paths, load()?),
    }
}

/// Start the agent and block until it is asked to stop.
///
/// `config` has already been loaded and validated by the caller, so a bad value
/// fails fast and visibly rather than after the process has claimed ports and files.
fn run(paths: AppPaths, config: AgentConfig) -> anyhow::Result<()> {
    paths
        .create_all()
        .context("could not create agent directories")?;

    let _logging = logging::init(paths.log_dir(), config.log_level.as_filter())
        .context("could not initialise logging")?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("rc-agent")
        .build()
        .context("could not start the async runtime")?;

    runtime.block_on(run_async(paths, config))
}

async fn run_async(paths: AppPaths, config: AgentConfig) -> anyhow::Result<()> {
    let host = HostInfo::detect();
    let (device_identity, identity_origin) = identity::load_identity(&paths, &config)?;

    tracing::info!(
        agent_version = env!("CARGO_PKG_VERSION"),
        protocol_version = %rc_protocol::CURRENT_VERSION,
        device_name = %config.device_name,
        hostname = %host.hostname,
        os = %host.os_version,
        arch = %host.architecture,
        cores = host.logical_cores,
        elevated = rc_platform::is_elevated(),
        "starting host agent"
    );

    let database = rc_storage::Database::open(paths.database_file())
        .await
        .context("could not open the agent database")?;
    database
        .health_check()
        .await
        .context("database health check failed")?;

    tracing::info!(
        schema_version = database.schema_version().await.unwrap_or(-1),
        path = %paths.database_file().display(),
        "database ready"
    );

    // Recorded once the database is available, so first-run identity creation leaves a
    // trail. An ordinary load writes nothing.
    identity::record_identity_event(
        &rc_storage::audit::AuditRepository::new(&database),
        identity_origin,
        &device_identity,
        &rc_security::SystemClock,
    )
    .await?;

    tracing::info!(
        device_id = %device_identity.device_id(),
        identity_fingerprint = %device_identity.public().identity_fingerprint,
        certificate_version = device_identity.public().certificate_version,
        "device identity ready"
    );

    tracing::info!(
        listen = %config.listen_socket(),
        remote_access = config.network.remote_access_enabled,
        max_sessions = config.network.max_sessions,
        "network configuration loaded"
    );

    if config.network.remote_access_enabled {
        tracing::warn!(
            "remote access is enabled; confirm the firewall guidance in              docs/installation.md has been applied"
        );
    }

    let health_port = config.network.health_port;
    let device_identity = std::sync::Arc::new(device_identity);

    let server = std::sync::Arc::new(server::AgentServer::new(
        std::sync::Arc::clone(&device_identity),
        config,
        database.clone(),
    ));

    // One shutdown signal, observed by both the listener and the local endpoint. A
    // broadcast rather than two waiters on the OS signal, because only one task can
    // own `ctrl_c`.
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    let local_shutdown = shutdown_tx.subscribe();

    tokio::spawn(async move {
        wait_for_shutdown().await;
        // A send failure means every receiver has already gone, which is the state
        // being asked for anyway.
        let _ = shutdown_tx.send(());
    });

    let health_task = spawn_health_endpoint(health_port, &database, &server, local_shutdown);

    server
        .run(async move {
            let _ = shutdown_rx.recv().await;
        })
        .await?;

    tracing::info!("shutdown signal received, stopping");
    if let Some(task) = health_task {
        // The endpoint has been told to stop; waiting for it keeps the shutdown
        // ordered rather than leaving a socket open behind the process.
        let _ = task.await;
    }
    database.close().await;
    tracing::info!("agent stopped cleanly");
    Ok(())
}

/// Start the loopback health endpoint, if it is enabled.
///
/// Best-effort: an agent that cannot serve health can still serve clients, and refusing
/// to start would turn a diagnostic facility into an outage.
fn spawn_health_endpoint(
    port: u16,
    database: &rc_storage::Database,
    server: &std::sync::Arc<server::AgentServer>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> Option<tokio::task::JoinHandle<()>> {
    if port == 0 {
        tracing::info!("the local health endpoint is disabled by configuration");
        return None;
    }

    let endpoint = std::sync::Arc::new(health::HealthEndpoint::new(
        database.clone(),
        server.sessions(),
        server.listener_ready(),
    ));

    Some(tokio::spawn(async move {
        if let Err(err) = endpoint
            .serve(port, async move {
                let _ = shutdown.recv().await;
            })
            .await
        {
            tracing::warn!(%err, port, "the local health endpoint stopped");
        }
    }))
}

/// Block until the OS asks the process to stop.
///
/// Handling SIGTERM as well as Ctrl+C is what lets `systemctl stop` and a Windows
/// service stop request shut the agent down cleanly instead of killing it.
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(sig) => sig,
            Err(err) => {
                tracing::error!(?err, "could not install SIGTERM handler; Ctrl+C only");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => tracing::debug!("received SIGINT"),
            _ = term.recv() => tracing::debug!("received SIGTERM"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn run_is_the_default_subcommand() {
        let cli = Cli::parse_from(["rc-agent"]);
        assert!(cli.command.is_none(), "no subcommand means Run");
    }

    #[test]
    fn root_override_is_accepted() {
        let cli = Cli::parse_from(["rc-agent", "--root", "/tmp/rc", "check"]);
        assert_eq!(cli.root, Some(PathBuf::from("/tmp/rc")));
        assert!(matches!(cli.command, Some(Command::Check)));
    }

    #[test]
    fn config_path_override_is_accepted() {
        let cli = Cli::parse_from(["rc-agent", "--config", "/etc/x.toml"]);
        assert_eq!(cli.config, Some(PathBuf::from("/etc/x.toml")));
    }
}
