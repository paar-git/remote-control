//! Structured, rotating logging for the agent.
//!
//! Two sinks are installed: a rolling file in the agent's log directory, and stderr
//! (useful under `systemd`, which captures it into the journal).
//!
//! # What is never logged
//!
//! Passwords, tokens, pairing codes, private keys, clipboard contents, file contents
//! and terminal I/O never reach a log. Those values are carried in types that are
//! documented as unloggable, and the code paths handling them record metadata only —
//! byte counts, durations, outcomes. This is a review-enforced rule, not something the
//! logging layer can detect for you.

use std::path::Path;

use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

/// Keeps the non-blocking writer's flush thread alive.
///
/// Dropping this guard flushes buffered log lines, so it must be held for the whole
/// life of the process.
pub struct LoggingGuard {
    _file: tracing_appender::non_blocking::WorkerGuard,
}

/// Install the global tracing subscriber.
///
/// `filter` is a `tracing` filter directive such as `"info"`. The `RUST_LOG`
/// environment variable overrides it when set.
///
/// # Errors
/// Fails if the log directory cannot be created.
pub fn init(log_dir: &Path, filter: &str) -> std::io::Result<LoggingGuard> {
    std::fs::create_dir_all(log_dir)?;

    let file_appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("rc-agent")
        .filename_suffix("log")
        // Bounds disk use without an external logrotate dependency.
        .max_log_files(14)
        .build(log_dir)
        .map_err(std::io::Error::other)?;

    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter));

    tracing_subscriber::registry()
        .with(env_filter)
        // Machine-readable for the log export feature.
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(non_blocking)
                .with_current_span(true)
                .with_span_list(false),
        )
        // Human-readable for the console / journal.
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_target(false)
                .with_ansi(false),
        )
        .init();

    Ok(LoggingGuard { _file: guard })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_creates_the_log_directory() {
        let dir = tempfile::tempdir().unwrap();
        let log_dir = dir.path().join("does").join("not").join("exist");

        // The global subscriber can only be installed once per process, so this test
        // asserts the directory side effect rather than the subscriber itself.
        let _ = init(&log_dir, "info");
        assert!(log_dir.is_dir());
    }
}
