//! Update-manager commands for the desktop client.
//!
//! Downloading may run in the background, but installation is exposed as a separate
//! command so the UI must ask the user before anything is installed.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use rc_security::permissions::Capability;
use rc_updater::database::download_key;
use rc_updater::disk::{check_disk_space, required_space};
use rc_updater::download::{DownloadConfig, DownloadManager, create_record};
use rc_updater::manifest::validate_release_url;
use rc_updater::{
    DownloadQueueState, InstallOutcome, Installer, ManifestPolicy, ManifestSignaturePolicy,
    ManifestSignatureVerifier, PackageFormat, PlatformInfo, ReleaseIndex, ReleaseManifest,
    SignaturePolicy, SignatureVerifier, UpdateDatabase, UpdateError, UpdateState,
    UpdateStateMachine, compare_versions,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::AppState;
use crate::commands::CommandError;

const UPDATE_CONFIG_FILE: &str = "update-config.json";
const DOWNLOAD_DB_FILE: &str = "downloads.json";

/// How long cancellation waits for a superseded download task to stop.
const CANCEL_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Signed release index consulted when nothing more specific is configured.
///
/// `releases/latest/download/<asset>` is a stable GitHub endpoint that redirects
/// to the newest published release, so a shipped build finds new versions with
/// no configuration from the user. `RC_UPDATE_METADATA_URL` at build time
/// repoints it for forks and private distributions; the runtime environment
/// variable and the saved config still take precedence over it.
const DEFAULT_METADATA_URL: &str = match option_env!("RC_UPDATE_METADATA_URL") {
    Some(url) => url,
    None => {
        "https://github.com/realpargitDEV/remote-control/releases/latest/download/release-index.json"
    }
};

pub type CommandResult<T> = Result<T, CommandError>;

#[derive(Clone)]
pub struct UpdateRuntime {
    root_dir: PathBuf,
    config_file: PathBuf,
    manager: Option<DownloadManager>,
    inner: Arc<Mutex<UpdateRuntimeInner>>,
    check_lock: Arc<Mutex<()>>,
    install_lock: Arc<Mutex<()>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateConfigFile {
    manifest_url: Option<String>,
}

#[derive(Debug)]
struct UpdateRuntimeInner {
    manifest_url: Option<String>,
    machine: UpdateStateMachine,
    platform: PlatformInfo,
    manifest: Option<ReleaseManifest>,
    selected: Option<SelectedArtifact>,
    active_key: Option<String>,
    ready_path: Option<PathBuf>,
    last_error: Option<String>,
    /// Incremented whenever an in-flight transfer is superseded or abandoned.
    ///
    /// A background download task captures this value when it is spawned and
    /// discards its own result if the value has moved on. Without it, a task
    /// that finishes just after the user cancels would overwrite the state the
    /// cancel handler just set -- which surfaced as a cancelled download
    /// flipping the UI into `Failed` with a "download cancelled" banner.
    generation: u64,
    /// Join handle for the in-flight download wrapper task, so cancellation can
    /// wait for it to release its slot in the download manager before a new
    /// download for the same artifact is started.
    active_task: Option<tauri::async_runtime::JoinHandle<()>>,
}

impl UpdateRuntimeInner {
    const fn state(&self) -> UpdateState {
        self.machine.state()
    }

    /// Apply a state transition, refusing the ones the state machine forbids.
    ///
    /// Commands surface the refusal to the caller instead of silently moving to
    /// an impossible state, so invoking (say) `pause` while nothing is
    /// downloading is now an error rather than a corrupted status.
    fn transition(&mut self, next: UpdateState) -> CommandResult<()> {
        self.machine.transition(next).map_err(|_| {
            CommandError::new(
                "invalid_update_state",
                format!(
                    "The update manager cannot move from {:?} to {next:?}.",
                    self.state()
                ),
            )
        })
    }

    /// Record a failure, moving to `Failed` when the state machine allows it.
    ///
    /// The message is always stored: a failure the user cannot see is worse
    /// than an unexpected state label.
    fn fail(&mut self, message: String) {
        let _ = self.machine.transition(UpdateState::Failed);
        self.last_error = Some(message);
    }
}

#[derive(Debug, Clone)]
struct SelectedArtifact {
    filename: String,
    package_format: PackageFormat,
    url: String,
    sha256: String,
    size: u64,
    install_size: Option<u64>,
    signature_required: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatusDto {
    state: UpdateState,
    manifest_url: Option<String>,
    current_version: String,
    available_version: Option<String>,
    release_notes: Option<String>,
    platform: PlatformInfo,
    package_format: Option<PackageFormat>,
    download: Option<DownloadProgressDto>,
    ready_path: Option<String>,
    last_error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadProgressDto {
    key: String,
    state: DownloadQueueState,
    downloaded_bytes: u64,
    total_bytes: u64,
    percent: f64,
    retry_count: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckUpdateRequest {
    manifest_url: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallResultDto {
    restart_required: bool,
    message: String,
}

impl UpdateRuntime {
    pub fn new(data_dir: &Path) -> Self {
        let root_dir = data_dir.join("updates");
        if let Err(err) = std::fs::create_dir_all(&root_dir) {
            tracing::error!(%err, path = %root_dir.display(), "could not create update directory");
        }
        let config_file = root_dir.join(UPDATE_CONFIG_FILE);
        let config = read_config(&config_file);
        let manager = match UpdateDatabase::open_resilient(root_dir.join(DOWNLOAD_DB_FILE))
            .and_then(|database| DownloadManager::new(database, DownloadConfig::default()))
        {
            Ok(manager) => Some(manager),
            Err(err) => {
                tracing::error!(%err, "could not initialise update database");
                None
            }
        };
        Self {
            root_dir,
            config_file,
            manager,
            check_lock: Arc::new(Mutex::new(())),
            install_lock: Arc::new(Mutex::new(())),
            inner: Arc::new(Mutex::new(UpdateRuntimeInner {
                manifest_url: config.manifest_url,
                machine: UpdateStateMachine::default(),
                platform: PlatformInfo::detect(),
                manifest: None,
                selected: None,
                active_key: None,
                ready_path: None,
                last_error: None,
                generation: 0,
                active_task: None,
            })),
        }
    }

    async fn status(&self) -> UpdateStatusDto {
        let inner = self.inner.lock().await;
        let download = inner.active_key.as_ref().and_then(|key| {
            self.manager
                .as_ref()
                .and_then(|manager| manager.record(key))
                .map(|record| DownloadProgressDto {
                    key: key.clone(),
                    state: record.state,
                    downloaded_bytes: record.downloaded_bytes,
                    total_bytes: record.expected_size,
                    percent: percentage(record.downloaded_bytes, record.expected_size),
                    retry_count: record.retry_count,
                })
        });
        let state = if matches!(
            download.as_ref().map(|download| download.state),
            Some(DownloadQueueState::WaitingForNetwork)
        ) && matches!(
            inner.state(),
            UpdateState::Downloading | UpdateState::Resuming
        ) {
            UpdateState::WaitingForNetwork
        } else {
            inner.state()
        };
        UpdateStatusDto {
            state,
            manifest_url: inner.manifest_url.clone(),
            current_version: env!("CARGO_PKG_VERSION").to_string(),
            available_version: inner
                .manifest
                .as_ref()
                .map(|manifest| manifest.version.clone()),
            release_notes: inner
                .manifest
                .as_ref()
                .map(|manifest| manifest.release_notes.clone()),
            platform: inner.platform.clone(),
            package_format: inner
                .selected
                .as_ref()
                .map(|selected| selected.package_format),
            download,
            ready_path: inner
                .ready_path
                .as_ref()
                .map(|path| path.display().to_string()),
            last_error: inner.last_error.clone(),
        }
    }

    async fn set_error(&self, error: &UpdateError) {
        let mut inner = self.inner.lock().await;
        inner.fail(safe_update_error_message(error));
    }
}

#[tauri::command]
pub async fn update_status(
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<UpdateStatusDto> {
    Ok(state.updater.status().await)
}

#[tauri::command]
pub async fn check_for_updates(
    request: CheckUpdateRequest,
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<UpdateStatusDto> {
    state.require_capability(Capability::SettingsManagement)?;
    let _check_guard = state.updater.check_lock.lock().await;
    let manifest_url = resolve_manifest_url(&state.updater, request.manifest_url).await;
    {
        let mut inner = state.updater.inner.lock().await;
        inner.transition(UpdateState::CheckingForUpdates)?;
        inner.generation = inner.generation.wrapping_add(1);
        inner.last_error = None;
        inner.ready_path = None;
        inner.active_key = None;
    }
    tracing::info!(manifest_url = %safe_url_for_log(&manifest_url), "update check started");
    let result = fetch_and_select_manifest(&manifest_url).await;
    match result {
        Ok((manifest, selected)) => {
            let ordering = match compare_versions(&manifest.version, env!("CARGO_PKG_VERSION")) {
                Ok(ordering) => ordering,
                Err(error) => {
                    state.updater.set_error(&error).await;
                    return Err(map_update_error(error));
                }
            };
            match ordering {
                Ordering::Less => {
                    let error = UpdateError::DowngradeRefused {
                        installed: env!("CARGO_PKG_VERSION").to_string(),
                        available: manifest.version.clone(),
                    };
                    state.updater.set_error(&error).await;
                    return Err(map_update_error(error));
                }
                Ordering::Equal => {
                    let mut inner = state.updater.inner.lock().await;
                    inner.manifest_url = Some(manifest_url.clone());
                    inner.manifest = Some(manifest);
                    inner.selected = None;
                    inner.transition(UpdateState::NoUpdateAvailable)?;
                    write_config(
                        &state.updater.config_file,
                        &UpdateConfigFile {
                            manifest_url: Some(manifest_url),
                        },
                    )?;
                    return Ok(state.updater.status().await);
                }
                Ordering::Greater => {}
            }
            if let Some(minimum) = manifest.minimum_supported_version()
                && compare_versions(env!("CARGO_PKG_VERSION"), minimum)
                    .is_ok_and(|ordering| ordering == Ordering::Less)
            {
                tracing::warn!(
                    installed = env!("CARGO_PKG_VERSION"),
                    minimum,
                    "installed version is too old for incremental update; full package will be used"
                );
            }
            let required = required_space(selected.size, selected.install_size);
            if let Err(error) = check_disk_space(&state.updater.root_dir, required) {
                state.updater.set_error(&error).await;
                return Err(map_update_error(error));
            }
            let mut inner = state.updater.inner.lock().await;
            inner.manifest_url = Some(manifest_url.clone());
            inner.manifest = Some(manifest);
            inner.selected = Some(selected);
            inner.transition(UpdateState::UpdateAvailable)?;
            write_config(
                &state.updater.config_file,
                &UpdateConfigFile {
                    manifest_url: Some(manifest_url),
                },
            )?;
        }
        Err(error) => {
            state.updater.set_error(&error).await;
            return Err(map_update_error(error));
        }
    }
    Ok(state.updater.status().await)
}

#[tauri::command]
pub async fn download_update(
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<UpdateStatusDto> {
    state.require_capability(Capability::SettingsManagement)?;
    // Validate before moving the state machine: an early return here used to
    // strand the runtime in `PreparingDownload` with no way back.
    let selected = {
        let mut inner = state.updater.inner.lock().await;
        let selected = inner.selected.clone().ok_or_else(|| {
            CommandError::new("no_update", "Check for updates before starting a download.")
        })?;
        inner.transition(UpdateState::PreparingDownload)?;
        inner.last_error = None;
        selected
    };
    let destination = state
        .updater
        .root_dir
        .join("downloads")
        .join(&selected.filename);
    let record = create_record(
        "remote-control",
        selected_version(&state.updater).await?,
        selected.url.clone(),
        destination.clone(),
        selected.size,
        selected.sha256.clone(),
    );
    let key = download_key(&record.application_id, &record.version, &record.url);
    let handle = state
        .updater
        .manager
        .as_ref()
        .ok_or_else(updater_unavailable)?
        .start(record, None)
        .map_err(map_update_error)?;
    let generation = {
        let mut inner = state.updater.inner.lock().await;
        inner.active_key = Some(key);
        inner.transition(UpdateState::Downloading)?;
        inner.generation = inner.generation.wrapping_add(1);
        inner.generation
    };
    watch_download(&state.updater, handle, selected, generation).await;
    Ok(state.updater.status().await)
}

/// Spawn the task that applies a finished download to the runtime state.
///
/// Shared by `download_update` and `resume_update_download`, which previously
/// carried two near-identical copies of this logic that had already drifted
/// apart in their logging and error handling.
async fn watch_download(
    runtime: &UpdateRuntime,
    handle: tokio::task::JoinHandle<rc_updater::Result<rc_updater::DownloadOutcome>>,
    selected: SelectedArtifact,
    generation: u64,
) {
    let task_runtime = runtime.clone();
    let task = tauri::async_runtime::spawn(async move {
        let runtime = task_runtime;
        let result = handle.await;
        // Verification is CPU-bound and must not run while the state lock is
        // held, so it happens before the lock is taken.
        let applied = match result {
            Ok(Ok(outcome)) => {
                let verified = SignatureVerifier.verify(
                    &outcome.path,
                    selected.package_format,
                    SignaturePolicy {
                        required: selected.signature_required,
                    },
                );
                match verified {
                    Ok(status) => {
                        tracing::info!(
                            ?status,
                            path = %outcome.path.display(),
                            "download verified and ready to install"
                        );
                        Ok(outcome.path)
                    }
                    Err(error) => {
                        tracing::error!(%error, "package signature verification failed");
                        Err((None, safe_update_error_message(&error)))
                    }
                }
            }
            Ok(Err(error)) => {
                let paused = matches!(error, UpdateError::DownloadPaused);
                Err((
                    paused.then_some(UpdateState::Paused),
                    safe_update_error_message(&error),
                ))
            }
            Err(error) => {
                tracing::error!(%error, "download task stopped unexpectedly");
                Err((None, "The download task stopped unexpectedly.".to_string()))
            }
        };

        let mut inner = runtime.inner.lock().await;
        if inner.generation != generation {
            // The user cancelled or started another check while this transfer
            // was finishing. Its result is stale and must not be applied.
            tracing::debug!(
                generation,
                current = inner.generation,
                "discarding the result of a superseded download"
            );
            return;
        }
        match applied {
            Ok(path) => {
                if let Err(error) = inner.transition(UpdateState::Verifying) {
                    tracing::warn!(?error, "could not enter the verifying state");
                }
                match inner.transition(UpdateState::ReadyToInstall) {
                    Ok(()) => {
                        inner.ready_path = Some(path);
                        inner.last_error = None;
                    }
                    Err(error) => {
                        tracing::warn!(?error, "verified download could not be marked ready");
                        inner.fail("The verified update could not be made ready.".to_string());
                    }
                }
            }
            Err((Some(paused), message)) => {
                if inner.transition(paused).is_ok() {
                    inner.last_error = Some(message);
                }
            }
            Err((None, message)) => inner.fail(message),
        }
    });
    let mut inner = runtime.inner.lock().await;
    inner.active_task = Some(task);
}

#[tauri::command]
pub async fn pause_update_download(
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<UpdateStatusDto> {
    state.require_capability(Capability::SettingsManagement)?;
    let key = active_key(&state.updater).await?;
    state
        .updater
        .manager
        .as_ref()
        .ok_or_else(updater_unavailable)?
        .pause(&key)
        .map_err(map_update_error)?;
    // The download task itself moves the state to `Paused` once it observes the
    // command, so this only records the user's intent when it is legal.
    {
        let mut inner = state.updater.inner.lock().await;
        if inner.state() == UpdateState::Downloading {
            inner.transition(UpdateState::Paused)?;
        }
    }
    Ok(state.updater.status().await)
}

#[tauri::command]
pub async fn resume_update_download(
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<UpdateStatusDto> {
    state.require_capability(Capability::SettingsManagement)?;
    let key = active_key(&state.updater).await?;
    let selected = selected_artifact(&state.updater).await?;
    let handle = state
        .updater
        .manager
        .as_ref()
        .ok_or_else(updater_unavailable)?
        .resume(&key, None)
        .map_err(map_update_error)?;
    let generation = {
        let mut inner = state.updater.inner.lock().await;
        inner.transition(UpdateState::Resuming)?;
        inner.transition(UpdateState::Downloading)?;
        inner.generation = inner.generation.wrapping_add(1);
        inner.last_error = None;
        inner.generation
    };
    watch_download(&state.updater, handle, selected, generation).await;
    Ok(state.updater.status().await)
}

#[tauri::command]
pub async fn cancel_update_download(
    delete_partial: bool,
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<UpdateStatusDto> {
    state.require_capability(Capability::SettingsManagement)?;
    let key = active_key(&state.updater).await?;
    state
        .updater
        .manager
        .as_ref()
        .ok_or_else(updater_unavailable)?
        .cancel(&key, delete_partial)
        .map_err(map_update_error)?;
    // Invalidate the in-flight task first so its result is discarded, then wait
    // for it to exit. The wait matters because the download manager only frees
    // the key's slot when the task ends; starting a new download for the same
    // artifact before then fails with `DuplicateDownload`.
    let task = {
        let mut inner = state.updater.inner.lock().await;
        inner.generation = inner.generation.wrapping_add(1);
        inner.active_task.take()
    };
    if let Some(task) = task
        && tokio::time::timeout(CANCEL_DRAIN_TIMEOUT, task)
            .await
            .is_err()
    {
        tracing::warn!("the cancelled download task did not stop within the drain timeout");
    }
    let mut inner = state.updater.inner.lock().await;
    inner.transition(UpdateState::UpdateAvailable)?;
    inner.active_key = None;
    inner.ready_path = None;
    inner.last_error = None;
    Ok(state.updater.status().await)
}

#[tauri::command]
pub async fn install_update(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<InstallResultDto> {
    state.require_capability(Capability::SettingsManagement)?;
    let _install_guard = state.updater.install_lock.lock().await;
    let (path, selected, version) = {
        let mut inner = state.updater.inner.lock().await;
        if inner.state() != UpdateState::ReadyToInstall {
            return Err(CommandError::new(
                "not_ready",
                "A verified update must be ready before installation can start.",
            ));
        }
        // Everything needed for the install is gathered before the state moves,
        // so a missing field cannot strand the runtime mid-transition.
        let path = inner.ready_path.clone().ok_or_else(|| {
            CommandError::new("not_ready", "No verified installer is ready to install.")
        })?;
        let selected = inner
            .selected
            .clone()
            .ok_or_else(|| CommandError::new("not_ready", "No update metadata is available."))?;
        let version = inner
            .manifest
            .as_ref()
            .map(|manifest| manifest.version.clone())
            .ok_or_else(|| CommandError::new("not_ready", "No update version is available."))?;
        inner.transition(UpdateState::WaitingForUserConfirmation)?;
        inner.transition(UpdateState::Installing)?;
        (path, selected, version)
    };
    tracing::info!(path = %path.display(), format = ?selected.package_format, "installation started after user confirmation");
    // A failed install must leave a recoverable state behind. Returning the
    // error directly used to strand the runtime in `Installing`, which disabled
    // every button in the UI until the application was restarted.
    let outcome = match install_verified_artifact(
        &state.updater.root_dir,
        &path,
        selected.package_format,
        &version,
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            let mut inner = state.updater.inner.lock().await;
            inner.fail(safe_update_error_message(&error));
            drop(inner);
            return Err(map_update_error(error));
        }
    };
    if selected.package_format == PackageFormat::TarGz {
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            app.exit(0);
        });
    }
    {
        let mut inner = state.updater.inner.lock().await;
        let settled = if outcome.restart_required {
            UpdateState::RestartRequired
        } else {
            UpdateState::Completed
        };
        inner.transition(settled)?;
        inner.last_error = None;
    }
    Ok(InstallResultDto {
        restart_required: outcome.restart_required,
        message: outcome.message,
    })
}

async fn resolve_manifest_url(runtime: &UpdateRuntime, provided: Option<String>) -> String {
    let saved = {
        let inner = runtime.inner.lock().await;
        inner.manifest_url.clone()
    };
    pick_metadata_url(
        provided.as_deref(),
        std::env::var("RC_UPDATE_MANIFEST_URL").ok().as_deref(),
        saved.as_deref(),
    )
}

/// Choose the release-metadata URL from the configured sources, most specific
/// first, falling back to the URL compiled into the build.
///
/// Kept free of I/O so the precedence rules can be tested directly instead of
/// through process-wide environment mutation.
fn pick_metadata_url(
    provided: Option<&str>,
    from_env: Option<&str>,
    saved: Option<&str>,
) -> String {
    [provided, from_env, saved]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|url| !url.is_empty())
        .unwrap_or(DEFAULT_METADATA_URL)
        .to_string()
}

async fn fetch_and_select_manifest(
    metadata_url: &str,
) -> rc_updater::Result<(ReleaseManifest, SelectedArtifact)> {
    let policy = manifest_policy();
    validate_release_url(metadata_url, &policy)?;
    let signature_policy = manifest_signature_policy();
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(20))
        .build()?;
    let bytes = fetch_signed_metadata(&client, metadata_url, &signature_policy, &policy).await?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if value.get("releases").is_some() {
        let index = ReleaseIndex::parse(&bytes, &policy)?;
        let platform = PlatformInfo::detect();
        let Some(entry) = index.select_latest_compatible(
            &platform,
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_VERSION"),
            &policy,
        )?
        else {
            return Err(UpdateError::IncompatiblePlatform(format!(
                "no compatible update newer than {} is available for {}",
                env!("CARGO_PKG_VERSION"),
                platform.key.0
            )));
        };
        let manifest_bytes =
            fetch_signed_metadata(&client, &entry.manifest_url, &signature_policy, &policy).await?;
        if let Some(expected) = &entry.manifest_sha256 {
            let actual = hex::encode(Sha256::digest(&manifest_bytes));
            if !actual.eq_ignore_ascii_case(expected) {
                return Err(UpdateError::InvalidManifest(
                    "release index manifest hash does not match fetched manifest".to_string(),
                ));
            }
        }
        let manifest = ReleaseManifest::parse(&manifest_bytes, &policy)?;
        if manifest.version != entry.version {
            return Err(UpdateError::InvalidManifest(format!(
                "release index points to version {}, but manifest is {}",
                entry.version, manifest.version
            )));
        }
        return select_manifest_artifact(manifest, &platform, &policy);
    }

    let manifest = ReleaseManifest::parse(&bytes, &policy)?;
    let platform = PlatformInfo::detect();
    select_manifest_artifact(manifest, &platform, &policy)
}

async fn fetch_signed_metadata(
    client: &reqwest::Client,
    metadata_url: &str,
    signature_policy: &ManifestSignaturePolicy,
    policy: &ManifestPolicy,
) -> rc_updater::Result<Vec<u8>> {
    validate_release_url(metadata_url, policy)?;
    let bytes = client
        .get(metadata_url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let signature =
        fetch_manifest_signature(client, metadata_url, signature_policy, policy).await?;
    ManifestSignatureVerifier.verify(&bytes, signature.as_deref(), signature_policy)?;
    Ok(bytes.to_vec())
}

fn select_manifest_artifact(
    manifest: ReleaseManifest,
    platform: &PlatformInfo,
    policy: &ManifestPolicy,
) -> rc_updater::Result<(ReleaseManifest, SelectedArtifact)> {
    manifest.ensure_updater_supported(env!("CARGO_PKG_VERSION"))?;
    manifest.ensure_os_supported(platform)?;
    let selection = manifest.select_for_platform(platform, policy)?;
    tracing::info!(version = %manifest.version, platform = %selection.platform_key.0, url = %safe_url_for_log(&selection.artifact.url), "update artifact selected");
    let selected = SelectedArtifact {
        filename: selection.filename,
        package_format: selection.package_format,
        url: selection.artifact.url,
        sha256: selection.artifact.sha256,
        size: selection.artifact.size,
        install_size: selection.artifact.install_size,
        signature_required: selection.artifact.signature_required,
    };
    Ok((manifest, selected))
}
fn manifest_policy() -> ManifestPolicy {
    let policy = ManifestPolicy::default();
    if cfg!(debug_assertions) {
        policy.allow_insecure_loopback_for_tests()
    } else {
        policy
    }
}

fn manifest_signature_policy() -> ManifestSignaturePolicy {
    let public_keys_base64 = compile_time_manifest_keys().or_else(|| {
        if cfg!(debug_assertions) {
            runtime_manifest_keys()
        } else {
            None
        }
    });
    match public_keys_base64 {
        Some(public_keys_base64) if !public_keys_base64.is_empty() => {
            ManifestSignaturePolicy::Required { public_keys_base64 }
        }
        None if cfg!(debug_assertions) => ManifestSignaturePolicy::AllowUnsignedForDevelopment,
        _ => ManifestSignaturePolicy::Required {
            public_keys_base64: Vec::new(),
        },
    }
}

fn compile_time_manifest_keys() -> Option<Vec<String>> {
    option_env!("RC_UPDATE_MANIFEST_PUBLIC_KEYS_B64")
        .or(option_env!("RC_UPDATE_MANIFEST_PUBLIC_KEY_B64"))
        .and_then(parse_manifest_keys)
}

fn runtime_manifest_keys() -> Option<Vec<String>> {
    std::env::var("RC_UPDATE_MANIFEST_PUBLIC_KEYS_B64")
        .ok()
        .or_else(|| std::env::var("RC_UPDATE_MANIFEST_PUBLIC_KEY_B64").ok())
        .and_then(|keys| parse_manifest_keys(&keys))
}

fn parse_manifest_keys(keys: &str) -> Option<Vec<String>> {
    let parsed: Vec<_> = keys
        .split(',')
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(str::to_string)
        .collect();
    (!parsed.is_empty()).then_some(parsed)
}

async fn fetch_manifest_signature(
    client: &reqwest::Client,
    manifest_url: &str,
    signature_policy: &ManifestSignaturePolicy,
    manifest_policy: &ManifestPolicy,
) -> rc_updater::Result<Option<String>> {
    if !matches!(signature_policy, ManifestSignaturePolicy::Required { .. }) {
        return Ok(None);
    }
    let signature_url = signature_url_for(manifest_url)?;
    validate_release_url(&signature_url, manifest_policy)?;
    let signature = client
        .get(signature_url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    Ok(Some(signature))
}

fn signature_url_for(manifest_url: &str) -> rc_updater::Result<String> {
    let mut url = reqwest::Url::parse(manifest_url)?;
    let signature_path = format!("{}.sig", url.path());
    url.set_path(&signature_path);
    Ok(url.to_string())
}

fn install_verified_artifact(
    root_dir: &Path,
    path: &Path,
    format: PackageFormat,
    version: &str,
) -> rc_updater::Result<InstallOutcome> {
    if format == PackageFormat::TarGz {
        let current_exe = std::env::current_exe()?;
        let current_dir = std::env::var_os("RC_UPDATE_CURRENT_DIR")
            .map(PathBuf::from)
            .or_else(|| current_exe.parent().map(Path::to_path_buf))
            .ok_or_else(|| {
                UpdateError::InstallFailed("could not locate current app directory".to_string())
            })?;
        let helper = updater_helper_path(&current_exe)?;
        let transaction_id = Uuid::new_v4().to_string();
        let stage_dir = root_dir.join("app.update").join(&transaction_id);
        let backup_dir = root_dir.join("app.old").join(&transaction_id);
        let transaction_file = root_dir
            .join("transactions")
            .join(format!("{transaction_id}.json"));
        rc_updater::helper::prepare_tar_gz_stage(path, &stage_dir)?;
        let launch_executable = current_dir.join(current_exe.file_name().ok_or_else(|| {
            UpdateError::InstallFailed("current executable has no file name".to_string())
        })?);
        let plan = rc_updater::StagedInstallPlan {
            current_dir,
            update_dir: stage_dir,
            backup_dir,
            launch_executable,
            parent_pid: Some(std::process::id()),
            transaction_file: Some(transaction_file.clone()),
            health_check: rc_updater::HealthCheck {
                transaction_id,
                expected_version: version.to_string(),
                args: Vec::new(),
                timeout_ms: 30_000,
            },
        };
        let plan_path = transaction_file.with_extension("plan.json");
        if let Some(parent) = plan_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&plan_path, serde_json::to_vec_pretty(&plan)?)?;
        Command::new(helper).arg("--plan").arg(&plan_path).spawn()?;
        return Ok(InstallOutcome {
            restart_required: true,
            message: "The updater helper has started. The app will close so the verified update can be installed.".to_string(),
        });
    }
    Installer::new(None).install(path, format)
}

fn updater_helper_path(current_exe: &Path) -> rc_updater::Result<PathBuf> {
    if let Some(path) = std::env::var_os("RC_UPDATER_HELPER").map(PathBuf::from)
        && path.is_file()
    {
        return Ok(path);
    }
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    let helper = current_exe.with_file_name(format!("rc-updater-helper{suffix}"));
    if helper.is_file() {
        return Ok(helper);
    }
    Err(UpdateError::InstallFailed(
        "The updater helper executable was not found next to the application.".to_string(),
    ))
}

async fn selected_version(runtime: &UpdateRuntime) -> CommandResult<String> {
    let inner = runtime.inner.lock().await;
    inner
        .manifest
        .as_ref()
        .map(|manifest| manifest.version.clone())
        .ok_or_else(|| {
            CommandError::new("no_update", "Check for updates before starting a download.")
        })
}

async fn selected_artifact(runtime: &UpdateRuntime) -> CommandResult<SelectedArtifact> {
    let inner = runtime.inner.lock().await;
    inner.selected.clone().ok_or_else(|| {
        CommandError::new("no_update", "Check for updates before starting a download.")
    })
}

async fn active_key(runtime: &UpdateRuntime) -> CommandResult<String> {
    let inner = runtime.inner.lock().await;
    inner
        .active_key
        .clone()
        .ok_or_else(|| CommandError::new("no_download", "No update download is active."))
}

fn read_config(path: &Path) -> UpdateConfigFile {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or(UpdateConfigFile { manifest_url: None })
}

fn write_config(path: &Path, config: &UpdateConfigFile) -> CommandResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| CommandError::new("update_config", err.to_string()))?;
    }
    let temp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(config)
        .map_err(|err| CommandError::new("update_config", err.to_string()))?;
    std::fs::write(&temp, json)
        .map_err(|err| CommandError::new("update_config", err.to_string()))?;
    std::fs::rename(temp, path).map_err(|err| CommandError::new("update_config", err.to_string()))
}

#[allow(clippy::cast_precision_loss)]
fn percentage(downloaded: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (downloaded as f64 / total as f64 * 100.0).clamp(0.0, 100.0)
    }
}

#[allow(clippy::needless_pass_by_value)]
fn map_update_error(error: UpdateError) -> CommandError {
    let code = match error {
        UpdateError::InvalidManifest(_) => "invalid_manifest",
        UpdateError::IncompatiblePlatform(_) => "incompatible_platform",
        UpdateError::UnsupportedOs { .. } => "unsupported_os",
        UpdateError::InvalidVersion(_) => "invalid_version",
        UpdateError::DowngradeRefused { .. } => "downgrade_refused",
        UpdateError::MinimumVersionNotMet { .. } => "full_install_required",
        UpdateError::UnsafeUrl(_) => "unsafe_url",
        UpdateError::UnsafeFileName(_) | UpdateError::UnsafePath(_) => "unsafe_path",
        UpdateError::InsufficientDiskSpace { .. } => "insufficient_disk_space",
        UpdateError::StalledDownload => "download_stalled",
        UpdateError::RetriesExhausted { .. } => "download_failed",
        UpdateError::DownloadPaused => "download_paused",
        UpdateError::DownloadCancelled => "download_cancelled",
        UpdateError::ResumeUnsupported => "resume_unsupported",
        UpdateError::InvalidRangeResponse(_) => "invalid_range_response",
        UpdateError::ChecksumMismatch => "checksum_mismatch",
        UpdateError::SignatureFailed(_) | UpdateError::SignatureUnsupported => "signature_failed",
        UpdateError::ManifestSignatureFailed(_) | UpdateError::ManifestSignatureRequired => {
            "manifest_signature_failed"
        }
        UpdateError::IllegalTransition { .. } => "illegal_transition",
        UpdateError::DuplicateDownload => "duplicate_download",
        UpdateError::InstallFailed(_) => "install_failed",
        UpdateError::HealthCheckFailed => "health_check_failed",
        UpdateError::RollbackFailed(_) => "rollback_failed",
        UpdateError::Io(_) => "io_failed",
        UpdateError::Network(_) => "network_failed",
        UpdateError::Json(_) => "json_failed",
        UpdateError::Url(_) => "url_failed",
    };
    let message = safe_update_error_message(&error);
    tracing::error!(code, %error, "update command failed");
    CommandError::new(code, message)
}

fn safe_update_error_message(error: &UpdateError) -> String {
    match error {
        UpdateError::InvalidManifest(_) => {
            "The update metadata is invalid and was rejected.".to_string()
        }
        UpdateError::IncompatiblePlatform(platform) => {
            format!("No update package is available for {platform}.")
        }
        UpdateError::UnsupportedOs { required, current } => format!(
            "This update cannot run on this computer. It requires {required}; your system is {current}."
        ),
        UpdateError::InvalidVersion(_) => {
            "The update metadata contains an invalid version number.".to_string()
        }
        UpdateError::DowngradeRefused { installed, available } => format!(
            "The update server offered older version {available}; this app is already on {installed}."
        ),
        UpdateError::MinimumVersionNotMet { minimum, .. } => format!(
            "This version is too old for an incremental update. Install the full application package for version {minimum} or newer."
        ),
        UpdateError::UnsafeUrl(_) => {
            "The update URL is not allowed. Production updates must use HTTPS.".to_string()
        }
        UpdateError::UnsafeFileName(_) | UpdateError::UnsafePath(_) => {
            "The update metadata contains an unsafe file path and was rejected.".to_string()
        }
        UpdateError::InsufficientDiskSpace {
            required_bytes,
            available_bytes,
        } => format!(
            "There is not enough disk space for this update. Required {required_bytes} bytes, available {available_bytes} bytes."
        ),
        UpdateError::StalledDownload => {
            "Download paused because the server stopped responding. It can be resumed.".to_string()
        }
        UpdateError::RetriesExhausted { .. } => {
            "Download failed after retrying. Check your connection and try again.".to_string()
        }
        UpdateError::DownloadPaused => "Download paused and can be resumed later.".to_string(),
        UpdateError::DownloadCancelled => "Download cancelled.".to_string(),
        UpdateError::ResumeUnsupported | UpdateError::InvalidRangeResponse(_) => {
            "The server could not resume safely, so the download will restart from the beginning.".to_string()
        }
        UpdateError::ChecksumMismatch => {
            "Verification failed. The downloaded installer did not match the expected SHA-256 checksum and was deleted.".to_string()
        }
        UpdateError::SignatureFailed(_)
        | UpdateError::SignatureUnsupported
        | UpdateError::ManifestSignatureFailed(_)
        | UpdateError::ManifestSignatureRequired => {
            "The update signature could not be verified, so installation was blocked.".to_string()
        }
        UpdateError::IllegalTransition { .. } => {
            "The update action is not valid in the current state.".to_string()
        }
        UpdateError::DuplicateDownload => {
            "This version is already downloading.".to_string()
        }
        UpdateError::InstallFailed(_) => {
            "Installation failed. Close the app and any running installer, then try again.".to_string()
        }
        UpdateError::HealthCheckFailed => {
            "The new version failed its startup health check. Rollback was attempted.".to_string()
        }
        UpdateError::RollbackFailed(_) => {
            "Rollback failed. Keep the app closed and restore from the backup before retrying.".to_string()
        }
        UpdateError::Io(_) => "The updater could not read or write one of its files.".to_string(),
        UpdateError::Network(_) => {
            "The update server could not be reached. Check your connection and try again.".to_string()
        }
        UpdateError::Json(_) => "The update metadata could not be parsed.".to_string(),
        UpdateError::Url(_) => "The update URL is not valid.".to_string(),
    }
}

fn safe_url_for_log(raw_url: &str) -> String {
    reqwest::Url::parse(raw_url).map_or_else(
        |_| "<invalid-url>".to_string(),
        |mut url| {
            url.set_query(None);
            url.set_fragment(None);
            url.to_string()
        },
    )
}

fn updater_unavailable() -> CommandError {
    CommandError::new(
        "updater_unavailable",
        "The update database could not be opened. Restart the application and check the logs if this continues.",
    )
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{
        DEFAULT_METADATA_URL, UpdateConfigFile, UpdateRuntime, UpdateState, percentage,
        pick_metadata_url, read_config, resolve_manifest_url, safe_url_for_log, signature_url_for,
        write_config,
    };

    #[test]
    fn a_shipped_build_falls_back_to_the_compiled_in_metadata_url() {
        assert_eq!(pick_metadata_url(None, None, None), DEFAULT_METADATA_URL);
    }

    #[test]
    fn the_compiled_in_metadata_url_points_at_a_signed_release_index() {
        let url = reqwest::Url::parse(DEFAULT_METADATA_URL).expect("default URL must parse");
        assert_eq!(
            url.scheme(),
            "https",
            "metadata must not be fetched over http"
        );
        assert!(
            DEFAULT_METADATA_URL.ends_with("release-index.json"),
            "default metadata must be the release index, got {DEFAULT_METADATA_URL}",
        );
    }

    #[test]
    fn metadata_url_precedence_prefers_the_most_specific_source() {
        assert_eq!(
            pick_metadata_url(
                Some("https://a/i.json"),
                Some("https://b/i.json"),
                Some("https://c/i.json")
            ),
            "https://a/i.json",
        );
        assert_eq!(
            pick_metadata_url(None, Some("https://b/i.json"), Some("https://c/i.json")),
            "https://b/i.json",
        );
        assert_eq!(
            pick_metadata_url(None, None, Some("https://c/i.json")),
            "https://c/i.json"
        );
    }

    #[test]
    fn blank_metadata_urls_are_ignored_rather_than_used() {
        assert_eq!(
            pick_metadata_url(Some("   "), None, None),
            DEFAULT_METADATA_URL
        );
        assert_eq!(
            pick_metadata_url(Some(""), Some("  "), Some("\t")),
            DEFAULT_METADATA_URL
        );
    }

    #[tokio::test]
    async fn an_unconfigured_runtime_still_resolves_a_metadata_url() {
        let dir = tempdir().unwrap();
        let runtime = UpdateRuntime::new(dir.path());
        // The empty-string argument is what the UI sends when the advanced
        // field is left blank, and it must not defeat the default.
        assert_eq!(
            resolve_manifest_url(&runtime, Some(String::new())).await,
            DEFAULT_METADATA_URL,
        );
    }

    #[test]
    fn the_saved_metadata_url_survives_a_restart() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("update-config.json");
        write_config(
            &path,
            &UpdateConfigFile {
                manifest_url: Some("https://example.com/release-index.json".to_string()),
            },
        )
        .unwrap();
        assert_eq!(
            read_config(&path).manifest_url.as_deref(),
            Some("https://example.com/release-index.json"),
        );
    }

    #[test]
    fn an_unreadable_config_falls_back_to_no_saved_url() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("update-config.json");
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(read_config(&path).manifest_url.is_none());
    }

    #[test]
    fn a_build_ships_with_at_least_one_trusted_metadata_key() {
        let keys = super::compile_time_manifest_keys()
            .expect("build.rs must embed the trusted release keys");
        assert!(
            !keys.is_empty(),
            "a build with no trusted key rejects every update check",
        );
        for key in &keys {
            let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, key)
                .unwrap_or_else(|_| panic!("trusted key must be valid base64: {key}"));
            assert_eq!(bytes.len(), 32, "an Ed25519 public key is 32 bytes: {key}");
        }
    }

    #[test]
    fn the_signature_policy_requires_signed_metadata() {
        assert!(
            matches!(
                super::manifest_signature_policy(),
                super::ManifestSignaturePolicy::Required { .. },
            ),
            "unsigned release metadata must never be accepted",
        );
    }

    #[test]
    fn the_signature_url_sits_next_to_the_metadata_it_signs() {
        assert_eq!(
            signature_url_for(DEFAULT_METADATA_URL).unwrap(),
            format!("{DEFAULT_METADATA_URL}.sig"),
        );
    }

    #[test]
    fn logged_urls_do_not_leak_query_parameters() {
        let logged = safe_url_for_log("https://example.com/index.json?token=secret#frag");
        assert!(
            !logged.contains("secret"),
            "token must not reach the logs: {logged}"
        );
        assert!(!logged.contains("frag"));
        assert_eq!(safe_url_for_log("not a url"), "<invalid-url>");
    }

    #[test]
    fn progress_percentage_stays_within_range() {
        assert!((percentage(0, 0) - 0.0).abs() < f64::EPSILON);
        assert!((percentage(5, 10) - 50.0).abs() < f64::EPSILON);
        // A server that reports fewer bytes than it sends must not produce a
        // progress bar wider than the track.
        assert!((percentage(20, 10) - 100.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn a_failed_install_leaves_a_recoverable_state() {
        let dir = tempdir().unwrap();
        let runtime = UpdateRuntime::new(dir.path());
        let mut inner = runtime.inner.lock().await;
        for state in [
            UpdateState::CheckingForUpdates,
            UpdateState::UpdateAvailable,
            UpdateState::PreparingDownload,
            UpdateState::Downloading,
            UpdateState::Verifying,
            UpdateState::ReadyToInstall,
            UpdateState::WaitingForUserConfirmation,
            UpdateState::Installing,
        ] {
            inner.transition(state).unwrap();
        }

        inner.fail("the installer exited with code 1603".to_string());

        assert_eq!(inner.state(), UpdateState::Failed);
        assert_eq!(
            inner.last_error.as_deref(),
            Some("the installer exited with code 1603"),
        );
        // The user must be able to retry rather than restart the application.
        inner.transition(UpdateState::CheckingForUpdates).unwrap();
    }

    #[tokio::test]
    async fn commands_refuse_transitions_the_state_machine_forbids() {
        let dir = tempdir().unwrap();
        let runtime = UpdateRuntime::new(dir.path());
        let mut inner = runtime.inner.lock().await;
        // Pausing with nothing in flight must be refused, not silently applied.
        let error = inner.transition(UpdateState::Paused).unwrap_err();
        assert_eq!(error.code, "invalid_update_state");
        assert_eq!(inner.state(), UpdateState::Idle);
    }

    #[tokio::test]
    async fn a_superseded_download_is_identified_by_its_generation() {
        let dir = tempdir().unwrap();
        let runtime = UpdateRuntime::new(dir.path());
        let mut inner = runtime.inner.lock().await;
        let observed = inner.generation;
        // Cancelling and re-checking both invalidate an in-flight transfer.
        inner.generation = inner.generation.wrapping_add(1);
        assert_ne!(
            observed, inner.generation,
            "a superseded task must be able to detect that it is stale",
        );
    }
}
