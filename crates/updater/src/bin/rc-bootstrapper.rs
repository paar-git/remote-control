#![allow(missing_docs)]
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use rc_updater::database::{download_key, now_ms};
use rc_updater::disk::{check_disk_space, required_space};
use rc_updater::platform::parse_installation_type;
use rc_updater::{
    ArtifactSelection, DownloadConfig, DownloadEvent, DownloadManager, DownloadOutcome,
    DownloadQueueState, DownloadRecord, Installer, ManifestPolicy, ManifestSignaturePolicy,
    ManifestSignatureVerifier, PackageFormat, PlatformInfo, ReleaseIndex, ReleaseManifest,
    SignaturePolicy, SignatureVerifier, UpdateDatabase, UpdateError, verify_sha256,
};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

#[derive(Debug, Parser)]
#[command(about = "Download and install Remote Control from signed release metadata")]
struct Args {
    #[arg(long, env = "RC_UPDATE_MANIFEST_URL")]
    metadata_url: String,
    #[arg(long, default_value = "remote-control")]
    application_id: String,
    #[arg(long, default_value = "0.0.0")]
    current_version: String,
    #[arg(long)]
    install_dir: Option<PathBuf>,
    #[arg(long, default_value = "downloads")]
    download_dir: PathBuf,
    #[arg(long, default_value = "downloads/downloads.json")]
    database: PathBuf,
    #[arg(
        long = "public-key-b64",
        env = "RC_UPDATE_MANIFEST_PUBLIC_KEYS_B64",
        value_delimiter = ','
    )]
    public_keys_b64: Vec<String>,
    #[arg(long, default_value_t = false)]
    allow_unsigned_dev_metadata: bool,
    #[arg(long, default_value_t = false)]
    allow_insecure_loopback: bool,
    #[arg(long)]
    installation_type: Option<String>,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{}", friendly_error(&error));
        eprintln!("technical detail: {error}");
        std::process::exit(1);
    }
}

async fn run() -> rc_updater::Result<()> {
    let args = Args::parse();
    prepare_paths(&args)?;
    let manifest_policy = manifest_policy(&args);
    let signature_policy = signature_policy(&args);
    let platform = detect_bootstrap_platform(&args)?;

    println!("Remote Control bootstrapper");
    println!("Platform: {}", platform.key.0);

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(20))
        .build()?;
    let (manifest, selection) = fetch_release_selection(
        &client,
        &args.metadata_url,
        &signature_policy,
        &manifest_policy,
        &platform,
        &args.current_version,
    )
    .await?;

    announce_selection(&manifest, &selection);
    let outcome = download_and_verify(&args, &manifest, &selection).await?;
    if !confirm_install(&outcome.path)? {
        return Ok(());
    }
    install_download(&args, &outcome.path, selection.package_format)
}

fn prepare_paths(args: &Args) -> rc_updater::Result<()> {
    std::fs::create_dir_all(&args.download_dir)?;
    if let Some(parent) = args.database.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn manifest_policy(args: &Args) -> ManifestPolicy {
    if args.allow_insecure_loopback {
        ManifestPolicy::default().allow_insecure_loopback_for_tests()
    } else {
        ManifestPolicy::default()
    }
}

fn signature_policy(args: &Args) -> ManifestSignaturePolicy {
    if args.allow_unsigned_dev_metadata {
        ManifestSignaturePolicy::AllowUnsignedForDevelopment
    } else {
        ManifestSignaturePolicy::Required {
            public_keys_base64: args.public_keys_b64.clone(),
        }
    }
}

fn detect_bootstrap_platform(args: &Args) -> rc_updater::Result<PlatformInfo> {
    let mut platform = PlatformInfo::detect();
    if let Some(value) = &args.installation_type {
        let installation_type = parse_installation_type(value).ok_or_else(|| {
            UpdateError::IncompatiblePlatform(format!("unsupported installation type `{value}`"))
        })?;
        platform = platform.with_installation_type(installation_type);
    }
    Ok(platform)
}

fn announce_selection(manifest: &ReleaseManifest, selection: &ArtifactSelection) {
    println!("Ready to download");
    println!("Version: {}", manifest.version);
    println!(
        "Artifact: {} ({})",
        selection.filename,
        selection.package_format.manifest_name()
    );
    println!("Size: {} bytes", selection.artifact.size);
}

async fn download_and_verify(
    args: &Args,
    manifest: &ReleaseManifest,
    selection: &ArtifactSelection,
) -> rc_updater::Result<DownloadOutcome> {
    let required = required_space(selection.artifact.size, selection.artifact.install_size);
    check_disk_space(&args.download_dir, required)?;
    let record = download_record(args, manifest, selection);
    let database = UpdateDatabase::open_resilient(&args.database)?;
    let manager = DownloadManager::new(database, DownloadConfig::default())?;
    let outcome = run_download(&manager, record).await?;
    verify_sha256(&outcome.path, &selection.artifact.sha256).await?;
    SignatureVerifier.verify(
        &outcome.path,
        selection.package_format,
        SignaturePolicy {
            required: selection.artifact.signature_required,
        },
    )?;
    Ok(outcome)
}

fn download_record(
    args: &Args,
    manifest: &ReleaseManifest,
    selection: &ArtifactSelection,
) -> DownloadRecord {
    let destination = args.download_dir.join(&selection.filename);
    let part_path = part_path_for(&destination);
    DownloadRecord {
        application_id: args.application_id.clone(),
        version: manifest.version.clone(),
        url: selection.artifact.url.clone(),
        destination_path: destination,
        part_path,
        expected_size: selection.artifact.size,
        downloaded_bytes: 0,
        sha256: selection.artifact.sha256.clone(),
        state: DownloadQueueState::Queued,
        retry_count: 0,
        created_at_ms: now_ms(),
        updated_at_ms: now_ms(),
        etag: None,
        last_modified: None,
    }
}

fn part_path_for(destination: &Path) -> PathBuf {
    destination.with_extension(format!(
        "{}.part",
        destination
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("download")
    ))
}

async fn run_download(
    manager: &DownloadManager,
    record: DownloadRecord,
) -> rc_updater::Result<DownloadOutcome> {
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<DownloadEvent>();
    let printer = tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            print_progress(&event);
        }
    });
    let key = download_key(&record.application_id, &record.version, &record.url);
    let handle = match manager.start(record, Some(event_tx)) {
        Ok(handle) => handle,
        Err(error) => {
            printer.abort();
            return Err(error);
        }
    };
    let outcome = handle
        .await
        .map_err(|error| UpdateError::InstallFailed(error.to_string()))??;
    printer.abort();
    println!();
    if let Some(record) = manager.record(&key) {
        println!("Download state: {:?}", record.state);
    }
    Ok(outcome)
}

fn confirm_install(path: &Path) -> rc_updater::Result<bool> {
    println!("Ready to install");
    println!("The application was downloaded and verified successfully.");
    println!("Type `install` and press Enter to install now, or anything else to exit.");
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if answer.trim() == "install" {
        Ok(true)
    } else {
        println!(
            "Installation deferred. The verified installer remains at {}.",
            path.display()
        );
        Ok(false)
    }
}

fn install_download(args: &Args, artifact: &Path, format: PackageFormat) -> rc_updater::Result<()> {
    let installer = Installer::new(args.install_dir.clone());
    let result = installer.install(artifact, format)?;
    println!("{}", result.message);
    if result.restart_required {
        println!("Restart is required before the installed version is fully active.");
    }
    Ok(())
}

async fn fetch_release_selection(
    client: &reqwest::Client,
    metadata_url: &str,
    signature_policy: &ManifestSignaturePolicy,
    manifest_policy: &ManifestPolicy,
    platform: &PlatformInfo,
    current_version: &str,
) -> rc_updater::Result<(ReleaseManifest, ArtifactSelection)> {
    let metadata_bytes =
        fetch_signed_metadata(client, metadata_url, signature_policy, manifest_policy).await?;
    let value: serde_json::Value = serde_json::from_slice(&metadata_bytes)?;
    let manifest_bytes = if value.get("releases").is_some() {
        manifest_from_index(
            client,
            &metadata_bytes,
            signature_policy,
            manifest_policy,
            platform,
            current_version,
        )
        .await?
    } else {
        metadata_bytes
    };
    select_manifest_artifact(&manifest_bytes, manifest_policy, platform)
}

async fn manifest_from_index(
    client: &reqwest::Client,
    metadata_bytes: &[u8],
    signature_policy: &ManifestSignaturePolicy,
    manifest_policy: &ManifestPolicy,
    platform: &PlatformInfo,
    current_version: &str,
) -> rc_updater::Result<Vec<u8>> {
    let index = ReleaseIndex::parse(metadata_bytes, manifest_policy)?;
    let entry = index
        .select_latest_compatible(
            platform,
            current_version,
            env!("CARGO_PKG_VERSION"),
            manifest_policy,
        )?
        .ok_or_else(|| {
            UpdateError::IncompatiblePlatform(format!(
                "no compatible release is available for {}",
                platform.key.0
            ))
        })?;
    let manifest_bytes = fetch_signed_metadata(
        client,
        &entry.manifest_url,
        signature_policy,
        manifest_policy,
    )
    .await?;
    if let Some(expected) = &entry.manifest_sha256 {
        let actual = hex::encode(Sha256::digest(&manifest_bytes));
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(UpdateError::InvalidManifest(
                "release index manifest hash does not match fetched manifest".to_string(),
            ));
        }
    }
    Ok(manifest_bytes)
}

fn select_manifest_artifact(
    manifest_bytes: &[u8],
    manifest_policy: &ManifestPolicy,
    platform: &PlatformInfo,
) -> rc_updater::Result<(ReleaseManifest, ArtifactSelection)> {
    let manifest = ReleaseManifest::parse(manifest_bytes, manifest_policy)?;
    manifest.ensure_updater_supported(env!("CARGO_PKG_VERSION"))?;
    manifest.ensure_os_supported(platform)?;
    let selection = manifest.select_for_platform(platform, manifest_policy)?;
    if matches!(selection.package_format, PackageFormat::TarGz) {
        return Err(UpdateError::InstallFailed(
            "tar.gz releases require the staged updater helper and are not supported by the bootstrapper installer".to_string(),
        ));
    }
    Ok((manifest, selection))
}

async fn fetch_signed_metadata(
    client: &reqwest::Client,
    url: &str,
    signature_policy: &ManifestSignaturePolicy,
    manifest_policy: &ManifestPolicy,
) -> rc_updater::Result<Vec<u8>> {
    rc_updater::manifest::validate_release_url(url, manifest_policy)?;
    let bytes = client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let signature = match signature_policy {
        ManifestSignaturePolicy::AllowUnsignedForDevelopment => None,
        ManifestSignaturePolicy::Required { .. } => {
            Some(fetch_signature(client, url, manifest_policy).await?)
        }
    };
    ManifestSignatureVerifier.verify(&bytes, signature.as_deref(), signature_policy)?;
    Ok(bytes.to_vec())
}

async fn fetch_signature(
    client: &reqwest::Client,
    url: &str,
    manifest_policy: &ManifestPolicy,
) -> rc_updater::Result<String> {
    let signature_url = format!("{url}.sig");
    rc_updater::manifest::validate_release_url(&signature_url, manifest_policy)?;
    Ok(client
        .get(signature_url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?)
}

fn print_progress(event: &DownloadEvent) {
    let percent = percent_label(event.downloaded_bytes, event.total_bytes);
    let eta = event
        .eta_secs
        .map_or_else(|| "unknown".to_string(), |seconds| format!("{seconds}s"));
    print!(
        "\rDownloading: {} / {} bytes ({percent}) {:.1} MB/s ETA {eta}     ",
        event.downloaded_bytes,
        event.total_bytes,
        event.current_speed_bytes_per_sec / 1024.0 / 1024.0,
    );
    let _ = io::stdout().flush();
}

fn percent_label(downloaded_bytes: u64, total_bytes: u64) -> String {
    if total_bytes == 0 {
        return "unknown".to_string();
    }
    let tenths = downloaded_bytes.saturating_mul(1000) / total_bytes;
    format!("{}.{:01}%", tenths / 10, tenths % 10)
}

fn friendly_error(error: &UpdateError) -> String {
    match error {
        UpdateError::ManifestSignatureRequired | UpdateError::ManifestSignatureFailed(_) => {
            "The release metadata signature could not be verified, so installation was blocked."
                .to_string()
        }
        UpdateError::ChecksumMismatch => {
            "The downloaded installer did not match the expected checksum and was rejected."
                .to_string()
        }
        UpdateError::UnsafeUrl(_) => {
            "The release metadata or installer URL is not allowed. Production downloads must use HTTPS."
                .to_string()
        }
        UpdateError::InsufficientDiskSpace {
            required_bytes,
            available_bytes,
        } => format!(
            "There is not enough disk space. Required {required_bytes} bytes, available {available_bytes} bytes."
        ),
        UpdateError::UnsupportedOs { required, current } => {
            format!("This release requires {required}; this computer is {current}.")
        }
        UpdateError::InstallFailed(message) => format!("Installation failed: {message}"),
        _ => "The application could not be downloaded or installed.".to_string(),
    }
}
