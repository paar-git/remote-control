#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::routing::get;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use flate2::Compression;
use flate2::write::GzEncoder;
use rc_updater::download::create_record;
use rc_updater::{
    DownloadConfig, DownloadManager, HealthCheck, Installer, ManifestPolicy,
    ManifestSignaturePolicy, ManifestSignatureVerifier, PackageFormat, PlatformInfo,
    ReleaseManifest, StagedInstallPlan, UpdateDatabase, run_staged_install,
};
use sha2::{Digest, Sha256};
use tar::Builder;
use tempfile::tempdir;

#[derive(Clone)]
struct TestServerState {
    manifest: Arc<Vec<u8>>,
    signature: Arc<String>,
    artifact: Arc<Vec<u8>>,
}

#[tokio::test]
async fn signed_manifest_download_and_staged_update_lifecycle_succeeds() {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let public_key_base64 =
        base64::engine::general_purpose::STANDARD.encode(signing_key.verifying_key().as_bytes());
    let platform = PlatformInfo::detect();
    let artifact = make_tar_gz_with_version("0.2.0");
    let artifact_digest = sha256(&artifact);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let artifact_url = format!("http://{addr}/remote-control-0.2.0.tar.gz");
    let manifest_bytes = format!(
        r#"{{
  "version": "0.2.0",
  "releaseDate": "2026-08-07",
  "minimumSupportedVersion": "0.1.0",
  "minimumUpdaterVersion": "0.1.0",
  "releaseNotes": "integration test",
  "platforms": {{
    "{}": {{
      "artifacts": [{{
        "format": "tar.gz",
        "url": "{}",
        "sha256": "{}",
        "size": {},
        "filename": "remote-control-0.2.0.tar.gz"
      }}]
    }}
  }}
}}"#,
        platform.key.0,
        artifact_url,
        artifact_digest,
        artifact.len()
    )
    .into_bytes();
    let signature = base64::engine::general_purpose::STANDARD
        .encode(signing_key.sign(&manifest_bytes).to_bytes());
    let state = TestServerState {
        manifest: Arc::new(manifest_bytes.clone()),
        signature: Arc::new(signature.clone()),
        artifact: Arc::new(artifact.clone()),
    };
    tokio::spawn(async move {
        let app = Router::new()
            .route("/release-manifest.json", get(manifest))
            .route("/release-manifest.json.sig", get(signature_response))
            .route("/remote-control-0.2.0.tar.gz", get(artifact_response))
            .with_state(state);
        axum::serve(listener, app).await.unwrap();
    });

    let client = reqwest::Client::new();
    let manifest_response = client
        .get(format!("http://{addr}/release-manifest.json"))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let signature_response = client
        .get(format!("http://{addr}/release-manifest.json.sig"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    ManifestSignatureVerifier
        .verify(
            &manifest_response,
            Some(&signature_response),
            &ManifestSignaturePolicy::Required {
                public_keys_base64: vec![public_key_base64],
            },
        )
        .unwrap();
    let policy = ManifestPolicy::default().allow_insecure_loopback_for_tests();
    let release = ReleaseManifest::parse(&manifest_response, &policy).unwrap();
    assert!(release.ensure_update_allowed("0.1.0").unwrap());
    let selection = release.select_for_platform(&platform, &policy).unwrap();

    let dir = tempdir().unwrap();
    let destination = dir.path().join(&selection.filename);
    let database = UpdateDatabase::open(dir.path().join("downloads.json")).unwrap();
    let manager = DownloadManager::new(database, DownloadConfig::default()).unwrap();
    let record = create_record(
        "remote-control",
        &release.version,
        selection.artifact.url,
        destination.clone(),
        selection.artifact.size,
        selection.artifact.sha256,
    );
    let outcome = manager.start(record, None).unwrap().await.unwrap().unwrap();
    assert_eq!(tokio::fs::read(&outcome.path).await.unwrap(), artifact);

    let current = dir.path().join("app");
    let stage = dir.path().join("app.update");
    let backup = dir.path().join("app.old");
    std::fs::create_dir_all(&current).unwrap();
    std::fs::write(current.join("version.txt"), b"0.1.0").unwrap();
    rc_updater::helper::prepare_tar_gz_stage(&destination, &stage).unwrap();
    let plan = StagedInstallPlan {
        current_dir: current.clone(),
        update_dir: stage,
        backup_dir: backup.clone(),
        launch_executable: health_script(dir.path(), "tx-lifecycle", "0.2.0"),
        parent_pid: None,
        transaction_file: Some(dir.path().join("transaction.json")),
        health_check: HealthCheck {
            transaction_id: "tx-lifecycle".to_string(),
            expected_version: "0.2.0".to_string(),
            args: Vec::new(),
            timeout_ms: 2_000,
        },
    };
    run_staged_install(&plan).unwrap();

    assert_eq!(
        std::fs::read_to_string(current.join("version.txt")).unwrap(),
        "0.2.0"
    );
    assert!(!backup.exists());
}

#[test]
fn reusable_full_application_download_install_path_can_install_appimage() {
    let dir = tempdir().unwrap();
    let artifact = dir.path().join("RemoteControl.AppImage");
    std::fs::write(&artifact, b"appimage-bytes").unwrap();
    let install_dir = dir.path().join("fresh-install");

    let outcome = Installer::new(Some(install_dir.clone()))
        .install(&artifact, PackageFormat::AppImage)
        .unwrap();

    assert!(!outcome.restart_required);
    assert_eq!(
        std::fs::read(install_dir.join("RemoteControl.AppImage")).unwrap(),
        b"appimage-bytes"
    );
}

async fn manifest(State(state): State<TestServerState>) -> Response {
    Response::builder()
        .header(header::CONTENT_LENGTH, state.manifest.len().to_string())
        .body(Body::from(state.manifest.as_ref().clone()))
        .unwrap()
}

async fn signature_response(State(state): State<TestServerState>) -> Response {
    Response::builder()
        .body(Body::from(state.signature.as_ref().clone()))
        .unwrap()
}

async fn artifact_response(State(state): State<TestServerState>, headers: HeaderMap) -> Response {
    let start = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("bytes="))
        .and_then(|value| value.strip_suffix('-'))
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let body = state.artifact[start..].to_vec();
    let mut builder = Response::builder();
    if start > 0 {
        builder = builder.status(StatusCode::PARTIAL_CONTENT).header(
            header::CONTENT_RANGE,
            format!(
                "bytes {start}-{}/{}",
                state.artifact.len() - 1,
                state.artifact.len()
            ),
        );
    }
    builder
        .header(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"))
        .header(header::CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .unwrap()
}

fn make_tar_gz_with_version(version: &str) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = Builder::new(encoder);
    let bytes = version.as_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_path("version.txt").unwrap();
    header.set_size(bytes.len() as u64);
    header.set_cksum();
    builder.append(&header, bytes).unwrap();
    builder.into_inner().unwrap().finish().unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn health_script(dir: &Path, transaction_id: &str, version: &str) -> PathBuf {
    #[cfg(windows)]
    {
        let path = dir.join("health.cmd");
        std::fs::write(
            &path,
            format!(
                "@echo off\r\necho UPDATE_BOOT_OK {{\"transactionId\":\"{transaction_id}\",\"version\":\"{version}\",\"status\":\"healthy\"}}\r\n"
            ),
        )
        .unwrap();
        path
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join("health.sh");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\necho 'UPDATE_BOOT_OK {{\"transactionId\":\"{transaction_id}\",\"version\":\"{version}\",\"status\":\"healthy\"}}'\n"
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).unwrap();
        path
    }
}
