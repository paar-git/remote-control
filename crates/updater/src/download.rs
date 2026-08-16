use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::header::{
    CONTENT_LENGTH, CONTENT_RANGE, ETAG, HeaderMap, IF_RANGE, LAST_MODIFIED, RANGE,
};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, watch};

use crate::database::{DownloadRecord, UpdateDatabase, download_key, now_ms};
use crate::error::{Result, UpdateError};
use crate::integrity::verify_sha256;
use crate::state::DownloadQueueState;

#[derive(Debug, Clone)]
pub struct DownloadConfig {
    pub retry_limit: u32,
    pub connection_timeout: Duration,
    pub stalled_timeout: Duration,
    pub retry_backoff: Duration,
}

impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            retry_limit: 3,
            connection_timeout: Duration::from_secs(20),
            stalled_timeout: Duration::from_secs(30),
            retry_backoff: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadCommand {
    Running,
    Paused,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadEvent {
    pub key: String,
    pub state: DownloadQueueState,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    pub current_speed_bytes_per_sec: f64,
    pub average_speed_bytes_per_sec: f64,
    pub eta_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadOutcome {
    pub key: String,
    pub path: PathBuf,
    pub bytes: u64,
}

#[derive(Clone)]
pub struct DownloadManager {
    client: reqwest::Client,
    database: Arc<Mutex<UpdateDatabase>>,
    active: Arc<Mutex<BTreeMap<String, watch::Sender<DownloadCommand>>>>,
    config: DownloadConfig,
}

impl DownloadManager {
    pub fn new(database: UpdateDatabase, config: DownloadConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(config.connection_timeout)
            .build()?;
        Ok(Self {
            client,
            database: Arc::new(Mutex::new(database)),
            active: Arc::new(Mutex::new(BTreeMap::new())),
            config,
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn start(
        &self,
        record: DownloadRecord,
        events: Option<mpsc::UnboundedSender<DownloadEvent>>,
    ) -> Result<tokio::task::JoinHandle<Result<DownloadOutcome>>> {
        let key = download_key(&record.application_id, &record.version, &record.url);
        let (control_tx, control_rx) = watch::channel(DownloadCommand::Running);
        {
            let mut active = self
                .active
                .lock()
                .map_err(|_| UpdateError::DuplicateDownload)?;
            if active.contains_key(&key) {
                return Err(UpdateError::DuplicateDownload);
            }
            active.insert(key.clone(), control_tx);
        }
        let effective_record = {
            let mut database = self
                .database
                .lock()
                .map_err(|_| UpdateError::DuplicateDownload)?;
            let effective_record = database
                .get(&key)
                .filter(|existing| can_reuse_record(existing, &record))
                .cloned()
                .unwrap_or_else(|| record.clone());
            database.upsert(key.clone(), effective_record.clone())?;
            effective_record
        };
        let manager = self.clone();
        Ok(tokio::spawn(async move {
            let result = manager
                .run_with_retries(key.clone(), effective_record, control_rx, events)
                .await;
            if let Ok(mut active) = manager.active.lock() {
                active.remove(&key);
            }
            result
        }))
    }

    pub fn pause(&self, key: &str) -> Result<()> {
        self.send(key, DownloadCommand::Paused)
    }

    pub fn resume(
        &self,
        key: &str,
        events: Option<mpsc::UnboundedSender<DownloadEvent>>,
    ) -> Result<tokio::task::JoinHandle<Result<DownloadOutcome>>> {
        let record = {
            let database = self
                .database
                .lock()
                .map_err(|_| UpdateError::DuplicateDownload)?;
            database.get(key).cloned().ok_or_else(|| {
                UpdateError::InstallFailed("download record was not found".to_string())
            })?
        };
        self.start(record, events)
    }

    pub fn cancel(&self, key: &str, delete_partial: bool) -> Result<()> {
        self.send(key, DownloadCommand::Cancelled)?;
        if delete_partial {
            let removed = {
                let mut database = self
                    .database
                    .lock()
                    .map_err(|_| UpdateError::DuplicateDownload)?;
                database.remove(key)?
            };
            if let Some(record) = removed {
                let _ = std::fs::remove_file(record.part_path);
            }
        }
        Ok(())
    }

    pub fn record(&self, key: &str) -> Option<DownloadRecord> {
        self.database
            .lock()
            .ok()
            .and_then(|database| database.get(key).cloned())
    }

    fn send(&self, key: &str, command: DownloadCommand) -> Result<()> {
        let active = self
            .active
            .lock()
            .map_err(|_| UpdateError::DuplicateDownload)?;
        let sender = active
            .get(key)
            .ok_or_else(|| UpdateError::InstallFailed("download is not active".to_string()))?;
        sender
            .send(command)
            .map_err(|_| UpdateError::DownloadCancelled)
    }

    async fn run_with_retries(
        &self,
        key: String,
        record: DownloadRecord,
        control_rx: watch::Receiver<DownloadCommand>,
        events: Option<mpsc::UnboundedSender<DownloadEvent>>,
    ) -> Result<DownloadOutcome> {
        let mut attempts = 0;
        loop {
            match self
                .run_attempt(&key, record.clone(), control_rx.clone(), events.clone())
                .await
            {
                Ok(outcome) => return Ok(outcome),
                Err(
                    err @ (UpdateError::DownloadPaused
                    | UpdateError::DownloadCancelled
                    | UpdateError::ChecksumMismatch),
                ) => {
                    return Err(err);
                }
                Err(err) => {
                    attempts += 1;
                    self.update_record(&key, |record| {
                        record.retry_count = attempts;
                        record.state = DownloadQueueState::WaitingForNetwork;
                    })?;
                    if attempts > self.config.retry_limit {
                        self.update_record(&key, |record| {
                            record.state = DownloadQueueState::Failed;
                        })?;
                        return Err(UpdateError::RetriesExhausted {
                            attempts,
                            source: Box::new(err),
                        });
                    }
                    tracing::warn!(attempts, %err, "download attempt failed; retrying");
                    tokio::time::sleep(self.config.retry_backoff).await;
                }
            }
        }
    }

    #[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
    async fn run_attempt(
        &self,
        key: &str,
        mut record: DownloadRecord,
        mut control_rx: watch::Receiver<DownloadCommand>,
        events: Option<mpsc::UnboundedSender<DownloadEvent>>,
    ) -> Result<DownloadOutcome> {
        if record.destination_path.exists() {
            match verify_sha256(&record.destination_path, &record.sha256).await {
                Ok(_) => {
                    self.update_record(key, |record| {
                        record.downloaded_bytes = record.expected_size;
                        record.state = DownloadQueueState::Completed;
                    })?;
                    return Ok(DownloadOutcome {
                        key: key.to_string(),
                        path: record.destination_path,
                        bytes: record.expected_size,
                    });
                }
                Err(_) => {
                    let _ = tokio::fs::remove_file(&record.destination_path).await;
                }
            }
        }

        if let Some(parent) = record.part_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut downloaded = match tokio::fs::metadata(&record.part_path).await {
            Ok(metadata) if metadata.len() > record.expected_size => {
                tracing::warn!(
                    path = %record.part_path.display(),
                    part_bytes = metadata.len(),
                    expected_bytes = record.expected_size,
                    "partial download is larger than expected; restarting from zero"
                );
                tokio::fs::write(&record.part_path, &[]).await?;
                0
            }
            Ok(metadata) => metadata.len(),
            Err(_) => 0,
        };

        let mut request = self.client.get(&record.url);
        if downloaded > 0 {
            request = request.header(RANGE, format!("bytes={downloaded}-"));
            if let Some(etag) = &record.etag {
                request = request.header(IF_RANGE, etag);
            }
        }

        self.update_record(key, |record| {
            record.downloaded_bytes = downloaded;
            record.state = DownloadQueueState::Downloading;
        })?;

        let response = tokio::select! {
            result = request.send() => result?,
            changed = control_rx.changed() => {
                let _ = changed;
                match *control_rx.borrow() {
                    DownloadCommand::Paused => {
                        self.update_record(key, |record| {
                            record.downloaded_bytes = downloaded;
                            record.state = DownloadQueueState::Paused;
                        })?;
                        return Err(UpdateError::DownloadPaused);
                    }
                    DownloadCommand::Cancelled => {
                        self.update_record(key, |record| {
                            record.downloaded_bytes = downloaded;
                            record.state = DownloadQueueState::Cancelled;
                        })?;
                        return Err(UpdateError::DownloadCancelled);
                    }
                    DownloadCommand::Running => return Err(UpdateError::DownloadCancelled),
                }
            }
        };
        if downloaded > 0 && response.status() == reqwest::StatusCode::OK {
            tokio::fs::write(&record.part_path, &[]).await?;
            downloaded = 0;
        } else if downloaded > 0 && response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
            return Err(UpdateError::ResumeUnsupported);
        }
        if !(response.status().is_success()
            || response.status() == reqwest::StatusCode::PARTIAL_CONTENT)
        {
            return Err(UpdateError::InstallFailed(format!(
                "download server returned HTTP {}",
                response.status()
            )));
        }
        if downloaded > 0 {
            validate_content_range(response.headers(), downloaded, record.expected_size)?;
            if validators_changed(&record, response.headers()) {
                tokio::fs::write(&record.part_path, &[]).await?;
                self.update_record(key, |record| {
                    record.downloaded_bytes = 0;
                    record.state = DownloadQueueState::Queued;
                    record.etag = None;
                    record.last_modified = None;
                })?;
                return Err(UpdateError::ResumeUnsupported);
            }
        }
        validate_content_length(response.headers(), downloaded, record.expected_size)?;
        remember_validators(&mut record, response.headers());
        self.update_record(key, |stored| {
            stored.etag.clone_from(&record.etag);
            stored.last_modified.clone_from(&record.last_modified);
        })?;

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&record.part_path)
            .await?;
        let start = Instant::now();
        let mut last_tick = Instant::now();
        let mut last_bytes = downloaded;
        let mut response = response;

        loop {
            match *control_rx.borrow() {
                DownloadCommand::Running => {}
                DownloadCommand::Paused => {
                    self.update_record(key, |record| {
                        record.downloaded_bytes = downloaded;
                        record.state = DownloadQueueState::Paused;
                    })?;
                    emit_event(
                        events.as_ref(),
                        key,
                        DownloadQueueState::Paused,
                        downloaded,
                        record.expected_size,
                        0.0,
                        average_speed(downloaded, start),
                        None,
                    );
                    return Err(UpdateError::DownloadPaused);
                }
                DownloadCommand::Cancelled => {
                    self.update_record(key, |record| {
                        record.downloaded_bytes = downloaded;
                        record.state = DownloadQueueState::Cancelled;
                    })?;
                    return Err(UpdateError::DownloadCancelled);
                }
            }

            let chunk = tokio::select! {
                result = tokio::time::timeout(self.config.stalled_timeout, response.chunk()) => {
                    result.map_err(|_| UpdateError::StalledDownload)??
                }
                changed = control_rx.changed() => {
                    let _ = changed;
                    match *control_rx.borrow() {
                        DownloadCommand::Paused => {
                            self.update_record(key, |record| {
                                record.downloaded_bytes = downloaded;
                                record.state = DownloadQueueState::Paused;
                            })?;
                            emit_event(events.as_ref(), key, DownloadQueueState::Paused, downloaded, record.expected_size, 0.0, average_speed(downloaded, start), None);
                            return Err(UpdateError::DownloadPaused);
                        }
                        DownloadCommand::Cancelled => {
                            self.update_record(key, |record| {
                                record.downloaded_bytes = downloaded;
                                record.state = DownloadQueueState::Cancelled;
                            })?;
                            return Err(UpdateError::DownloadCancelled);
                        }
                        DownloadCommand::Running => continue,
                    }
                }
            };
            let Some(chunk) = chunk else {
                break;
            };
            file.write_all(&chunk).await?;
            downloaded = downloaded.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
            let elapsed = last_tick.elapsed().as_secs_f64().max(0.001);
            let current_speed = (downloaded.saturating_sub(last_bytes)) as f64 / elapsed;
            let average_speed = average_speed(downloaded, start);
            let eta = Some(eta(downloaded, record.expected_size, average_speed));
            last_tick = Instant::now();
            last_bytes = downloaded;
            self.update_record(key, |record| {
                record.downloaded_bytes = downloaded;
                record.state = DownloadQueueState::Downloading;
            })?;
            emit_event(
                events.as_ref(),
                key,
                DownloadQueueState::Downloading,
                downloaded,
                record.expected_size,
                current_speed,
                average_speed,
                eta,
            );
        }
        file.flush().await?;
        drop(file);

        if downloaded != record.expected_size {
            return Err(UpdateError::InstallFailed(format!(
                "download size mismatch: expected {} bytes, got {downloaded}",
                record.expected_size
            )));
        }

        verify_sha256(&record.part_path, &record.sha256).await?;
        tokio::fs::rename(&record.part_path, &record.destination_path).await?;
        self.update_record(key, |record| {
            record.downloaded_bytes = downloaded;
            record.state = DownloadQueueState::Completed;
        })?;
        emit_event(
            events.as_ref(),
            key,
            DownloadQueueState::Completed,
            downloaded,
            record.expected_size,
            0.0,
            average_speed(downloaded, start),
            Some(0),
        );
        Ok(DownloadOutcome {
            key: key.to_string(),
            path: record.destination_path,
            bytes: downloaded,
        })
    }

    fn update_record(&self, key: &str, mutate: impl FnOnce(&mut DownloadRecord)) -> Result<()> {
        let mut database = self
            .database
            .lock()
            .map_err(|_| UpdateError::DuplicateDownload)?;
        database.update(key, mutate)
    }
}

pub fn create_record(
    application_id: impl Into<String>,
    version: impl Into<String>,
    url: impl Into<String>,
    destination_path: PathBuf,
    expected_size: u64,
    sha256: impl Into<String>,
) -> DownloadRecord {
    let now = now_ms();
    DownloadRecord {
        application_id: application_id.into(),
        version: version.into(),
        url: url.into(),
        part_path: destination_path.with_extension(format!(
            "{}part",
            destination_path
                .extension()
                .and_then(|extension| extension.to_str())
                .map_or_else(String::new, |extension| format!("{extension}."))
        )),
        destination_path,
        expected_size,
        downloaded_bytes: 0,
        sha256: sha256.into(),
        state: DownloadQueueState::Queued,
        retry_count: 0,
        created_at_ms: now,
        updated_at_ms: now,
        etag: None,
        last_modified: None,
    }
}

fn can_reuse_record(existing: &DownloadRecord, requested: &DownloadRecord) -> bool {
    existing.application_id == requested.application_id
        && existing.version == requested.version
        && existing.url == requested.url
        && existing.destination_path == requested.destination_path
        && existing.part_path == requested.part_path
        && existing.expected_size == requested.expected_size
        && existing.sha256.eq_ignore_ascii_case(&requested.sha256)
}

fn validate_content_length(
    headers: &HeaderMap,
    already_downloaded: u64,
    expected: u64,
) -> Result<()> {
    let Some(length) = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return Ok(());
    };
    let remaining = expected.saturating_sub(already_downloaded);
    if length > remaining {
        return Err(UpdateError::InvalidRangeResponse(format!(
            "content length {length} exceeds remaining bytes {remaining}"
        )));
    }
    Ok(())
}

fn validate_content_range(
    headers: &HeaderMap,
    requested_start: u64,
    expected_total: u64,
) -> Result<()> {
    let value = headers
        .get(CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| UpdateError::InvalidRangeResponse("missing Content-Range".to_string()))?;
    let range = value
        .strip_prefix("bytes ")
        .ok_or_else(|| UpdateError::InvalidRangeResponse(value.to_string()))?;
    let (span, total) = range
        .split_once('/')
        .ok_or_else(|| UpdateError::InvalidRangeResponse(value.to_string()))?;
    let (start, end) = span
        .split_once('-')
        .ok_or_else(|| UpdateError::InvalidRangeResponse(value.to_string()))?;
    let start = start
        .parse::<u64>()
        .map_err(|_| UpdateError::InvalidRangeResponse(value.to_string()))?;
    let end = end
        .parse::<u64>()
        .map_err(|_| UpdateError::InvalidRangeResponse(value.to_string()))?;
    let total = total
        .parse::<u64>()
        .map_err(|_| UpdateError::InvalidRangeResponse(value.to_string()))?;
    if start != requested_start || end < start || total != expected_total {
        return Err(UpdateError::InvalidRangeResponse(value.to_string()));
    }
    Ok(())
}

fn validators_changed(record: &DownloadRecord, headers: &HeaderMap) -> bool {
    let etag_changed = record.etag.as_deref().is_some_and(|etag| {
        headers
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|remote| remote != etag)
    });
    let modified_changed = record
        .last_modified
        .as_deref()
        .is_some_and(|last_modified| {
            headers
                .get(LAST_MODIFIED)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|remote| remote != last_modified)
        });
    etag_changed || modified_changed
}

fn remember_validators(record: &mut DownloadRecord, headers: &HeaderMap) {
    if let Some(etag) = headers.get(ETAG).and_then(|value| value.to_str().ok()) {
        record.etag = Some(etag.to_string());
    }
    if let Some(last_modified) = headers
        .get(LAST_MODIFIED)
        .and_then(|value| value.to_str().ok())
    {
        record.last_modified = Some(last_modified.to_string());
    }
    let _ = headers.get(CONTENT_LENGTH);
}

fn emit_event(
    events: Option<&mpsc::UnboundedSender<DownloadEvent>>,
    key: &str,
    state: DownloadQueueState,
    downloaded_bytes: u64,
    total_bytes: u64,
    current_speed_bytes_per_sec: f64,
    average_speed_bytes_per_sec: f64,
    eta_secs: Option<u64>,
) {
    if let Some(events) = events {
        let _ = events.send(DownloadEvent {
            key: key.to_string(),
            state,
            downloaded_bytes,
            total_bytes,
            current_speed_bytes_per_sec,
            average_speed_bytes_per_sec,
            eta_secs,
        });
    }
}

#[allow(clippy::cast_precision_loss)]
fn average_speed(downloaded: u64, start: Instant) -> f64 {
    downloaded as f64 / start.elapsed().as_secs_f64().max(0.001)
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn eta(downloaded: u64, total: u64, speed: f64) -> u64 {
    if speed <= 0.0 || downloaded >= total {
        return 0;
    }
    ((total - downloaded) as f64 / speed).ceil() as u64
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use axum::Router;
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
    use axum::response::Response;
    use axum::routing::get;
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::{DownloadConfig, DownloadManager, create_record};
    use crate::database::{UpdateDatabase, download_key};
    use crate::error::UpdateError;
    use crate::state::DownloadQueueState;

    #[derive(Clone)]
    struct ServerState {
        bytes: Arc<Vec<u8>>,
        fail_first: bool,
        response_delay_ms: u64,
        calls: Arc<AtomicUsize>,
    }

    async fn start_server(bytes: Vec<u8>, fail_first: bool) -> String {
        start_server_with_delay(bytes, fail_first, 0).await
    }

    async fn start_server_with_delay(
        bytes: Vec<u8>,
        fail_first: bool,
        response_delay_ms: u64,
    ) -> String {
        let state = ServerState {
            bytes: Arc::new(bytes),
            fail_first,
            response_delay_ms,
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let app = Router::new()
            .route("/file", get(file))
            .route("/bad-range", get(bad_range))
            .route("/changed-etag", get(changed_etag))
            .route("/no-range", get(no_range))
            .route("/short", get(short_body))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/file")
    }

    fn sibling_url(url: &str, path: &str) -> String {
        url.strip_suffix("/file").unwrap().to_string() + path
    }

    async fn file(State(state): State<ServerState>, headers: HeaderMap) -> Response {
        if state.response_delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(state.response_delay_ms)).await;
        }
        let call = state.calls.fetch_add(1, Ordering::SeqCst);
        if state.fail_first && call == 0 {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap();
        }
        let start = headers
            .get(header::RANGE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("bytes="))
            .and_then(|value| value.strip_suffix('-'))
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let body = state.bytes[start..].to_vec();
        let mut builder = Response::builder();
        if start > 0 {
            builder = builder.status(StatusCode::PARTIAL_CONTENT).header(
                header::CONTENT_RANGE,
                format!(
                    "bytes {start}-{}/{}",
                    state.bytes.len() - 1,
                    state.bytes.len()
                ),
            );
        }
        builder
            .header(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"))
            .header(header::CONTENT_LENGTH, body.len().to_string())
            .body(Body::from(body))
            .unwrap()
    }

    async fn bad_range(State(state): State<ServerState>, headers: HeaderMap) -> Response {
        let start = headers
            .get(header::RANGE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("bytes="))
            .and_then(|value| value.strip_suffix('-'))
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let body = state.bytes[start..].to_vec();
        Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(
                header::CONTENT_RANGE,
                format!("bytes 0-{}/{}", state.bytes.len() - 1, state.bytes.len()),
            )
            .header(header::CONTENT_LENGTH, body.len().to_string())
            .body(Body::from(body))
            .unwrap()
    }

    async fn changed_etag(State(state): State<ServerState>, headers: HeaderMap) -> Response {
        let mut response = file(State(state), headers).await;
        response
            .headers_mut()
            .insert(header::ETAG, HeaderValue::from_static("\"new\""));
        response
    }

    async fn no_range(State(state): State<ServerState>) -> Response {
        let body = state.bytes.as_ref().clone();
        Response::builder()
            .header(header::CONTENT_LENGTH, body.len().to_string())
            .body(Body::from(body))
            .unwrap()
    }

    async fn short_body(State(state): State<ServerState>) -> Response {
        let body = state.bytes[..state.bytes.len() / 2].to_vec();
        Response::builder()
            .header(header::CONTENT_LENGTH, body.len().to_string())
            .body(Body::from(body))
            .unwrap()
    }

    fn digest(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        hex::encode(digest)
    }

    #[tokio::test]
    async fn downloads_stream_to_part_then_rename_after_checksum() {
        let bytes = b"hello downloader".repeat(1024);
        let url = start_server(bytes.clone(), false).await;
        let dir = tempdir().unwrap();
        let destination = dir.path().join("app.bin");
        let db = UpdateDatabase::open(dir.path().join("db.json")).unwrap();
        let manager = DownloadManager::new(db, DownloadConfig::default()).unwrap();
        let record = create_record(
            "app",
            "1.0.0",
            url,
            destination.clone(),
            bytes.len() as u64,
            digest(&bytes),
        );
        let handle = manager.start(record, None).unwrap();
        let outcome = handle.await.unwrap().unwrap();
        assert_eq!(outcome.path, destination);
        assert_eq!(tokio::fs::read(destination).await.unwrap(), bytes);
    }

    #[tokio::test]
    async fn interrupted_download_resumes_with_range() {
        let bytes = b"resume-me".repeat(4096);
        let url = start_server(bytes.clone(), false).await;
        let dir = tempdir().unwrap();
        let destination = dir.path().join("app.bin");
        let part = destination.with_extension("bin.part");
        tokio::fs::write(&part, &bytes[..100]).await.unwrap();
        let db = UpdateDatabase::open(dir.path().join("db.json")).unwrap();
        let manager = DownloadManager::new(db, DownloadConfig::default()).unwrap();
        let record = create_record(
            "app",
            "1.0.1",
            url,
            destination.clone(),
            bytes.len() as u64,
            digest(&bytes),
        );
        let handle = manager.start(record, None).unwrap();
        handle.await.unwrap().unwrap();
        assert_eq!(tokio::fs::read(destination).await.unwrap(), bytes);
    }

    #[tokio::test]
    async fn persisted_partial_download_resumes_after_manager_restart() {
        let bytes = b"restart-resume".repeat(4096);
        let url = start_server(bytes.clone(), false).await;
        let dir = tempdir().unwrap();
        let destination = dir.path().join("app.bin");
        let part = destination.with_extension("bin.part");
        tokio::fs::write(&part, &bytes[..512]).await.unwrap();
        let key = download_key("app", "1.0.12", &url);
        let db_path = dir.path().join("db.json");
        let mut record = create_record(
            "app",
            "1.0.12",
            url,
            destination.clone(),
            bytes.len() as u64,
            digest(&bytes),
        );
        record.downloaded_bytes = 512;
        record.state = DownloadQueueState::Paused;
        UpdateDatabase::open(&db_path)
            .unwrap()
            .upsert(key.clone(), record)
            .unwrap();

        let db = UpdateDatabase::open(&db_path).unwrap();
        let manager = DownloadManager::new(db, DownloadConfig::default()).unwrap();
        let handle = manager.resume(&key, None).unwrap();

        handle.await.unwrap().unwrap();
        assert_eq!(tokio::fs::read(destination).await.unwrap(), bytes);
    }

    #[tokio::test]
    async fn retries_transient_server_failures() {
        let bytes = b"retry".repeat(4096);
        let url = start_server(bytes.clone(), true).await;
        let dir = tempdir().unwrap();
        let destination = dir.path().join("app.bin");
        let db = UpdateDatabase::open(dir.path().join("db.json")).unwrap();
        let config = DownloadConfig {
            retry_backoff: Duration::from_millis(1),
            ..DownloadConfig::default()
        };
        let manager = DownloadManager::new(db, config).unwrap();
        let record = create_record(
            "app",
            "1.0.2",
            url,
            destination,
            bytes.len() as u64,
            digest(&bytes),
        );
        let handle = manager.start(record, None).unwrap();
        assert!(handle.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn duplicate_downloads_are_rejected() {
        let bytes = b"dupe".repeat(4096);
        let url = start_server(bytes.clone(), false).await;
        let dir = tempdir().unwrap();
        let destination = dir.path().join("app.bin");
        let db = UpdateDatabase::open(dir.path().join("db.json")).unwrap();
        let manager = DownloadManager::new(db, DownloadConfig::default()).unwrap();
        let record = create_record(
            "app",
            "1.0.3",
            url,
            destination,
            bytes.len() as u64,
            digest(&bytes),
        );
        let _handle = manager.start(record.clone(), None).unwrap();
        assert!(matches!(
            manager.start(record, None),
            Err(UpdateError::DuplicateDownload)
        ));
    }

    #[tokio::test]
    async fn checksum_mismatch_removes_partial_download() {
        let bytes = b"bad-hash".repeat(1024);
        let url = start_server(bytes.clone(), false).await;
        let dir = tempdir().unwrap();
        let destination = dir.path().join("app.bin");
        let db = UpdateDatabase::open(dir.path().join("db.json")).unwrap();
        let manager = DownloadManager::new(db, DownloadConfig::default()).unwrap();
        let record = create_record(
            "app",
            "1.0.4",
            url,
            destination.clone(),
            bytes.len() as u64,
            "0".repeat(64),
        );
        let part = record.part_path.clone();
        let handle = manager.start(record, None).unwrap();
        assert!(matches!(
            handle.await.unwrap(),
            Err(UpdateError::ChecksumMismatch)
        ));
        assert!(!destination.exists());
        assert!(!part.exists());
    }

    #[tokio::test]
    async fn server_refusing_range_restarts_safely_from_zero() {
        let bytes = b"no-range".repeat(4096);
        let url = sibling_url(&start_server(bytes.clone(), false).await, "/no-range");
        let dir = tempdir().unwrap();
        let destination = dir.path().join("app.bin");
        let part = destination.with_extension("bin.part");
        tokio::fs::write(&part, &bytes[..100]).await.unwrap();
        let db = UpdateDatabase::open(dir.path().join("db.json")).unwrap();
        let manager = DownloadManager::new(db, DownloadConfig::default()).unwrap();
        let record = create_record(
            "app",
            "1.0.5",
            url,
            destination.clone(),
            bytes.len() as u64,
            digest(&bytes),
        );
        let handle = manager.start(record, None).unwrap();
        handle.await.unwrap().unwrap();
        assert_eq!(tokio::fs::read(destination).await.unwrap(), bytes);
    }

    #[tokio::test]
    async fn mismatched_content_range_is_rejected() {
        let bytes = b"bad-range".repeat(4096);
        let url = sibling_url(&start_server(bytes.clone(), false).await, "/bad-range");
        let dir = tempdir().unwrap();
        let destination = dir.path().join("app.bin");
        let part = destination.with_extension("bin.part");
        tokio::fs::write(&part, &bytes[..128]).await.unwrap();
        let db = UpdateDatabase::open(dir.path().join("db.json")).unwrap();
        let config = DownloadConfig {
            retry_limit: 0,
            ..DownloadConfig::default()
        };
        let manager = DownloadManager::new(db, config).unwrap();
        let record = create_record(
            "app",
            "1.0.9",
            url,
            destination.clone(),
            bytes.len() as u64,
            digest(&bytes),
        );
        let handle = manager.start(record, None).unwrap();

        assert!(handle.await.unwrap().is_err());
        assert!(!destination.exists());
    }

    #[tokio::test]
    async fn changed_remote_validator_restarts_from_zero() {
        let bytes = b"validator".repeat(4096);
        let url = sibling_url(&start_server(bytes.clone(), false).await, "/changed-etag");
        let dir = tempdir().unwrap();
        let destination = dir.path().join("app.bin");
        let part = destination.with_extension("bin.part");
        tokio::fs::write(&part, &bytes[..256]).await.unwrap();
        let db = UpdateDatabase::open(dir.path().join("db.json")).unwrap();
        let config = DownloadConfig {
            retry_backoff: Duration::from_millis(1),
            ..DownloadConfig::default()
        };
        let manager = DownloadManager::new(db, config).unwrap();
        let mut record = create_record(
            "app",
            "1.0.10",
            url,
            destination.clone(),
            bytes.len() as u64,
            digest(&bytes),
        );
        record.etag = Some("\"old\"".to_string());
        let handle = manager.start(record, None).unwrap();

        handle.await.unwrap().unwrap();
        assert_eq!(tokio::fs::read(destination).await.unwrap(), bytes);
    }

    #[tokio::test]
    async fn oversized_partial_file_restarts_from_zero() {
        let bytes = b"oversized".repeat(4096);
        let url = start_server(bytes.clone(), false).await;
        let dir = tempdir().unwrap();
        let destination = dir.path().join("app.bin");
        let part = destination.with_extension("bin.part");
        let oversized = vec![0_u8; bytes.len() + 10];
        tokio::fs::write(&part, oversized).await.unwrap();
        let db = UpdateDatabase::open(dir.path().join("db.json")).unwrap();
        let manager = DownloadManager::new(db, DownloadConfig::default()).unwrap();
        let record = create_record(
            "app",
            "1.0.11",
            url,
            destination.clone(),
            bytes.len() as u64,
            digest(&bytes),
        );
        let handle = manager.start(record, None).unwrap();

        handle.await.unwrap().unwrap();
        assert_eq!(tokio::fs::read(destination).await.unwrap(), bytes);
    }

    #[tokio::test]
    async fn short_server_body_fails_size_verification() {
        let bytes = b"short".repeat(4096);
        let url = sibling_url(&start_server(bytes.clone(), false).await, "/short");
        let dir = tempdir().unwrap();
        let destination = dir.path().join("app.bin");
        let db = UpdateDatabase::open(dir.path().join("db.json")).unwrap();
        let config = DownloadConfig {
            retry_limit: 0,
            ..DownloadConfig::default()
        };
        let manager = DownloadManager::new(db, config).unwrap();
        let record = create_record(
            "app",
            "1.0.6",
            url,
            destination,
            bytes.len() as u64,
            digest(&bytes),
        );
        let handle = manager.start(record, None).unwrap();
        assert!(handle.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn http_404_is_reported_as_download_failure() {
        let bytes = b"missing".repeat(1024);
        let url = sibling_url(&start_server(bytes.clone(), false).await, "/missing");
        let dir = tempdir().unwrap();
        let destination = dir.path().join("app.bin");
        let db = UpdateDatabase::open(dir.path().join("db.json")).unwrap();
        let config = DownloadConfig {
            retry_limit: 0,
            ..DownloadConfig::default()
        };
        let manager = DownloadManager::new(db, config).unwrap();
        let record = create_record(
            "app",
            "1.0.7",
            url,
            destination,
            bytes.len() as u64,
            digest(&bytes),
        );
        let handle = manager.start(record, None).unwrap();
        assert!(handle.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn cancellation_interrupts_a_waiting_network_request() {
        let bytes = b"cancel".repeat(1024);
        let url = start_server_with_delay(bytes.clone(), false, 2_000).await;
        let dir = tempdir().unwrap();
        let destination = dir.path().join("app.bin");
        let db = UpdateDatabase::open(dir.path().join("db.json")).unwrap();
        let manager = DownloadManager::new(db, DownloadConfig::default()).unwrap();
        let record = create_record(
            "app",
            "1.0.8",
            url.clone(),
            destination,
            bytes.len() as u64,
            digest(&bytes),
        );
        let key = download_key("app", "1.0.8", &url);
        let handle = manager.start(record, None).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        manager.cancel(&key, true).unwrap();
        assert!(matches!(
            handle.await.unwrap(),
            Err(UpdateError::DownloadCancelled)
        ));
    }
}
