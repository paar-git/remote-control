use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use serde::{Deserialize, Serialize};

use crate::error::{Result, UpdateError};
use crate::state::DownloadQueueState;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadRecord {
    pub application_id: String,
    pub version: String,
    pub url: String,
    pub destination_path: PathBuf,
    pub part_path: PathBuf,
    pub expected_size: u64,
    pub downloaded_bytes: u64,
    pub sha256: String,
    pub state: DownloadQueueState,
    pub retry_count: u32,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpdateDatabase {
    path: PathBuf,
    records: BTreeMap<String, DownloadRecord>,
    /// Monotonic counter that keeps each atomic-save temporary file distinct.
    /// A wall-clock timestamp is not enough: two saves inside the same
    /// millisecond would collide on the same temporary path.
    revision: Arc<AtomicU64>,
}

impl UpdateDatabase {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let records = if path.exists() {
            let json = std::fs::read_to_string(&path)?;
            serde_json::from_str(&json)?
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            path,
            records,
            revision: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn open_resilient(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        match Self::open(&path) {
            Ok(database) => Ok(database),
            Err(UpdateError::Json(_)) => {
                let quarantine = path.with_extension(format!("json.corrupt.{}", now_ms()));
                std::fs::rename(&path, quarantine)?;
                Self::open(path)
            }
            Err(error) => Err(error),
        }
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&DownloadRecord> {
        self.records.get(key)
    }

    #[must_use]
    pub fn records(&self) -> &BTreeMap<String, DownloadRecord> {
        &self.records
    }

    pub fn upsert(&mut self, key: String, record: DownloadRecord) -> Result<()> {
        self.records.insert(key, record);
        self.save()
    }

    pub fn remove(&mut self, key: &str) -> Result<Option<DownloadRecord>> {
        let removed = self.records.remove(key);
        self.save()?;
        Ok(removed)
    }

    pub fn update(&mut self, key: &str, mutate: impl FnOnce(&mut DownloadRecord)) -> Result<()> {
        if let Some(record) = self.records.get_mut(key) {
            mutate(record);
            record.updated_at_ms = now_ms();
            self.save()?;
        }
        Ok(())
    }

    /// Write the record set atomically.
    ///
    /// The temporary file is removed when the rename fails so a failed save
    /// cannot leave `*.json.tmp.*` litter accumulating in the update directory.
    pub fn save(&self) -> Result<()> {
        let temp = self.path.with_extension(format!(
            "json.tmp.{}.{}",
            std::process::id(),
            self.revision.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        let bytes = serde_json::to_vec_pretty(&self.records)?;
        std::fs::write(&temp, bytes)?;
        if let Err(error) = std::fs::rename(&temp, &self.path) {
            let _ = std::fs::remove_file(&temp);
            return Err(error.into());
        }
        Ok(())
    }
}

pub fn download_key(application_id: &str, version: &str, url: &str) -> String {
    format!("{application_id}:{version}:{url}")
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{DownloadRecord, UpdateDatabase, download_key};
    use crate::state::DownloadQueueState;

    fn record(dir: &std::path::Path) -> DownloadRecord {
        DownloadRecord {
            application_id: "app".to_string(),
            version: "1.2.3".to_string(),
            url: "https://example.com/app.msi".to_string(),
            destination_path: dir.join("app.msi"),
            part_path: dir.join("app.msi.part"),
            expected_size: 10,
            downloaded_bytes: 0,
            sha256: "a".repeat(64),
            state: DownloadQueueState::Queued,
            retry_count: 0,
            created_at_ms: 1,
            updated_at_ms: 1,
            etag: None,
            last_modified: None,
        }
    }

    #[test]
    fn database_persists_download_state() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("downloads.json");
        let key = download_key("app", "1.2.3", "https://example.com/app.msi");
        let mut db = UpdateDatabase::open(&path).unwrap();
        db.upsert(key.clone(), record(dir.path())).unwrap();
        let db = UpdateDatabase::open(&path).unwrap();
        assert_eq!(db.get(&key).unwrap().version, "1.2.3");
    }

    #[test]
    fn corrupted_database_is_quarantined_and_recreated() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("downloads.json");
        std::fs::write(&path, b"{not json").unwrap();

        let db = UpdateDatabase::open_resilient(&path).unwrap();

        assert!(db.records().is_empty());
        let quarantined = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().contains("corrupt"));
        assert!(quarantined);
    }
}
