use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use tar::Archive;

use crate::error::{Result, UpdateError};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StagedInstallPlan {
    pub current_dir: PathBuf,
    pub update_dir: PathBuf,
    pub backup_dir: PathBuf,
    pub launch_executable: PathBuf,
    pub parent_pid: Option<u32>,
    #[serde(default)]
    pub transaction_file: Option<PathBuf>,
    pub health_check: HealthCheck,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheck {
    pub transaction_id: String,
    pub expected_version: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstallTransactionState<'a> {
    transaction_id: &'a str,
    expected_version: &'a str,
    phase: &'a str,
    updated_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HealthReport {
    transaction_id: String,
    version: String,
    status: String,
}

pub fn prepare_tar_gz_stage(archive_path: &Path, stage_dir: &Path) -> Result<()> {
    if stage_dir.exists() {
        std::fs::remove_dir_all(stage_dir)?;
    }
    std::fs::create_dir_all(stage_dir)?;
    let file = std::fs::File::open(archive_path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        if path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(UpdateError::UnsafePath(path.into_owned()));
        }
        entry.unpack_in(stage_dir)?;
    }
    Ok(())
}

pub fn run_staged_install(plan: &StagedInstallPlan) -> Result<()> {
    validate_plan(plan)?;
    write_transaction_state(plan, "waiting_for_parent")?;
    wait_for_parent(plan.parent_pid, Duration::from_secs(60));

    if plan.backup_dir.exists() {
        write_transaction_state(plan, "removing_stale_backup")?;
        std::fs::remove_dir_all(&plan.backup_dir)?;
    }

    let mut moved_current = false;
    let mut moved_update = false;

    let install_result = (|| -> Result<()> {
        write_transaction_state(plan, "moving_current_to_backup")?;
        std::fs::rename(&plan.current_dir, &plan.backup_dir)?;
        moved_current = true;
        write_transaction_state(plan, "moving_update_into_place")?;
        std::fs::rename(&plan.update_dir, &plan.current_dir)?;
        moved_update = true;
        write_transaction_state(plan, "running_health_check")?;
        run_health_check(plan)
    })();

    match install_result {
        Ok(()) => {
            write_transaction_state(plan, "cleaning_backup")?;
            if plan.backup_dir.exists() {
                std::fs::remove_dir_all(&plan.backup_dir)?;
            }
            write_transaction_state(plan, "completed")?;
            Ok(())
        }
        Err(err) => {
            write_transaction_state(plan, "rolling_back")?;
            rollback(plan, moved_current, moved_update)?;
            write_transaction_state(plan, "rolled_back")?;
            Err(err)
        }
    }
}

fn validate_plan(plan: &StagedInstallPlan) -> Result<()> {
    if !plan.current_dir.is_dir() {
        return Err(UpdateError::InstallFailed(format!(
            "current app directory `{}` does not exist",
            plan.current_dir.display()
        )));
    }
    if !plan.update_dir.is_dir() {
        return Err(UpdateError::InstallFailed(format!(
            "staged update directory `{}` does not exist",
            plan.update_dir.display()
        )));
    }
    if plan.current_dir == plan.update_dir || plan.current_dir == plan.backup_dir {
        return Err(UpdateError::InstallFailed(
            "staged update paths must be distinct".to_string(),
        ));
    }
    Ok(())
}

fn wait_for_parent(parent_pid: Option<u32>, timeout: Duration) {
    let Some(parent_pid) = parent_pid else {
        return;
    };
    let start = Instant::now();
    while start.elapsed() < timeout && process_is_running(parent_pid) {
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn process_is_running(pid: u32) -> bool {
    #[cfg(windows)]
    {
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output()
            .is_ok_and(|output| String::from_utf8_lossy(&output.stdout).contains(&pid.to_string()))
    }
    #[cfg(unix)]
    {
        Path::new("/proc").join(pid.to_string()).exists()
    }
    #[cfg(not(any(windows, unix)))]
    {
        false
    }
}

fn run_health_check(plan: &StagedInstallPlan) -> Result<()> {
    let timeout = Duration::from_millis(plan.health_check.timeout_ms.max(1));
    let mut args = plan.health_check.args.clone();
    args.extend([
        "--update-health-check".to_string(),
        "--update-transaction-id".to_string(),
        plan.health_check.transaction_id.clone(),
        "--update-expected-version".to_string(),
        plan.health_check.expected_version.clone(),
    ]);
    let mut child = Command::new(&plan.launch_executable)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let start = Instant::now();
    loop {
        if start.elapsed() > timeout {
            let _ = child.kill();
            return Err(UpdateError::HealthCheckFailed);
        }
        if child.try_wait()?.is_some() {
            let output = child.wait_with_output()?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            if output.status.success() && health_report_matches(&stdout, &plan.health_check) {
                return Ok(());
            }
            return Err(UpdateError::HealthCheckFailed);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn health_report_matches(stdout: &str, health_check: &HealthCheck) -> bool {
    stdout.lines().any(|line| {
        line.strip_prefix("UPDATE_BOOT_OK ")
            .and_then(|json| serde_json::from_str::<HealthReport>(json).ok())
            .is_some_and(|report| {
                report.transaction_id == health_check.transaction_id
                    && report.version == health_check.expected_version
                    && report.status == "healthy"
            })
    })
}

fn write_transaction_state(plan: &StagedInstallPlan, phase: &str) -> Result<()> {
    let Some(path) = &plan.transaction_file else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let state = InstallTransactionState {
        transaction_id: &plan.health_check.transaction_id,
        expected_version: &plan.health_check.expected_version,
        phase,
        updated_at_ms: chrono::Utc::now().timestamp_millis(),
    };
    let temp = path.with_extension(format!("json.tmp.{}", state.updated_at_ms));
    std::fs::write(&temp, serde_json::to_vec_pretty(&state)?)?;
    std::fs::rename(temp, path)?;
    Ok(())
}

fn rollback(plan: &StagedInstallPlan, moved_current: bool, moved_update: bool) -> Result<()> {
    if moved_update && plan.current_dir.exists() {
        std::fs::remove_dir_all(&plan.current_dir)
            .map_err(|err| UpdateError::RollbackFailed(err.to_string()))?;
    }
    if moved_current && plan.backup_dir.exists() {
        std::fs::rename(&plan.backup_dir, &plan.current_dir)
            .map_err(|err| UpdateError::RollbackFailed(err.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{HealthCheck, StagedInstallPlan, run_staged_install};

    fn health_script(
        dir: &std::path::Path,
        transaction_id: &str,
        version: &str,
    ) -> std::path::PathBuf {
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

    #[test]
    fn failed_health_check_rolls_back_previous_version() {
        let dir = tempdir().unwrap();
        let current = dir.path().join("app");
        let update = dir.path().join("app.update");
        let backup = dir.path().join("app.old");
        std::fs::create_dir_all(&current).unwrap();
        std::fs::write(current.join("version.txt"), b"2.3.0").unwrap();
        std::fs::create_dir_all(&update).unwrap();
        std::fs::write(update.join("version.txt"), b"2.4.0").unwrap();
        let plan = StagedInstallPlan {
            current_dir: current.clone(),
            update_dir: update,
            backup_dir: backup,
            launch_executable: dir.path().join("missing-health-check.exe"),
            parent_pid: None,
            transaction_file: Some(dir.path().join("install-transaction.json")),
            health_check: HealthCheck {
                transaction_id: "tx-fail".to_string(),
                expected_version: "2.4.0".to_string(),
                args: Vec::new(),
                timeout_ms: 100,
            },
        };
        assert!(run_staged_install(&plan).is_err());
        assert_eq!(
            std::fs::read_to_string(current.join("version.txt")).unwrap(),
            "2.3.0"
        );
    }

    #[test]
    fn successful_health_check_removes_backup_and_marks_completed() {
        let dir = tempdir().unwrap();
        let current = dir.path().join("app");
        let update = dir.path().join("app.update");
        let backup = dir.path().join("app.old");
        let transaction = dir.path().join("install-transaction.json");
        std::fs::create_dir_all(&current).unwrap();
        std::fs::write(current.join("version.txt"), b"2.3.0").unwrap();
        std::fs::create_dir_all(&update).unwrap();
        std::fs::write(update.join("version.txt"), b"2.4.0").unwrap();
        let launch = health_script(dir.path(), "tx-ok", "2.4.0");
        let plan = StagedInstallPlan {
            current_dir: current.clone(),
            update_dir: update,
            backup_dir: backup.clone(),
            launch_executable: launch,
            parent_pid: None,
            transaction_file: Some(transaction.clone()),
            health_check: HealthCheck {
                transaction_id: "tx-ok".to_string(),
                expected_version: "2.4.0".to_string(),
                args: Vec::new(),
                timeout_ms: 2_000,
            },
        };

        run_staged_install(&plan).unwrap();

        assert_eq!(
            std::fs::read_to_string(current.join("version.txt")).unwrap(),
            "2.4.0"
        );
        assert!(!backup.exists());
        assert!(
            std::fs::read_to_string(transaction)
                .unwrap()
                .contains("completed")
        );
    }
}
