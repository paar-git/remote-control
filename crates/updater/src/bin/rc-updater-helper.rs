#![allow(missing_docs)]
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Parser;
use rc_updater::{StagedInstallPlan, run_staged_install};

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    plan: PathBuf,
    #[arg(long, default_value_t = false)]
    running_from_safe_copy: bool,
}

fn main() {
    let args = Args::parse();
    if !args.running_from_safe_copy {
        match reexec_from_safe_copy(&args.plan) {
            Ok(status) => std::process::exit(status),
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
    }
    let result = std::fs::read_to_string(&args.plan)
        .map_err(|err| err.to_string())
        .and_then(|json| {
            serde_json::from_str::<StagedInstallPlan>(&json).map_err(|err| err.to_string())
        })
        .and_then(|plan| run_staged_install(&plan).map_err(|err| err.to_string()));
    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn reexec_from_safe_copy(plan: &Path) -> Result<i32, String> {
    let current_exe = std::env::current_exe().map_err(|err| err.to_string())?;
    let file_name = current_exe
        .file_name()
        .ok_or_else(|| "updater helper path has no file name".to_string())?;
    let safe_dir = std::env::temp_dir().join(format!(
        "rc-updater-helper-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_millis()
    ));
    std::fs::create_dir_all(&safe_dir).map_err(|err| err.to_string())?;
    let safe_exe = safe_dir.join(file_name);
    std::fs::copy(&current_exe, &safe_exe).map_err(|err| err.to_string())?;
    let status = Command::new(safe_exe)
        .arg("--plan")
        .arg(plan)
        .arg("--running-from-safe-copy")
        .status()
        .map_err(|err| err.to_string())?;
    Ok(status.code().unwrap_or(1))
}
