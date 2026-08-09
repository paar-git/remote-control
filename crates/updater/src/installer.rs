use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::error::{Result, UpdateError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PackageFormat {
    #[serde(rename = "exe")]
    Exe,
    #[serde(rename = "msi")]
    Msi,
    #[serde(rename = "dmg")]
    Dmg,
    #[serde(rename = "pkg")]
    Pkg,
    #[serde(rename = "appimage", alias = "app-image")]
    AppImage,
    #[serde(rename = "deb")]
    Deb,
    #[serde(rename = "rpm")]
    Rpm,
    #[serde(rename = "tar.gz", alias = "tar-gz", alias = "tgz")]
    TarGz,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallOutcome {
    pub restart_required: bool,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct Installer {
    install_dir: Option<PathBuf>,
}

impl Installer {
    #[must_use]
    pub const fn new(install_dir: Option<PathBuf>) -> Self {
        Self { install_dir }
    }

    pub fn install(&self, artifact: &Path, format: PackageFormat) -> Result<InstallOutcome> {
        if !artifact.is_file() {
            return Err(UpdateError::InstallFailed(format!(
                "installer `{}` does not exist",
                artifact.display()
            )));
        }
        match format {
            PackageFormat::Msi => install_windows_msi(artifact),
            PackageFormat::Exe => install_windows_exe(artifact),
            PackageFormat::Pkg => install_macos_pkg(artifact),
            PackageFormat::Dmg => install_macos_dmg(artifact),
            PackageFormat::Deb => install_linux_deb(artifact),
            PackageFormat::Rpm => install_linux_rpm(artifact),
            PackageFormat::AppImage => self.install_appimage(artifact),
            PackageFormat::TarGz => Err(UpdateError::InstallFailed(
                "tar.gz application bundles must be installed through the staged updater helper"
                    .to_string(),
            )),
        }
    }

    fn install_appimage(&self, artifact: &Path) -> Result<InstallOutcome> {
        let Some(dir) = &self.install_dir else {
            return Err(UpdateError::InstallFailed(
                "an install directory is required for AppImage installation".to_string(),
            ));
        };
        std::fs::create_dir_all(dir)?;
        let target = dir.join(artifact.file_name().ok_or_else(|| {
            UpdateError::InstallFailed("AppImage path has no file name".to_string())
        })?);
        std::fs::copy(artifact, &target)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&target)?.permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&target, permissions)?;
        }
        Ok(InstallOutcome {
            restart_required: false,
            message: format!("Installed AppImage to {}", target.display()),
        })
    }
}

impl PackageFormat {
    #[must_use]
    pub const fn manifest_name(self) -> &'static str {
        match self {
            Self::Exe => "exe",
            Self::Msi => "msi",
            Self::Dmg => "dmg",
            Self::Pkg => "pkg",
            Self::AppImage => "appimage",
            Self::Deb => "deb",
            Self::Rpm => "rpm",
            Self::TarGz => "tar.gz",
        }
    }

    #[must_use]
    pub fn from_path(path: &Path) -> Option<Self> {
        let extension = path.extension()?.to_str()?;
        if extension.eq_ignore_ascii_case("tgz")
            || (extension.eq_ignore_ascii_case("gz")
                && path
                    .file_stem()
                    .and_then(|stem| Path::new(stem).extension())
                    .and_then(|nested| nested.to_str())
                    .is_some_and(|nested| nested.eq_ignore_ascii_case("tar")))
        {
            return Some(Self::TarGz);
        }
        if extension.eq_ignore_ascii_case("exe") {
            Some(Self::Exe)
        } else if extension.eq_ignore_ascii_case("msi") {
            Some(Self::Msi)
        } else if extension.eq_ignore_ascii_case("dmg") {
            Some(Self::Dmg)
        } else if extension.eq_ignore_ascii_case("pkg") {
            Some(Self::Pkg)
        } else if extension.eq_ignore_ascii_case("appimage") {
            Some(Self::AppImage)
        } else if extension.eq_ignore_ascii_case("deb") {
            Some(Self::Deb)
        } else if extension.eq_ignore_ascii_case("rpm") {
            Some(Self::Rpm)
        } else {
            None
        }
    }
}

#[cfg(windows)]
fn install_windows_msi(artifact: &Path) -> Result<InstallOutcome> {
    let argument_list = format!("/i \"{}\"", artifact.display());
    let status = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "try { $process = Start-Process -FilePath msiexec.exe -ArgumentList $args[0] -Verb RunAs -Wait -PassThru; exit $process.ExitCode } catch { Write-Error $_.Exception.Message; exit 1602 }",
        ])
        .arg(argument_list)
        .status()?;
    classify_windows_installer_status("MSI installer", status.code())
}

/// Map a Windows installer exit code onto an install outcome.
///
/// Compiled on Windows, where the MSI and EXE installers call it, and in test
/// builds on every platform: the mapping is pure integer logic that is worth
/// covering everywhere rather than only on Windows runners.
#[cfg(any(windows, test))]
fn classify_windows_installer_status(installer: &str, code: Option<i32>) -> Result<InstallOutcome> {
    let Some(code) = code else {
        return Err(UpdateError::InstallFailed(format!(
            "{installer} exited without reporting an exit code"
        )));
    };
    match code {
        0 => Ok(InstallOutcome {
            restart_required: true,
            message: format!("{installer} completed. Restart the app to use the new version."),
        }),
        1641 | 3010 => Ok(InstallOutcome {
            restart_required: true,
            message: format!(
                "{installer} completed and Windows reports that a computer restart is required. Save your work before restarting Windows."
            ),
        }),
        1602 => Err(UpdateError::InstallFailed(format!(
            "{installer} was cancelled by the user before installation completed"
        ))),
        1618 => Err(UpdateError::InstallFailed(
            "Another Windows installation is already running. Wait for it to finish, then try again."
                .to_string(),
        )),
        1603 => Err(UpdateError::InstallFailed(format!(
            "{installer} reported a fatal installation error. Check the installer log for details."
        ))),
        other => Err(UpdateError::InstallFailed(format!(
            "{installer} exited with Windows Installer code {other}"
        ))),
    }
}

#[cfg(not(windows))]
fn install_windows_msi(_artifact: &Path) -> Result<InstallOutcome> {
    Err(UpdateError::InstallFailed(
        "MSI installation is only supported on Windows".to_string(),
    ))
}

#[cfg(windows)]
fn install_windows_exe(artifact: &Path) -> Result<InstallOutcome> {
    let status = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "try { $process = Start-Process -FilePath $args[0] -Verb RunAs -Wait -PassThru; exit $process.ExitCode } catch { Write-Error $_.Exception.Message; exit 1602 }",
        ])
        .arg(artifact)
        .status()?;
    classify_windows_installer_status("EXE installer", status.code())
}

#[cfg(not(windows))]
fn install_windows_exe(_artifact: &Path) -> Result<InstallOutcome> {
    Err(UpdateError::InstallFailed(
        "EXE installation is only supported on Windows".to_string(),
    ))
}

#[cfg(target_os = "macos")]
fn install_macos_pkg(artifact: &Path) -> Result<InstallOutcome> {
    let status = Command::new("open").arg("-W").arg(artifact).status()?;
    if status.success() {
        Ok(InstallOutcome {
            restart_required: true,
            message:
                "The macOS package installer closed. Restart the app after installation finishes."
                    .to_string(),
        })
    } else {
        Err(UpdateError::InstallFailed(format!(
            "macOS installer exited with {status}"
        )))
    }
}

#[cfg(not(target_os = "macos"))]
fn install_macos_pkg(_artifact: &Path) -> Result<InstallOutcome> {
    Err(UpdateError::InstallFailed(
        "PKG installation is only supported on macOS".to_string(),
    ))
}

#[cfg(target_os = "macos")]
fn install_macos_dmg(artifact: &Path) -> Result<InstallOutcome> {
    let status = Command::new("open").arg("-W").arg(artifact).status()?;
    if status.success() {
        Ok(InstallOutcome {
            restart_required: true,
            message:
                "The DMG was opened. Complete the macOS installation flow, then restart the app."
                    .to_string(),
        })
    } else {
        Err(UpdateError::InstallFailed(format!(
            "open exited with {status}"
        )))
    }
}

#[cfg(not(target_os = "macos"))]
fn install_macos_dmg(_artifact: &Path) -> Result<InstallOutcome> {
    Err(UpdateError::InstallFailed(
        "DMG installation is only supported on macOS".to_string(),
    ))
}

#[cfg(target_os = "linux")]
fn install_linux_deb(artifact: &Path) -> Result<InstallOutcome> {
    run_elevated_linux("dpkg", &["-i"], artifact)
}

#[cfg(not(target_os = "linux"))]
fn install_linux_deb(_artifact: &Path) -> Result<InstallOutcome> {
    Err(UpdateError::InstallFailed(
        "DEB installation is only supported on Linux".to_string(),
    ))
}

#[cfg(target_os = "linux")]
fn install_linux_rpm(artifact: &Path) -> Result<InstallOutcome> {
    run_elevated_linux("rpm", &["-Uvh"], artifact)
}

#[cfg(not(target_os = "linux"))]
fn install_linux_rpm(_artifact: &Path) -> Result<InstallOutcome> {
    Err(UpdateError::InstallFailed(
        "RPM installation is only supported on Linux".to_string(),
    ))
}

#[cfg(target_os = "linux")]
fn run_elevated_linux(program: &str, args: &[&str], artifact: &Path) -> Result<InstallOutcome> {
    if !linux_command_exists(program) {
        return Err(UpdateError::InstallFailed(format!(
            "required Linux package tool `{program}` is not available on this system"
        )));
    }
    if !linux_command_exists("pkexec") {
        return Err(UpdateError::InstallFailed(
            "pkexec is required to request installation privileges for system packages".to_string(),
        ));
    }
    let status = Command::new("pkexec")
        .arg(program)
        .args(args)
        .arg(artifact)
        .stdin(std::process::Stdio::null())
        .status()?;
    if status.success() {
        Ok(InstallOutcome {
            restart_required: true,
            message: "The Linux package manager completed. Restart the app to use the new version."
                .to_string(),
        })
    } else {
        Err(UpdateError::InstallFailed(format!(
            "package manager exited with {status}"
        )))
    }
}

#[cfg(target_os = "linux")]
fn linux_command_exists(program: &str) -> bool {
    Command::new("sh")
        .args(["-c", "command -v -- \"$1\" >/dev/null 2>&1", "sh", program])
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{PackageFormat, classify_windows_installer_status};

    #[test]
    fn package_format_is_inferred_from_filename() {
        assert_eq!(
            PackageFormat::from_path(Path::new("app.msi")),
            Some(PackageFormat::Msi)
        );
        assert_eq!(
            PackageFormat::from_path(Path::new("app.tar.gz")),
            Some(PackageFormat::TarGz)
        );
        assert_eq!(
            PackageFormat::from_path(Path::new("app.AppImage")),
            Some(PackageFormat::AppImage)
        );
    }

    #[test]
    fn windows_installer_exit_codes_are_classified() {
        let success = classify_windows_installer_status("MSI installer", Some(0)).unwrap();
        assert!(success.restart_required);
        let restart = classify_windows_installer_status("MSI installer", Some(3010)).unwrap();
        assert!(restart.message.contains("computer restart"));
        let cancelled = classify_windows_installer_status("MSI installer", Some(1602)).unwrap_err();
        assert!(cancelled.to_string().contains("cancelled by the user"));
        let busy = classify_windows_installer_status("MSI installer", Some(1618)).unwrap_err();
        assert!(busy.to_string().contains("already running"));
    }
}
