use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperatingSystem {
    Windows,
    MacOs,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    X64,
    Arm64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstallationType {
    WindowsMsi,
    WindowsExe,
    MacosAppBundle,
    MacosPkg,
    LinuxDeb,
    LinuxRpm,
    LinuxAppImage,
    PortableArchive,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformKey(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformInfo {
    pub os: OperatingSystem,
    pub os_version: String,
    #[serde(default)]
    pub os_build: Option<u32>,
    #[serde(default)]
    pub linux_kernel_version: Option<String>,
    #[serde(default)]
    pub linux_glibc_version: Option<String>,
    #[serde(default)]
    pub linux_distribution: Option<String>,
    pub cpu_architecture: Architecture,
    pub installation_architecture: Architecture,
    pub installation_type: InstallationType,
    pub key: PlatformKey,
}

impl PlatformInfo {
    #[must_use]
    pub fn detect() -> Self {
        let os = detect_os();
        let arch = detect_arch(std::env::consts::ARCH);
        let os_version = detect_os_version(os)
            .or_else(sysinfo::System::long_os_version)
            .unwrap_or_else(|| std::env::consts::OS.to_string());
        let mut info = Self::from_parts(os, os_version, arch, arch);
        info.os_build = detect_os_build(os);
        if os == OperatingSystem::Linux {
            info.linux_kernel_version = detect_linux_kernel_version();
            info.linux_glibc_version = detect_linux_glibc_version();
            info.linux_distribution = detect_linux_distribution();
        }
        info.installation_type = detect_installation_type(std::env::current_exe().ok().as_deref());
        info
    }

    #[must_use]
    pub fn from_parts(
        os: OperatingSystem,
        os_version: impl Into<String>,
        cpu_architecture: Architecture,
        installation_architecture: Architecture,
    ) -> Self {
        let key = PlatformKey(format!(
            "{}-{}",
            os.as_key(),
            installation_architecture.as_key()
        ));
        Self {
            os,
            os_version: os_version.into(),
            os_build: None,
            linux_kernel_version: None,
            linux_glibc_version: None,
            linux_distribution: None,
            cpu_architecture,
            installation_architecture,
            installation_type: InstallationType::Unknown,
            key,
        }
    }

    #[must_use]
    pub const fn with_installation_type(mut self, installation_type: InstallationType) -> Self {
        self.installation_type = installation_type;
        self
    }

    #[must_use]
    pub const fn with_os_build(mut self, build: u32) -> Self {
        self.os_build = Some(build);
        self
    }

    #[must_use]
    pub fn with_linux_runtime(
        mut self,
        kernel: Option<String>,
        glibc: Option<String>,
        distribution: Option<String>,
    ) -> Self {
        self.linux_kernel_version = kernel;
        self.linux_glibc_version = glibc;
        self.linux_distribution = distribution;
        self
    }
}

impl OperatingSystem {
    #[must_use]
    pub const fn as_key(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::MacOs => "macos",
            Self::Linux => "linux",
        }
    }
}

impl Architecture {
    #[must_use]
    pub const fn as_key(self) -> &'static str {
        match self {
            Self::X64 => "x64",
            Self::Arm64 => "arm64",
        }
    }
}

#[must_use]
pub const fn detect_os() -> OperatingSystem {
    if cfg!(target_os = "windows") {
        OperatingSystem::Windows
    } else if cfg!(target_os = "macos") {
        OperatingSystem::MacOs
    } else {
        OperatingSystem::Linux
    }
}

#[must_use]
pub fn detect_arch(value: &str) -> Architecture {
    match value {
        "aarch64" | "arm64" => Architecture::Arm64,
        _ => Architecture::X64,
    }
}

#[must_use]
pub fn detect_installation_type(current_exe: Option<&Path>) -> InstallationType {
    if let Ok(value) = std::env::var("RC_INSTALLATION_TYPE")
        && let Some(parsed) = parse_installation_type(&value)
    {
        return parsed;
    }

    if cfg!(target_os = "linux") && std::env::var_os("APPIMAGE").is_some() {
        return InstallationType::LinuxAppImage;
    }

    if let Some(exe) = current_exe {
        let path = exe.to_string_lossy().to_ascii_lowercase();
        if cfg!(target_os = "macos") && path.contains(".app/contents/macos/") {
            return InstallationType::MacosAppBundle;
        }
        if cfg!(target_os = "linux") {
            if command_succeeds("dpkg-query", &["-S", exe.to_string_lossy().as_ref()]) {
                return InstallationType::LinuxDeb;
            }
            if command_succeeds("rpm", &["-qf", exe.to_string_lossy().as_ref()]) {
                return InstallationType::LinuxRpm;
            }
        }
    }

    InstallationType::Unknown
}

#[must_use]
pub fn parse_installation_type(value: &str) -> Option<InstallationType> {
    match value.trim().to_ascii_lowercase().as_str() {
        "windows-msi" | "msi" => Some(InstallationType::WindowsMsi),
        "windows-exe" | "exe" => Some(InstallationType::WindowsExe),
        "macos-app-bundle" | "app-bundle" | "dmg" => Some(InstallationType::MacosAppBundle),
        "macos-pkg" | "pkg" => Some(InstallationType::MacosPkg),
        "linux-deb" | "deb" => Some(InstallationType::LinuxDeb),
        "linux-rpm" | "rpm" => Some(InstallationType::LinuxRpm),
        "linux-appimage" | "appimage" | "app-image" => Some(InstallationType::LinuxAppImage),
        "portable-archive" | "tar.gz" | "archive" => Some(InstallationType::PortableArchive),
        "unknown" => Some(InstallationType::Unknown),
        _ => None,
    }
}

fn command_succeeds(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn detect_os_version(os: OperatingSystem) -> Option<String> {
    match os {
        OperatingSystem::Windows => windows_version_from_registry().map(|(_, display)| display),
        OperatingSystem::MacOs => command_stdout("sw_vers", &["-productVersion"]),
        OperatingSystem::Linux => sysinfo::System::long_os_version(),
    }
}

fn detect_os_build(os: OperatingSystem) -> Option<u32> {
    match os {
        OperatingSystem::Windows => windows_version_from_registry().and_then(|(build, _)| build),
        _ => None,
    }
}

#[cfg(windows)]
fn windows_version_from_registry() -> Option<(Option<u32>, String)> {
    let script = "($v=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'); ($v.ProductName + ' ' + $v.DisplayVersion + ' build ' + $v.CurrentBuildNumber)";
    let display = command_stdout(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", script],
    )?;
    let build = display
        .split_whitespace()
        .rev()
        .find_map(|part| part.parse::<u32>().ok());
    Some((build, display))
}

#[cfg(not(windows))]
fn windows_version_from_registry() -> Option<(Option<u32>, String)> {
    None
}

fn detect_linux_kernel_version() -> Option<String> {
    if cfg!(target_os = "linux") {
        command_stdout("uname", &["-r"])
    } else {
        None
    }
}

fn detect_linux_glibc_version() -> Option<String> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    command_stdout("getconf", &["GNU_LIBC_VERSION"])
        .and_then(|value| value.split_whitespace().last().map(ToOwned::to_owned))
}

fn detect_linux_distribution() -> Option<String> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let os_release = std::fs::read_to_string("/etc/os-release").ok()?;
    os_release.lines().find_map(|line| {
        line.strip_prefix("ID=")
            .map(|value| value.trim_matches('"').to_string())
    })
}

fn command_stdout(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        Architecture, InstallationType, OperatingSystem, PlatformInfo, detect_arch,
        parse_installation_type,
    };

    #[test]
    fn platform_key_matches_manifest_names() {
        let platform = PlatformInfo::from_parts(
            OperatingSystem::Windows,
            "Windows 11",
            Architecture::X64,
            Architecture::X64,
        );
        assert_eq!(platform.key.0, "windows-x64");
    }

    #[test]
    fn architecture_detection_normalizes_arm64() {
        assert_eq!(detect_arch("aarch64"), Architecture::Arm64);
        assert_eq!(detect_arch("x86_64"), Architecture::X64);
    }

    #[test]
    fn installation_type_names_are_parsed() {
        assert_eq!(
            parse_installation_type("deb"),
            Some(InstallationType::LinuxDeb)
        );
        assert_eq!(
            parse_installation_type("app-image"),
            Some(InstallationType::LinuxAppImage)
        );
        assert_eq!(parse_installation_type("mystery"), None);
    }
}
