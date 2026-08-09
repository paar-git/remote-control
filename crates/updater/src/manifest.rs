use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{Result, UpdateError};
use crate::installer::PackageFormat;
use crate::platform::{InstallationType, OperatingSystem, PlatformInfo, PlatformKey};
use crate::version::{compare_versions, parse_version};

#[derive(Debug, Clone)]
pub struct ManifestPolicy {
    pub max_artifact_size: u64,
    pub allow_insecure_loopback: bool,
}

impl Default for ManifestPolicy {
    fn default() -> Self {
        Self {
            max_artifact_size: 1024 * 1024 * 1024 * 4,
            allow_insecure_loopback: false,
        }
    }
}

impl ManifestPolicy {
    #[must_use]
    pub const fn allow_insecure_loopback_for_tests(mut self) -> Self {
        self.allow_insecure_loopback = true;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseManifest {
    pub version: String,
    pub release_date: String,
    #[serde(default)]
    pub minimum_version: Option<String>,
    #[serde(default)]
    pub minimum_supported_version: Option<String>,
    #[serde(default)]
    pub minimum_updater_version: Option<String>,
    #[serde(default, rename = "minimumOSVersion", alias = "minimumOsVersion")]
    pub minimum_os_version: Option<MinimumOsVersion>,
    #[serde(default)]
    pub mandatory_update: bool,
    #[serde(default)]
    pub release_notes: String,
    #[serde(default)]
    pub platforms: BTreeMap<String, ReleasePlatform>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePlatform {
    pub artifacts: Vec<ReleaseArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseArtifact {
    pub url: String,
    pub sha256: String,
    pub size: u64,
    #[serde(rename = "format", alias = "packageFormat")]
    pub package_format: PackageFormat,
    #[serde(default)]
    pub install_size: Option<u64>,
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(default)]
    pub signature_required: bool,
    #[serde(default)]
    pub allow_package_migration: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MinimumOsVersion {
    Simple(String),
    ByOs(MinimumOsRequirements),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MinimumOsRequirements {
    #[serde(default)]
    pub windows: Option<WindowsOsRequirement>,
    #[serde(default)]
    pub macos: Option<String>,
    #[serde(default)]
    pub linux: Option<LinuxOsRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsOsRequirement {
    #[serde(default)]
    pub build: Option<u32>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub display: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinuxOsRequirement {
    #[serde(default)]
    pub kernel: Option<String>,
    #[serde(default)]
    pub glibc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseIndex {
    pub schema_version: u32,
    pub generated_at: String,
    pub releases: Vec<ReleaseIndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseIndexEntry {
    pub version: String,
    pub release_date: String,
    pub manifest_url: String,
    #[serde(default)]
    pub manifest_sha256: Option<String>,
    #[serde(default)]
    pub minimum_version: Option<String>,
    #[serde(default)]
    pub minimum_supported_version: Option<String>,
    #[serde(default)]
    pub minimum_updater_version: Option<String>,
    #[serde(default, rename = "minimumOSVersion", alias = "minimumOsVersion")]
    pub minimum_os_version: Option<MinimumOsVersion>,
    #[serde(default)]
    pub platforms: BTreeMap<String, ReleasePlatformSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePlatformSummary {
    pub formats: Vec<PackageFormat>,
}

#[derive(Debug, Clone)]
pub struct ArtifactSelection {
    pub platform_key: PlatformKey,
    pub artifact: ReleaseArtifact,
    pub package_format: PackageFormat,
    pub filename: String,
}

impl ReleaseManifest {
    pub fn parse(bytes: &[u8], policy: &ManifestPolicy) -> Result<Self> {
        let manifest: Self = serde_json::from_slice(bytes)?;
        manifest.validate(policy)?;
        Ok(manifest)
    }

    pub fn validate(&self, policy: &ManifestPolicy) -> Result<()> {
        parse_version(&self.version)?;
        if let Some(minimum) = &self.minimum_version {
            parse_version(minimum)?;
        }
        if let Some(minimum) = &self.minimum_supported_version {
            parse_version(minimum)?;
        }
        if let Some(minimum) = &self.minimum_updater_version {
            parse_version(minimum)?;
        }
        if let Some(requirement) = &self.minimum_os_version {
            requirement.validate()?;
        }
        if self.platforms.is_empty() {
            return Err(UpdateError::InvalidManifest(
                "at least one platform artifact is required".to_string(),
            ));
        }
        for (platform, entry) in &self.platforms {
            validate_platform_key(platform)?;
            entry.validate(policy)?;
        }
        Ok(())
    }

    pub fn select_for_platform(
        &self,
        platform: &PlatformInfo,
        policy: &ManifestPolicy,
    ) -> Result<ArtifactSelection> {
        self.validate(policy)?;
        self.ensure_os_supported(platform)?;
        let platform_entry = self
            .platforms
            .get(&platform.key.0)
            .ok_or_else(|| UpdateError::IncompatiblePlatform(platform.key.0.clone()))?;
        let package_format = select_best_format(
            platform.os,
            platform.installation_type,
            platform_entry
                .artifacts
                .iter()
                .map(|artifact| artifact.package_format),
        )?;
        let artifact = platform_entry
            .artifacts
            .iter()
            .find(|artifact| artifact.package_format == package_format)
            .cloned()
            .ok_or_else(|| UpdateError::IncompatiblePlatform(platform.key.0.clone()))?;
        let filename = artifact.safe_filename()?;
        Ok(ArtifactSelection {
            platform_key: platform.key.clone(),
            artifact,
            package_format,
            filename,
        })
    }

    pub fn ensure_update_allowed(&self, installed_version: &str) -> Result<bool> {
        use std::cmp::Ordering;

        if let Some(minimum) = self.minimum_supported_version()
            && compare_versions(installed_version, minimum)? == Ordering::Less
        {
            return Err(UpdateError::MinimumVersionNotMet {
                installed: installed_version.to_string(),
                minimum: minimum.to_string(),
            });
        }
        match compare_versions(&self.version, installed_version)? {
            Ordering::Greater => Ok(true),
            Ordering::Equal => Ok(false),
            Ordering::Less => Err(UpdateError::DowngradeRefused {
                installed: installed_version.to_string(),
                available: self.version.clone(),
            }),
        }
    }

    pub fn ensure_updater_supported(&self, updater_version: &str) -> Result<()> {
        use std::cmp::Ordering;

        if let Some(minimum) = &self.minimum_updater_version
            && compare_versions(updater_version, minimum)? == Ordering::Less
        {
            return Err(UpdateError::MinimumVersionNotMet {
                installed: updater_version.to_string(),
                minimum: minimum.clone(),
            });
        }
        Ok(())
    }

    pub fn ensure_os_supported(&self, platform: &PlatformInfo) -> Result<()> {
        if let Some(requirement) = &self.minimum_os_version {
            requirement.ensure_supported(platform)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn minimum_supported_version(&self) -> Option<&str> {
        self.minimum_supported_version
            .as_deref()
            .or(self.minimum_version.as_deref())
    }
}

impl ReleasePlatform {
    pub fn validate(&self, policy: &ManifestPolicy) -> Result<()> {
        if self.artifacts.is_empty() {
            return Err(UpdateError::InvalidManifest(
                "platform entry must contain at least one artifact".to_string(),
            ));
        }
        let mut formats = BTreeSet::new();
        for artifact in &self.artifacts {
            artifact.validate(policy)?;
            if !formats.insert(artifact.package_format) {
                return Err(UpdateError::InvalidManifest(format!(
                    "duplicate artifact format `{}`",
                    artifact.package_format.manifest_name()
                )));
            }
        }
        Ok(())
    }
}

fn validate_platform_key(platform: &str) -> Result<()> {
    match platform {
        "windows-x64" | "windows-arm64" | "macos-x64" | "macos-arm64" | "linux-x64"
        | "linux-arm64" => Ok(()),
        _ if platform.trim().is_empty() || !platform.contains('-') => Err(
            UpdateError::InvalidManifest(format!("invalid platform key `{platform}`")),
        ),
        _ => Err(UpdateError::InvalidManifest(format!(
            "unsupported platform key `{platform}`"
        ))),
    }
}

impl ReleaseArtifact {
    pub fn validate(&self, policy: &ManifestPolicy) -> Result<()> {
        validate_release_url(&self.url, policy)?;
        validate_sha256(&self.sha256)?;
        if self.size == 0 || self.size > policy.max_artifact_size {
            return Err(UpdateError::InvalidManifest(format!(
                "artifact size {} is outside the allowed range",
                self.size
            )));
        }
        if let Some(filename) = &self.filename {
            validate_safe_filename(filename)?;
        }
        Ok(())
    }

    pub fn safe_filename(&self) -> Result<String> {
        if let Some(filename) = &self.filename {
            validate_safe_filename(filename)?;
            return Ok(filename.clone());
        }
        let url = Url::parse(&self.url)?;
        let filename = url
            .path_segments()
            .and_then(Iterator::last)
            .filter(|segment| !segment.is_empty())
            .ok_or_else(|| UpdateError::UnsafeFileName(self.url.clone()))?;
        validate_safe_filename(filename)?;
        Ok(filename.to_string())
    }
}

impl ReleaseIndex {
    pub fn parse(bytes: &[u8], policy: &ManifestPolicy) -> Result<Self> {
        let index: Self = serde_json::from_slice(bytes)?;
        index.validate(policy)?;
        Ok(index)
    }

    pub fn validate(&self, policy: &ManifestPolicy) -> Result<()> {
        if self.schema_version != 1 {
            return Err(UpdateError::InvalidManifest(format!(
                "unsupported release index schema version {}",
                self.schema_version
            )));
        }
        if self.releases.is_empty() {
            return Err(UpdateError::InvalidManifest(
                "release index must contain at least one release".to_string(),
            ));
        }
        let mut versions = BTreeSet::new();
        for release in &self.releases {
            release.validate(policy)?;
            if !versions.insert(release.version.clone()) {
                return Err(UpdateError::InvalidManifest(format!(
                    "duplicate release version `{}` in index",
                    release.version
                )));
            }
        }
        Ok(())
    }

    pub fn select_latest_compatible(
        &self,
        platform: &PlatformInfo,
        installed_version: &str,
        updater_version: &str,
        policy: &ManifestPolicy,
    ) -> Result<Option<ReleaseIndexEntry>> {
        self.validate(policy)?;
        let mut compatible = Vec::new();
        for release in &self.releases {
            if compare_versions(&release.version, installed_version)? != std::cmp::Ordering::Greater
            {
                continue;
            }
            if release.ensure_updater_supported(updater_version).is_err()
                || release.ensure_minimum_supported(installed_version).is_err()
                || release.ensure_os_supported(platform).is_err()
                || release.select_format(platform).is_err()
            {
                continue;
            }
            compatible.push(release.clone());
        }
        compatible.sort_by(|left, right| {
            compare_versions(&right.version, &left.version).unwrap_or(std::cmp::Ordering::Equal)
        });
        Ok(compatible.into_iter().next())
    }
}

impl ReleaseIndexEntry {
    pub fn validate(&self, policy: &ManifestPolicy) -> Result<()> {
        parse_version(&self.version)?;
        if let Some(minimum) = &self.minimum_version {
            parse_version(minimum)?;
        }
        if let Some(minimum) = &self.minimum_supported_version {
            parse_version(minimum)?;
        }
        if let Some(minimum) = &self.minimum_updater_version {
            parse_version(minimum)?;
        }
        validate_release_url(&self.manifest_url, policy)?;
        if let Some(hash) = &self.manifest_sha256 {
            validate_sha256(hash)?;
        }
        if let Some(requirement) = &self.minimum_os_version {
            requirement.validate()?;
        }
        if self.platforms.is_empty() {
            return Err(UpdateError::InvalidManifest(
                "release index entry must list supported platforms".to_string(),
            ));
        }
        for (platform, summary) in &self.platforms {
            validate_platform_key(platform)?;
            summary.validate()?;
        }
        Ok(())
    }

    pub fn ensure_updater_supported(&self, updater_version: &str) -> Result<()> {
        if let Some(minimum) = &self.minimum_updater_version
            && compare_versions(updater_version, minimum)? == std::cmp::Ordering::Less
        {
            return Err(UpdateError::MinimumVersionNotMet {
                installed: updater_version.to_string(),
                minimum: minimum.clone(),
            });
        }
        Ok(())
    }

    pub fn ensure_minimum_supported(&self, installed_version: &str) -> Result<()> {
        if let Some(minimum) = self.minimum_supported_version()
            && compare_versions(installed_version, minimum)? == std::cmp::Ordering::Less
        {
            return Err(UpdateError::MinimumVersionNotMet {
                installed: installed_version.to_string(),
                minimum: minimum.to_string(),
            });
        }
        Ok(())
    }

    pub fn ensure_os_supported(&self, platform: &PlatformInfo) -> Result<()> {
        if let Some(requirement) = &self.minimum_os_version {
            requirement.ensure_supported(platform)?;
        }
        Ok(())
    }

    pub fn select_format(&self, platform: &PlatformInfo) -> Result<PackageFormat> {
        let summary = self
            .platforms
            .get(&platform.key.0)
            .ok_or_else(|| UpdateError::IncompatiblePlatform(platform.key.0.clone()))?;
        select_best_format(
            platform.os,
            platform.installation_type,
            summary.formats.iter().copied(),
        )
    }

    #[must_use]
    pub fn minimum_supported_version(&self) -> Option<&str> {
        self.minimum_supported_version
            .as_deref()
            .or(self.minimum_version.as_deref())
    }
}

impl ReleasePlatformSummary {
    pub fn validate(&self) -> Result<()> {
        if self.formats.is_empty() {
            return Err(UpdateError::InvalidManifest(
                "platform summary must contain at least one format".to_string(),
            ));
        }
        let unique: BTreeSet<_> = self.formats.iter().copied().collect();
        if unique.len() != self.formats.len() {
            return Err(UpdateError::InvalidManifest(
                "platform summary contains duplicate formats".to_string(),
            ));
        }
        Ok(())
    }
}

impl MinimumOsVersion {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Simple(value) => validate_version_like(value, "minimumOSVersion"),
            Self::ByOs(requirements) => requirements.validate(),
        }
    }

    pub fn ensure_supported(&self, platform: &PlatformInfo) -> Result<()> {
        match self {
            Self::Simple(value) => ensure_simple_os_requirement(value, platform),
            Self::ByOs(requirements) => requirements.ensure_supported(platform),
        }
    }
}

impl MinimumOsRequirements {
    pub fn validate(&self) -> Result<()> {
        if self.windows.is_none() && self.macos.is_none() && self.linux.is_none() {
            return Err(UpdateError::InvalidManifest(
                "minimumOSVersion must contain at least one OS requirement".to_string(),
            ));
        }
        if let Some(requirement) = &self.windows {
            requirement.validate()?;
        }
        if let Some(requirement) = &self.macos {
            validate_version_like(requirement, "minimumOSVersion.macos")?;
        }
        if let Some(requirement) = &self.linux {
            requirement.validate()?;
        }
        Ok(())
    }

    pub fn ensure_supported(&self, platform: &PlatformInfo) -> Result<()> {
        match platform.os {
            OperatingSystem::Windows => {
                if let Some(requirement) = &self.windows {
                    requirement.ensure_supported(platform)?;
                }
            }
            OperatingSystem::MacOs => {
                if let Some(requirement) = &self.macos {
                    ensure_version_at_least(&platform.os_version, requirement, "macOS")?;
                }
            }
            OperatingSystem::Linux => {
                if let Some(requirement) = &self.linux {
                    requirement.ensure_supported(platform)?;
                }
            }
        }
        Ok(())
    }
}

impl WindowsOsRequirement {
    pub fn validate(&self) -> Result<()> {
        if self.build.is_none() && self.version.is_none() {
            return Err(UpdateError::InvalidManifest(
                "windows OS requirement must include build or version".to_string(),
            ));
        }
        if let Some(version) = &self.version {
            validate_version_like(version, "minimumOSVersion.windows.version")?;
        }
        Ok(())
    }

    pub fn ensure_supported(&self, platform: &PlatformInfo) -> Result<()> {
        if let Some(required_build) = self.build {
            let Some(current_build) = platform.os_build else {
                return Err(UpdateError::UnsupportedOs {
                    required: self
                        .display
                        .clone()
                        .unwrap_or_else(|| format!("Windows build {required_build}+")),
                    current: platform.os_version.clone(),
                });
            };
            if current_build < required_build {
                return Err(UpdateError::UnsupportedOs {
                    required: self
                        .display
                        .clone()
                        .unwrap_or_else(|| format!("Windows build {required_build}+")),
                    current: platform.os_version.clone(),
                });
            }
        }
        if let Some(version) = &self.version {
            ensure_version_at_least(&platform.os_version, version, "Windows")?;
        }
        Ok(())
    }
}

impl LinuxOsRequirement {
    pub fn validate(&self) -> Result<()> {
        if self.kernel.is_none() && self.glibc.is_none() {
            return Err(UpdateError::InvalidManifest(
                "linux OS requirement must include kernel or glibc".to_string(),
            ));
        }
        if let Some(kernel) = &self.kernel {
            validate_version_like(kernel, "minimumOSVersion.linux.kernel")?;
        }
        if let Some(glibc) = &self.glibc {
            validate_version_like(glibc, "minimumOSVersion.linux.glibc")?;
        }
        Ok(())
    }

    pub fn ensure_supported(&self, platform: &PlatformInfo) -> Result<()> {
        if let Some(required) = &self.kernel {
            let current = platform.linux_kernel_version.as_deref().ok_or_else(|| {
                UpdateError::UnsupportedOs {
                    required: format!("Linux kernel {required}+"),
                    current: platform.os_version.clone(),
                }
            })?;
            ensure_version_at_least(current, required, "Linux kernel")?;
        }
        if let Some(required) = &self.glibc {
            let current = platform.linux_glibc_version.as_deref().ok_or_else(|| {
                UpdateError::UnsupportedOs {
                    required: format!("glibc {required}+"),
                    current: platform.os_version.clone(),
                }
            })?;
            ensure_version_at_least(current, required, "glibc")?;
        }
        Ok(())
    }
}

pub fn select_best_format(
    os: OperatingSystem,
    installation_type: InstallationType,
    available: impl IntoIterator<Item = PackageFormat>,
) -> Result<PackageFormat> {
    let available: BTreeSet<_> = available.into_iter().collect();
    let preferences: &[PackageFormat] = match (os, installation_type) {
        (OperatingSystem::Windows, InstallationType::WindowsExe) => &[PackageFormat::Exe],
        (OperatingSystem::Windows, InstallationType::WindowsMsi) => &[PackageFormat::Msi],
        (OperatingSystem::Windows, _) => {
            &[PackageFormat::Msi, PackageFormat::Exe, PackageFormat::TarGz]
        }
        (OperatingSystem::MacOs, InstallationType::MacosPkg) => &[PackageFormat::Pkg],
        (OperatingSystem::MacOs, _) => {
            &[PackageFormat::Dmg, PackageFormat::Pkg, PackageFormat::TarGz]
        }
        (OperatingSystem::Linux, InstallationType::LinuxDeb) => &[PackageFormat::Deb],
        (OperatingSystem::Linux, InstallationType::LinuxRpm) => &[PackageFormat::Rpm],
        (OperatingSystem::Linux, InstallationType::LinuxAppImage) => &[PackageFormat::AppImage],
        (OperatingSystem::Linux, InstallationType::PortableArchive) => &[PackageFormat::TarGz],
        (OperatingSystem::Linux, _) => &[
            PackageFormat::AppImage,
            PackageFormat::TarGz,
            PackageFormat::Deb,
            PackageFormat::Rpm,
        ],
    };
    preferences
        .iter()
        .copied()
        .find(|format| available.contains(format))
        .ok_or_else(|| {
            UpdateError::IncompatiblePlatform(format!(
                "no compatible artifact for installation type {installation_type:?}"
            ))
        })
}

pub fn validate_release_url(raw_url: &str, policy: &ManifestPolicy) -> Result<()> {
    let url = Url::parse(raw_url)?;
    if url.scheme() == "https" {
        return Ok(());
    }
    if policy.allow_insecure_loopback
        && url.scheme() == "http"
        && let Some(host) = url.host_str()
        && matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
    {
        return Ok(());
    }
    Err(UpdateError::UnsafeUrl(url.to_string()))
}

fn validate_sha256(value: &str) -> Result<()> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(UpdateError::InvalidManifest(
            "sha256 must be 64 hexadecimal characters".to_string(),
        ))
    }
}

fn ensure_simple_os_requirement(requirement: &str, platform: &PlatformInfo) -> Result<()> {
    match platform.os {
        OperatingSystem::Windows => {
            ensure_version_at_least(&platform.os_version, requirement, "Windows")
        }
        OperatingSystem::MacOs => {
            ensure_version_at_least(&platform.os_version, requirement, "macOS")
        }
        OperatingSystem::Linux => {
            let current = platform
                .linux_kernel_version
                .as_deref()
                .unwrap_or(&platform.os_version);
            ensure_version_at_least(current, requirement, "Linux kernel")
        }
    }
}

fn ensure_version_at_least(current: &str, required: &str, label: &str) -> Result<()> {
    let current_parts =
        parse_version_components(current).ok_or_else(|| UpdateError::UnsupportedOs {
            required: format!("{label} {required}+"),
            current: current.to_string(),
        })?;
    let required_parts = parse_version_components(required).ok_or_else(|| {
        UpdateError::InvalidManifest(format!("invalid {label} version requirement `{required}`"))
    })?;
    if compare_component_versions(&current_parts, &required_parts) == std::cmp::Ordering::Less {
        return Err(UpdateError::UnsupportedOs {
            required: format!("{label} {required}+"),
            current: current.to_string(),
        });
    }
    Ok(())
}

fn validate_version_like(value: &str, field: &str) -> Result<()> {
    if parse_version_components(value).is_some() {
        Ok(())
    } else {
        Err(UpdateError::InvalidManifest(format!(
            "{field} must contain a numeric version"
        )))
    }
}

fn parse_version_components(value: &str) -> Option<Vec<u32>> {
    let mut parts = Vec::new();
    for token in value.split(|ch: char| !ch.is_ascii_digit()) {
        if token.is_empty() {
            continue;
        }
        parts.push(token.parse().ok()?);
    }
    (!parts.is_empty()).then_some(parts)
}

fn compare_component_versions(left: &[u32], right: &[u32]) -> std::cmp::Ordering {
    let width = left.len().max(right.len());
    for index in 0..width {
        let left_part = left.get(index).copied().unwrap_or(0);
        let right_part = right.get(index).copied().unwrap_or(0);
        match left_part.cmp(&right_part) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    std::cmp::Ordering::Equal
}

fn validate_safe_filename(value: &str) -> Result<()> {
    let path = Path::new(value);
    let unsafe_name = value.is_empty()
        || value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || path.file_name().and_then(|name| name.to_str()) != Some(value);
    if unsafe_name {
        Err(UpdateError::UnsafeFileName(value.to_string()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ManifestPolicy, MinimumOsVersion, ReleaseIndex, ReleaseManifest, select_best_format,
    };
    use crate::installer::PackageFormat;
    use crate::platform::{Architecture, InstallationType, OperatingSystem, PlatformInfo};

    fn manifest_json(url: &str) -> String {
        format!(
            r#"{{
              "version":"2.4.1",
              "releaseDate":"2026-08-07",
              "minimumVersion":"1.5.0",
              "releaseNotes":"Fixed crashes.",
              "platforms":{{
                "windows-x64":{{"artifacts":[
                  {{"format":"msi","url":"{url}","sha256":"{}","size":42,"filename":"app-2.4.1.msi"}},
                  {{"format":"exe","url":"https://example.com/app.exe","sha256":"{}","size":43,"filename":"app-2.4.1.exe"}}
                ]}}
              }}
            }}"#,
            "a".repeat(64),
            "b".repeat(64)
        )
    }

    #[test]
    fn manifest_validation_accepts_expected_shape() {
        let manifest = ReleaseManifest::parse(
            manifest_json("https://example.com/app.msi").as_bytes(),
            &ManifestPolicy::default(),
        )
        .unwrap();
        assert_eq!(manifest.version, "2.4.1");
        assert_eq!(manifest.platforms["windows-x64"].artifacts.len(), 2);
    }

    #[test]
    fn manifest_validation_rejects_insecure_remote_urls() {
        let result = ReleaseManifest::parse(
            manifest_json("http://example.com/app.msi").as_bytes(),
            &ManifestPolicy::default(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn manifest_validation_allows_loopback_only_with_explicit_test_policy() {
        let policy = ManifestPolicy::default().allow_insecure_loopback_for_tests();
        let result = ReleaseManifest::parse(
            manifest_json("http://127.0.0.1:9999/app.msi").as_bytes(),
            &policy,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn manifest_validation_rejects_unknown_platform_keys() {
        let json =
            manifest_json("https://example.com/app.msi").replace("windows-x64", "windows-riscv64");
        let result = ReleaseManifest::parse(json.as_bytes(), &ManifestPolicy::default());
        assert!(result.is_err());
    }

    #[test]
    fn manifest_selection_rejects_incompatible_platforms() {
        let manifest = ReleaseManifest::parse(
            manifest_json("https://example.com/app.msi").as_bytes(),
            &ManifestPolicy::default(),
        )
        .unwrap();
        let linux = PlatformInfo::from_parts(
            OperatingSystem::Linux,
            "Linux",
            Architecture::X64,
            Architecture::X64,
        );
        assert!(
            manifest
                .select_for_platform(&linux, &ManifestPolicy::default())
                .is_err()
        );
    }

    #[test]
    fn manifest_selection_prefers_current_installation_format() {
        let manifest = ReleaseManifest::parse(
            manifest_json("https://example.com/app.msi").as_bytes(),
            &ManifestPolicy::default(),
        )
        .unwrap();
        let windows_exe = PlatformInfo::from_parts(
            OperatingSystem::Windows,
            "Windows 11 build 22631",
            Architecture::X64,
            Architecture::X64,
        )
        .with_installation_type(InstallationType::WindowsExe);
        let selection = manifest
            .select_for_platform(&windows_exe, &ManifestPolicy::default())
            .unwrap();
        assert_eq!(selection.package_format, PackageFormat::Exe);
    }

    #[test]
    fn linux_deb_install_does_not_silently_migrate_to_appimage() {
        assert!(
            select_best_format(
                OperatingSystem::Linux,
                InstallationType::LinuxDeb,
                [PackageFormat::AppImage],
            )
            .is_err()
        );
    }

    #[test]
    fn downgrade_and_minimum_version_are_enforced() {
        let manifest = ReleaseManifest::parse(
            manifest_json("https://example.com/app.msi").as_bytes(),
            &ManifestPolicy::default(),
        )
        .unwrap();
        assert!(manifest.ensure_update_allowed("1.4.9").is_err());
        assert!(manifest.ensure_update_allowed("2.5.0").is_err());
        assert!(!manifest.ensure_update_allowed("2.4.1").unwrap());
        assert!(manifest.ensure_update_allowed("2.4.0").unwrap());
    }

    #[test]
    fn minimum_updater_version_is_enforced() {
        let json = manifest_json("https://example.com/app.msi").replace(
            "\"minimumVersion\":\"1.5.0\"",
            "\"minimumVersion\":\"1.5.0\",\"minimumUpdaterVersion\":\"1.8.0\"",
        );
        let manifest = ReleaseManifest::parse(json.as_bytes(), &ManifestPolicy::default()).unwrap();
        assert!(manifest.ensure_updater_supported("1.7.9").is_err());
        assert!(manifest.ensure_updater_supported("1.8.0").is_ok());
    }

    #[test]
    fn minimum_windows_build_is_enforced_before_download() {
        let json = manifest_json("https://example.com/app.msi").replace(
            "\"releaseNotes\":\"Fixed crashes.\"",
            "\"releaseNotes\":\"Fixed crashes.\",\"minimumOSVersion\":{\"windows\":{\"build\":22631,\"display\":\"Windows 11 23H2\"}}",
        );
        let manifest = ReleaseManifest::parse(json.as_bytes(), &ManifestPolicy::default()).unwrap();
        let windows10 = PlatformInfo::from_parts(
            OperatingSystem::Windows,
            "Windows 10 22H2 build 19045",
            Architecture::X64,
            Architecture::X64,
        )
        .with_os_build(19045);
        assert!(manifest.ensure_os_supported(&windows10).is_err());
    }

    #[test]
    fn minimum_macos_version_is_compared_semantically() {
        let requirement = MinimumOsVersion::Simple("14.0".to_string());
        let macos13 = PlatformInfo::from_parts(
            OperatingSystem::MacOs,
            "13.6.1",
            Architecture::Arm64,
            Architecture::Arm64,
        );
        assert!(requirement.ensure_supported(&macos13).is_err());
    }

    #[test]
    fn release_index_selects_latest_compatible_release() {
        let json = r#"{
          "schemaVersion":1,
          "generatedAt":"2026-08-08T00:00:00Z",
          "releases":[
            {"version":"2.5.0","releaseDate":"2026-08-08","manifestUrl":"https://example.com/2.5/release-manifest.json","minimumOSVersion":{"windows":{"build":22631}},"platforms":{"windows-x64":{"formats":["msi"]}}},
            {"version":"2.4.3","releaseDate":"2026-08-07","manifestUrl":"https://example.com/2.4/release-manifest.json","platforms":{"windows-x64":{"formats":["msi"]}}}
          ]
        }"#;
        let index = ReleaseIndex::parse(json.as_bytes(), &ManifestPolicy::default()).unwrap();
        let windows10 = PlatformInfo::from_parts(
            OperatingSystem::Windows,
            "Windows 10 build 19045",
            Architecture::X64,
            Architecture::X64,
        )
        .with_os_build(19045)
        .with_installation_type(InstallationType::WindowsMsi);
        let selected = index
            .select_latest_compatible(&windows10, "2.4.0", "2.4.0", &ManifestPolicy::default())
            .unwrap()
            .unwrap();
        assert_eq!(selected.version, "2.4.3");
    }
}
