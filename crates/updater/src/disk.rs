use std::path::Path;

use sysinfo::Disks;

use crate::error::{Result, UpdateError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskSpaceCheck {
    pub required_bytes: u64,
    pub available_bytes: u64,
}

impl DiskSpaceCheck {
    #[must_use]
    pub const fn has_enough_space(&self) -> bool {
        self.available_bytes >= self.required_bytes
    }
}

pub fn required_space(download_size: u64, install_size: Option<u64>) -> u64 {
    download_size
        .saturating_mul(2)
        .saturating_add(install_size.unwrap_or(download_size))
        .saturating_add(256 * 1024 * 1024)
}

/// Refuse the update when the target volume is known to lack room for it.
///
/// When the volume cannot be identified at all -- an unusual mount point, a
/// network share, a container bind mount -- the check is skipped rather than
/// treated as zero bytes free. Reporting "insufficient disk space" for a disk
/// we simply failed to measure would block every update on that machine, which
/// is far worse than letting the download fail later with a real write error.
pub fn check_disk_space(target: &Path, required_bytes: u64) -> Result<DiskSpaceCheck> {
    let available_bytes = available_space_for_path(target);
    if available_bytes.is_none() {
        tracing::warn!(
            path = %target.display(),
            "could not determine free space for the update volume; skipping the disk-space check"
        );
    }
    evaluate_disk_space(required_bytes, available_bytes)
}

/// The decision half of [`check_disk_space`], separated so both the "measured"
/// and "unmeasurable" branches can be tested without a real filesystem.
pub fn evaluate_disk_space(
    required_bytes: u64,
    available_bytes: Option<u64>,
) -> Result<DiskSpaceCheck> {
    let Some(available_bytes) = available_bytes else {
        return Ok(DiskSpaceCheck {
            required_bytes,
            available_bytes: u64::MAX,
        });
    };
    let check = DiskSpaceCheck {
        required_bytes,
        available_bytes,
    };
    if check.has_enough_space() {
        Ok(check)
    } else {
        Err(UpdateError::InsufficientDiskSpace {
            required_bytes,
            available_bytes,
        })
    }
}

fn available_space_for_path(target: &Path) -> Option<u64> {
    let target = target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf());
    let disks = Disks::new_with_refreshed_list();
    disks
        .iter()
        .filter(|disk| target.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().as_os_str().len())
        .map(sysinfo::Disk::available_space)
}

#[cfg(test)]
mod tests {
    use super::{DiskSpaceCheck, evaluate_disk_space, required_space};

    #[test]
    fn disk_space_calculation_includes_download_install_and_backup() {
        assert!(required_space(100, Some(400)) >= 700);
    }

    #[test]
    fn insufficient_disk_space_is_detected() {
        let check = DiskSpaceCheck {
            required_bytes: 10,
            available_bytes: 9,
        };
        assert!(!check.has_enough_space());
    }

    #[test]
    fn measured_volume_without_room_is_rejected() {
        assert!(evaluate_disk_space(10, Some(9)).is_err());
    }

    #[test]
    fn measured_volume_with_room_is_accepted() {
        assert!(evaluate_disk_space(10, Some(10)).is_ok());
    }

    #[test]
    fn unmeasurable_volume_does_not_block_the_update() {
        let check = evaluate_disk_space(u64::MAX, None)
            .expect("an unmeasurable volume must not fail the check");
        assert_eq!(check.available_bytes, u64::MAX);
    }
}
