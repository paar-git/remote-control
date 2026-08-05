//! Reading directories and file metadata.
//!
//! # Symlinks are reported, never followed
//!
//! Metadata is read with `symlink_metadata`, so a link is reported *as a link* with its
//! recorded target. Using ordinary `metadata` would follow it, and a link to a
//! 40-gigabyte file elsewhere on the disk would be listed as an ordinary 40-gigabyte
//! file sitting in the directory — which is not what is there, and is exactly the
//! confusion a symlink escape relies on.
//!
//! What happens when the operator *opens* one is a separate decision, made by
//! [`crate::path::PathPolicy`], which refuses a link that leaves the permitted roots.
//!
//! # Listings are bounded
//!
//! A directory can hold millions of entries. The result is truncated and says so, so a
//! client shows "showing the first 10,000 of many" rather than waiting for a frame that
//! would exceed the channel ceiling.

use std::path::Path;

use rc_protocol::files::{DirEntry, EntryKind};
use rc_protocol::limits::MAX_DIR_ENTRIES;

use crate::error::{FileError, Result};

/// Read a directory.
///
/// `path` must already have been resolved by [`crate::path::PathPolicy::resolve`].
/// Returns the entries and whether the listing was truncated.
///
/// # Errors
/// [`FileError::NotFound`], [`FileError::PermissionDenied`] or [`FileError::WrongKind`]
/// if the path is not a directory.
pub fn list_directory(path: &Path, include_hidden: bool) -> Result<(Vec<DirEntry>, bool)> {
    let metadata = std::fs::symlink_metadata(path).map_err(|err| FileError::from_io(&err))?;
    if !metadata.is_dir() {
        return Err(FileError::WrongKind);
    }

    let reader = std::fs::read_dir(path).map_err(|err| FileError::from_io(&err))?;

    let mut entries = Vec::new();
    let mut truncated = false;

    for item in reader {
        // One unreadable entry must not fail the whole listing: a directory routinely
        // contains something the agent's account cannot stat, and refusing to show the
        // other 500 files because of it would make the browser useless.
        let Ok(item) = item else {
            continue;
        };

        let name = item.file_name().to_string_lossy().into_owned();
        let hidden = is_hidden(&name, item.path().as_path());
        if hidden && !include_hidden {
            continue;
        }

        if entries.len() >= MAX_DIR_ENTRIES {
            truncated = true;
            break;
        }

        entries.push(describe(&name, &item.path(), hidden));
    }

    // Directories first, then by name. Case-insensitive so a listing does not put every
    // capitalised name in a block above the rest, which is not how anyone reads a
    // folder.
    entries.sort_by(|a, b| {
        let kind = directory_first(a.kind).cmp(&directory_first(b.kind));
        kind.then_with(|| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then_with(|| a.name.cmp(&b.name))
        })
    });

    Ok((entries, truncated))
}

/// Describe a single path.
///
/// # Errors
/// [`FileError::NotFound`] or [`FileError::PermissionDenied`].
pub fn stat(path: &Path) -> Result<DirEntry> {
    // Existence is checked here so a missing path reports `NotFound` rather than being
    // described with default metadata.
    std::fs::symlink_metadata(path).map_err(|err| FileError::from_io(&err))?;

    let name = path.file_name().map_or_else(
        || path.to_string_lossy().into_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    let hidden = is_hidden(&name, path);

    Ok(describe(&name, path, hidden))
}

/// Build the description of one entry.
///
/// Never fails: an entry whose metadata cannot be read is described as unreadable
/// rather than omitted, because an operator needs to see that something is there even
/// when the agent cannot look at it.
fn describe(name: &str, path: &Path, hidden: bool) -> DirEntry {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return DirEntry {
            name: name.to_owned(),
            kind: EntryKind::Other,
            size_bytes: 0,
            modified_ms: None,
            hidden,
            readable: false,
            writable: false,
            permissions: "unreadable".to_owned(),
            symlink_target: None,
        };
    };

    let file_type = metadata.file_type();
    let kind = if file_type.is_symlink() {
        EntryKind::Symlink
    } else if file_type.is_dir() {
        EntryKind::Directory
    } else if file_type.is_file() {
        EntryKind::File
    } else {
        EntryKind::Other
    };

    DirEntry {
        name: name.to_owned(),
        kind,
        size_bytes: metadata.len(),
        modified_ms: modified_ms(&metadata),
        hidden,
        // Probed by attempting the operation rather than by reading a mode bit: on
        // Windows the mode says almost nothing, and on Unix an ACL can contradict it.
        readable: is_readable(path, kind),
        writable: !metadata.permissions().readonly(),
        permissions: permission_string(&metadata),
        // The *recorded* target, not where it resolves to. Untrusted text; the UI must
        // render it as inert.
        symlink_target: if kind == EntryKind::Symlink {
            std::fs::read_link(path)
                .ok()
                .map(|target| target.to_string_lossy().into_owned())
        } else {
            None
        },
    }
}

/// Last-modified time in milliseconds since the Unix epoch.
fn modified_ms(metadata: &std::fs::Metadata) -> Option<i64> {
    let modified = metadata.modified().ok()?;
    let since_epoch = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    i64::try_from(since_epoch.as_millis()).ok()
}

/// Whether the agent can open this entry for reading.
fn is_readable(path: &Path, kind: EntryKind) -> bool {
    match kind {
        // Opening a directory as a file fails on most platforms, so readability is
        // probed by whether it can be enumerated.
        EntryKind::Directory => std::fs::read_dir(path).is_ok(),
        EntryKind::File => std::fs::File::open(path).is_ok(),
        // A symlink's readability is a question about its target, which this listing
        // deliberately does not follow.
        _ => false,
    }
}

/// A human-readable permission summary.
fn permission_string(metadata: &std::fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mode = metadata.permissions().mode();
        let bit = |shift: u32, flag: u32, symbol: char| {
            if (mode >> shift) & flag == flag {
                symbol
            } else {
                '-'
            }
        };

        return [
            bit(6, 4, 'r'),
            bit(6, 2, 'w'),
            bit(6, 1, 'x'),
            bit(3, 4, 'r'),
            bit(3, 2, 'w'),
            bit(3, 1, 'x'),
            bit(0, 4, 'r'),
            bit(0, 2, 'w'),
            bit(0, 1, 'x'),
        ]
        .into_iter()
        .collect();
    }

    #[cfg(not(unix))]
    {
        // Windows has no mode bits worth rendering as `rwx`. Reporting the one thing
        // the API actually answers is more honest than inventing nine characters.
        if metadata.permissions().readonly() {
            "read-only".to_owned()
        } else {
            "read/write".to_owned()
        }
    }
}

/// Whether the platform considers this entry hidden.
fn is_hidden(name: &str, path: &Path) -> bool {
    // A leading dot on every platform: a repository checked out on Windows still has a
    // `.git` directory, and an operator browsing it expects it to be hidden.
    if name.starts_with('.') && name != "." && name != ".." {
        return true;
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
        const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;

        if let Ok(metadata) = std::fs::symlink_metadata(path) {
            let attributes = metadata.file_attributes();
            return attributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) != 0;
        }
    }

    #[cfg(not(windows))]
    let _ = path;

    false
}

/// Sort key placing directories before everything else.
const fn directory_first(kind: EntryKind) -> u8 {
    match kind {
        EntryKind::Directory => 0,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory with a known set of entries.
    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("beta.txt"), b"hello").unwrap();
        std::fs::write(dir.path().join("Alpha.txt"), b"hi").unwrap();
        std::fs::write(dir.path().join(".hidden"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("zeta-dir")).unwrap();
        dir
    }

    #[test]
    fn a_directory_lists_its_entries() {
        let dir = fixture();
        let (entries, truncated) = list_directory(dir.path(), false).unwrap();

        assert!(!truncated);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"beta.txt"));
        assert!(names.contains(&"Alpha.txt"));
        assert!(names.contains(&"zeta-dir"));
    }

    #[test]
    fn hidden_entries_are_excluded_unless_asked_for() {
        let dir = fixture();

        let (without, _) = list_directory(dir.path(), false).unwrap();
        assert!(without.iter().all(|e| e.name != ".hidden"));

        let (with, _) = list_directory(dir.path(), true).unwrap();
        let hidden = with.iter().find(|e| e.name == ".hidden").unwrap();
        assert!(hidden.hidden, "it must also be marked hidden");
    }

    #[test]
    fn directories_sort_before_files_and_names_ignore_case() {
        // Otherwise every capitalised name lands in a block above the rest, which is
        // not how anyone reads a folder.
        let dir = fixture();
        let (entries, _) = list_directory(dir.path(), false).unwrap();

        assert_eq!(entries[0].name, "zeta-dir", "directories come first");
        let files: Vec<&str> = entries[1..].iter().map(|e| e.name.as_str()).collect();
        assert_eq!(files, vec!["Alpha.txt", "beta.txt"]);
    }

    #[test]
    fn a_files_size_and_kind_are_reported() {
        let dir = fixture();
        let (entries, _) = list_directory(dir.path(), false).unwrap();

        let file = entries.iter().find(|e| e.name == "beta.txt").unwrap();
        assert_eq!(file.kind, EntryKind::File);
        assert_eq!(file.size_bytes, 5);
        assert!(file.readable);
        assert!(file.modified_ms.is_some());
        assert!(!file.permissions.is_empty());
    }

    #[test]
    fn listing_a_file_rather_than_a_directory_is_refused() {
        let dir = fixture();
        assert_eq!(
            list_directory(&dir.path().join("beta.txt"), false),
            Err(FileError::WrongKind)
        );
    }

    #[test]
    fn listing_a_missing_directory_reports_not_found() {
        let dir = fixture();
        assert_eq!(
            list_directory(&dir.path().join("no-such-dir"), false),
            Err(FileError::NotFound)
        );
    }

    #[test]
    fn stat_describes_a_single_entry() {
        let dir = fixture();
        let entry = stat(&dir.path().join("beta.txt")).unwrap();

        assert_eq!(entry.name, "beta.txt");
        assert_eq!(entry.kind, EntryKind::File);
        assert_eq!(entry.size_bytes, 5);
    }

    #[test]
    fn stat_on_a_missing_path_reports_not_found() {
        let dir = fixture();
        assert_eq!(
            stat(&dir.path().join("nothing-here")),
            Err(FileError::NotFound)
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_reported_as_a_link_not_as_its_target() {
        // Following it would list a link to a 40 GB file as a 40 GB file sitting in
        // this directory, which is not what is there.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.txt");
        std::fs::write(&target, vec![b'x'; 1024]).unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("link.txt")).unwrap();

        let (entries, _) = list_directory(dir.path(), false).unwrap();
        let link = entries.iter().find(|e| e.name == "link.txt").unwrap();

        assert_eq!(link.kind, EntryKind::Symlink);
        assert_ne!(
            link.size_bytes, 1024,
            "the link's own size, not its target's"
        );
        assert!(
            link.symlink_target
                .as_deref()
                .is_some_and(|t| t.contains("real.txt")),
            "the recorded target must be reported"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_broken_symlink_still_appears_in_the_listing() {
        // An operator needs to see that it is there in order to delete it.
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(
            dir.path().join("does-not-exist"),
            dir.path().join("dangling"),
        )
        .unwrap();

        let (entries, _) = list_directory(dir.path(), false).unwrap();
        let dangling = entries.iter().find(|e| e.name == "dangling").unwrap();

        assert_eq!(dangling.kind, EntryKind::Symlink);
    }

    #[test]
    fn an_empty_directory_lists_nothing_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        let (entries, truncated) = list_directory(dir.path(), false).unwrap();

        assert!(entries.is_empty());
        assert!(!truncated);
    }

    #[test]
    fn a_hostile_file_name_is_carried_through_unchanged() {
        // Sanitising is the UI's job; mangling it here would mean the name shown could
        // not be used to act on the file.
        let dir = tempfile::tempdir().unwrap();
        let hostile = "co\u{202e}gnp.exe";
        std::fs::write(dir.path().join(hostile), b"x").unwrap();

        let (entries, _) = list_directory(dir.path(), false).unwrap();
        assert!(entries.iter().any(|e| e.name == hostile));
    }

    #[test]
    fn a_large_directory_is_truncated_and_says_so() {
        // A client must be able to show "the first 10,000 of many" rather than waiting
        // for a frame that would exceed the channel ceiling.
        let dir = tempfile::tempdir().unwrap();
        for index in 0..(MAX_DIR_ENTRIES + 50) {
            std::fs::write(dir.path().join(format!("f{index}")), b"").unwrap();
        }

        let (entries, truncated) = list_directory(dir.path(), false).unwrap();
        assert_eq!(entries.len(), MAX_DIR_ENTRIES);
        assert!(truncated);
    }

    #[test]
    fn a_directory_is_reported_as_readable_when_it_can_be_enumerated() {
        let dir = fixture();
        let (entries, _) = list_directory(dir.path(), false).unwrap();

        let directory = entries.iter().find(|e| e.name == "zeta-dir").unwrap();
        assert_eq!(directory.kind, EntryKind::Directory);
        assert!(directory.readable);
    }
}
