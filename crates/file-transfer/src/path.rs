//! Turning an untrusted path into one it is safe to touch.
//!
//! # The threat
//!
//! Every path in a file message is chosen by the peer. Three classes of attack follow
//! from that, and this module exists to close all three:
//!
//! | Attack | Example | Closed by |
//! |---|---|---|
//! | Traversal | `roots/../../etc/shadow` | Lexical normalisation before any I/O |
//! | Symlink escape | `roots/link` → `/etc` | Canonicalising and re-checking after resolution |
//! | Reserved names | `roots/CON`, `roots/x.` on Windows | An explicit refusal list |
//!
//! # Why the check happens twice
//!
//! A path is normalised *lexically* first — `..` components are resolved without
//! touching the filesystem — and the result is checked against the configured roots.
//! Then, if the path exists, it is canonicalised by the operating system, which follows
//! symlinks, and the result is checked **again**.
//!
//! Both are necessary. The lexical pass alone misses a symlink pointing outside the
//! root. The canonical pass alone cannot run on a path that does not exist yet, which
//! is exactly the case for every upload destination and every new directory.
//!
//! # Confinement is opt-in and stated
//!
//! With no roots configured, any absolute path is permitted. That is the right default
//! for a server the operator administers — confining them to one directory on their own
//! machine would be theatre — but it is a deliberate choice, written down here and in
//! the agent's configuration, not an accident.
//!
//! Traversal and symlink checks still run when there are no roots: they normalise the
//! path so what is opened is what the audit trail records, and they still refuse
//! reserved names.

use std::path::{Component, Path, PathBuf};

use crate::error::{FileError, Result};

/// Names Windows refuses to treat as ordinary files, in any directory and with any
/// extension.
///
/// Creating `CON.txt` does not create a file — it opens the console device. A transfer
/// that appeared to succeed and wrote nowhere is worse than one that failed, so these
/// are refused outright.
const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Where a peer is allowed to read and write.
#[derive(Debug, Clone, Default)]
pub struct PathPolicy {
    /// Directories the peer is confined to.
    ///
    /// Empty means the whole filesystem, which is appropriate for a server the operator
    /// administers and is stated explicitly rather than assumed.
    roots: Vec<PathBuf>,
}

impl PathPolicy {
    /// A policy confining access to `roots`.
    ///
    /// # Errors
    /// [`FileError::BadRoot`] if a root is not absolute. A relative root would be
    /// resolved against whatever directory the agent happened to be started in, which
    /// is not a confinement anyone could reason about.
    pub fn confined_to(roots: impl IntoIterator<Item = PathBuf>) -> Result<Self> {
        let roots: Vec<PathBuf> = roots.into_iter().collect();

        for root in &roots {
            if !root.is_absolute() {
                return Err(FileError::BadRoot);
            }
        }

        Ok(Self { roots })
    }

    /// A policy permitting any absolute path.
    #[must_use]
    pub const fn unconfined() -> Self {
        Self { roots: Vec::new() }
    }

    /// Whether any confinement is in force.
    #[must_use]
    pub fn is_confined(&self) -> bool {
        !self.roots.is_empty()
    }

    /// Whether `path` lies inside a configured root.
    ///
    /// Compared component by component rather than as strings: `/data` must not appear
    /// to contain `/database`, which a `starts_with` on the text would happily conclude.
    #[must_use]
    pub fn permits(&self, path: &Path) -> bool {
        if self.roots.is_empty() {
            return true;
        }
        self.roots.iter().any(|root| path.starts_with(root))
    }

    /// Resolve an untrusted path into one that is safe to touch.
    ///
    /// # Errors
    /// * [`FileError::NotAbsolute`] — a relative path has no meaning across a network.
    /// * [`FileError::OutsideRoot`] — traversal, or a symlink pointing out of a root.
    /// * [`FileError::ReservedName`] — a Windows device name.
    /// * [`FileError::InvalidPath`] — embedded NUL or an otherwise unusable value.
    pub fn resolve(&self, raw: &str) -> Result<PathBuf> {
        // A NUL truncates the path at the system-call boundary, so a value containing
        // one names a different file than it appears to.
        if raw.contains('\0') {
            return Err(FileError::InvalidPath);
        }
        if raw.trim().is_empty() {
            return Err(FileError::InvalidPath);
        }

        let path = Path::new(raw);
        if !path.is_absolute() {
            return Err(FileError::NotAbsolute);
        }

        let lexical = normalise(path)?;
        reject_reserved_names(&lexical)?;

        if !self.permits(&lexical) {
            return Err(FileError::OutsideRoot);
        }

        // Second pass, for anything that exists: the OS follows symlinks, and the
        // result must land inside a root too. A path that does not exist yet — every
        // upload destination — cannot be canonicalised, so the lexical check stands
        // alone for it, and its *parent* is checked instead.
        let Ok(canonical) = lexical.canonicalize() else {
            // The path does not exist. Its parent must, and must be inside a root —
            // otherwise a peer could create a file through a symlinked parent that
            // points outside.
            if let Some(parent) = lexical.parent()
                && let Ok(canonical_parent) = parent.canonicalize()
                && !self.permits(&strip_verbatim_prefix(canonical_parent))
            {
                return Err(FileError::OutsideRoot);
            }
            return Ok(lexical);
        };

        let canonical = strip_verbatim_prefix(canonical);
        if self.permits(&canonical) {
            Ok(canonical)
        } else {
            // A symlink pointing out of the root. Reported as the same error as
            // traversal: from the peer's side they are the same refusal, and
            // distinguishing them would describe the filesystem layout.
            Err(FileError::OutsideRoot)
        }
    }
}

/// Resolve `.` and `..` without touching the filesystem.
///
/// # Errors
/// [`FileError::OutsideRoot`] if the path climbs above its own root, which is a
/// traversal attempt rather than a path that could ever be valid.
fn normalise(path: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    let mut depth = 0usize;

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            // `.` is a no-op, not a component.
            Component::CurDir => {}
            Component::ParentDir => {
                if depth == 0 {
                    // `/..` has nowhere to go. On a real filesystem it silently stays
                    // at the root; treating it as an error makes the attempt visible.
                    return Err(FileError::OutsideRoot);
                }
                out.pop();
                depth -= 1;
            }
            Component::Normal(name) => {
                out.push(name);
                depth += 1;
            }
        }
    }

    Ok(out)
}

/// Refuse Windows device names, which do not behave like files.
fn reject_reserved_names(path: &Path) -> Result<()> {
    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let Some(name) = name.to_str() else {
            continue;
        };

        // The device name applies with any extension: `CON`, `CON.txt` and `CON.a.b`
        // all open the console.
        let stem = name.split('.').next().unwrap_or(name);
        if WINDOWS_RESERVED
            .iter()
            .any(|reserved| stem.eq_ignore_ascii_case(reserved))
        {
            return Err(FileError::ReservedName);
        }

        // A trailing space or dot is silently stripped by Windows, so `secret.txt.`
        // and `secret.txt ` both open `secret.txt` — a name that does not mean what it
        // says is a name to refuse.
        if name.ends_with(' ') || name.ends_with('.') {
            return Err(FileError::ReservedName);
        }
    }

    Ok(())
}

/// Remove the `\\?\` prefix Windows adds when canonicalising.
///
/// Left in place it would make every path comparison against a configured root fail,
/// and would put an unfamiliar prefix in front of every path shown to the operator.
fn strip_verbatim_prefix(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();

    if let Some(stripped) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{stripped}"));
    }
    if let Some(stripped) = text.strip_prefix(r"\\?\") {
        return PathBuf::from(stripped);
    }
    path
}

/// Whether a file name is safe to create from an untrusted value.
///
/// Used for the *name* half of an upload, where the peer supplies a bare name rather
/// than a path. A name containing a separator would place the file somewhere other than
/// the directory the operator chose.
///
/// # Errors
/// [`FileError::InvalidPath`] or [`FileError::ReservedName`].
pub fn validate_file_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(FileError::InvalidPath);
    }
    if name.contains('\0') {
        return Err(FileError::InvalidPath);
    }
    // Both separators are checked on both platforms: a name containing a backslash is
    // a subdirectory on Windows, and refusing it on Unix costs nothing while stopping
    // a name that would become a traversal if the file were later copied.
    if name.contains('/') || name.contains('\\') {
        return Err(FileError::InvalidPath);
    }
    if name.len() > 255 {
        return Err(FileError::InvalidPath);
    }

    reject_reserved_names(Path::new(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("a temporary directory")
    }

    /// A policy confined to `dir`, with the directory canonicalised as the agent would.
    fn confined(dir: &Path) -> PathPolicy {
        let canonical = strip_verbatim_prefix(dir.canonicalize().unwrap());
        PathPolicy::confined_to([canonical]).unwrap()
    }

    fn as_str(path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }

    // -- traversal -----------------------------------------------------------

    #[test]
    fn a_traversal_out_of_a_root_is_refused() {
        let root = temp_root();
        let policy = confined(root.path());

        let escape = format!("{}/../../etc/passwd", as_str(root.path()));
        assert_eq!(policy.resolve(&escape), Err(FileError::OutsideRoot));
    }

    #[test]
    fn a_traversal_that_returns_inside_the_root_is_allowed() {
        // `root/sub/../file` is just `root/file`. Refusing it would break ordinary
        // paths that happen to contain `..`, which is not what the check is for.
        let root = temp_root();
        std::fs::create_dir(root.path().join("sub")).unwrap();
        let policy = confined(root.path());

        let path = format!("{}/sub/../file.txt", as_str(root.path()));
        let resolved = policy.resolve(&path).expect("a path that stays inside");

        assert!(resolved.ends_with("file.txt"));
        assert!(!as_str(&resolved).contains(".."), "must be normalised");
    }

    #[test]
    fn climbing_above_the_filesystem_root_is_refused() {
        let policy = PathPolicy::unconfined();
        let attempt = if cfg!(windows) {
            r"C:\..\..\windows"
        } else {
            "/../../etc"
        };
        assert_eq!(policy.resolve(attempt), Err(FileError::OutsideRoot));
    }

    #[test]
    fn a_relative_path_is_refused() {
        // A relative path would be resolved against whatever directory the agent
        // happened to be started in, which the peer cannot know.
        let policy = PathPolicy::unconfined();
        assert_eq!(policy.resolve("etc/passwd"), Err(FileError::NotAbsolute));
        assert_eq!(policy.resolve("../x"), Err(FileError::NotAbsolute));
    }

    #[test]
    fn a_path_outside_every_root_is_refused_even_without_traversal() {
        let root = temp_root();
        let other = temp_root();
        let policy = confined(root.path());

        let path = format!("{}/file.txt", as_str(other.path()));
        assert_eq!(policy.resolve(&path), Err(FileError::OutsideRoot));
    }

    #[test]
    fn a_sibling_directory_with_a_shared_prefix_is_not_inside_the_root() {
        // The bug a string `starts_with` would introduce: `/data` appearing to contain
        // `/database`.
        let policy = PathPolicy::confined_to([PathBuf::from(if cfg!(windows) {
            r"C:\data"
        } else {
            "/data"
        })])
        .unwrap();

        let sibling = Path::new(if cfg!(windows) {
            r"C:\database\secret"
        } else {
            "/database/secret"
        });
        assert!(!policy.permits(sibling));
    }

    // -- symlinks ------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn a_symlink_pointing_out_of_the_root_is_refused() {
        // The attack the lexical check alone would miss entirely.
        let root = temp_root();
        let outside = temp_root();
        std::fs::write(outside.path().join("secret.txt"), b"secret").unwrap();

        std::os::unix::fs::symlink(outside.path(), root.path().join("escape")).unwrap();
        let policy = confined(root.path());

        let through_link = format!("{}/escape/secret.txt", as_str(root.path()));
        assert_eq!(policy.resolve(&through_link), Err(FileError::OutsideRoot));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_staying_inside_the_root_is_allowed() {
        let root = temp_root();
        std::fs::create_dir(root.path().join("real")).unwrap();
        std::fs::write(root.path().join("real/file.txt"), b"data").unwrap();
        std::os::unix::fs::symlink(root.path().join("real"), root.path().join("link")).unwrap();

        let policy = confined(root.path());
        let through_link = format!("{}/link/file.txt", as_str(root.path()));

        assert!(policy.resolve(&through_link).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn creating_a_file_through_a_symlinked_parent_outside_the_root_is_refused() {
        // The destination does not exist, so it cannot be canonicalised — the parent is
        // checked instead. Without that, an upload could write outside the root.
        let root = temp_root();
        let outside = temp_root();
        std::os::unix::fs::symlink(outside.path(), root.path().join("escape")).unwrap();

        let policy = confined(root.path());
        let new_file = format!("{}/escape/planted.txt", as_str(root.path()));

        assert_eq!(policy.resolve(&new_file), Err(FileError::OutsideRoot));
    }

    // -- reserved names ------------------------------------------------------

    #[test]
    fn windows_device_names_are_refused_with_any_extension() {
        // `CON.txt` does not create a file; it opens the console. A transfer that
        // appeared to succeed and wrote nowhere is worse than one that failed.
        let policy = PathPolicy::unconfined();
        let prefix = if cfg!(windows) { r"C:\tmp\" } else { "/tmp/" };

        for name in ["CON", "con", "CON.txt", "NUL", "lpt1.log", "AUX.tar.gz"] {
            assert_eq!(
                policy.resolve(&format!("{prefix}{name}")),
                Err(FileError::ReservedName),
                "{name} must be refused"
            );
        }
    }

    #[test]
    fn a_name_ending_in_a_space_or_dot_is_refused() {
        // Windows strips both, so `secret.txt.` opens `secret.txt` — a name that does
        // not mean what it says.
        let policy = PathPolicy::unconfined();
        let prefix = if cfg!(windows) { r"C:\tmp\" } else { "/tmp/" };

        assert_eq!(
            policy.resolve(&format!("{prefix}secret.txt.")),
            Err(FileError::ReservedName)
        );
        assert_eq!(
            policy.resolve(&format!("{prefix}secret.txt ")),
            Err(FileError::ReservedName)
        );
    }

    #[test]
    fn a_name_merely_containing_a_reserved_word_is_allowed() {
        // `CONFIG` is not `CON`. Over-refusing would make ordinary files untransferable.
        let policy = PathPolicy::unconfined();
        let prefix = if cfg!(windows) { r"C:\tmp\" } else { "/tmp/" };

        assert!(policy.resolve(&format!("{prefix}CONFIG.txt")).is_ok());
        assert!(policy.resolve(&format!("{prefix}nul-report.log")).is_ok());
    }

    // -- malformed input -----------------------------------------------------

    #[test]
    fn a_path_containing_a_nul_is_refused() {
        // A NUL truncates at the system-call boundary, so the value names a different
        // file than it appears to.
        let policy = PathPolicy::unconfined();
        let attempt = if cfg!(windows) {
            "C:\\tmp\\safe.txt\0/etc/passwd"
        } else {
            "/tmp/safe.txt\0/etc/passwd"
        };
        assert_eq!(policy.resolve(attempt), Err(FileError::InvalidPath));
    }

    #[test]
    fn an_empty_or_blank_path_is_refused() {
        let policy = PathPolicy::unconfined();
        assert_eq!(policy.resolve(""), Err(FileError::InvalidPath));
        assert_eq!(policy.resolve("   "), Err(FileError::InvalidPath));
    }

    // -- policy construction -------------------------------------------------

    #[test]
    fn a_relative_root_is_refused() {
        // It would be resolved against the agent's working directory, which is not a
        // confinement anyone could reason about.
        assert_eq!(
            PathPolicy::confined_to([PathBuf::from("data")]).err(),
            Some(FileError::BadRoot)
        );
    }

    #[test]
    fn an_unconfined_policy_permits_any_absolute_path_and_says_so() {
        let policy = PathPolicy::unconfined();

        assert!(!policy.is_confined());
        let anywhere = if cfg!(windows) {
            r"C:\Windows\System32\drivers\etc\hosts"
        } else {
            "/etc/hosts"
        };
        assert!(policy.resolve(anywhere).is_ok());
    }

    #[test]
    fn a_confined_policy_reports_that_it_is_confined() {
        let root = temp_root();
        assert!(confined(root.path()).is_confined());
    }

    #[test]
    fn several_roots_are_all_permitted() {
        let first = temp_root();
        let second = temp_root();
        let policy = PathPolicy::confined_to([
            strip_verbatim_prefix(first.path().canonicalize().unwrap()),
            strip_verbatim_prefix(second.path().canonicalize().unwrap()),
        ])
        .unwrap();

        assert!(
            policy
                .resolve(&format!("{}/a.txt", as_str(first.path())))
                .is_ok()
        );
        assert!(
            policy
                .resolve(&format!("{}/b.txt", as_str(second.path())))
                .is_ok()
        );
    }

    // -- file names ----------------------------------------------------------

    #[test]
    fn a_file_name_containing_a_separator_is_refused() {
        // A name is a name. One containing a separator would place the file somewhere
        // other than the directory the operator chose.
        assert_eq!(validate_file_name("../escape"), Err(FileError::InvalidPath));
        assert_eq!(validate_file_name("sub/file"), Err(FileError::InvalidPath));
        assert_eq!(validate_file_name(r"sub\file"), Err(FileError::InvalidPath));
    }

    #[test]
    fn dot_names_are_refused_as_file_names() {
        assert_eq!(validate_file_name("."), Err(FileError::InvalidPath));
        assert_eq!(validate_file_name(".."), Err(FileError::InvalidPath));
        assert_eq!(validate_file_name(""), Err(FileError::InvalidPath));
    }

    #[test]
    fn an_ordinary_file_name_is_accepted() {
        assert!(validate_file_name("report.pdf").is_ok());
        assert!(validate_file_name(".hidden").is_ok());
        assert!(validate_file_name("file with spaces.txt").is_ok());
        assert!(validate_file_name("日本語.txt").is_ok());
    }

    #[test]
    fn an_overlong_file_name_is_refused() {
        assert_eq!(
            validate_file_name(&"a".repeat(300)),
            Err(FileError::InvalidPath)
        );
    }

    #[test]
    fn a_reserved_file_name_is_refused() {
        assert_eq!(validate_file_name("CON"), Err(FileError::ReservedName));
        assert_eq!(validate_file_name("nul.txt"), Err(FileError::ReservedName));
    }

    // -- normalisation -------------------------------------------------------

    #[test]
    fn normalisation_removes_current_directory_components() {
        let path = Path::new(if cfg!(windows) {
            r"C:\a\.\b\.\c"
        } else {
            "/a/./b/./c"
        });
        let normalised = normalise(path).unwrap();
        assert!(!as_str(&normalised).contains("\\.\\"));
        assert!(!as_str(&normalised).contains("/./"));
        assert!(normalised.ends_with("c"));
    }

    #[test]
    fn a_resolved_path_never_contains_a_parent_component() {
        // What is opened must be what the audit trail records.
        let root = temp_root();
        std::fs::create_dir(root.path().join("a")).unwrap();
        let policy = confined(root.path());

        let resolved = policy
            .resolve(&format!("{}/a/../a/./file", as_str(root.path())))
            .unwrap();

        assert!(
            resolved
                .components()
                .all(|c| !matches!(c, Component::ParentDir | Component::CurDir))
        );
    }
}
