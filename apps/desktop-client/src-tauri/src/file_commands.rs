//! File-manager commands: the remote pane and the local one.
//!
//! # Two panes, two very different trust positions
//!
//! The **remote** pane talks to the agent, which resolves and confines every path it is
//! given. The **local** pane touches this machine's own filesystem directly.
//!
//! The local side is not "safe because it is local". The paths still arrive from a
//! webview, so they are resolved the same way — the difference is only that the policy
//! is unconfined, because confining an operator to part of their own machine would be
//! theatre. What the resolution still buys is that a path with a NUL, a traversal or a
//! reserved name is refused before it reaches an `open`, and that what is opened is what
//! gets shown.
//!
//! # Transfers stream through the backend
//!
//! File bytes never enter the webview. An upload is read here and pushed to the agent;
//! a download is received here and written to disk. Passing a gigabyte through a
//! JavaScript string would be slow, would double its memory, and would put file contents
//! somewhere a rendering bug could reach them.

use std::path::PathBuf;
use std::sync::Arc;

use rc_file_transfer::PathPolicy;
use rc_protocol::TransferId;
use rc_protocol::files::{Checksum, ConflictPolicy, DirEntry, FileAgentMessage, FileClientMessage};
use rc_security::Permission;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::commands::CommandError;

type CommandResult<T> = Result<T, CommandError>;

/// One entry in either pane.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryDto {
    /// File name only. **Untrusted**: may contain newlines or bidirectional overrides,
    /// so the UI renders it as inert text.
    pub name: String,
    /// `file`, `directory`, `symlink` or `other`.
    pub kind: String,
    /// Size in bytes. Meaningless for directories.
    pub size_bytes: u64,
    /// Last-modified time, when the platform reported one.
    pub modified_ms: Option<i64>,
    /// Whether the platform marks it hidden.
    pub hidden: bool,
    /// Whether the agent could open it.
    pub readable: bool,
    /// Whether it can be written.
    pub writable: bool,
    /// Human-readable permission summary.
    pub permissions: String,
    /// For a symlink, the target as recorded on disk. Untrusted.
    pub symlink_target: Option<String>,
}

impl From<DirEntry> for EntryDto {
    fn from(entry: DirEntry) -> Self {
        use rc_protocol::files::EntryKind;

        Self {
            name: entry.name,
            kind: match entry.kind {
                EntryKind::File => "file",
                EntryKind::Directory => "directory",
                EntryKind::Symlink => "symlink",
                _ => "other",
            }
            .to_owned(),
            size_bytes: entry.size_bytes,
            modified_ms: entry.modified_ms,
            hidden: entry.hidden,
            readable: entry.readable,
            writable: entry.writable,
            permissions: entry.permissions,
            symlink_target: entry.symlink_target,
        }
    }
}

/// A directory listing.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListingDto {
    /// The path actually listed, after resolution. Differs from what was asked for
    /// whenever a symlink or a `..` was involved, which the operator needs to see.
    pub path: String,
    /// The entries.
    pub entries: Vec<EntryDto>,
    /// Whether entries were dropped because the directory was very large.
    pub truncated: bool,
}

/// How a transfer ended.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferResultDto {
    /// Bytes moved.
    pub bytes_transferred: u64,
    /// Where the file ended up, for display.
    pub path: String,
}

/// What the UI asks for when transferring.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferInput {
    /// Path on this machine.
    pub local_path: String,
    /// Path on the server.
    pub remote_path: String,
    /// `fail`, `overwrite`, `resume` or `rename`.
    pub conflict: String,
}

/// List a directory on the server.
///
/// # Errors
/// [`CommandError`] if nothing is connected, the session lacks the capability, or the
/// server refuses the path.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn list_remote_directory(
    state: tauri::State<'_, Arc<AppState>>,
    path: String,
    include_hidden: bool,
) -> CommandResult<ListingDto> {
    state.require_permission(Permission::TransferFiles)?;
    let manager = connection(&state)?;

    let replies = manager
        .file_request(
            &FileClientMessage::List {
                path,
                include_hidden,
            },
            |message| {
                matches!(
                    message,
                    FileAgentMessage::Listing { .. } | FileAgentMessage::Error { .. }
                )
            },
        )
        .await
        .map_err(|err| CommandError::from_transport(&err))?;

    match replies.into_iter().next_back() {
        Some(FileAgentMessage::Listing {
            path,
            entries,
            truncated,
        }) => Ok(ListingDto {
            path,
            entries: entries.into_iter().map(Into::into).collect(),
            truncated,
        }),
        Some(FileAgentMessage::Error { message, .. }) => {
            Err(CommandError::new("file_refused", message))
        }
        _ => Err(unexpected()),
    }
}

/// List a directory on this machine.
///
/// # Errors
/// [`CommandError`] if the path is unusable or cannot be read.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn list_local_directory(
    state: tauri::State<'_, Arc<AppState>>,
    path: String,
    include_hidden: bool,
) -> CommandResult<ListingDto> {
    // The local pane still needs an unlocked application: the file manager is not a
    // way around the lock screen.
    state.require_permission(Permission::TransferFiles)?;

    // Unconfined, because confining an operator to part of their own machine would be
    // theatre — but still *resolved*, so a NUL, a traversal or a reserved name is
    // refused before it reaches an `open`.
    let policy = PathPolicy::unconfined();
    let resolved = policy
        .resolve(&path)
        .map_err(|err| CommandError::new("invalid_path", err.to_string()))?;

    let (entries, truncated) = rc_file_transfer::list_directory(&resolved, include_hidden)
        .map_err(|err| CommandError::new("local_read_failed", err.to_string()))?;

    Ok(ListingDto {
        path: resolved.to_string_lossy().into_owned(),
        entries: entries.into_iter().map(Into::into).collect(),
        truncated,
    })
}

/// The directory the local pane opens on.
///
/// The user's home directory, or the filesystem root if it cannot be determined — never
/// the process's working directory, which for a packaged application is wherever the
/// launcher happened to be.
#[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)]
#[tauri::command]
pub fn default_local_directory() -> CommandResult<String> {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .ok()
        .map(PathBuf::from)
        .filter(|path| path.is_dir());

    Ok(home.map_or_else(
        || if cfg!(windows) { "C:\\" } else { "/" }.to_owned(),
        |path| path.to_string_lossy().into_owned(),
    ))
}

/// Create a directory on the server.
///
/// # Errors
/// [`CommandError`] if the session lacks the capability or the server refuses.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn create_remote_directory(
    state: tauri::State<'_, Arc<AppState>>,
    path: String,
) -> CommandResult<()> {
    state.require_permission(Permission::TransferFiles)?;
    simple_request(&state, FileClientMessage::CreateDirectory { path }).await
}

/// Delete a path on the server.
///
/// The UI shows the full resolved path and requires confirmation before calling this;
/// `recursive` is passed through exactly as the operator chose it, never inferred.
///
/// # Errors
/// [`CommandError`] if the session lacks the capability or the server refuses.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn delete_remote_path(
    state: tauri::State<'_, Arc<AppState>>,
    path: String,
    recursive: bool,
) -> CommandResult<()> {
    state.require_permission(Permission::TransferFiles)?;
    simple_request(
        &state,
        FileClientMessage::Delete {
            path,
            // There is no recycle-bin path in this build, so every delete is permanent
            // and the UI says so rather than implying a recoverable one.
            permanent: true,
            recursive,
        },
    )
    .await
}

/// Rename or move a path on the server.
///
/// # Errors
/// [`CommandError`] if the session lacks the capability or the server refuses.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn rename_remote_path(
    state: tauri::State<'_, Arc<AppState>>,
    from: String,
    to: String,
) -> CommandResult<()> {
    state.require_permission(Permission::TransferFiles)?;
    simple_request(
        &state,
        FileClientMessage::Rename {
            from,
            to,
            // Renaming over an existing file is a distinct decision from renaming, so
            // it is refused here and the operator is asked.
            conflict: ConflictPolicy::Fail,
        },
    )
    .await
}

/// Upload a local file to the server.
///
/// # Errors
/// [`CommandError`] naming what the operator can do about it: an unreadable source, a
/// refused destination, or a transfer the server rejected.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn upload_file(
    state: tauri::State<'_, Arc<AppState>>,
    input: TransferInput,
) -> CommandResult<TransferResultDto> {
    state.require_permission(Permission::TransferFiles)?;
    let manager = connection(&state)?;

    let source = PathPolicy::unconfined()
        .resolve(&input.local_path)
        .map_err(|err| CommandError::new("invalid_path", err.to_string()))?;

    let metadata = std::fs::metadata(&source)
        .map_err(|_| CommandError::new("local_read_failed", "That local file cannot be read."))?;
    if metadata.is_dir() {
        return Err(CommandError::new(
            "unsupported",
            "Folder upload is not available yet; send the files inside it individually.",
        ));
    }

    // Hashed before anything is sent, so the server knows what it should end up with
    // rather than being told afterwards what it happens to have.
    let checksum = rc_file_transfer::checksum_file(&source)
        .map_err(|err| CommandError::new("local_read_failed", err.to_string()))?;

    let transfer_id = TransferId::generate();
    let conflict = parse_conflict(&input.conflict);

    let ready = manager
        .file_request(
            &FileClientMessage::UploadBegin {
                transfer_id,
                destination: input.remote_path.clone(),
                total_bytes: metadata.len(),
                checksum,
                conflict,
            },
            |message| {
                matches!(
                    message,
                    FileAgentMessage::UploadReady { .. }
                        | FileAgentMessage::TransferFailed { .. }
                        | FileAgentMessage::Error { .. }
                )
            },
        )
        .await
        .map_err(|err| CommandError::from_transport(&err))?;

    let resume_offset = match ready.into_iter().next_back() {
        Some(FileAgentMessage::UploadReady { resume_offset, .. }) => resume_offset,
        Some(
            FileAgentMessage::TransferFailed { message, .. }
            | FileAgentMessage::Error { message, .. },
        ) => {
            return Err(CommandError::new("transfer_refused", message));
        }
        _ => return Err(unexpected()),
    };

    send_chunks(&manager, transfer_id, &source, resume_offset).await?;

    let finished = manager
        .file_request(&FileClientMessage::UploadEnd { transfer_id }, |message| {
            matches!(
                message,
                FileAgentMessage::TransferComplete { .. }
                    | FileAgentMessage::TransferFailed { .. }
                    | FileAgentMessage::Error { .. }
            )
        })
        .await
        .map_err(|err| CommandError::from_transport(&err))?;

    match finished.into_iter().next_back() {
        Some(FileAgentMessage::TransferComplete {
            bytes_transferred, ..
        }) => Ok(TransferResultDto {
            bytes_transferred,
            path: input.remote_path,
        }),
        Some(
            FileAgentMessage::TransferFailed { message, .. }
            | FileAgentMessage::Error { message, .. },
        ) => Err(CommandError::new("transfer_failed", message)),
        _ => Err(unexpected()),
    }
}

/// Download a file from the server to this machine.
///
/// # Errors
/// As [`upload_file`], plus a checksum mismatch — in which case the partial local file
/// is removed rather than left where it would be mistaken for the real thing.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn download_file(
    state: tauri::State<'_, Arc<AppState>>,
    input: TransferInput,
) -> CommandResult<TransferResultDto> {
    state.require_permission(Permission::TransferFiles)?;
    let manager = connection(&state)?;

    let destination = PathPolicy::unconfined()
        .resolve(&input.local_path)
        .map_err(|err| CommandError::new("invalid_path", err.to_string()))?;

    let transfer_id = TransferId::generate();

    let replies = manager
        .file_request(
            &FileClientMessage::DownloadBegin {
                transfer_id,
                source: input.remote_path,
                start_offset: 0,
            },
            |message| {
                matches!(
                    message,
                    FileAgentMessage::TransferComplete { .. }
                        | FileAgentMessage::TransferFailed { .. }
                        | FileAgentMessage::Error { .. }
                )
            },
        )
        .await
        .map_err(|err| CommandError::from_transport(&err))?;

    write_download(&destination, replies, transfer_id)
}

/// Write the chunks of a completed download and verify them.
fn write_download(
    destination: &std::path::Path,
    replies: Vec<FileAgentMessage>,
    transfer_id: TransferId,
) -> CommandResult<TransferResultDto> {
    use std::io::Write as _;

    // Written to a partial file and renamed only after the checksum verifies, for the
    // same reason the agent does it: a failed download must not leave something at the
    // destination that looks like the file.
    let mut partial = destination.as_os_str().to_owned();
    partial.push(".rc-partial");
    let partial = PathBuf::from(partial);

    let mut expected: Option<Checksum> = None;
    let mut written = 0u64;

    {
        let mut file = std::fs::File::create(&partial).map_err(|_| {
            CommandError::new("local_write_failed", "That local file cannot be written.")
        })?;

        for reply in replies {
            match reply {
                FileAgentMessage::DownloadBegin { checksum, .. } => expected = Some(checksum),
                FileAgentMessage::DownloadChunk { data, .. } => {
                    file.write_all(&data).map_err(|_| {
                        let _ = std::fs::remove_file(&partial);
                        CommandError::new("local_write_failed", "Writing the file failed.")
                    })?;
                    written += data.len() as u64;
                }
                FileAgentMessage::TransferFailed { message, .. }
                | FileAgentMessage::Error { message, .. } => {
                    let _ = std::fs::remove_file(&partial);
                    return Err(CommandError::new("transfer_failed", message));
                }
                // `TransferComplete` ends the stream and carries nothing to write;
                // anything else is a message this request did not ask for.
                _ => {}
            }
        }
    }

    let Some(expected) = expected else {
        let _ = std::fs::remove_file(&partial);
        return Err(unexpected());
    };

    let actual = rc_file_transfer::checksum_file(&partial).map_err(|err| {
        let _ = std::fs::remove_file(&partial);
        CommandError::new("local_read_failed", err.to_string())
    })?;

    if actual.digest != expected.digest {
        // Discarded, not kept with a warning. A file that is silently wrong is worse
        // than a transfer that failed.
        let _ = std::fs::remove_file(&partial);
        tracing::warn!(%transfer_id, "a download failed its checksum; discarding it");
        return Err(CommandError::new(
            "checksum_mismatch",
            "The downloaded file does not match its checksum and has been discarded. \
             Try again.",
        ));
    }

    std::fs::rename(&partial, destination).map_err(|_| {
        let _ = std::fs::remove_file(&partial);
        CommandError::new(
            "local_write_failed",
            "The downloaded file could not be saved.",
        )
    })?;

    Ok(TransferResultDto {
        bytes_transferred: written,
        path: destination.to_string_lossy().into_owned(),
    })
}

/// Read `source` from `offset` and push it to the agent in chunks.
async fn send_chunks(
    manager: &crate::connection::ConnectionManager,
    transfer_id: TransferId,
    source: &std::path::Path,
    offset: u64,
) -> CommandResult<()> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let mut file = std::fs::File::open(source)
        .map_err(|_| CommandError::new("local_read_failed", "That local file cannot be read."))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| CommandError::new("local_read_failed", "That local file cannot be read."))?;

    let mut position = offset;
    let mut buffer = vec![0u8; rc_file_transfer::CHUNK_BYTES];

    loop {
        let read = file.read(&mut buffer).map_err(|_| {
            CommandError::new(
                "local_read_failed",
                "Reading the file failed part-way through.",
            )
        })?;
        if read == 0 {
            return Ok(());
        }

        // Chunks draw no reply, so `until` is never consulted — the send itself is what
        // matters, and the agent reports any problem when the transfer is ended.
        manager
            .send_file_message(&FileClientMessage::UploadChunk {
                transfer_id,
                offset: position,
                data: buffer[..read].to_vec(),
            })
            .await
            .map_err(|err| CommandError::from_transport(&err))?;

        position += read as u64;
    }
}

/// Send a request whose only answer is success or failure.
async fn simple_request(state: &AppState, request: FileClientMessage) -> CommandResult<()> {
    let manager = connection(state)?;

    let replies = manager
        .file_request(&request, |message| {
            matches!(
                message,
                FileAgentMessage::Ok | FileAgentMessage::Error { .. }
            )
        })
        .await
        .map_err(|err| CommandError::from_transport(&err))?;

    match replies.into_iter().next_back() {
        Some(FileAgentMessage::Ok) => Ok(()),
        Some(FileAgentMessage::Error { message, .. }) => {
            Err(CommandError::new("file_refused", message))
        }
        _ => Err(unexpected()),
    }
}

/// The connection manager, or a message saying nothing is connected.
fn connection(state: &AppState) -> CommandResult<Arc<crate::connection::ConnectionManager>> {
    state
        .connection
        .as_ref()
        .map(Arc::clone)
        .ok_or_else(|| CommandError::new("not_connected", "Connect to a server first."))
}

/// A reply that does not belong to the request that was sent.
fn unexpected() -> CommandError {
    CommandError::new(
        "unexpected_response",
        "The server sent an unexpected reply. Check that both sides are on the same version.",
    )
}

/// Map a conflict name from the UI onto the protocol's closed set.
///
/// Anything unrecognised becomes `Fail`, which is the only safe default: the others all
/// destroy or rename something.
fn parse_conflict(value: &str) -> ConflictPolicy {
    match value {
        "overwrite" => ConflictPolicy::Overwrite,
        "resume" => ConflictPolicy::Resume,
        "rename" => ConflictPolicy::Rename,
        _ => ConflictPolicy::Fail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unrecognised_conflict_policy_fails_rather_than_destroying_anything() {
        // Every other policy overwrites or renames something. Defaulting to one of
        // those on an unknown value would make a UI bug destructive.
        assert_eq!(parse_conflict("overwrite"), ConflictPolicy::Overwrite);
        assert_eq!(parse_conflict("rename"), ConflictPolicy::Rename);
        assert_eq!(parse_conflict("resume"), ConflictPolicy::Resume);

        assert_eq!(parse_conflict(""), ConflictPolicy::Fail);
        assert_eq!(parse_conflict("delete-everything"), ConflictPolicy::Fail);
    }

    #[test]
    fn the_local_pane_opens_somewhere_predictable() {
        // Never the process's working directory, which for a packaged application is
        // wherever the launcher happened to be.
        let default = default_local_directory().unwrap();

        assert!(!default.is_empty());
        assert!(std::path::Path::new(&default).is_absolute());
    }

    #[test]
    fn an_entry_reports_its_kind_as_a_name_the_schema_accepts() {
        use rc_protocol::files::EntryKind;

        let entry = |kind| DirEntry {
            name: "x".to_owned(),
            kind,
            size_bytes: 0,
            modified_ms: None,
            hidden: false,
            readable: true,
            writable: true,
            permissions: String::new(),
            symlink_target: None,
        };

        assert_eq!(EntryDto::from(entry(EntryKind::File)).kind, "file");
        assert_eq!(
            EntryDto::from(entry(EntryKind::Directory)).kind,
            "directory"
        );
        assert_eq!(EntryDto::from(entry(EntryKind::Symlink)).kind, "symlink");
        assert_eq!(EntryDto::from(entry(EntryKind::Other)).kind, "other");
    }

    #[test]
    fn a_symlinks_target_is_carried_through_as_a_claim() {
        // The UI shows it so the operator can see where a link points; it is not
        // followed, and it is untrusted text.
        use rc_protocol::files::EntryKind;

        let dto = EntryDto::from(DirEntry {
            name: "link".to_owned(),
            kind: EntryKind::Symlink,
            size_bytes: 0,
            modified_ms: None,
            hidden: false,
            readable: false,
            writable: false,
            permissions: String::new(),
            symlink_target: Some("../../etc".to_owned()),
        });

        assert_eq!(dto.symlink_target.as_deref(), Some("../../etc"));
    }

    #[test]
    fn a_hostile_file_name_reaches_the_ui_unchanged() {
        // Sanitising here would mean the name shown could not be used to act on the
        // file. The UI renders it as inert text instead.
        use rc_protocol::files::EntryKind;

        let hostile = "co\u{202e}gnp.exe";
        let dto = EntryDto::from(DirEntry {
            name: hostile.to_owned(),
            kind: EntryKind::File,
            size_bytes: 0,
            modified_ms: None,
            hidden: false,
            readable: true,
            writable: true,
            permissions: String::new(),
            symlink_target: None,
        });

        assert_eq!(dto.name, hostile);
    }
}
