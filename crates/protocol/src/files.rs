//! File-transfer channel messages.
//!
//! All paths crossing this boundary are untrusted. The agent must normalise and
//! re-validate every path against its configured roots before touching the
//! filesystem — see `rc-file-transfer`.

use serde::{Deserialize, Serialize};

use crate::ids::TransferId;

/// What a directory entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link. The UI must show these distinctly because following them can
    /// escape the intended root.
    Symlink,
    /// A device node, socket, FIFO, or anything else.
    Other,
}

/// One entry in a directory listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    /// File name only, never a path. Untrusted: may contain newlines, right-to-left
    /// overrides or path separators, so the UI must render it as inert text.
    pub name: String,
    /// What kind of entry this is.
    pub kind: EntryKind,
    /// Size in bytes for files; meaningless for directories.
    pub size_bytes: u64,
    /// Last-modified time, milliseconds since the Unix epoch.
    pub modified_ms: Option<i64>,
    /// Whether the OS considers this hidden.
    pub hidden: bool,
    /// Whether the agent can read it.
    pub readable: bool,
    /// Whether the agent can write it.
    pub writable: bool,
    /// Human-readable permission string, e.g. `"rwxr-xr-x"` or a Windows summary.
    pub permissions: String,
    /// For symlinks, the raw target as recorded on disk. Untrusted.
    pub symlink_target: Option<String>,
}

/// How to resolve a name collision at the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    /// Fail the operation and report the conflict.
    Fail,
    /// Replace the destination.
    Overwrite,
    /// Continue an existing partial file if the checksum of the common prefix matches.
    Resume,
    /// Write to a new name derived from the original.
    Rename,
}

/// Checksum algorithm used to verify transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ChecksumAlgorithm {
    /// BLAKE3. Fast, and used for both whole-file and per-chunk digests.
    Blake3,
}

/// A checksum over some range of bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checksum {
    /// Algorithm used.
    pub algorithm: ChecksumAlgorithm,
    /// Raw digest bytes.
    pub digest: Vec<u8>,
}

/// Client → agent file operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FileClientMessage {
    /// List a directory.
    List {
        /// Absolute path on the host. Untrusted.
        path: String,
        /// Whether to include entries the OS marks hidden.
        include_hidden: bool,
    },
    /// Stat a single path.
    Stat {
        /// Absolute path on the host. Untrusted.
        path: String,
    },
    /// Create a directory, including missing parents.
    CreateDirectory {
        /// Absolute path on the host. Untrusted.
        path: String,
    },
    /// Rename or move within the same host.
    Rename {
        /// Existing path.
        from: String,
        /// Desired path.
        to: String,
        /// What to do if `to` exists.
        conflict: ConflictPolicy,
    },
    /// Copy within the same host.
    Copy {
        /// Source path.
        from: String,
        /// Destination path.
        to: String,
        /// What to do if `to` exists.
        conflict: ConflictPolicy,
    },
    /// Delete a path.
    Delete {
        /// Absolute path on the host. Untrusted.
        path: String,
        /// When true, bypass the recycle bin / trash and unlink permanently. The UI
        /// must show the full resolved path and require confirmation first.
        permanent: bool,
        /// Recurse into directories.
        recursive: bool,
    },
    /// Begin sending a file to the host.
    UploadBegin {
        /// Client-assigned transfer id, reused verbatim when resuming.
        transfer_id: TransferId,
        /// Destination path on the host.
        destination: String,
        /// Total size of the file being sent.
        total_bytes: u64,
        /// Whole-file checksum, verified by the agent on completion.
        checksum: Checksum,
        /// Collision behaviour.
        conflict: ConflictPolicy,
    },
    /// A chunk of upload data.
    UploadChunk {
        /// Transfer this belongs to.
        transfer_id: TransferId,
        /// Byte offset of this chunk within the file.
        offset: u64,
        /// Chunk payload.
        data: Vec<u8>,
    },
    /// All chunks have been sent.
    UploadEnd {
        /// Transfer being finished.
        transfer_id: TransferId,
    },
    /// Begin receiving a file from the host.
    DownloadBegin {
        /// Client-assigned transfer id.
        transfer_id: TransferId,
        /// Source path on the host.
        source: String,
        /// Resume point. `0` starts from the beginning.
        start_offset: u64,
    },
    /// Abort a transfer in either direction and release its resources.
    TransferCancel {
        /// Transfer to abort.
        transfer_id: TransferId,
    },
    /// Ask the host for the checksum of a byte range, used to validate a resume point.
    VerifyRange {
        /// Path to hash.
        path: String,
        /// First byte of the range.
        offset: u64,
        /// Number of bytes to hash.
        length: u64,
    },
}

/// Agent → client file responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FileAgentMessage {
    /// A directory listing.
    Listing {
        /// The path that was listed, after normalisation.
        path: String,
        /// Entries, truncated to [`crate::limits::MAX_DIR_ENTRIES`].
        entries: Vec<DirEntry>,
        /// True when entries were dropped because of the limit.
        truncated: bool,
    },
    /// A single entry's metadata.
    Stat {
        /// Normalised path.
        path: String,
        /// Metadata.
        entry: DirEntry,
    },
    /// An operation with no payload succeeded.
    Ok,
    /// The agent is ready to receive upload chunks.
    UploadReady {
        /// Transfer concerned.
        transfer_id: TransferId,
        /// Offset the client should start from. Non-zero when resuming.
        resume_offset: u64,
    },
    /// Metadata preceding download chunks.
    DownloadBegin {
        /// Transfer concerned.
        transfer_id: TransferId,
        /// Total file size.
        total_bytes: u64,
        /// Whole-file checksum for end-to-end verification.
        checksum: Checksum,
    },
    /// A chunk of download data.
    DownloadChunk {
        /// Transfer concerned.
        transfer_id: TransferId,
        /// Byte offset within the file.
        offset: u64,
        /// Chunk payload.
        data: Vec<u8>,
    },
    /// A transfer finished successfully and its checksum verified.
    TransferComplete {
        /// Transfer concerned.
        transfer_id: TransferId,
        /// Bytes moved in this session, excluding any resumed prefix.
        bytes_transferred: u64,
    },
    /// A transfer failed or was cancelled.
    TransferFailed {
        /// Transfer concerned.
        transfer_id: TransferId,
        /// Machine-readable code.
        code: crate::control::ErrorCode,
        /// Operator-facing message.
        message: String,
    },
    /// Result of a [`FileClientMessage::VerifyRange`].
    RangeChecksum {
        /// Digest over the requested range.
        checksum: Checksum,
        /// Bytes actually hashed, which may be fewer than requested at end-of-file.
        length: u64,
    },
    /// A file operation failed.
    Error {
        /// Machine-readable code.
        code: crate::control::ErrorCode,
        /// Operator-facing message with no sensitive path detail beyond what the
        /// caller already supplied.
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_defaults_are_explicit_on_the_wire() {
        let msg = FileClientMessage::Delete {
            path: "/tmp/x".into(),
            permanent: false,
            recursive: false,
        };
        let bytes = postcard::to_stdvec(&msg).unwrap();
        assert_eq!(
            postcard::from_bytes::<FileClientMessage>(&bytes).unwrap(),
            msg
        );
    }

    #[test]
    fn hostile_file_names_survive_serialization_unchanged() {
        // The protocol must transport these faithfully; sanitising is the UI's job.
        for name in [
            "../../etc/passwd",
            "a\nb",
            "co\u{202e}gnp.exe",
            "C:\\Windows\\x",
        ] {
            let entry = DirEntry {
                name: name.to_string(),
                kind: EntryKind::File,
                size_bytes: 0,
                modified_ms: None,
                hidden: false,
                readable: true,
                writable: false,
                permissions: "r--r--r--".into(),
                symlink_target: None,
            };
            let bytes = postcard::to_stdvec(&entry).unwrap();
            assert_eq!(postcard::from_bytes::<DirEntry>(&bytes).unwrap().name, name);
        }
    }
}
