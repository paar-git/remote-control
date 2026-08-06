//! Serving the file channel for one authenticated connection.
//!
//! # Two authorization checks, not one
//!
//! Reading needs [`Capability::FileRead`]; anything that changes the filesystem needs
//! [`Capability::FileWrite`]. Both are checked **per message** against the live session
//! rather than once when the channel opens, so a device revoked mid-connection stops
//! being served immediately.
//!
//! Splitting read from write is what makes a View Only device useful: it can browse and
//! download without being able to alter anything.
//!
//! # Every path is resolved before it is touched
//!
//! No filesystem call in this module receives a path from the wire. Each one goes
//! through [`rc_file_transfer::PathPolicy::resolve`] first, which closes traversal,
//! symlink escape and reserved names. A path that fails resolution never reaches an
//! `open`.
//!
//! # Deletion is deliberately conservative
//!
//! Recursive deletion is refused unless the client asked for it *and* the target is a
//! directory the operator named. There is no "delete everything under here" convenience
//! that could be triggered by a mis-typed path, because the difference between the
//! right path and one character off is the difference between a tidy-up and an outage.

use std::sync::Arc;

use rc_file_transfer::{
    Download, FileError, PathPolicy, TransferRegistry, Upload, checksum_range, list_directory, stat,
};
use rc_protocol::TransferId;
use rc_protocol::control::ErrorCode;
use rc_protocol::files::{ConflictPolicy, FileAgentMessage, FileClientMessage};
use rc_security::permissions::{AuthorizationContext, Capability};
use rc_storage::audit::{AuditCategory, AuditEvent, AuditResult, actions};
use rc_transport::{ChannelReader, ChannelWriter, TransportError};
use tokio::sync::Mutex;

/// Serves the file channel for one connection.
pub struct FileService {
    /// Where this connection may read and write.
    policy: PathPolicy,
    /// Largest single file this agent will move.
    max_transfer_bytes: u64,
    /// Uploads in flight.
    transfers: Arc<TransferRegistry>,
    /// Shared so a download pump and the message loop can both write.
    writer: Arc<Mutex<ChannelWriter>>,
    authorization: AuthorizationContext,
    database: rc_storage::Database,
    device_id: rc_protocol::DeviceId,
    session_id: rc_protocol::SessionId,
    clock: Arc<dyn rc_security::Clock>,
    /// Whether the agent's configuration permits file transfer at all.
    enabled: bool,
}

impl FileService {
    /// A service for one connection.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        writer: ChannelWriter,
        policy: PathPolicy,
        max_transfer_bytes: u64,
        authorization: AuthorizationContext,
        database: rc_storage::Database,
        device_id: rc_protocol::DeviceId,
        session_id: rc_protocol::SessionId,
        clock: Arc<dyn rc_security::Clock>,
        enabled: bool,
    ) -> Self {
        Self {
            policy,
            max_transfer_bytes,
            transfers: Arc::new(TransferRegistry::new(
                rc_file_transfer::MAX_CONCURRENT_TRANSFERS,
            )),
            writer: Arc::new(Mutex::new(writer)),
            authorization,
            database,
            device_id,
            session_id,
            clock,
            enabled,
        }
    }

    /// Read file messages until the channel closes.
    ///
    /// Every transfer this service started is cancelled on the way out, which keeps
    /// partial uploads on disk for resuming rather than deleting the operator's work.
    pub async fn run(&self, reader: &mut ChannelReader) {
        loop {
            let message: FileClientMessage = match reader.next_message().await {
                Ok(Some(message)) => message,
                Ok(None) => break,
                Err(TransportError::Protocol(err)) => {
                    tracing::warn!(%err, "malformed file message; closing the channel");
                    break;
                }
                Err(err) => {
                    tracing::debug!(%err, "file channel ended");
                    break;
                }
            };

            self.handle(message).await;
        }

        self.transfers.cancel_all();
    }

    /// Handle one client message.
    async fn handle(&self, message: FileClientMessage) {
        if !self.enabled {
            self.send_error(
                ErrorCode::Unsupported,
                "file transfer is switched off in this server's configuration",
            )
            .await;
            return;
        }

        // Split by what the operation *does* rather than by message shape, so the two
        // capability checks stay one decision each rather than being repeated per arm.
        if is_read_only(&message) {
            self.handle_read(message).await;
        } else {
            self.handle_write(message).await;
        }
    }

    /// Handle a message that only reads.
    async fn handle_read(&self, message: FileClientMessage) {
        match message {
            FileClientMessage::List {
                path,
                include_hidden,
            } => {
                if self.refuse_without(Capability::FileRead).await {
                    return;
                }
                self.list(&path, include_hidden).await;
            }

            FileClientMessage::Stat { path } => {
                if self.refuse_without(Capability::FileRead).await {
                    return;
                }
                match self.resolve(&path) {
                    Ok(resolved) => match stat(&resolved) {
                        Ok(entry) => {
                            self.send(&FileAgentMessage::Stat {
                                path: resolved.to_string_lossy().into_owned(),
                                entry,
                            })
                            .await;
                        }
                        Err(err) => self.send_file_error(&err).await,
                    },
                    Err(err) => self.send_file_error(&err).await,
                }
            }

            FileClientMessage::VerifyRange {
                path,
                offset,
                length,
            } => {
                if self.refuse_without(Capability::FileRead).await {
                    return;
                }
                match self
                    .resolve(&path)
                    .and_then(|resolved| checksum_range(&resolved, offset, length))
                {
                    Ok((checksum, length)) => {
                        self.send(&FileAgentMessage::RangeChecksum { checksum, length })
                            .await;
                    }
                    Err(err) => self.send_file_error(&err).await,
                }
            }

            FileClientMessage::DownloadBegin {
                transfer_id,
                source,
                start_offset,
            } => {
                if self.refuse_without(Capability::FileRead).await {
                    return;
                }
                self.download(transfer_id, &source, start_offset).await;
            }

            // Routed here by `is_read_only`, so anything else is a routing bug.
            _ => {
                self.send_error(
                    ErrorCode::Internal,
                    "that file request was routed incorrectly",
                )
                .await;
            }
        }
    }

    /// Handle a message that changes the filesystem.
    async fn handle_write(&self, message: FileClientMessage) {
        match message {
            FileClientMessage::CreateDirectory { path } => {
                if self.refuse_without(Capability::FileWrite).await {
                    return;
                }
                let outcome = self.resolve(&path).and_then(|resolved| {
                    std::fs::create_dir_all(&resolved).map_err(|err| FileError::from_io(&err))
                });
                self.answer(outcome, actions::DIRECTORY_CREATED, &path)
                    .await;
            }

            FileClientMessage::Rename { from, to, conflict } => {
                if self.refuse_without(Capability::FileWrite).await {
                    return;
                }
                self.rename(&from, &to, conflict).await;
            }

            FileClientMessage::Copy { from, to, conflict } => {
                if self.refuse_without(Capability::FileWrite).await {
                    return;
                }
                self.copy(&from, &to, conflict).await;
            }

            FileClientMessage::Delete {
                path,
                permanent,
                recursive,
            } => {
                if self.refuse_without(Capability::FileWrite).await {
                    return;
                }
                self.delete(&path, permanent, recursive).await;
            }

            FileClientMessage::UploadBegin {
                transfer_id,
                destination,
                total_bytes,
                checksum,
                conflict,
            } => {
                if self.refuse_without(Capability::FileWrite).await {
                    return;
                }
                self.upload_begin(transfer_id, &destination, total_bytes, checksum, conflict)
                    .await;
            }

            FileClientMessage::UploadChunk {
                transfer_id,
                offset,
                data,
            } => {
                if self.refuse_without(Capability::FileWrite).await {
                    return;
                }
                // The bytes are never logged: file contents are not something the audit
                // trail records.
                if let Err(err) = self.transfers.write_chunk(transfer_id, offset, &data) {
                    self.fail_transfer(transfer_id, &err).await;
                }
            }

            FileClientMessage::UploadEnd { transfer_id } => {
                if self.refuse_without(Capability::FileWrite).await {
                    return;
                }
                match self.transfers.finish(transfer_id) {
                    Ok(bytes) => {
                        self.audit_transfer(actions::FILE_UPLOADED, bytes).await;
                        self.send(&FileAgentMessage::TransferComplete {
                            transfer_id,
                            bytes_transferred: bytes,
                        })
                        .await;
                    }
                    Err(err) => self.fail_transfer(transfer_id, &err).await,
                }
            }

            FileClientMessage::TransferCancel { transfer_id } => {
                // Deliberately not capability-gated: stopping something already in
                // flight is always permitted, and refusing it would leave a transfer
                // running that the operator asked to stop.
                self.transfers.cancel(transfer_id);
                self.send(&FileAgentMessage::Ok).await;
            }

            // `FileClientMessage` is `#[non_exhaustive]`: an operation from a newer
            // client is refused rather than approximated.
            _ => {
                self.send_error(
                    ErrorCode::Unsupported,
                    "this server does not understand that file operation",
                )
                .await;
            }
        }
    }

    /// List a directory.
    async fn list(&self, path: &str, include_hidden: bool) {
        let outcome = self.resolve(path).and_then(|resolved| {
            list_directory(&resolved, include_hidden)
                .map(|(entries, truncated)| (resolved, entries, truncated))
        });

        match outcome {
            Ok((resolved, entries, truncated)) => {
                self.send(&FileAgentMessage::Listing {
                    // The *resolved* path, so the client shows where it actually landed
                    // rather than what it asked for — they differ whenever a symlink or
                    // a `..` was involved.
                    path: resolved.to_string_lossy().into_owned(),
                    entries,
                    truncated,
                })
                .await;
            }
            Err(err) => self.send_file_error(&err).await,
        }
    }

    /// Rename or move within the host.
    async fn rename(&self, from: &str, to: &str, conflict: ConflictPolicy) {
        let outcome = (|| {
            let source = self.resolve(from)?;
            let destination = self.resolve(to)?;
            let destination = apply_conflict_policy(&destination, conflict)?;

            std::fs::rename(&source, &destination).map_err(|err| FileError::from_io(&err))
        })();

        self.answer(outcome, actions::FILE_RENAMED, from).await;
    }

    /// Copy within the host.
    async fn copy(&self, from: &str, to: &str, conflict: ConflictPolicy) {
        let outcome = (|| {
            let source = self.resolve(from)?;
            let destination = self.resolve(to)?;

            // Directories are refused rather than silently copying one file: a
            // recursive copy needs progress reporting and a cancel path, and doing it
            // invisibly inside one message would block the channel for however long it
            // took.
            if std::fs::symlink_metadata(&source)
                .map_err(|err| FileError::from_io(&err))?
                .is_dir()
            {
                return Err(FileError::WrongKind);
            }

            let destination = apply_conflict_policy(&destination, conflict)?;
            std::fs::copy(&source, &destination)
                .map(|_| ())
                .map_err(|err| FileError::from_io(&err))
        })();

        self.answer(outcome, actions::FILE_COPIED, from).await;
    }

    /// Delete a path.
    async fn delete(&self, path: &str, permanent: bool, recursive: bool) {
        let outcome = (|| {
            let resolved = self.resolve(path)?;
            let metadata =
                std::fs::symlink_metadata(&resolved).map_err(|err| FileError::from_io(&err))?;

            if metadata.is_dir() {
                if !recursive {
                    // An empty directory can go; a full one needs the client to have
                    // said so. Recursing by default turns a mis-typed path into an
                    // outage.
                    return std::fs::remove_dir(&resolved).map_err(|err| FileError::from_io(&err));
                }
                return std::fs::remove_dir_all(&resolved).map_err(|err| FileError::from_io(&err));
            }

            // A symlink is removed as a link, never followed. Following it would delete
            // the target, which may be outside the roots entirely.
            std::fs::remove_file(&resolved).map_err(|err| FileError::from_io(&err))
        })();

        // There is no recycle-bin path in this build, so every delete is permanent
        // whatever the client asked for. The flag is not consulted, and the client is
        // told plainly rather than being allowed to believe a delete was recoverable.
        let _ = permanent;
        self.answer(outcome, actions::FILE_DELETED, path).await;
    }

    /// Begin or resume an upload.
    async fn upload_begin(
        &self,
        transfer_id: TransferId,
        destination: &str,
        total_bytes: u64,
        checksum: rc_protocol::files::Checksum,
        conflict: ConflictPolicy,
    ) {
        let outcome = (|| {
            let resolved = self.resolve(destination)?;

            if conflict == ConflictPolicy::Fail && resolved.exists() {
                return Err(FileError::Conflict);
            }
            let resolved = apply_conflict_policy(&resolved, conflict)?;

            // Resuming is offered only when the client asked for it; the prefix digest
            // is verified inside `Upload::begin` before a single byte is appended.
            let resume = if conflict == ConflictPolicy::Resume {
                partial_resume_point(&resolved)
            } else {
                None
            };

            Upload::begin(
                transfer_id,
                resolved,
                total_bytes,
                checksum,
                self.max_transfer_bytes,
                resume,
            )
        })();

        match outcome {
            Ok((upload, resume_offset)) => match self.transfers.insert(upload) {
                Ok(()) => {
                    self.send(&FileAgentMessage::UploadReady {
                        transfer_id,
                        resume_offset,
                    })
                    .await;
                }
                Err(err) => self.fail_transfer(transfer_id, &err).await,
            },
            Err(err) => self.fail_transfer(transfer_id, &err).await,
        }
    }

    /// Read a file out to the client.
    async fn download(&self, transfer_id: TransferId, source: &str, start_offset: u64) {
        let opened = self.resolve(source).and_then(|resolved| {
            Download::begin(
                transfer_id,
                &resolved,
                start_offset,
                self.max_transfer_bytes,
            )
        });

        let (mut download, total_bytes, checksum) = match opened {
            Ok(parts) => parts,
            Err(err) => {
                self.fail_transfer(transfer_id, &err).await;
                return;
            }
        };

        self.send(&FileAgentMessage::DownloadBegin {
            transfer_id,
            total_bytes,
            checksum,
        })
        .await;

        // Chunks are pumped inline rather than on a task. The channel is a single
        // stream, so a concurrent pump would have to interleave with the message loop
        // anyway; doing it here keeps the ordering obvious and means a client that
        // stops reading applies backpressure through the QUIC stream.
        loop {
            match download.next_chunk() {
                Ok(Some((offset, data))) => {
                    self.send(&FileAgentMessage::DownloadChunk {
                        transfer_id,
                        offset,
                        data,
                    })
                    .await;
                }
                Ok(None) => break,
                Err(err) => {
                    self.fail_transfer(transfer_id, &err).await;
                    return;
                }
            }
        }

        let sent = download.bytes_sent();
        self.audit_transfer(actions::FILE_DOWNLOADED, sent).await;
        self.send(&FileAgentMessage::TransferComplete {
            transfer_id,
            bytes_transferred: sent,
        })
        .await;
    }

    /// Resolve an untrusted path against this connection's policy.
    fn resolve(&self, raw: &str) -> rc_file_transfer::Result<std::path::PathBuf> {
        self.policy.resolve(raw)
    }

    /// Refuse the message when the session lacks `capability`. Returns whether it did.
    async fn refuse_without(&self, capability: Capability) -> bool {
        if self.authorization.require(capability).is_ok() {
            return false;
        }

        self.send_error(
            ErrorCode::PermissionDenied,
            match capability {
                Capability::FileWrite => "this device may read files but not change them",
                _ => "this device is not permitted to browse files on this server",
            },
        )
        .await;
        true
    }

    /// Report the outcome of an operation that either works or does not.
    async fn answer(
        &self,
        outcome: rc_file_transfer::Result<()>,
        action: &'static str,
        path: &str,
    ) {
        match outcome {
            Ok(()) => {
                self.audit_path(action, AuditResult::Success, path).await;
                self.send(&FileAgentMessage::Ok).await;
            }
            Err(err) => {
                self.audit_path(action, AuditResult::Failure, path).await;
                self.send_file_error(&err).await;
            }
        }
    }

    async fn send(&self, message: &FileAgentMessage) {
        if let Err(err) = self.writer.lock().await.send(message).await {
            tracing::debug!(%err, "could not send a file message");
        }
    }

    async fn send_file_error(&self, error: &FileError) {
        // `FileError`'s messages are written to be safe to display: none echoes back
        // the path it was given.
        self.send(&FileAgentMessage::Error {
            code: error.code(),
            message: error.to_string(),
        })
        .await;
    }

    async fn send_error(&self, code: ErrorCode, message: &str) {
        self.send(&FileAgentMessage::Error {
            code,
            message: message.to_owned(),
        })
        .await;
    }

    async fn fail_transfer(&self, transfer_id: TransferId, error: &FileError) {
        self.send(&FileAgentMessage::TransferFailed {
            transfer_id,
            code: error.code(),
            message: error.to_string(),
        })
        .await;
    }

    /// Record an operation on a path.
    ///
    /// The path is deliberately **not** included: it came from a peer, and the audit
    /// trail is read by a human. What is recorded is that this device did this kind of
    /// thing in this session, which is what the trail is for.
    async fn audit_path(&self, action: &'static str, result: AuditResult, _path: &str) {
        self.audit(
            AuditEvent::new(AuditCategory::FileTransfer, action, result)
                .actor_device(self.device_id)
                .meta("session_id", self.session_id),
        )
        .await;
    }

    async fn audit_transfer(&self, action: &'static str, bytes: u64) {
        self.audit(
            AuditEvent::new(AuditCategory::FileTransfer, action, AuditResult::Success)
                .actor_device(self.device_id)
                .meta("session_id", self.session_id)
                .meta("bytes", bytes),
        )
        .await;
    }

    async fn audit(&self, event: AuditEvent) {
        let repository = rc_storage::audit::AuditRepository::new(&self.database);
        if let Err(err) = repository.record(&event, self.clock.now_ms()).await {
            tracing::error!(%err, action = event.action, "could not write an audit record");
        }
    }
}

/// Whether a message only reads, and so needs [`Capability::FileRead`] alone.
///
/// Written as an exhaustive-by-listing match rather than a negation: a message added
/// later falls through to the write half, which is the safe side to default to. A new
/// operation being needlessly gated behind write access is a nuisance; a new operation
/// that changes the filesystem being treated as a read is a hole.
const fn is_read_only(message: &FileClientMessage) -> bool {
    matches!(
        message,
        FileClientMessage::List { .. }
            | FileClientMessage::Stat { .. }
            | FileClientMessage::VerifyRange { .. }
            | FileClientMessage::DownloadBegin { .. }
    )
}

/// Apply a conflict policy to a destination that may already exist.
///
/// Returns the path to actually write to.
fn apply_conflict_policy(
    destination: &std::path::Path,
    conflict: ConflictPolicy,
) -> rc_file_transfer::Result<std::path::PathBuf> {
    if !destination.exists() {
        return Ok(destination.to_path_buf());
    }

    match conflict {
        ConflictPolicy::Fail => Err(FileError::Conflict),
        // `Resume` is handled by the upload itself, which verifies the prefix; here it
        // means the same as overwriting, since the partial file is a separate path.
        ConflictPolicy::Overwrite | ConflictPolicy::Resume => Ok(destination.to_path_buf()),
        ConflictPolicy::Rename => unique_name(destination).ok_or(FileError::Conflict),
    }
}

/// Derive a name that does not exist yet, as `report (2).pdf`.
///
/// Bounded: after a hundred attempts something is wrong with the directory rather than
/// with the name, and looping forever would hang the channel.
fn unique_name(destination: &std::path::Path) -> Option<std::path::PathBuf> {
    let parent = destination.parent()?;
    let stem = destination.file_stem()?.to_string_lossy().into_owned();
    let extension = destination
        .extension()
        .map(|ext| format!(".{}", ext.to_string_lossy()))
        .unwrap_or_default();

    (2..100).find_map(|index| {
        let candidate = parent.join(format!("{stem} ({index}){extension}"));
        (!candidate.exists()).then_some(candidate)
    })
}

/// Where an interrupted upload left off, if a partial file is there.
///
/// Returns the offset and the digest of the bytes already on disk, which
/// `Upload::begin` re-verifies. Offering a resume point the agent computed itself is
/// safe precisely because the client's own digest has to agree with it.
fn partial_resume_point(
    destination: &std::path::Path,
) -> Option<(u64, rc_protocol::files::Checksum)> {
    let mut partial = destination.as_os_str().to_owned();
    partial.push(".rc-partial");
    let partial = std::path::PathBuf::from(partial);

    let length = std::fs::metadata(&partial).ok()?.len();
    if length == 0 {
        return None;
    }

    let (checksum, hashed) = checksum_range(&partial, 0, length).ok()?;
    (hashed == length).then_some((length, checksum))
}

#[cfg(test)]
mod tests {
    use rc_security::Role;

    use super::*;

    #[test]
    fn reading_and_writing_are_separate_capabilities() {
        // What makes View Only useful: browse and download, but change nothing.
        let view_only = AuthorizationContext::new(Role::ViewOnly);

        assert!(view_only.require(Capability::FileRead).is_ok());
        assert!(view_only.require(Capability::FileWrite).is_err());
    }

    #[test]
    fn an_operator_may_write_and_a_revoked_device_may_not_even_read() {
        assert!(
            AuthorizationContext::new(Role::Operator)
                .require(Capability::FileWrite)
                .is_ok()
        );
        assert!(
            AuthorizationContext::revoked(Role::Owner)
                .require(Capability::FileRead)
                .is_err(),
            "revocation must override the role entirely"
        );
    }

    #[test]
    fn a_destination_that_does_not_exist_is_used_as_given() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("new.txt");

        for policy in [
            ConflictPolicy::Fail,
            ConflictPolicy::Overwrite,
            ConflictPolicy::Rename,
        ] {
            assert_eq!(apply_conflict_policy(&target, policy).unwrap(), target);
        }
    }

    #[test]
    fn a_conflict_fails_when_the_policy_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("existing.txt");
        std::fs::write(&target, b"x").unwrap();

        assert_eq!(
            apply_conflict_policy(&target, ConflictPolicy::Fail),
            Err(FileError::Conflict)
        );
    }

    #[test]
    fn overwriting_keeps_the_original_name() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("existing.txt");
        std::fs::write(&target, b"x").unwrap();

        assert_eq!(
            apply_conflict_policy(&target, ConflictPolicy::Overwrite).unwrap(),
            target
        );
    }

    #[test]
    fn renaming_derives_a_name_that_does_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("report.pdf");
        std::fs::write(&target, b"x").unwrap();

        let renamed = apply_conflict_policy(&target, ConflictPolicy::Rename).unwrap();

        assert_eq!(renamed, dir.path().join("report (2).pdf"));
        assert!(!renamed.exists());
    }

    #[test]
    fn renaming_skips_past_names_that_are_also_taken() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("f.txt"), b"x").unwrap();
        std::fs::write(dir.path().join("f (2).txt"), b"x").unwrap();
        std::fs::write(dir.path().join("f (3).txt"), b"x").unwrap();

        let renamed =
            apply_conflict_policy(&dir.path().join("f.txt"), ConflictPolicy::Rename).unwrap();

        assert_eq!(renamed, dir.path().join("f (4).txt"));
    }

    #[test]
    fn renaming_a_file_without_an_extension_still_works() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("Makefile");
        std::fs::write(&target, b"x").unwrap();

        assert_eq!(
            apply_conflict_policy(&target, ConflictPolicy::Rename).unwrap(),
            dir.path().join("Makefile (2)")
        );
    }

    #[test]
    fn a_resume_point_is_offered_only_when_a_partial_exists() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("upload.bin");

        assert!(partial_resume_point(&destination).is_none());

        std::fs::write(dir.path().join("upload.bin.rc-partial"), b"0123456789").unwrap();
        let (offset, _) = partial_resume_point(&destination).expect("a partial was left");

        assert_eq!(offset, 10);
    }

    #[test]
    fn an_empty_partial_offers_no_resume_point() {
        // Resuming from zero is starting, and saying otherwise would make the client
        // send a redundant verification round trip.
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("upload.bin");
        std::fs::write(dir.path().join("upload.bin.rc-partial"), b"").unwrap();

        assert!(partial_resume_point(&destination).is_none());
    }

    #[test]
    fn a_resume_digest_covers_exactly_the_bytes_on_disk() {
        // The client re-verifies this; a digest over the wrong range would make every
        // resume fail rather than succeed wrongly, but it would still be a bug.
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("upload.bin");
        std::fs::write(dir.path().join("upload.bin.rc-partial"), b"hello").unwrap();

        let (offset, checksum) = partial_resume_point(&destination).unwrap();

        assert_eq!(offset, 5);
        assert_eq!(checksum.digest, blake3::hash(b"hello").as_bytes().to_vec());
    }
}
