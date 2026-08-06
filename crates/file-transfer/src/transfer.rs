//! Resumable, verified file transfers.
//!
//! # A transfer is verified, not assumed
//!
//! Every transfer agrees a whole-file BLAKE3 digest before the first byte moves. On
//! completion the received file is hashed and compared, and a mismatch **discards** the
//! file rather than keeping it with a warning.
//!
//! That is deliberate. A file that is silently wrong is worse than a transfer that
//! failed: the failure is discovered now, by the person who can retry it, whereas the
//! corruption is discovered later, by whoever depended on it.
//!
//! # Resuming verifies the prefix
//!
//! Continuing an interrupted upload hashes the bytes already on disk over the same
//! range and compares against the client's digest for that range. A resume that trusted
//! the offset alone would splice two different files together and produce something
//! that passed no check until the final digest — by which point the whole transfer has
//! been spent.
//!
//! # Writes go to a temporary file
//!
//! An upload is written beside its destination and renamed into place only after its
//! checksum verifies. An interrupted transfer therefore leaves a partial file with an
//! obvious name, never a truncated file under the real one — which is what would happen
//! if a half-finished upload overwrote a good file in place.

use std::collections::HashMap;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use parking_lot::Mutex;
use rc_protocol::TransferId;
use rc_protocol::files::{Checksum, ChecksumAlgorithm};

use crate::error::{FileError, Result};

/// Bytes per chunk on the wire.
///
/// Matches the protocol's preferred size: large enough that a gigabyte file is not
/// four thousand round trips, small enough to stay far inside the file channel's
/// ceiling and to keep progress reporting responsive.
pub const CHUNK_BYTES: usize = rc_protocol::limits::FILE_CHUNK_SIZE;

/// How many transfers one connection may have in flight.
pub const MAX_CONCURRENT_TRANSFERS: usize = 8;

/// Suffix given to a partially written upload.
///
/// Visible on purpose. An operator who finds one should be able to tell at a glance
/// that it is incomplete, rather than discovering it is truncated when they open it.
const PARTIAL_SUFFIX: &str = ".rc-partial";

/// Compute the BLAKE3 digest of a whole file.
///
/// # Errors
/// [`FileError::NotFound`], [`FileError::PermissionDenied`] or [`FileError::Io`].
pub fn checksum_file(path: &Path) -> Result<Checksum> {
    let mut file = std::fs::File::open(path).map_err(|err| FileError::from_io(&err))?;
    let mut hasher = blake3::Hasher::new();

    // Streamed rather than read whole: the point of a file transfer is files that do
    // not fit in memory.
    let mut buffer = vec![0u8; CHUNK_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|err| FileError::from_io(&err))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(Checksum {
        algorithm: ChecksumAlgorithm::Blake3,
        digest: hasher.finalize().as_bytes().to_vec(),
    })
}

/// Compute the digest of a byte range, for validating a resume point.
///
/// Returns the digest and how many bytes were actually hashed, which is fewer than
/// requested at end of file.
///
/// # Errors
/// As [`checksum_file`].
pub fn checksum_range(path: &Path, offset: u64, length: u64) -> Result<(Checksum, u64)> {
    let mut file = std::fs::File::open(path).map_err(|err| FileError::from_io(&err))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|err| FileError::from_io(&err))?;

    let mut hasher = blake3::Hasher::new();
    let mut remaining = length;
    let mut bytes_read = 0u64;
    let mut buffer = vec![0u8; CHUNK_BYTES];

    while remaining > 0 {
        // The read is bounded by what is left of the range, so a caller asking for a
        // huge length does not make the agent allocate one.
        let want = usize::try_from(remaining.min(CHUNK_BYTES as u64)).unwrap_or(CHUNK_BYTES);
        let read = file
            .read(&mut buffer[..want])
            .map_err(|err| FileError::from_io(&err))?;
        if read == 0 {
            break;
        }

        hasher.update(&buffer[..read]);
        bytes_read += read as u64;
        remaining -= read as u64;
    }

    Ok((
        Checksum {
            algorithm: ChecksumAlgorithm::Blake3,
            digest: hasher.finalize().as_bytes().to_vec(),
        },
        bytes_read,
    ))
}

/// An upload in progress.
///
/// Writes to a partial file beside the destination and renames into place only once the
/// whole-file checksum verifies.
pub struct Upload {
    id: TransferId,
    destination: PathBuf,
    partial: PathBuf,
    file: std::fs::File,
    /// Byte offset the next chunk must start at.
    expected_offset: u64,
    total_bytes: u64,
    expected: Checksum,
    /// Bytes written in this session, excluding any resumed prefix.
    written: u64,
}

impl std::fmt::Debug for Upload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The destination is deliberately absent: this is rendered into logs, and the
        // path came from a peer.
        f.debug_struct("Upload")
            .field("id", &self.id)
            .field("expected_offset", &self.expected_offset)
            .field("total_bytes", &self.total_bytes)
            .finish_non_exhaustive()
    }
}

impl Upload {
    /// Begin or resume an upload.
    ///
    /// Returns the upload and the offset the client should send from — non-zero when a
    /// partial file was found whose prefix matches.
    ///
    /// # Errors
    /// [`FileError::TooLarge`] if the file exceeds `max_bytes`,
    /// [`FileError::InsufficientSpace`] if the volume cannot hold it, or an I/O failure.
    pub fn begin(
        id: TransferId,
        destination: PathBuf,
        total_bytes: u64,
        expected: Checksum,
        max_bytes: u64,
        resume_from: Option<(u64, Checksum)>,
    ) -> Result<(Self, u64)> {
        if total_bytes > max_bytes {
            return Err(FileError::TooLarge);
        }

        let partial = partial_path(&destination);

        // Resuming is only offered when the caller proves the existing prefix matches.
        // Without that proof this would happily splice two different files together.
        let resume_offset = match resume_from {
            Some((offset, prefix_digest)) if offset > 0 => {
                verify_resume_point(&partial, offset, &prefix_digest)?;
                offset
            }
            _ => {
                // Any previous attempt is discarded rather than appended to.
                let _ = std::fs::remove_file(&partial);
                0
            }
        };

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(resume_offset == 0)
            .open(&partial)
            .map_err(|err| FileError::from_io(&err))?;

        file.seek(SeekFrom::Start(resume_offset))
            .map_err(|err| FileError::from_io(&err))?;

        Ok((
            Self {
                id,
                destination,
                partial,
                file,
                expected_offset: resume_offset,
                total_bytes,
                expected,
                written: 0,
            },
            resume_offset,
        ))
    }

    /// This transfer's id.
    #[must_use]
    pub const fn id(&self) -> TransferId {
        self.id
    }

    /// How many bytes have been written in this session.
    #[must_use]
    pub const fn bytes_written(&self) -> u64 {
        self.written
    }

    /// The offset the next chunk must start at.
    #[must_use]
    pub const fn expected_offset(&self) -> u64 {
        self.expected_offset
    }

    /// Write one chunk.
    ///
    /// # Errors
    /// [`FileError::OutOfOrderChunk`] if the offset is not the expected one, or
    /// [`FileError::TooLarge`] if the chunk would take the file past its agreed size.
    pub fn write_chunk(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        // Chunks must arrive in order at exactly the expected offset. Accepting an
        // arbitrary offset would let a peer write anywhere in the file, including past
        // the size it agreed, and would leave holes no checksum could explain.
        if offset != self.expected_offset {
            return Err(FileError::OutOfOrderChunk);
        }

        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(FileError::TooLarge)?;
        if end > self.total_bytes {
            // More data than the transfer agreed to carry.
            return Err(FileError::TooLarge);
        }

        self.file
            .write_all(data)
            .map_err(|err| FileError::from_io(&err))?;

        self.expected_offset = end;
        self.written += data.len() as u64;
        Ok(())
    }

    /// Finish the upload: verify the checksum and move it into place.
    ///
    /// # Errors
    /// [`FileError::ChecksumMismatch`] — and the partial file is **deleted**, because a
    /// file that is silently wrong is worse than a transfer that failed.
    pub fn finish(mut self) -> Result<u64> {
        if self.expected_offset != self.total_bytes {
            // The client said it was done before sending everything it promised.
            let _ = std::fs::remove_file(&self.partial);
            return Err(FileError::ChecksumMismatch);
        }

        self.file
            .flush()
            .and_then(|()| self.file.sync_all())
            .map_err(|err| FileError::from_io(&err))?;
        // Closed before hashing and renaming: on Windows an open handle prevents the
        // rename outright.
        drop(self.file);

        let actual = checksum_file(&self.partial)?;
        if actual.digest != self.expected.digest {
            tracing::warn!(
                transfer_id = %self.id,
                "an upload failed its checksum; discarding it"
            );
            let _ = std::fs::remove_file(&self.partial);
            return Err(FileError::ChecksumMismatch);
        }

        std::fs::rename(&self.partial, &self.destination).map_err(|err| {
            let _ = std::fs::remove_file(&self.partial);
            FileError::from_io(&err)
        })?;

        tracing::info!(
            transfer_id = %self.id,
            bytes = self.written,
            "upload complete and verified"
        );
        Ok(self.written)
    }

    /// Abandon the upload, leaving the partial file so it can be resumed.
    pub fn cancel(self) {
        // The partial file is kept on purpose: a cancelled transfer is usually one the
        // operator means to resume, and deleting the work would make Cancel and Restart
        // the same button.
        drop(self.file);
        tracing::info!(transfer_id = %self.id, "upload cancelled; partial file kept");
    }
}

/// Where a partial upload is written.
fn partial_path(destination: &Path) -> PathBuf {
    let mut name = destination.as_os_str().to_owned();
    name.push(PARTIAL_SUFFIX);
    PathBuf::from(name)
}

/// Check that an existing partial file matches the client's digest for its prefix.
fn verify_resume_point(partial: &Path, offset: u64, expected: &Checksum) -> Result<()> {
    let metadata = std::fs::metadata(partial).map_err(|_| FileError::ResumeMismatch)?;

    // A partial shorter than the claimed resume point cannot contain the prefix; one
    // that is longer has bytes past it that the digest does not cover.
    if metadata.len() < offset {
        return Err(FileError::ResumeMismatch);
    }

    let (actual, covered) = checksum_range(partial, 0, offset)?;
    if covered != offset || actual.digest != expected.digest {
        tracing::warn!("a resume was refused: the partial file does not match");
        return Err(FileError::ResumeMismatch);
    }

    Ok(())
}

/// A download in progress: a file being read out to a peer.
///
/// Reads are streamed, never buffered whole. The whole point of a file transfer is
/// files that do not fit in memory, and a download that read its source into a `Vec`
/// would let a peer choose how much the agent allocates by choosing which file to ask
/// for.
pub struct Download {
    id: TransferId,
    file: std::fs::File,
    /// Offset of the next chunk to send.
    offset: u64,
    total_bytes: u64,
    /// Bytes sent in this session, excluding any resumed prefix.
    sent: u64,
}

impl std::fmt::Debug for Download {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The source path is deliberately absent: this is rendered into logs, and the
        // path came from a peer.
        f.debug_struct("Download")
            .field("id", &self.id)
            .field("offset", &self.offset)
            .field("total_bytes", &self.total_bytes)
            .finish_non_exhaustive()
    }
}

impl Download {
    /// Open a file for reading out.
    ///
    /// Returns the download, the total size and the whole-file checksum, so the peer can
    /// verify what it receives end to end.
    ///
    /// # Errors
    /// [`FileError::NotFound`], [`FileError::PermissionDenied`],
    /// [`FileError::WrongKind`] for a directory, or [`FileError::TooLarge`].
    pub fn begin(
        id: TransferId,
        source: &Path,
        start_offset: u64,
        max_bytes: u64,
    ) -> Result<(Self, u64, Checksum)> {
        // `symlink_metadata` rather than `metadata`: a request to download a symlink is
        // answered about the link, and following it is a decision that belongs to
        // `PathPolicy`, which has already run by the time this is called.
        let metadata = std::fs::symlink_metadata(source).map_err(|err| FileError::from_io(&err))?;
        if metadata.is_dir() {
            return Err(FileError::WrongKind);
        }

        let total_bytes = metadata.len();
        if total_bytes > max_bytes {
            return Err(FileError::TooLarge);
        }
        // A resume point past the end of the file describes a file the peer has not
        // got; continuing from it would send nothing and report success.
        if start_offset > total_bytes {
            return Err(FileError::ResumeMismatch);
        }

        // Hashed before any chunk is sent, so the peer knows what it should end up with
        // rather than being told afterwards what it happens to have.
        let checksum = checksum_file(source)?;

        let mut file = std::fs::File::open(source).map_err(|err| FileError::from_io(&err))?;
        file.seek(SeekFrom::Start(start_offset))
            .map_err(|err| FileError::from_io(&err))?;

        Ok((
            Self {
                id,
                file,
                offset: start_offset,
                total_bytes,
                sent: 0,
            },
            total_bytes,
            checksum,
        ))
    }

    /// This transfer's id.
    #[must_use]
    pub const fn id(&self) -> TransferId {
        self.id
    }

    /// Bytes sent in this session.
    #[must_use]
    pub const fn bytes_sent(&self) -> u64 {
        self.sent
    }

    /// Whether every byte has been read out.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.offset >= self.total_bytes
    }

    /// Read the next chunk, or `None` at end of file.
    ///
    /// Returns the chunk's offset alongside its bytes so the receiver can place it
    /// without tracking a running total of its own.
    ///
    /// # Errors
    /// [`FileError::Io`] or [`FileError::PermissionDenied`] if the read fails.
    pub fn next_chunk(&mut self) -> Result<Option<(u64, Vec<u8>)>> {
        if self.is_complete() {
            return Ok(None);
        }

        let mut buffer = vec![0u8; CHUNK_BYTES];
        let read = self
            .file
            .read(&mut buffer)
            .map_err(|err| FileError::from_io(&err))?;

        if read == 0 {
            // The file shrank while it was being read. Reporting the end here is right;
            // the peer's checksum will fail, which is what should happen when the file
            // it was promised is not the file that exists.
            return Ok(None);
        }

        buffer.truncate(read);
        let offset = self.offset;
        self.offset += read as u64;
        self.sent += read as u64;

        Ok(Some((offset, buffer)))
    }
}

/// Every transfer belonging to one connection.
///
/// Bounded, and dropped with the connection — which is what stops a client from
/// accumulating half-finished transfers across reconnects.
#[derive(Default)]
pub struct TransferRegistry {
    uploads: Mutex<HashMap<TransferId, Upload>>,
    max_transfers: usize,
}

impl std::fmt::Debug for TransferRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferRegistry")
            .field("active", &self.uploads.lock().len())
            .field("max_transfers", &self.max_transfers)
            .finish()
    }
}

impl TransferRegistry {
    /// A registry admitting at most `max_transfers` concurrent uploads.
    #[must_use]
    pub fn new(max_transfers: usize) -> Self {
        Self {
            uploads: Mutex::new(HashMap::new()),
            max_transfers: max_transfers.max(1),
        }
    }

    /// How many uploads are in flight.
    #[must_use]
    pub fn len(&self) -> usize {
        self.uploads.lock().len()
    }

    /// Whether none are in flight.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Register an upload.
    ///
    /// # Errors
    /// [`FileError::TooManyTransfers`] when the cap is reached.
    pub fn insert(&self, upload: Upload) -> Result<()> {
        let mut uploads = self.uploads.lock();

        if uploads.len() >= self.max_transfers {
            // `upload` is dropped here, which closes its file. The partial stays on
            // disk and can be resumed.
            return Err(FileError::TooManyTransfers);
        }

        uploads.insert(upload.id(), upload);
        Ok(())
    }

    /// Write a chunk to a registered upload.
    ///
    /// # Errors
    /// [`FileError::UnknownTransfer`] or whatever the write reports.
    pub fn write_chunk(&self, id: TransferId, offset: u64, data: &[u8]) -> Result<()> {
        let mut uploads = self.uploads.lock();
        let upload = uploads.get_mut(&id).ok_or(FileError::UnknownTransfer)?;
        upload.write_chunk(offset, data)
    }

    /// Finish an upload, removing it from the registry.
    ///
    /// # Errors
    /// [`FileError::UnknownTransfer`], or a verification failure.
    pub fn finish(&self, id: TransferId) -> Result<u64> {
        let upload = self
            .uploads
            .lock()
            .remove(&id)
            .ok_or(FileError::UnknownTransfer)?;
        upload.finish()
    }

    /// Cancel an upload, keeping its partial file.
    pub fn cancel(&self, id: TransferId) {
        if let Some(upload) = self.uploads.lock().remove(&id) {
            upload.cancel();
        }
    }

    /// Cancel every upload. Called when a connection ends.
    pub fn cancel_all(&self) {
        let uploads: Vec<Upload> = self.uploads.lock().drain().map(|(_, u)| u).collect();
        for upload in uploads {
            upload.cancel();
        }
    }
}

impl Drop for TransferRegistry {
    fn drop(&mut self) {
        self.cancel_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_of(bytes: &[u8]) -> Checksum {
        Checksum {
            algorithm: ChecksumAlgorithm::Blake3,
            digest: blake3::hash(bytes).as_bytes().to_vec(),
        }
    }

    const NO_LIMIT: u64 = u64::MAX;

    /// Upload `content` in one chunk, returning the destination path.
    fn upload_all(dir: &Path, content: &[u8]) -> Result<PathBuf> {
        let destination = dir.join("uploaded.bin");
        let (mut upload, resume) = Upload::begin(
            TransferId::generate(),
            destination.clone(),
            content.len() as u64,
            digest_of(content),
            NO_LIMIT,
            None,
        )?;

        assert_eq!(resume, 0);
        upload.write_chunk(0, content)?;
        upload.finish()?;
        Ok(destination)
    }

    // -- checksums -----------------------------------------------------------

    #[test]
    fn a_whole_file_checksum_matches_the_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"hello world").unwrap();

        assert_eq!(checksum_file(&path).unwrap(), digest_of(b"hello world"));
    }

    #[test]
    fn a_checksum_of_a_missing_file_reports_not_found() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            checksum_file(&dir.path().join("nothing")),
            Err(FileError::NotFound)
        );
    }

    #[test]
    fn a_range_checksum_covers_only_the_range() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"0123456789").unwrap();

        let (checksum, hashed) = checksum_range(&path, 2, 4).unwrap();
        assert_eq!(hashed, 4);
        assert_eq!(checksum, digest_of(b"2345"));
    }

    #[test]
    fn a_range_past_the_end_hashes_only_what_exists() {
        // The caller is told how much was actually hashed rather than being given a
        // digest over imagined zeroes.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"12345").unwrap();

        let (checksum, hashed) = checksum_range(&path, 3, 1000).unwrap();
        assert_eq!(hashed, 2);
        assert_eq!(checksum, digest_of(b"45"));
    }

    // -- uploads -------------------------------------------------------------

    #[test]
    fn an_upload_lands_at_its_destination_with_the_right_content() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"the quick brown fox";

        let destination = upload_all(dir.path(), content).unwrap();

        assert_eq!(std::fs::read(&destination).unwrap(), content);
        assert!(
            !partial_path(&destination).exists(),
            "the partial file must be gone"
        );
    }

    #[test]
    fn an_upload_arrives_in_several_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let content: Vec<u8> = (0..2000u32).map(|index| (index % 251) as u8).collect();
        let destination = dir.path().join("chunked.bin");

        let (mut upload, _) = Upload::begin(
            TransferId::generate(),
            destination.clone(),
            content.len() as u64,
            digest_of(&content),
            NO_LIMIT,
            None,
        )
        .unwrap();

        let mut offset = 0u64;
        for chunk in content.chunks(512) {
            upload.write_chunk(offset, chunk).unwrap();
            offset += chunk.len() as u64;
        }

        assert_eq!(upload.finish().unwrap(), content.len() as u64);
        assert_eq!(std::fs::read(&destination).unwrap(), content);
    }

    #[test]
    fn a_corrupted_upload_is_discarded_rather_than_kept() {
        // The property that matters most here: a file that is silently wrong is worse
        // than a transfer that failed.
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("corrupt.bin");

        let (mut upload, _) = Upload::begin(
            TransferId::generate(),
            destination.clone(),
            4,
            // A digest of something else entirely.
            digest_of(b"good"),
            NO_LIMIT,
            None,
        )
        .unwrap();

        upload.write_chunk(0, b"BAD!").unwrap();

        assert_eq!(upload.finish(), Err(FileError::ChecksumMismatch));
        assert!(!destination.exists(), "nothing must be left at the target");
        assert!(
            !partial_path(&destination).exists(),
            "the bad partial must be removed too"
        );
    }

    #[test]
    fn an_upload_that_ends_early_is_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("short.bin");

        let (mut upload, _) = Upload::begin(
            TransferId::generate(),
            destination.clone(),
            100,
            digest_of(&[0u8; 100]),
            NO_LIMIT,
            None,
        )
        .unwrap();

        upload.write_chunk(0, &[0u8; 10]).unwrap();
        assert_eq!(upload.finish(), Err(FileError::ChecksumMismatch));
        assert!(!destination.exists());
    }

    #[test]
    fn a_chunk_at_the_wrong_offset_is_refused() {
        // Accepting an arbitrary offset would let a peer write anywhere in the file and
        // leave holes no checksum could explain.
        let dir = tempfile::tempdir().unwrap();
        let (mut upload, _) = Upload::begin(
            TransferId::generate(),
            dir.path().join("f.bin"),
            100,
            digest_of(&[0u8; 100]),
            NO_LIMIT,
            None,
        )
        .unwrap();

        upload.write_chunk(0, &[1u8; 10]).unwrap();
        assert_eq!(
            upload.write_chunk(50, &[2u8; 10]),
            Err(FileError::OutOfOrderChunk)
        );
        assert_eq!(
            upload.write_chunk(5, &[3u8; 10]),
            Err(FileError::OutOfOrderChunk),
            "an overlapping rewrite is refused too"
        );
    }

    #[test]
    fn a_chunk_past_the_agreed_size_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (mut upload, _) = Upload::begin(
            TransferId::generate(),
            dir.path().join("f.bin"),
            10,
            digest_of(&[0u8; 10]),
            NO_LIMIT,
            None,
        )
        .unwrap();

        assert_eq!(
            upload.write_chunk(0, &[0u8; 50]),
            Err(FileError::TooLarge),
            "more data than the transfer agreed to carry"
        );
    }

    #[test]
    fn a_file_over_the_limit_is_refused_before_anything_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("huge.bin");

        assert_eq!(
            Upload::begin(
                TransferId::generate(),
                destination.clone(),
                1_000_000,
                digest_of(b""),
                1024,
                None,
            )
            .err(),
            Some(FileError::TooLarge)
        );
        assert!(!partial_path(&destination).exists());
    }

    // -- resume --------------------------------------------------------------

    #[test]
    fn an_interrupted_upload_resumes_from_its_partial_file() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("resumed.bin");
        let content: Vec<u8> = (0..1000u32).map(|index| (index % 97) as u8).collect();
        let id = TransferId::generate();

        // First attempt: half the file, then the connection drops.
        let (mut first, _) = Upload::begin(
            id,
            destination.clone(),
            content.len() as u64,
            digest_of(&content),
            NO_LIMIT,
            None,
        )
        .unwrap();
        first.write_chunk(0, &content[..400]).unwrap();
        first.cancel();

        assert!(
            partial_path(&destination).exists(),
            "a cancelled transfer keeps its work"
        );

        // Second attempt, proving the prefix matches.
        let prefix_digest = digest_of(&content[..400]);
        let (mut second, resume_from) = Upload::begin(
            id,
            destination.clone(),
            content.len() as u64,
            digest_of(&content),
            NO_LIMIT,
            Some((400, prefix_digest)),
        )
        .unwrap();

        assert_eq!(resume_from, 400, "the client is told where to continue");
        second.write_chunk(400, &content[400..]).unwrap();

        assert_eq!(
            second.finish().unwrap(),
            600,
            "only the bytes sent this time are counted"
        );
        assert_eq!(std::fs::read(&destination).unwrap(), content);
    }

    #[test]
    fn a_resume_whose_prefix_does_not_match_is_refused() {
        // Without this, two different files would be spliced together and nothing would
        // notice until the final digest — by which point the whole transfer is spent.
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("mismatch.bin");
        let id = TransferId::generate();

        let (mut first, _) = Upload::begin(
            id,
            destination.clone(),
            100,
            digest_of(&[0u8; 100]),
            NO_LIMIT,
            None,
        )
        .unwrap();
        first.write_chunk(0, &[1u8; 40]).unwrap();
        first.cancel();

        // A digest of something the partial does not contain.
        let wrong_prefix = digest_of(&[9u8; 40]);
        assert_eq!(
            Upload::begin(
                id,
                destination,
                100,
                digest_of(&[0u8; 100]),
                NO_LIMIT,
                Some((40, wrong_prefix)),
            )
            .err(),
            Some(FileError::ResumeMismatch)
        );
    }

    #[test]
    fn a_resume_past_the_end_of_the_partial_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("short-partial.bin");
        let id = TransferId::generate();

        let (mut first, _) = Upload::begin(
            id,
            destination.clone(),
            100,
            digest_of(&[0u8; 100]),
            NO_LIMIT,
            None,
        )
        .unwrap();
        first.write_chunk(0, &[1u8; 10]).unwrap();
        first.cancel();

        assert_eq!(
            Upload::begin(
                id,
                destination,
                100,
                digest_of(&[0u8; 100]),
                NO_LIMIT,
                Some((50, digest_of(&[1u8; 50]))),
            )
            .err(),
            Some(FileError::ResumeMismatch)
        );
    }

    #[test]
    fn starting_fresh_discards_any_previous_partial() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("fresh.bin");

        let (mut stale, _) = Upload::begin(
            TransferId::generate(),
            destination.clone(),
            100,
            digest_of(&[0u8; 100]),
            NO_LIMIT,
            None,
        )
        .unwrap();
        stale.write_chunk(0, &[7u8; 60]).unwrap();
        stale.cancel();

        // A new transfer with no resume point must not append to the old work.
        let content = b"fresh content";
        upload_all(dir.path(), content).unwrap();

        let (mut restart, resume) = Upload::begin(
            TransferId::generate(),
            destination.clone(),
            5,
            digest_of(b"clean"),
            NO_LIMIT,
            None,
        )
        .unwrap();
        assert_eq!(resume, 0);
        restart.write_chunk(0, b"clean").unwrap();
        restart.finish().unwrap();

        assert_eq!(std::fs::read(&destination).unwrap(), b"clean");
    }

    #[test]
    fn a_partial_file_is_named_so_it_is_obviously_incomplete() {
        // An operator who finds one should not discover it is truncated by opening it.
        let partial = partial_path(Path::new("/data/report.pdf"));
        assert!(partial.to_string_lossy().ends_with(PARTIAL_SUFFIX));
        assert!(partial.to_string_lossy().contains("report.pdf"));
    }

    #[test]
    fn an_upload_never_overwrites_the_destination_until_it_verifies() {
        // Writing in place would truncate a good file the moment a transfer started.
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("existing.bin");
        std::fs::write(&destination, b"the original contents").unwrap();

        let (mut upload, _) = Upload::begin(
            TransferId::generate(),
            destination.clone(),
            4,
            digest_of(b"good"),
            NO_LIMIT,
            None,
        )
        .unwrap();
        upload.write_chunk(0, b"BAD!").unwrap();

        // Mid-transfer, the original is untouched.
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            b"the original contents"
        );

        assert_eq!(upload.finish(), Err(FileError::ChecksumMismatch));
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            b"the original contents",
            "a failed transfer must leave the original intact"
        );
    }

    // -- registry ------------------------------------------------------------

    #[test]
    fn the_registry_caps_concurrent_uploads() {
        let dir = tempfile::tempdir().unwrap();
        let registry = TransferRegistry::new(2);

        for index in 0..2 {
            let (upload, _) = Upload::begin(
                TransferId::generate(),
                dir.path().join(format!("f{index}.bin")),
                10,
                digest_of(&[0u8; 10]),
                NO_LIMIT,
                None,
            )
            .unwrap();
            registry.insert(upload).unwrap();
        }

        let (extra, _) = Upload::begin(
            TransferId::generate(),
            dir.path().join("extra.bin"),
            10,
            digest_of(&[0u8; 10]),
            NO_LIMIT,
            None,
        )
        .unwrap();

        assert_eq!(registry.insert(extra), Err(FileError::TooManyTransfers));
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn a_chunk_for_an_unknown_transfer_is_refused() {
        let registry = TransferRegistry::new(4);
        assert_eq!(
            registry.write_chunk(TransferId::generate(), 0, b"x"),
            Err(FileError::UnknownTransfer)
        );
        assert_eq!(
            registry.finish(TransferId::generate()),
            Err(FileError::UnknownTransfer)
        );
    }

    #[test]
    fn a_transfer_completes_through_the_registry() {
        let dir = tempfile::tempdir().unwrap();
        let registry = TransferRegistry::new(4);
        let id = TransferId::generate();
        let destination = dir.path().join("via-registry.bin");

        let (upload, _) = Upload::begin(
            id,
            destination.clone(),
            5,
            digest_of(b"hello"),
            NO_LIMIT,
            None,
        )
        .unwrap();
        registry.insert(upload).unwrap();

        registry.write_chunk(id, 0, b"hello").unwrap();
        assert_eq!(registry.finish(id).unwrap(), 5);

        assert!(
            registry.is_empty(),
            "a finished transfer leaves the registry"
        );
        assert_eq!(std::fs::read(&destination).unwrap(), b"hello");
    }

    #[test]
    fn cancelling_everything_keeps_the_partial_files() {
        // A connection that drops is usually one the operator means to resume.
        let dir = tempfile::tempdir().unwrap();
        let registry = TransferRegistry::new(4);
        let destination = dir.path().join("keep-me.bin");

        let (mut upload, _) = Upload::begin(
            TransferId::generate(),
            destination.clone(),
            100,
            digest_of(&[0u8; 100]),
            NO_LIMIT,
            None,
        )
        .unwrap();
        upload.write_chunk(0, &[1u8; 30]).unwrap();
        registry.insert(upload).unwrap();

        registry.cancel_all();

        assert!(registry.is_empty());
        assert!(partial_path(&destination).exists());
    }

    #[test]
    fn an_upload_debug_line_does_not_carry_the_destination_path() {
        // It is rendered into logs, and the path came from a peer.
        let dir = tempfile::tempdir().unwrap();
        let (upload, _) = Upload::begin(
            TransferId::generate(),
            dir.path().join("secret-report.pdf"),
            10,
            digest_of(&[0u8; 10]),
            NO_LIMIT,
            None,
        )
        .unwrap();

        let rendered = format!("{upload:?}");
        assert!(!rendered.contains("secret-report"));
        assert!(rendered.contains("Upload"));
    }

    #[test]
    fn a_registry_cap_of_zero_is_treated_as_one() {
        assert_eq!(TransferRegistry::new(0).max_transfers, 1);
    }

    // -- downloads -----------------------------------------------------------

    #[test]
    fn a_download_reads_a_whole_file_in_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.bin");
        let content: Vec<u8> = (0..(CHUNK_BYTES * 2 + 17))
            .map(|index| u8::try_from(index % 251).unwrap_or(0))
            .collect();
        std::fs::write(&path, &content).unwrap();

        let (mut download, total, checksum) =
            Download::begin(TransferId::generate(), &path, 0, NO_LIMIT).unwrap();

        assert_eq!(total, content.len() as u64);
        assert_eq!(checksum, digest_of(&content));

        let mut received = Vec::new();
        while let Some((offset, chunk)) = download.next_chunk().unwrap() {
            assert_eq!(
                offset,
                received.len() as u64,
                "chunks must arrive in order at the offset they claim"
            );
            received.extend_from_slice(&chunk);
        }

        assert_eq!(received, content);
        assert!(download.is_complete());
        assert_eq!(download.bytes_sent(), content.len() as u64);
    }

    #[test]
    fn a_download_resumes_from_an_offset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.bin");
        std::fs::write(&path, b"0123456789").unwrap();

        let (mut download, total, _) =
            Download::begin(TransferId::generate(), &path, 4, NO_LIMIT).unwrap();

        assert_eq!(total, 10, "the total is the file's size, not what is left");

        let (offset, chunk) = download.next_chunk().unwrap().unwrap();
        assert_eq!(offset, 4);
        assert_eq!(chunk, b"456789");
        assert_eq!(
            download.bytes_sent(),
            6,
            "only the bytes sent this time are counted"
        );
    }

    #[test]
    fn a_download_of_an_empty_file_completes_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        std::fs::write(&path, b"").unwrap();

        let (mut download, total, _) =
            Download::begin(TransferId::generate(), &path, 0, NO_LIMIT).unwrap();

        assert_eq!(total, 0);
        assert!(download.is_complete());
        assert!(download.next_chunk().unwrap().is_none());
    }

    #[test]
    fn a_resume_point_past_the_end_of_the_file_is_refused() {
        // Continuing from it would send nothing and report success, leaving the peer
        // with a file it never received.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.bin");
        std::fs::write(&path, b"short").unwrap();

        assert_eq!(
            Download::begin(TransferId::generate(), &path, 999, NO_LIMIT).err(),
            Some(FileError::ResumeMismatch)
        );
    }

    #[test]
    fn downloading_a_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            Download::begin(TransferId::generate(), dir.path(), 0, NO_LIMIT).err(),
            Some(FileError::WrongKind)
        );
    }

    #[test]
    fn downloading_a_missing_file_reports_not_found() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            Download::begin(
                TransferId::generate(),
                &dir.path().join("nothing"),
                0,
                NO_LIMIT
            )
            .err(),
            Some(FileError::NotFound)
        );
    }

    #[test]
    fn a_file_over_the_limit_is_refused_before_it_is_hashed() {
        // Hashing a file the transfer will refuse anyway is work the operator did not
        // ask for, on a machine they are trying not to load.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.bin");
        std::fs::write(&path, vec![0u8; 4096]).unwrap();

        assert_eq!(
            Download::begin(TransferId::generate(), &path, 0, 1024).err(),
            Some(FileError::TooLarge)
        );
    }

    #[test]
    fn a_download_debug_line_does_not_carry_the_source_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret-report.pdf");
        std::fs::write(&path, b"x").unwrap();

        let (download, _, _) = Download::begin(TransferId::generate(), &path, 0, NO_LIMIT).unwrap();
        let rendered = format!("{download:?}");

        assert!(!rendered.contains("secret-report"));
        assert!(rendered.contains("Download"));
    }
}
