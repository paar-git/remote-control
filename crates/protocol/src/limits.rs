//! Hard limits applied to anything read off the wire.
//!
//! These bound memory use before any allocation is made, so a hostile or buggy peer
//! cannot force the process into an out-of-memory condition. Every limit here is a
//! ceiling: individual channels may negotiate something smaller, never larger.

/// Largest control-channel message body, in bytes.
pub const MAX_CONTROL_FRAME: usize = 256 * 1024;

/// Largest terminal-channel message body, in bytes.
pub const MAX_TERMINAL_FRAME: usize = 512 * 1024;

/// Largest file-transfer message body, in bytes. Chunks are sized well under this.
pub const MAX_FILE_FRAME: usize = 8 * 1024 * 1024;

/// Largest video message body, in bytes. A keyframe at high resolution can be large.
pub const MAX_VIDEO_FRAME: usize = 16 * 1024 * 1024;

/// Absolute ceiling for any frame on any channel.
pub const MAX_ANY_FRAME: usize = MAX_VIDEO_FRAME;

/// Preferred file-transfer chunk size, in bytes.
pub const FILE_CHUNK_SIZE: usize = 256 * 1024;

/// Maximum number of bytes in a single filesystem path.
pub const MAX_PATH_BYTES: usize = 4096;

/// Maximum number of entries returned by a single directory listing.
pub const MAX_DIR_ENTRIES: usize = 10_000;

/// Maximum length of a device's user-visible name, in bytes.
pub const MAX_DEVICE_NAME_BYTES: usize = 128;

/// Maximum number of concurrent terminal sessions per connection.
pub const MAX_TERMINAL_SESSIONS: usize = 8;

/// Maximum number of concurrently queued file transfers per connection.
pub const MAX_QUEUED_TRANSFERS: usize = 256;

/// Maximum accepted clock skew between peers, in seconds, for replay checks.
pub const MAX_CLOCK_SKEW_SECS: i64 = 60;

/// Number of recently seen nonces retained for replay detection.
pub const REPLAY_WINDOW_SIZE: usize = 4096;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_limits_are_within_absolute_ceiling() {
        for limit in [
            MAX_CONTROL_FRAME,
            MAX_TERMINAL_FRAME,
            MAX_FILE_FRAME,
            MAX_VIDEO_FRAME,
        ] {
            assert!(limit <= MAX_ANY_FRAME, "{limit} exceeds MAX_ANY_FRAME");
            assert!(limit > 0);
        }
    }

    #[test]
    fn file_chunk_fits_in_a_file_frame_with_header_room() {
        const { assert!(FILE_CHUNK_SIZE * 2 < MAX_FILE_FRAME) }
    }

    #[test]
    fn every_frame_length_fits_in_the_u32_header_field() {
        const { assert!(MAX_ANY_FRAME <= u32::MAX as usize) }
    }
}
