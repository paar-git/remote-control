//! Turning captured frames into wire frames.
//!
//! # Why a keyframe may be several frames
//!
//! A full refresh of a 4K screen is 31.6 MiB of raw RGBA against a 16 MiB channel
//! ceiling, and a noisy tiled keyframe can break it too. So a refresh is a *tile range*
//! rather than a whole screen: it is emitted as however many frames it takes, each
//! carrying a contiguous run of tiles and saying how many are still to come.

use rc_protocol::desktop::{Rect, VideoCodec, VideoFrame};
use rc_protocol::limits::MAX_VIDEO_FRAME;

use crate::capture::CapturedFrame;
use crate::diff::TileHashes;
use crate::tile::TileGrid;
use crate::{Result, VideoError};

/// Compression level. 1 is zstd's fastest; this stream values latency far above ratio,
/// and the tile differ has already removed the bulk of the redundancy.
const ZSTD_LEVEL: i32 = 1;

/// Bytes reserved in a frame for everything that is not the pixel payload.
///
/// The channel limit applies to the serialized `VideoFrame`, not to `data` alone: a
/// frame also carries its sequence, timestamp, flags and — the part that actually
/// scales — one `Rect` per changed tile. A `Rect` is four `u32`s, so at postcard's
/// worst-case varint width a full 4K refresh of 2040 tiles spends roughly 41 KB on
/// damage before a single pixel. Reserving 64 KiB covers that with margin, at a cost
/// of 0.4% of the ceiling.
const FRAME_OVERHEAD: usize = 64 * 1024;

/// Encodes captured frames for one display at one size.
#[derive(Debug)]
pub struct Encoder {
    codec: VideoCodec,
    grid: TileGrid,
    hashes: TileHashes,
    sequence: u64,
    budget: usize,
}

impl Encoder {
    /// An encoder for `width` by `height` frames, using the whole channel limit.
    ///
    /// # Errors
    /// If the codec is not one this build produces, or the size is zero.
    pub fn new(codec: VideoCodec, width: u32, height: u32) -> Result<Self> {
        Self::with_budget(codec, width, height, MAX_VIDEO_FRAME - FRAME_OVERHEAD)
    }

    /// As [`Self::new`], but with an explicit per-frame byte ceiling, for tests.
    ///
    /// # Errors
    /// If the codec is not one this build produces, or the size is zero.
    pub fn with_budget(codec: VideoCodec, width: u32, height: u32, budget: usize) -> Result<Self> {
        if !matches!(codec, VideoCodec::TiledZstd | VideoCodec::RawRgba) {
            return Err(VideoError::Unsupported(
                "this build encodes only tiled_zstd and raw_rgba",
            ));
        }
        if width == 0 || height == 0 {
            return Err(VideoError::Encode("a display with no area".to_owned()));
        }
        let grid = TileGrid::new(width, height);
        Ok(Self {
            codec,
            grid,
            hashes: TileHashes::new(grid.count()),
            sequence: 0,
            budget,
        })
    }

    /// The next sequence number this encoder will use.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Encode `frame`, returning zero frames if nothing changed.
    ///
    /// A refresh larger than the byte ceiling comes back as several frames.
    ///
    /// # Errors
    /// If the frame size does not match this encoder, or compression fails, or a
    /// single tile cannot be made to fit the ceiling.
    pub fn encode(
        &mut self,
        frame: &CapturedFrame,
        captured_at_us: u64,
        force_keyframe: bool,
    ) -> Result<Vec<VideoFrame>> {
        if frame.width != self.grid.width() || frame.height != self.grid.height() {
            return Err(VideoError::Encode(format!(
                "frame is {}x{} but this encoder was built for {}x{}",
                frame.width,
                frame.height,
                self.grid.width(),
                self.grid.height()
            )));
        }
        let expected = (frame.width as usize) * (frame.height as usize) * 4;
        if frame.rgba.len() != expected {
            return Err(VideoError::Encode(format!(
                "frame carries {} bytes, expected {expected}",
                frame.rgba.len()
            )));
        }

        if force_keyframe {
            self.hashes.forget();
        }
        let changed = self.hashes.changed(&self.grid, &frame.rgba);
        if changed.is_empty() {
            return Ok(Vec::new());
        }
        let keyframe = force_keyframe || changed.len() == self.grid.count() as usize;

        // Group the changed tiles into runs that each fit the ceiling.
        //
        // Slices are closed on *raw* size and compressed once, rather than compressing
        // after every tile. Compressing per tile is O(n^2): a 4K keyframe is 2040 tiles,
        // so it would compress a growing 30 MiB buffer 2040 times, costing seconds. The
        // raw threshold only decides where to cut; the coded size is still checked
        // against the budget below, so the guarantee does not rest on the estimate.
        let mut slices: Vec<(Vec<Rect>, Vec<u8>)> = Vec::new();
        let mut pending: Vec<u32> = Vec::new();
        let mut pending_raw = 0usize;

        for index in changed {
            let tile = self.grid.tile_bytes(index);
            if !pending.is_empty() && pending_raw + tile > self.raw_threshold() {
                self.flush(&frame.rgba, &pending, &mut slices)?;
                pending.clear();
                pending_raw = 0;
            }
            pending.push(index);
            pending_raw += tile;
        }
        if !pending.is_empty() {
            self.flush(&frame.rgba, &pending, &mut slices)?;
        }

        let total = slices.len();
        let mut out = Vec::with_capacity(total);
        for (position, (damage, data)) in slices.into_iter().enumerate() {
            let remaining = u16::try_from(total - 1 - position)
                .map_err(|_| VideoError::Encode("a refresh in more than 65535 parts".to_owned()))?;
            out.push(VideoFrame {
                sequence: self.sequence,
                captured_at_us,
                keyframe,
                data,
                damage,
                refresh_remaining: remaining,
            });
            self.sequence += 1;
        }
        Ok(out)
    }

    /// How many raw bytes to gather before closing a slice.
    ///
    /// For `RawRgba` the coded size is the raw size, so the budget is exact. For
    /// `TiledZstd` this is a deliberate under-estimate of the compression ratio:
    /// guessing low costs an extra slice, guessing high costs a retry, and screen
    /// content reliably beats 3:1.
    const fn raw_threshold(&self) -> usize {
        match self.codec {
            VideoCodec::RawRgba => self.budget,
            _ => self.budget.saturating_mul(3),
        }
    }

    /// Code `tiles` into one or more slices, splitting if the coded result overruns.
    ///
    /// The split is halving rather than per-tile backtracking: an overrun means the
    /// ratio estimate was wrong for this content, and halving converges in a few steps
    /// without another O(n^2) path.
    fn flush(
        &self,
        rgba: &[u8],
        tiles: &[u32],
        slices: &mut Vec<(Vec<Rect>, Vec<u8>)>,
    ) -> Result<()> {
        let mut raw = Vec::new();
        for &index in tiles {
            self.grid.copy_out(rgba, index, &mut raw);
        }
        let coded = self.code(&raw)?;
        if coded.len() <= self.budget {
            slices.push((tiles.iter().map(|&i| self.grid.rect(i)).collect(), coded));
            return Ok(());
        }
        if tiles.len() == 1 {
            return Err(VideoError::FrameTooLarge {
                bytes: coded.len(),
                limit: self.budget,
            });
        }
        let (left, right) = tiles.split_at(tiles.len() / 2);
        self.flush(rgba, left, slices)?;
        self.flush(rgba, right, slices)
    }

    /// Apply the codec to a concatenated tile payload.
    fn code(&self, raw: &[u8]) -> Result<Vec<u8>> {
        match self.codec {
            VideoCodec::RawRgba => Ok(raw.to_vec()),
            _ => zstd::bulk::compress(raw, ZSTD_LEVEL)
                .map_err(|err| VideoError::Encode(err.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::CapturedFrame;

    fn frame(width: u32, height: u32, fill: u8) -> CapturedFrame {
        CapturedFrame {
            width,
            height,
            rgba: vec![fill; (width as usize) * (height as usize) * 4],
        }
    }

    #[test]
    fn the_first_frame_is_a_keyframe_covering_the_screen() {
        let mut encoder = Encoder::new(VideoCodec::TiledZstd, 128, 128).expect("valid size");
        let out = encoder
            .encode(&frame(128, 128, 0), 1_000, false)
            .expect("encode");

        assert_eq!(out.len(), 1);
        assert!(out[0].keyframe, "nothing preceded it");
        assert_eq!(out[0].refresh_remaining, 0, "it fits in one frame");
        assert_eq!(out[0].damage.len(), 4, "a 2x2 grid of tiles");
    }

    #[test]
    fn a_still_screen_produces_no_frame_at_all() {
        // Not an empty frame — no frame. A still desktop must cost nothing.
        let mut encoder = Encoder::new(VideoCodec::TiledZstd, 128, 128).expect("valid size");
        let still = frame(128, 128, 0);
        encoder.encode(&still, 1_000, false).expect("first");
        let out = encoder.encode(&still, 2_000, false).expect("second");
        assert!(out.is_empty());
    }

    #[test]
    fn a_forced_keyframe_resends_everything() {
        let mut encoder = Encoder::new(VideoCodec::TiledZstd, 128, 128).expect("valid size");
        let still = frame(128, 128, 0);
        encoder.encode(&still, 1_000, false).expect("first");
        let out = encoder.encode(&still, 2_000, true).expect("forced");
        assert_eq!(out.len(), 1);
        assert!(out[0].keyframe);
        assert_eq!(out[0].damage.len(), 4);
    }

    #[test]
    fn a_keyframe_too_big_for_one_frame_is_split_and_counted_down() {
        // The 4K case: raw RGBA is 31.6 MiB against a 16 MiB channel limit. Every
        // slice must fit, and the last one must say the refresh is complete.
        //
        // 40 KiB is chosen against the tile size, not arbitrarily: one 64x64 RGBA tile
        // is exactly 16_384 bytes, so a budget below that would make a single tile
        // unsplittable and the encoder would correctly refuse rather than slice. 40_960
        // holds two tiles but not three, so a 16-tile frame yields eight slices.
        let budget = 40 * 1024;
        let mut encoder =
            Encoder::with_budget(VideoCodec::RawRgba, 256, 256, budget).expect("valid size");

        // Incompressible content, so RawRgba's size is the honest worst case.
        let mut noisy = frame(256, 256, 0);
        for (i, byte) in noisy.rgba.iter_mut().enumerate() {
            *byte = u8::try_from((i * 7919) % 256).expect("modulo keeps this in range");
        }

        let out = encoder.encode(&noisy, 1_000, true).expect("encode");

        assert!(out.len() > 1, "one frame could not have held it");
        for slice in &out {
            assert!(slice.keyframe, "every slice of a refresh stands alone");
            assert!(
                slice.data.len() <= budget,
                "each slice must fit the ceiling"
            );
        }
        for (i, slice) in out.iter().enumerate() {
            let expected = u16::try_from(out.len() - 1 - i).expect("few slices");
            assert_eq!(slice.refresh_remaining, expected);
        }
        assert_eq!(out.last().expect("non-empty").refresh_remaining, 0);
    }

    #[test]
    fn sequence_numbers_advance_without_gaps() {
        // The client detects loss by gaps, so the encoder must not create them.
        let mut encoder = Encoder::new(VideoCodec::TiledZstd, 128, 128).expect("valid size");
        let mut out = Vec::new();
        for tick in 0..3u8 {
            out.extend(
                encoder
                    .encode(&frame(128, 128, tick), u64::from(tick), false)
                    .expect("encode"),
            );
        }
        let sequences: Vec<u64> = out.iter().map(|f| f.sequence).collect();
        let expected: Vec<u64> = (0..sequences.len() as u64).collect();
        assert_eq!(sequences, expected);
    }

    fn noisy_frame(width: u32, height: u32) -> CapturedFrame {
        let mut frame = frame(width, height, 0);
        for (i, byte) in frame.rgba.iter_mut().enumerate() {
            *byte = u8::try_from((i * 7919) % 256).expect("modulo keeps this in range");
        }
        frame
    }

    #[test]
    fn an_emitted_frame_fits_the_channel_once_its_damage_is_counted() {
        // The ceiling applies to the serialized frame, not to the pixel payload alone.
        // Budgeting the whole limit for `data` leaves a frame that this encoder considers
        // legal and the transport rejects.
        //
        // 2048x2048 is chosen deliberately: raw RGBA is exactly 2048*2048*4 =
        // 16_777_216 bytes, exactly `MAX_VIDEO_FRAME`. With no headroom reserved this
        // sits right at the old budget, so the 1024 tiles' worth of damage rectangles
        // pushes the *serialized* frame over the ceiling even though `data` alone did
        // not. A smaller frame would leave slack that the fix's 64 KiB reservation
        // could hide behind; this size does not.
        let mut encoder = Encoder::new(VideoCodec::RawRgba, 2048, 2048).expect("valid size");
        let frames = encoder
            .encode(&noisy_frame(2048, 2048), 1_000, true)
            .expect("encode");
        for frame in &frames {
            let wire = postcard::to_allocvec(frame).expect("serialize");
            assert!(
                wire.len() <= MAX_VIDEO_FRAME,
                "a {} byte frame exceeds the {MAX_VIDEO_FRAME} byte channel limit",
                wire.len(),
            );
        }
    }
}
