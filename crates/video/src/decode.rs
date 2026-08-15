//! Rebuilding a screen from wire frames.
//!
//! The decoder owns the framebuffer. Tiles are differential — a frame carries only what
//! changed — so a lost frame leaves the picture permanently wrong until a full refresh.
//! That is why a sequence gap sets [`Decoder::needs_keyframe`] rather than being logged
//! and forgotten.

use rc_protocol::desktop::{Rect, VideoCodec, VideoFrame};

use crate::tile::TileGrid;
use crate::{Result, VideoError};

/// Bytes per pixel, RGBA.
const BPP: usize = 4;

/// Rebuilds frames for one display at one size.
#[derive(Debug)]
pub struct Decoder {
    codec: VideoCodec,
    grid: TileGrid,
    framebuffer: Vec<u8>,
    next_sequence: Option<u64>,
    needs_keyframe: bool,
    complete: bool,
}

impl Decoder {
    /// A decoder for `width` by `height` frames.
    ///
    /// # Errors
    /// If the codec is not one this build consumes, or the size is zero.
    pub fn new(codec: VideoCodec, width: u32, height: u32) -> Result<Self> {
        if !matches!(codec, VideoCodec::TiledZstd | VideoCodec::RawRgba) {
            return Err(VideoError::Unsupported(
                "this build decodes only tiled_zstd and raw_rgba",
            ));
        }
        if width == 0 || height == 0 {
            return Err(VideoError::Encode("a display with no area".to_owned()));
        }
        Ok(Self {
            codec,
            grid: TileGrid::new(width, height),
            framebuffer: vec![0; (width as usize) * (height as usize) * BPP],
            next_sequence: None,
            needs_keyframe: false,
            complete: false,
        })
    }

    /// The current picture, RGBA, `width * height * 4` bytes.
    #[must_use]
    pub fn framebuffer(&self) -> &[u8] {
        &self.framebuffer
    }

    /// Whether the last refresh finished, so the picture is whole.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Whether a frame was missed and only a full refresh can put it right.
    #[must_use]
    pub const fn needs_keyframe(&self) -> bool {
        self.needs_keyframe
    }

    /// Apply `frame`, returning the rectangles it changed.
    ///
    /// # Errors
    /// If decompression fails, or the frame's damage does not fit the payload or the
    /// framebuffer.
    pub fn apply(&mut self, frame: &VideoFrame) -> Result<Vec<Rect>> {
        if let Some(expected) = self.next_sequence
            && frame.sequence != expected
        {
            self.needs_keyframe = true;
        }
        self.next_sequence = Some(frame.sequence + 1);
        if frame.keyframe && frame.refresh_remaining == 0 {
            self.needs_keyframe = false;
        }

        let raw = if self.codec == VideoCodec::RawRgba {
            frame.data.clone()
        } else {
            let ceiling = self.framebuffer.len();
            zstd::bulk::decompress(&frame.data, ceiling)
                .map_err(|err| VideoError::Encode(err.to_string()))?
        };

        let mut offset = 0usize;
        for rect in &frame.damage {
            self.check(rect)?;
            let run = (rect.width as usize) * BPP;
            let need = run * (rect.height as usize);
            if offset + need > raw.len() {
                return Err(VideoError::Encode(
                    "damage claims more pixels than the payload carries".to_owned(),
                ));
            }
            let stride = (self.grid.width() as usize) * BPP;
            for row in 0..rect.height {
                let to = ((rect.y + row) as usize) * stride + (rect.x as usize) * BPP;
                let from = offset + (row as usize) * run;
                self.framebuffer[to..to + run].copy_from_slice(&raw[from..from + run]);
            }
            offset += need;
        }

        self.complete = frame.refresh_remaining == 0;
        Ok(frame.damage.clone())
    }

    /// Reject a rectangle that does not fit inside the frame.
    fn check(&self, rect: &Rect) -> Result<()> {
        let fits = rect
            .x
            .checked_add(rect.width)
            .is_some_and(|right| right <= self.grid.width())
            && rect
                .y
                .checked_add(rect.height)
                .is_some_and(|bottom| bottom <= self.grid.height());
        if fits {
            Ok(())
        } else {
            Err(VideoError::Encode(format!(
                "damage rect {}x{} at ({},{}) falls outside a {}x{} frame",
                rect.width,
                rect.height,
                rect.x,
                rect.y,
                self.grid.width(),
                self.grid.height()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::CapturedFrame;
    use crate::encode::Encoder;

    fn noisy(width: u32, height: u32, salt: usize) -> CapturedFrame {
        let mut rgba = vec![0u8; (width as usize) * (height as usize) * 4];
        for (i, byte) in rgba.iter_mut().enumerate() {
            *byte = u8::try_from((i.wrapping_mul(7919).wrapping_add(salt)) % 256)
                .expect("modulo keeps this in range");
        }
        CapturedFrame {
            width,
            height,
            rgba,
        }
    }

    /// The whole lossless claim, in one assertion.
    #[test]
    fn what_comes_out_is_byte_for_byte_what_went_in() {
        for codec in [VideoCodec::TiledZstd, VideoCodec::RawRgba] {
            let mut encoder = Encoder::new(codec, 200, 140).expect("valid size");
            let mut decoder = Decoder::new(codec, 200, 140).expect("valid size");

            for salt in [0usize, 13, 4242] {
                let source = noisy(200, 140, salt);
                for wire in encoder.encode(&source, 1_000, false).expect("encode") {
                    decoder.apply(&wire).expect("apply");
                }
                assert_eq!(
                    decoder.framebuffer(),
                    source.rgba.as_slice(),
                    "{codec:?} lost or altered a byte"
                );
            }
        }
    }

    #[test]
    fn a_split_refresh_is_only_complete_when_the_last_slice_lands() {
        // Presenting a half-applied refresh shows the operator a torn screen.
        // See Task 5 on why 40 KiB: it must exceed one 16_384-byte tile.
        let budget = 40 * 1024;
        let mut encoder =
            Encoder::with_budget(VideoCodec::RawRgba, 256, 256, budget).expect("valid size");
        let mut decoder = Decoder::new(VideoCodec::RawRgba, 256, 256).expect("valid size");

        let slices = encoder
            .encode(&noisy(256, 256, 1), 1_000, true)
            .expect("encode");
        assert!(slices.len() > 1, "this test needs a split refresh");

        for (i, slice) in slices.iter().enumerate() {
            decoder.apply(slice).expect("apply");
            let last = i + 1 == slices.len();
            assert_eq!(
                decoder.complete(),
                last,
                "slice {i} reported completeness wrongly"
            );
        }
    }

    #[test]
    fn a_gap_in_the_sequence_asks_for_a_keyframe() {
        // Tiles are differential: a dropped frame means the framebuffer is wrong and
        // will stay wrong until a full refresh, so silence is not an option.
        let mut encoder = Encoder::new(VideoCodec::TiledZstd, 128, 128).expect("valid size");
        let mut decoder = Decoder::new(VideoCodec::TiledZstd, 128, 128).expect("valid size");

        let mut screen = noisy(128, 128, 0);
        for wire in encoder.encode(&screen, 1_000, false).expect("encode") {
            decoder.apply(&wire).expect("apply");
        }
        assert!(!decoder.needs_keyframe());

        // Touch one pixel, so the next frame updates a single tile and is therefore a
        // differential update rather than a standalone keyframe. A keyframe would
        // legitimately repair the gap, leaving nothing for this test to detect.
        screen.rgba[0] ^= 0xFF;
        let mut later = encoder.encode(&screen, 2_000, false).expect("encode");
        let partial = later.remove(0);
        assert!(
            !partial.keyframe,
            "a one-tile change must not be a keyframe, or this test proves nothing"
        );

        let mut jumped = partial.clone();
        jumped.sequence = partial.sequence + 5;
        decoder.apply(&jumped).expect("apply");

        assert!(decoder.needs_keyframe(), "a gap must be noticed");
    }

    #[test]
    fn damage_outside_the_frame_is_refused_rather_than_written() {
        // A malformed or hostile peer must not be able to steer a write past the
        // framebuffer.
        let mut decoder = Decoder::new(VideoCodec::RawRgba, 128, 128).expect("valid size");
        let bogus = VideoFrame {
            sequence: 0,
            captured_at_us: 0,
            keyframe: true,
            data: vec![0; 64 * 64 * 4],
            damage: vec![Rect {
                x: 4_000,
                y: 4_000,
                width: 64,
                height: 64,
            }],
            refresh_remaining: 0,
        };
        assert!(decoder.apply(&bogus).is_err());
    }
}
