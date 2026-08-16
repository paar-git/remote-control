//! Fixed-size tiles over a frame.
//!
//! The grid is the unit of change detection, of compression and of damage reporting.
//! Tiles on the right and bottom edges are clipped rather than padded, so every pixel
//! belongs to exactly one tile and a screen whose dimensions are not multiples of
//! [`TILE`] still updates completely.

use rc_protocol::desktop::Rect;

/// Tile edge length in pixels.
///
/// 64 balances two costs: smaller tiles detect change more precisely but spend more
/// bytes on damage rectangles, larger ones resend untouched pixels around a small edit.
pub const TILE: u32 = 64;

/// Bytes per pixel, RGBA.
const BPP: usize = 4;

/// A tiling of one frame size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TileGrid {
    width: u32,
    height: u32,
    cols: u32,
    rows: u32,
}

impl TileGrid {
    /// The grid covering a `width` by `height` frame.
    #[must_use]
    pub const fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            cols: width.div_ceil(TILE),
            rows: height.div_ceil(TILE),
        }
    }

    /// Frame width in pixels.
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// Frame height in pixels.
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// How many tiles cover the frame.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.cols * self.rows
    }

    /// The rectangle tile `index` occupies, clipped to the frame.
    #[must_use]
    pub const fn rect(&self, index: u32) -> Rect {
        let col = index % self.cols;
        let row = index / self.cols;
        let x = col * TILE;
        let y = row * TILE;
        Rect {
            x,
            y,
            width: if x + TILE > self.width {
                self.width - x
            } else {
                TILE
            },
            height: if y + TILE > self.height {
                self.height - y
            } else {
                TILE
            },
        }
    }

    /// How many bytes tile `index` holds.
    #[must_use]
    pub const fn tile_bytes(&self, index: u32) -> usize {
        let r = self.rect(index);
        (r.width as usize) * (r.height as usize) * BPP
    }

    /// Append tile `index` of `rgba` to `dst`, row by row.
    pub fn copy_out(&self, rgba: &[u8], index: u32, dst: &mut Vec<u8>) {
        let r = self.rect(index);
        let stride = (self.width as usize) * BPP;
        let run = (r.width as usize) * BPP;
        for row in 0..r.height {
            let start = ((r.y + row) as usize) * stride + (r.x as usize) * BPP;
            dst.extend_from_slice(&rgba[start..start + run]);
        }
    }

    /// Write `src` into tile `index` of `rgba`, row by row.
    pub fn copy_in(&self, rgba: &mut [u8], index: u32, src: &[u8]) {
        let r = self.rect(index);
        let stride = (self.width as usize) * BPP;
        let run = (r.width as usize) * BPP;
        for row in 0..r.height {
            let start = ((r.y + row) as usize) * stride + (r.x as usize) * BPP;
            let from = (row as usize) * run;
            rgba[start..start + run].copy_from_slice(&src[from..from + run]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_screen_that_does_not_divide_evenly_still_covers_every_pixel() {
        // 1920x1080 is the common case and 1080 is not a multiple of 64. If the last
        // row of tiles were dropped or sized wrong, the bottom 24 pixels of every
        // screen would never update.
        let grid = TileGrid::new(1920, 1080);
        assert_eq!(grid.count(), 30 * 17, "30 columns, 17 rows");

        let last = grid.rect(grid.count() - 1);
        assert_eq!(last.x, 29 * TILE);
        assert_eq!(last.y, 16 * TILE);
        assert_eq!(last.width, TILE);
        assert_eq!(last.height, 1080 - 16 * TILE, "the short final row");

        let covered: u32 = (0..grid.count())
            .map(|i| {
                let r = grid.rect(i);
                r.width * r.height
            })
            .sum();
        assert_eq!(
            covered,
            1920 * 1080,
            "every pixel belongs to exactly one tile"
        );
    }

    #[test]
    fn a_tile_copied_out_and_back_is_unchanged() {
        let grid = TileGrid::new(130, 70);
        let mut source = vec![0u8; 130 * 70 * 4];
        for (i, byte) in source.iter_mut().enumerate() {
            *byte = u8::try_from(i % 251).expect("modulo keeps this in range");
        }

        let mut destination = vec![0u8; source.len()];
        let mut scratch = Vec::new();
        for index in 0..grid.count() {
            scratch.clear();
            grid.copy_out(&source, index, &mut scratch);
            assert_eq!(scratch.len(), grid.tile_bytes(index));
            grid.copy_in(&mut destination, index, &scratch);
        }

        assert_eq!(destination, source, "tiling must be lossless");
    }
}
