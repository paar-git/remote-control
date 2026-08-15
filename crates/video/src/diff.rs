//! Which tiles changed since the last frame.
//!
//! Hashes rather than byte comparison: a hash per tile is 8 bytes of state against
//! a whole previous frame, and comparing 8 bytes beats comparing 16 KiB when, as is
//! typical for a desktop, almost nothing moved.

use std::hash::{Hash as _, Hasher as _};

use rustc_hash::FxHasher;

use crate::tile::TileGrid;

/// Per-tile fingerprints of the last frame sent.
#[derive(Debug, Clone)]
pub struct TileHashes {
    /// `None` means the client is not known to hold this tile.
    hashes: Vec<Option<u64>>,
    scratch: Vec<u8>,
}

impl TileHashes {
    /// Fingerprints for a grid of `count` tiles, holding nothing yet.
    #[must_use]
    pub fn new(count: u32) -> Self {
        Self {
            hashes: vec![None; count as usize],
            scratch: Vec::new(),
        }
    }

    /// The indices of tiles in `rgba` that differ from what was last recorded, in
    /// ascending order, recording the new state as it goes.
    pub fn changed(&mut self, grid: &TileGrid, rgba: &[u8]) -> Vec<u32> {
        if self.hashes.len() != grid.count() as usize {
            self.hashes = vec![None; grid.count() as usize];
        }
        let mut changed = Vec::new();
        for index in 0..grid.count() {
            self.scratch.clear();
            grid.copy_out(rgba, index, &mut self.scratch);
            let mut hasher = FxHasher::default();
            self.scratch.hash(&mut hasher);
            let hash = hasher.finish();
            let slot = &mut self.hashes[index as usize];
            if *slot != Some(hash) {
                *slot = Some(hash);
                changed.push(index);
            }
        }
        changed
    }

    /// Forget everything, so the next call reports every tile.
    pub fn forget(&mut self) {
        self.hashes.fill(None);
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use crate::tile::{TILE, TileGrid};

    fn blank(grid: &TileGrid) -> Vec<u8> {
        vec![0u8; (grid.width() as usize) * (grid.height() as usize) * 4]
    }

    #[test]
    fn the_first_frame_changes_every_tile() {
        // Nothing has been sent, so the client holds nothing; every tile is new.
        let grid = TileGrid::new(128, 128);
        let mut hashes = TileHashes::new(grid.count());
        let changed = hashes.changed(&grid, &blank(&grid));
        assert_eq!(changed.len() as u32, grid.count());
    }

    #[test]
    fn an_unchanged_frame_sends_nothing() {
        // A still screen must cost no bandwidth. This is the whole point of differing.
        let grid = TileGrid::new(128, 128);
        let mut hashes = TileHashes::new(grid.count());
        let frame = blank(&grid);
        hashes.changed(&grid, &frame);
        assert!(hashes.changed(&grid, &frame).is_empty());
    }

    #[test]
    fn one_edited_pixel_changes_exactly_one_tile() {
        // Over-reporting wastes the link; under-reporting leaves stale pixels on the
        // operator's screen, which is worse because it looks like the remote froze.
        let grid = TileGrid::new(128, 128);
        let mut hashes = TileHashes::new(grid.count());
        let mut frame = blank(&grid);
        hashes.changed(&grid, &frame);

        // A pixel inside tile index 3 — column 1, row 1 of a 2x2 grid.
        let x = TILE + 5;
        let y = TILE + 7;
        let at = ((y as usize) * 128 + (x as usize)) * 4;
        frame[at] = 255;

        assert_eq!(hashes.changed(&grid, &frame), vec![3]);
    }

    #[test]
    fn forgetting_makes_the_next_frame_a_full_refresh() {
        // What a keyframe request has to do: drop all knowledge of what the client
        // holds, so the next frame stands alone.
        let grid = TileGrid::new(128, 128);
        let mut hashes = TileHashes::new(grid.count());
        let frame = blank(&grid);
        hashes.changed(&grid, &frame);
        hashes.forget();
        assert_eq!(hashes.changed(&grid, &frame).len() as u32, grid.count());
    }
}
