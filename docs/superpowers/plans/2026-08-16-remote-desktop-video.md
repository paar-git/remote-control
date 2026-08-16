# Remote Desktop Video Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stream a remote display to the client so an operator can see the machine they are controlling.

**Architecture:** A new `rc-video` crate captures RGBA frames through a `CaptureSource` trait, splits them into 64×64 tiles, sends only tiles whose hash changed, and compresses them with zstd. The agent serves this on `Channel::Video` from a `video_service` modelled on the existing `input_service`. The client decompresses in Rust, keeps a persistent framebuffer, and pushes changed tiles to the webview over Tauri's binary IPC channel, where a 2D canvas blits them with `putImageData`.

**Tech Stack:** Rust, `xcap` 0.9.8 (capture, behind a feature flag), `zstd` (compression), `rustc-hash` (tile hashing), Tauri 2.11.5 binary IPC, TypeScript + Canvas 2D.

**Spec:** `docs/superpowers/specs/2026-08-16-remote-desktop-video-design.md`

## Global Constraints

- Rust edition 2024. `rustfmt.toml` sets `max_width = 100`; rustfmt's `fn_call_width` default of 60 also applies.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` must pass. This repo denies warnings, including `unfulfilled_lint_expectations` — prefer `#[allow]` over `#[expect]` for any lint whose firing depends on `cfg`.
- `cargo fmt --all -- --check` must pass. Use `#[rustfmt::skip]` with a comment when a hand-built table's layout is deliberate.
- Pixels are **RGBA**, never BGRA, at every layer. No byte-order swizzle anywhere.
- Tile size is 64×64. `pub const TILE: u32 = 64;`
- `MAX_VIDEO_FRAME` is 16 MiB (`crates/protocol/src/limits.rs`). No encoded frame may exceed it.
- The real capture backend lives behind a `capture` feature, default **off**, mirroring `rc-input`'s `inject`. `cargo check -p rc-video` must succeed with no features.
- Never approximate an unsupported capability. Return a typed error naming the real cause, the way `rc-input` returns `NotPermitted` / `Blocked` / `Unavailable`.
- Every public item needs a doc comment; the workspace denies `missing_docs`.

---

### Task 1: Protocol — RGBA codec name and splittable keyframes

**Files:**
- Modify: `crates/protocol/src/desktop.rs:37-48` (`VideoCodec`), `crates/protocol/src/desktop.rs:163-176` (`VideoFrame`)
- Test: `crates/protocol/src/desktop.rs` (inline `mod tests`)

**Interfaces:**
- Consumes: nothing.
- Produces: `VideoCodec::RawRgba` (replaces `RawBgra`); `VideoFrame { sequence: u64, captured_at_us: u64, keyframe: bool, data: Vec<u8>, damage: Vec<Rect>, refresh_remaining: u16 }`.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `crates/protocol/src/desktop.rs`:

```rust
#[test]
fn a_split_refresh_says_how_much_is_still_coming() {
    // A full refresh too large for one frame arrives as several. The client has to
    // know when it holds a complete image, or it will present a half-drawn screen
    // and the operator will read it as a rendering bug.
    let last = VideoFrame {
        sequence: 7,
        captured_at_us: 1_000,
        keyframe: true,
        data: vec![1, 2, 3],
        damage: vec![Rect { x: 0, y: 0, width: 64, height: 64 }],
        refresh_remaining: 0,
    };
    assert_eq!(last.refresh_remaining, 0, "zero means the refresh is complete");

    let encoded = postcard::to_allocvec(&last).expect("encode");
    let decoded: VideoFrame = postcard::from_bytes(&encoded).expect("decode");
    assert_eq!(decoded, last);
}

#[test]
fn the_raw_codec_is_named_for_the_byte_order_it_actually_carries() {
    // Capture yields RGBA and putImageData consumes RGBA. A variant named for BGRA
    // would invite a swizzle that no layer in this pipeline needs.
    let codec = VideoCodec::RawRgba;
    let encoded = postcard::to_allocvec(&codec).expect("encode");
    let decoded: VideoCodec = postcard::from_bytes(&encoded).expect("decode");
    assert_eq!(decoded, VideoCodec::RawRgba);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rc-protocol desktop`
Expected: FAIL — `no variant named RawRgba found for enum VideoCodec`, and `struct VideoFrame has no field named refresh_remaining`.

- [ ] **Step 3: Write minimal implementation**

In `crates/protocol/src/desktop.rs`, rename the variant:

```rust
    /// Raw RGBA, only usable on a fast LAN. Always supported as the last-resort path.
    ///
    /// RGBA rather than BGRA because that is what both ends already speak: the capture
    /// backend produces it and the browser's `putImageData` consumes it. Naming the
    /// variant for a byte order neither side uses would invite a pointless swizzle of
    /// an 8 MiB buffer, twice per frame.
    RawRgba,
```

Add the field to `VideoFrame`, after `damage`:

```rust
    /// Frames still to come for this refresh, or zero when it is complete.
    ///
    /// A full-screen refresh can exceed [`crate::limits::MAX_VIDEO_FRAME`] — raw RGBA
    /// at 4K is 31.6 MiB against a 16 MiB ceiling — so it is emitted as several frames,
    /// each carrying a contiguous slice of tiles. The client applies each as it lands
    /// and knows the image is whole when this reaches zero.
    pub refresh_remaining: u16,
```

Add `postcard` to `[dev-dependencies]` in `crates/protocol/Cargo.toml` if it is not already there:

```toml
[dev-dependencies]
postcard = { workspace = true }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rc-protocol` then `cargo build --workspace`
Expected: PASS. The build confirms no other code referenced `RawBgra`; if it does, update those references.

- [ ] **Step 5: Commit**

```bash
git add crates/protocol/src/desktop.rs crates/protocol/Cargo.toml
git commit -m "feat(protocol): name the raw codec for RGBA and allow split refreshes"
```

---

### Task 2: The rc-video crate, its errors, and a mock capture source

**Files:**
- Create: `crates/video/Cargo.toml`, `crates/video/src/lib.rs`, `crates/video/src/capture.rs`, `crates/video/src/capture/mock.rs`
- Modify: `Cargo.toml` (workspace members and dependencies)

**Interfaces:**
- Consumes: `rc_protocol::desktop::DisplayInfo`.
- Produces:
  - `rc_video::VideoError` with variants `NoSuchDisplay(u8)`, `Unsupported(&'static str)`, `Capture(String)`, `Encode(String)`, `FrameTooLarge { bytes: usize, limit: usize }`
  - `rc_video::Result<T> = std::result::Result<T, VideoError>`
  - `rc_video::capture::CapturedFrame { width: u32, height: u32, rgba: Vec<u8> }`
  - `rc_video::capture::CaptureSource` trait with `displays(&self) -> Result<Vec<DisplayInfo>>` and `grab(&mut self, index: u8) -> Result<CapturedFrame>`
  - `rc_video::capture::mock::MockSource` with `new(width: u32, height: u32) -> Self`, `push(&mut self, frame: CapturedFrame)`, `set_solid(&mut self, rgba: [u8; 4])`, `fail_next(&mut self, err: VideoError)`

- [ ] **Step 1: Write the failing test**

Create `crates/video/src/capture/mock.rs` containing only its test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mock_hands_back_the_frames_it_was_given() {
        let mut source = MockSource::new(4, 2);
        source.set_solid([10, 20, 30, 255]);

        let frame = source.grab(0).expect("the mock always has display 0");

        assert_eq!(frame.width, 4);
        assert_eq!(frame.height, 2);
        assert_eq!(frame.rgba.len(), 4 * 2 * 4, "four bytes per pixel");
        assert_eq!(&frame.rgba[0..4], &[10, 20, 30, 255]);
    }

    #[test]
    fn asking_for_a_display_that_is_not_there_names_the_index() {
        // An operator whose second monitor was unplugged mid-session needs the error
        // to say which display vanished, not just that something failed.
        let mut source = MockSource::new(4, 2);
        let err = source.grab(7).expect_err("display 7 does not exist");
        assert!(matches!(err, VideoError::NoSuchDisplay(7)));
    }

    #[test]
    fn a_capture_failure_is_reported_rather_than_papered_over() {
        let mut source = MockSource::new(4, 2);
        source.fail_next(VideoError::Unsupported("wayland has no capture path"));
        let err = source.grab(0).expect_err("the injected failure must surface");
        assert!(matches!(err, VideoError::Unsupported(_)));
        // The failure is consumed, not sticky.
        assert!(source.grab(0).is_ok());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rc-video`
Expected: FAIL — the package does not exist yet.

- [ ] **Step 3: Write minimal implementation**

`crates/video/Cargo.toml`:

```toml
[package]
name = "rc-video"
description = "Screen capture, tile-differencing encode and decode for the remote desktop stream."
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
authors.workspace = true
repository.workspace = true

[features]
# The real capture backend is off by default so the encoder — and every test that
# covers it — builds on a machine with no desktop at all, including CI containers.
# Enabling it pulls in the only dependency that talks to a display server.
default = []
capture = ["dep:xcap"]

[dependencies]
rc-protocol = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }
zstd = { workspace = true }
rustc-hash = { workspace = true }
xcap = { version = "0.9.8", optional = true }

[dev-dependencies]
postcard = { workspace = true }

[lints]
workspace = true
```

In the root `Cargo.toml`, add `"crates/video"` to `[workspace] members`, and under `[workspace.dependencies]`:

```toml
rc-video = { path = "crates/video" }
zstd = "0.13"
rustc-hash = "2.1"
```

`crates/video/src/lib.rs`:

```rust
//! Remote desktop video: capture, encode, decode.
//!
//! # Why tiles rather than a video codec
//!
//! This stream carries terminals, config files and log output. Compression artifacts
//! on 9pt text are the failure that matters, not bandwidth, so the default path is
//! lossless: the frame is split into fixed tiles, only tiles whose contents changed are
//! sent, and those are compressed with zstd.
//!
//! Tiling also means the operating system is never asked for dirty regions. Damage is
//! computed here, identically on all three platforms, from data this crate already has.

#![forbid(unsafe_code)]

pub mod capture;

/// Anything that can go wrong capturing or coding a frame.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VideoError {
    /// No display carries this index.
    #[error("no display with index {0}")]
    NoSuchDisplay(u8),
    /// This platform or session cannot capture at all, and here is why.
    #[error("capture is not available here: {0}")]
    Unsupported(&'static str),
    /// The capture backend refused or failed.
    #[error("capture failed: {0}")]
    Capture(String),
    /// The frame could not be coded.
    #[error("encode failed: {0}")]
    Encode(String),
    /// A single frame exceeded what the transport will carry.
    #[error("frame of {bytes} bytes exceeds the {limit} byte channel limit")]
    FrameTooLarge {
        /// Size of the offending frame.
        bytes: usize,
        /// The ceiling it broke.
        limit: usize,
    },
}

/// Result carrying a [`VideoError`].
pub type Result<T> = std::result::Result<T, VideoError>;
```

`crates/video/src/capture.rs`:

```rust
//! Turning a display into frames.
//!
//! [`mock`] is always available and is what the test suite runs against, which is what
//! lets the encoder be tested on a machine with no display server. The real backend is
//! behind the `capture` feature for the same reason.

use rc_protocol::desktop::DisplayInfo;

use crate::Result;

pub mod mock;

// NOTE: `pub mod xcap_source;` is deliberately NOT declared here. Task 7 creates that
// file and adds its declaration in the same commit. Declaring it now would break
// `cargo clippy --all-features` — which CI runs — for every commit until Task 7 lands.

/// One captured frame, in RGBA order.
///
/// RGBA rather than BGRA throughout: the capture backend produces it and the browser's
/// `putImageData` consumes it, so no layer in this pipeline swizzles bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedFrame {
    /// Width in physical pixels.
    pub width: u32,
    /// Height in physical pixels.
    pub height: u32,
    /// `width * height * 4` bytes, row-major, RGBA.
    pub rgba: Vec<u8>,
}

/// A source of frames.
pub trait CaptureSource {
    /// Every display this source can capture.
    ///
    /// # Errors
    /// If the platform cannot enumerate displays.
    fn displays(&self) -> Result<Vec<DisplayInfo>>;

    /// Capture the display at `index`.
    ///
    /// # Errors
    /// If the index is unknown, or the platform refuses or fails the capture.
    fn grab(&mut self, index: u8) -> Result<CapturedFrame>;
}
```

`crates/video/src/capture/mock.rs`, above the test module written in Step 1:

```rust
//! A capture source with no operating system behind it.

use rc_protocol::desktop::DisplayInfo;

use super::{CaptureSource, CapturedFrame};
use crate::{Result, VideoError};

/// A scripted capture source for tests.
#[derive(Debug)]
pub struct MockSource {
    width: u32,
    height: u32,
    solid: [u8; 4],
    queued: Vec<CapturedFrame>,
    fail_next: Option<VideoError>,
}

impl MockSource {
    /// A source presenting one display of `width` by `height`, initially black.
    #[must_use]
    pub const fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            solid: [0, 0, 0, 255],
            queued: Vec::new(),
            fail_next: None,
        }
    }

    /// Make every subsequent generated frame this colour.
    pub const fn set_solid(&mut self, rgba: [u8; 4]) {
        self.solid = rgba;
    }

    /// Hand back `frame` before any generated one.
    pub fn push(&mut self, frame: CapturedFrame) {
        self.queued.push(frame);
    }

    /// Fail the next `grab` with `err`, once.
    pub fn fail_next(&mut self, err: VideoError) {
        self.fail_next = Some(err);
    }
}

impl CaptureSource for MockSource {
    fn displays(&self) -> Result<Vec<DisplayInfo>> {
        Ok(vec![DisplayInfo {
            index: 0,
            name: "mock".to_owned(),
            width: self.width,
            height: self.height,
            scale_factor: 1.0,
            origin_x: 0,
            origin_y: 0,
            primary: true,
            refresh_hz: Some(60),
        }])
    }

    fn grab(&mut self, index: u8) -> Result<CapturedFrame> {
        if index != 0 {
            return Err(VideoError::NoSuchDisplay(index));
        }
        if let Some(err) = self.fail_next.take() {
            return Err(err);
        }
        if !self.queued.is_empty() {
            return Ok(self.queued.remove(0));
        }
        let pixels = (self.width as usize) * (self.height as usize);
        let mut rgba = Vec::with_capacity(pixels * 4);
        for _ in 0..pixels {
            rgba.extend_from_slice(&self.solid);
        }
        Ok(CapturedFrame {
            width: self.width,
            height: self.height,
            rgba,
        })
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rc-video` then `cargo check -p rc-video`
Expected: PASS, and the featureless check confirms the crate builds with no capture backend.

- [ ] **Step 5: Commit**

```bash
git add crates/video Cargo.toml Cargo.lock
git commit -m "feat(video): rc-video crate with a capture trait and a mock source"
```

---

### Task 3: Tile geometry

**Files:**
- Create: `crates/video/src/tile.rs`
- Modify: `crates/video/src/lib.rs` (add `pub mod tile;`)

**Interfaces:**
- Consumes: `rc_protocol::desktop::Rect`.
- Produces: `rc_video::tile::TILE: u32`; `rc_video::tile::TileGrid` with `new(width: u32, height: u32) -> Self`, `width(&self) -> u32`, `height(&self) -> u32`, `count(&self) -> u32`, `rect(&self, index: u32) -> Rect`, `copy_out(&self, rgba: &[u8], index: u32, dst: &mut Vec<u8>)`, `copy_in(&self, rgba: &mut [u8], index: u32, src: &[u8])`, `tile_bytes(&self, index: u32) -> usize`. All are `const fn` except `copy_out` and `copy_in`.

- [ ] **Step 1: Write the failing test**

Create `crates/video/src/tile.rs` with this test module:

```rust
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
        assert_eq!(covered, 1920 * 1080, "every pixel belongs to exactly one tile");
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rc-video tile`
Expected: FAIL — `cannot find type TileGrid`.

- [ ] **Step 3: Write minimal implementation**

Above the test module in `crates/video/src/tile.rs`:

```rust
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
            width: if x + TILE > self.width { self.width - x } else { TILE },
            height: if y + TILE > self.height { self.height - y } else { TILE },
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
```

Add to `crates/video/src/lib.rs`:

```rust
pub mod tile;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rc-video tile`
Expected: PASS, both tests.

- [ ] **Step 5: Commit**

```bash
git add crates/video/src/tile.rs crates/video/src/lib.rs
git commit -m "feat(video): tile geometry that covers partial edge tiles exactly"
```

---

### Task 4: Tile differencing

**Files:**
- Create: `crates/video/src/diff.rs`
- Modify: `crates/video/src/lib.rs` (add `pub mod diff;`)

**Interfaces:**
- Consumes: `rc_video::tile::TileGrid`.
- Produces: `rc_video::diff::TileHashes` with `new(count: u32) -> Self`, `changed(&mut self, grid: &TileGrid, rgba: &[u8]) -> Vec<u32>`, `forget(&mut self)`.

- [ ] **Step 1: Write the failing test**

Create `crates/video/src/diff.rs` with:

```rust
#[cfg(test)]
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rc-video diff`
Expected: FAIL — `cannot find type TileHashes`.

- [ ] **Step 3: Write minimal implementation**

Above the test module:

```rust
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
```

Add to `crates/video/src/lib.rs`:

```rust
pub mod diff;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rc-video diff`
Expected: PASS, all four tests.

- [ ] **Step 5: Commit**

```bash
git add crates/video/src/diff.rs crates/video/src/lib.rs
git commit -m "feat(video): per-tile hashing to find what changed"
```

---

### Task 5: Encoder, with keyframes split under the frame ceiling

**Files:**
- Create: `crates/video/src/encode.rs`
- Modify: `crates/video/src/lib.rs` (add `pub mod encode;`)

**Interfaces:**
- Consumes: `TileGrid`, `TileHashes`, `CapturedFrame`, `VideoCodec`, `VideoFrame`, `Rect`.
- Produces: `rc_video::encode::Encoder` with `new(codec: VideoCodec, width: u32, height: u32) -> Result<Self>`, `with_budget(codec: VideoCodec, width: u32, height: u32, budget: usize) -> Result<Self>`, `encode(&mut self, frame: &CapturedFrame, captured_at_us: u64, force_keyframe: bool) -> Result<Vec<VideoFrame>>`, `sequence(&self) -> u64`.

- [ ] **Step 1: Write the failing test**

Create `crates/video/src/encode.rs` with:

```rust
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
        let out = encoder.encode(&frame(128, 128, 0), 1_000, false).expect("encode");

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
        let mut encoder = Encoder::with_budget(VideoCodec::RawRgba, 256, 256, budget)
            .expect("valid size");

        // Incompressible content, so RawRgba's size is the honest worst case.
        let mut noisy = frame(256, 256, 0);
        for (i, byte) in noisy.rgba.iter_mut().enumerate() {
            *byte = u8::try_from((i * 7919) % 256).expect("modulo keeps this in range");
        }

        let out = encoder.encode(&noisy, 1_000, true).expect("encode");

        assert!(out.len() > 1, "one frame could not have held it");
        for slice in &out {
            assert!(slice.keyframe, "every slice of a refresh stands alone");
            assert!(slice.data.len() <= budget, "each slice must fit the ceiling");
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
            out.extend(encoder.encode(&frame(128, 128, tick), u64::from(tick), false).expect("encode"));
        }
        let sequences: Vec<u64> = out.iter().map(|f| f.sequence).collect();
        let expected: Vec<u64> = (0..sequences.len() as u64).collect();
        assert_eq!(sequences, expected);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rc-video encode`
Expected: FAIL — `cannot find type Encoder`.

- [ ] **Step 3: Write minimal implementation**

Above the test module:

```rust
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
        Self::with_budget(codec, width, height, MAX_VIDEO_FRAME)
    }

    /// As [`Self::new`], but with an explicit per-frame byte ceiling, for tests.
    ///
    /// # Errors
    /// If the codec is not one this build produces, or the size is zero.
    pub fn with_budget(
        codec: VideoCodec,
        width: u32,
        height: u32,
        budget: usize,
    ) -> Result<Self> {
        if !matches!(codec, VideoCodec::TiledZstd | VideoCodec::RawRgba) {
            return Err(VideoError::Unsupported("this build encodes only tiled_zstd and raw_rgba"));
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
        let keyframe = force_keyframe || changed.len() as u32 == self.grid.count();

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
```

Add to `crates/video/src/lib.rs`:

```rust
pub mod encode;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rc-video encode`
Expected: PASS, all five tests.

- [ ] **Step 5: Commit**

```bash
git add crates/video/src/encode.rs crates/video/src/lib.rs
git commit -m "feat(video): encoder that splits oversized refreshes across frames"
```

---

### Task 6: Decoder, and the lossless round-trip property

**Files:**
- Create: `crates/video/src/decode.rs`
- Modify: `crates/video/src/lib.rs` (add `pub mod decode;`)

**Interfaces:**
- Consumes: `TileGrid`, `VideoFrame`, `VideoCodec`, `Encoder`.
- Produces: `rc_video::decode::Decoder` with `new(codec: VideoCodec, width: u32, height: u32) -> Result<Self>`, `apply(&mut self, frame: &VideoFrame) -> Result<Vec<Rect>>`, `framebuffer(&self) -> &[u8]`, `complete(&self) -> bool`, `needs_keyframe(&self) -> bool`.

- [ ] **Step 1: Write the failing test**

Create `crates/video/src/decode.rs` with:

```rust
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
        CapturedFrame { width, height, rgba }
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

        let slices = encoder.encode(&noisy(256, 256, 1), 1_000, true).expect("encode");
        assert!(slices.len() > 1, "this test needs a split refresh");

        for (i, slice) in slices.iter().enumerate() {
            decoder.apply(slice).expect("apply");
            let last = i + 1 == slices.len();
            assert_eq!(decoder.complete(), last, "slice {i} reported completeness wrongly");
        }
    }

    #[test]
    fn a_gap_in_the_sequence_asks_for_a_keyframe() {
        // Tiles are differential: a dropped frame means the framebuffer is wrong and
        // will stay wrong until a full refresh, so silence is not an option.
        let mut encoder = Encoder::new(VideoCodec::TiledZstd, 128, 128).expect("valid size");
        let mut decoder = Decoder::new(VideoCodec::TiledZstd, 128, 128).expect("valid size");

        let first = encoder.encode(&noisy(128, 128, 0), 1_000, false).expect("encode");
        for wire in &first {
            decoder.apply(wire).expect("apply");
        }
        assert!(!decoder.needs_keyframe());

        let mut later = encoder.encode(&noisy(128, 128, 9), 2_000, false).expect("encode");
        let dropped = later.remove(0);
        let mut jumped = dropped.clone();
        jumped.sequence = dropped.sequence + 5;
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
            damage: vec![Rect { x: 4_000, y: 4_000, width: 64, height: 64 }],
            refresh_remaining: 0,
        };
        assert!(decoder.apply(&bogus).is_err());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rc-video decode`
Expected: FAIL — `cannot find type Decoder`.

- [ ] **Step 3: Write minimal implementation**

Above the test module:

```rust
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
            return Err(VideoError::Unsupported("this build decodes only tiled_zstd and raw_rgba"));
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

        let raw = match self.codec {
            VideoCodec::RawRgba => frame.data.clone(),
            _ => {
                let ceiling = self.framebuffer.len();
                zstd::bulk::decompress(&frame.data, ceiling)
                    .map_err(|err| VideoError::Encode(err.to_string()))?
            }
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
```

Add to `crates/video/src/lib.rs`:

```rust
pub mod decode;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rc-video` then `cargo clippy -p rc-video --all-targets -- -D warnings`
Expected: PASS, all tests including the round-trip property. Clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/video/src/decode.rs crates/video/src/lib.rs
git commit -m "feat(video): decoder with a byte-for-byte round-trip property test"
```

---

### Task 7: The real capture backend

**Files:**
- Create: `crates/video/src/capture/xcap_source.rs`, `crates/video/tests/live_capture.rs`
- Modify: `.github/workflows/ci.yml` (add a `--features capture` test step)

**Interfaces:**
- Consumes: `CaptureSource`, `CapturedFrame`, `DisplayInfo`, `VideoError`.
- Produces: `rc_video::capture::xcap_source::XcapSource` with `new() -> Result<Self>` and its `CaptureSource` impl.

**Note on ordering:** displays are sorted left-to-right then top-to-bottom and given a
stable index, matching `rc_input`'s display ordering exactly, so that unplugging a
monitor cannot silently renumber the others and move the session to a different screen.

- [ ] **Step 1: Write the failing test**

Create `crates/video/tests/live_capture.rs`:

```rust
//! Capture against the real display server.
//!
//! Ignored by default: these need a desktop, and a headless CI container has none.
//! Run by hand with `cargo test -p rc-video --features capture -- --ignored --nocapture`.

#![cfg(feature = "capture")]

use rc_video::capture::{CaptureSource as _, xcap_source::XcapSource};

#[test]
#[ignore = "needs a real display server"]
fn displays_are_enumerated_and_ordered_left_to_right() {
    let source = XcapSource::new().expect("a desktop session");
    let displays = source.displays().expect("enumerate");
    assert!(!displays.is_empty(), "a desktop has at least one display");

    for (position, display) in displays.iter().enumerate() {
        assert_eq!(
            usize::from(display.index),
            position,
            "indices must be dense and in order"
        );
        assert!(display.width > 0 && display.height > 0);
        println!(
            "display {} {:?} {}x{} at ({},{}) primary={} {:?}Hz",
            display.index,
            display.name,
            display.width,
            display.height,
            display.origin_x,
            display.origin_y,
            display.primary,
            display.refresh_hz
        );
    }

    let mut sorted = displays.clone();
    sorted.sort_by_key(|d| (d.origin_x, d.origin_y));
    let order: Vec<u8> = sorted.iter().map(|d| d.index).collect();
    let expected: Vec<u8> = (0..u8::try_from(displays.len()).expect("few displays")).collect();
    assert_eq!(order, expected, "index order must follow position");
}

#[test]
#[ignore = "needs a real display server"]
fn a_captured_frame_is_the_size_the_display_advertised() {
    let mut source = XcapSource::new().expect("a desktop session");
    let displays = source.displays().expect("enumerate");
    let first = &displays[0];

    let frame = source.grab(first.index).expect("capture");

    assert_eq!(frame.width, first.width);
    assert_eq!(frame.height, first.height);
    assert_eq!(
        frame.rgba.len(),
        (frame.width as usize) * (frame.height as usize) * 4,
        "four bytes per pixel, no padding"
    );
    assert!(
        frame.rgba.iter().any(|&b| b != 0),
        "a real desktop is not uniformly black"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rc-video --features capture -- --ignored`
Expected: FAIL to compile — `could not find xcap_source in capture`.

- [ ] **Step 3: Write minimal implementation**

First add the module declaration that Task 2 deliberately left out. In
`crates/video/src/capture.rs`, replacing the NOTE comment Task 2 put there:

```rust
#[cfg(feature = "capture")]
pub mod xcap_source;
```

Then create `crates/video/src/capture/xcap_source.rs`:

```rust
//! Capture through `xcap`.
//!
//! # What this backend will and will not claim
//!
//! xcap supports Windows, macOS and X11, and has no Wayland path. A Wayland session
//! therefore gets a refusal naming Wayland rather than a stream of black frames, which
//! is the same choice the input backend makes there.
//!
//! Every xcap accessor returns a `Result`, including the ones that read like plain
//! properties, so a monitor that fails to describe itself is skipped rather than
//! reported with invented dimensions.

use rc_protocol::desktop::DisplayInfo;

use super::{CaptureSource, CapturedFrame};
use crate::{Result, VideoError};

/// Capture backed by the host's display server.
#[derive(Debug)]
pub struct XcapSource {
    _private: (),
}

impl XcapSource {
    /// Open the display server.
    ///
    /// # Errors
    /// If no display server is reachable, or the session is Wayland, which xcap cannot
    /// capture.
    pub fn new() -> Result<Self> {
        if is_wayland() {
            return Err(VideoError::Unsupported(
                "Wayland has no screen capture path in this build",
            ));
        }
        // Prove a display server answers now, rather than at the first frame.
        xcap::Monitor::all().map_err(|err| VideoError::Capture(err.to_string()))?;
        Ok(Self { _private: () })
    }

    /// Monitors, ordered left-to-right then top-to-bottom.
    ///
    /// The ordering is what makes the index stable: unplugging one monitor must not
    /// renumber the others and silently move the session to a different screen.
    fn ordered() -> Result<Vec<xcap::Monitor>> {
        let mut monitors =
            xcap::Monitor::all().map_err(|err| VideoError::Capture(err.to_string()))?;
        monitors.retain(|m| m.x().is_ok() && m.y().is_ok() && m.width().is_ok());
        monitors.sort_by_key(|m| (m.x().unwrap_or(0), m.y().unwrap_or(0)));
        Ok(monitors)
    }
}

impl CaptureSource for XcapSource {
    fn displays(&self) -> Result<Vec<DisplayInfo>> {
        let monitors = Self::ordered()?;
        let mut out = Vec::with_capacity(monitors.len());
        for (position, monitor) in monitors.iter().enumerate() {
            let Ok(index) = u8::try_from(position) else {
                break; // more than 255 displays; the protocol indexes with a u8
            };
            let (Ok(width), Ok(height)) = (monitor.width(), monitor.height()) else {
                continue;
            };
            out.push(DisplayInfo {
                index,
                name: monitor.name().unwrap_or_else(|_| format!("display {index}")),
                width,
                height,
                scale_factor: monitor.scale_factor().unwrap_or(1.0),
                origin_x: monitor.x().unwrap_or(0),
                origin_y: monitor.y().unwrap_or(0),
                primary: monitor.is_primary().unwrap_or(false),
                refresh_hz: monitor.frequency().ok().and_then(round_hz),
            });
        }
        Ok(out)
    }

    fn grab(&mut self, index: u8) -> Result<CapturedFrame> {
        let monitors = Self::ordered()?;
        let monitor = monitors
            .get(usize::from(index))
            .ok_or(VideoError::NoSuchDisplay(index))?;
        let image = monitor
            .capture_image()
            .map_err(|err| VideoError::Capture(err.to_string()))?;
        let width = image.width();
        let height = image.height();
        Ok(CapturedFrame {
            width,
            height,
            rgba: image.into_raw(),
        })
    }
}

/// Round a reported refresh rate, rejecting values that are not a sane frequency.
///
/// `frequency()` is an `f32` while `DisplayInfo::refresh_hz` is `Option<u32>`. A
/// nonsense reading becomes `None` rather than a nonsense integer: a display claiming
/// 0 Hz or NaN is a display that did not answer, and saying so is more use than
/// printing a number nobody should trust.
fn round_hz(hz: f32) -> Option<u32> {
    if !hz.is_finite() || hz <= 0.0 || hz > f32::from(u16::MAX) {
        return None;
    }
    // Bounded above by u16::MAX and below by zero, so this conversion cannot truncate
    // or wrap. Written as a checked conversion rather than `as` because the workspace
    // denies clippy's cast lints.
    u32::try_from(hz.round() as i64).ok()
}

/// Whether this looks like a Wayland session.
fn is_wayland() -> bool {
    cfg!(target_os = "linux")
        && std::env::var("XDG_SESSION_TYPE").is_ok_and(|kind| kind.eq_ignore_ascii_case("wayland"))
}
```

Add the CI step in `.github/workflows/ci.yml`, after the existing "Input builds without an injection backend" step:

```yaml
      # The capture backend needs a display server, so only its compile is checked
      # here; the tests that touch a real screen are #[ignore]d and run by hand.
      - name: Video capture backend compiles
        run: cargo clippy -p rc-video --features capture --all-targets -- -D warnings
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rc-video --features capture -- --ignored --nocapture`
Expected: PASS. Output should list your two 1920×1080 monitors with the secondary at origin `(-1920, 0)`, matching the probe recorded in the spec.

- [ ] **Step 5: Commit**

```bash
git add crates/video/src/capture/xcap_source.rs crates/video/tests/live_capture.rs .github/workflows/ci.yml
git commit -m "feat(video): xcap capture backend that refuses Wayland honestly"
```

---

### Task 8: The agent's video service

**Files:**
- Create: `crates/host-agent/src/video_service.rs`
- Modify: `crates/host-agent/src/lib.rs` (add `pub mod video_service;`), `crates/host-agent/Cargo.toml` (add `rc-video`, and `capture` to the `inject` feature list)

**Interfaces:**
- Consumes: `rc_video::{capture::CaptureSource, encode::Encoder}`, `rc_protocol::desktop::{DesktopClientMessage, DesktopAgentMessage, QualityPreset, InteractionMode}`, `rc_transport::{ChannelReader, ChannelWriter}`, `crate::session::Session`.
- Produces: `VideoService::new(writer: ChannelWriter, session: Session, source: S, enabled: bool) -> Self` and `async fn run(self, reader: &mut ChannelReader)`.

**Read first:** `crates/host-agent/src/input_service.rs` in full. This service mirrors its
structure, its permission re-checking per message, and its teardown discipline.

- [ ] **Step 1: Write the failing test**

Create `crates/host-agent/src/video_service.rs` with its test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rc_video::capture::mock::MockSource;

    fn viewing() -> PermissionSet {
        PermissionSet::from_iter([Permission::ViewScreen])
    }

    #[test]
    fn listing_displays_answers_with_what_the_source_reports() {
        let mut service = Harness::new(viewing(), MockSource::new(128, 128), true);
        let replies = service.handle(DesktopClientMessage::ListDisplays);
        assert!(matches!(
            replies.as_slice(),
            [DesktopAgentMessage::Displays(displays)] if displays.len() == 1
        ));
    }

    #[test]
    fn a_session_without_view_permission_is_refused_and_told_why() {
        // Silence here is indistinguishable from a dead link, and the operator would
        // sit waiting for a picture that is never coming.
        let mut service = Harness::new(PermissionSet::NONE, MockSource::new(128, 128), true);
        let replies = service.handle(DesktopClientMessage::StartStream {
            display_index: 0,
            accepted_codecs: vec![VideoCodec::TiledZstd],
            quality: QualityPreset::Balanced,
            max_fps: 30,
            interaction: InteractionMode::ViewOnly,
        });
        assert!(matches!(
            replies.as_slice(),
            [DesktopAgentMessage::Error { .. }]
        ));
    }

    #[test]
    fn a_codec_neither_side_shares_is_refused_rather_than_guessed() {
        let mut service = Harness::new(viewing(), MockSource::new(128, 128), true);
        let replies = service.handle(DesktopClientMessage::StartStream {
            display_index: 0,
            accepted_codecs: vec![VideoCodec::Av1],
            quality: QualityPreset::Balanced,
            max_fps: 30,
            interaction: InteractionMode::ViewOnly,
        });
        assert!(matches!(
            replies.as_slice(),
            [DesktopAgentMessage::Error { .. }]
        ));
    }

    #[test]
    fn the_negotiated_codec_is_the_clients_first_choice_that_we_can_produce() {
        let mut service = Harness::new(viewing(), MockSource::new(128, 128), true);
        let replies = service.handle(DesktopClientMessage::StartStream {
            display_index: 0,
            accepted_codecs: vec![VideoCodec::H264, VideoCodec::TiledZstd, VideoCodec::RawRgba],
            quality: QualityPreset::Balanced,
            max_fps: 30,
            interaction: InteractionMode::ViewOnly,
        });
        assert!(matches!(
            replies.as_slice(),
            [DesktopAgentMessage::StreamStarted { codec: VideoCodec::TiledZstd, width: 128, height: 128, .. }]
        ));
    }

    #[test]
    fn a_build_without_capture_says_so_rather_than_going_quiet() {
        let mut service = Harness::new(viewing(), MockSource::new(128, 128), false);
        let replies = service.handle(DesktopClientMessage::StartStream {
            display_index: 0,
            accepted_codecs: vec![VideoCodec::TiledZstd],
            quality: QualityPreset::Balanced,
            max_fps: 30,
            interaction: InteractionMode::ViewOnly,
        });
        assert!(matches!(
            replies.as_slice(),
            [DesktopAgentMessage::Error { .. }]
        ));
    }

    #[test]
    fn a_keyframe_request_forces_a_full_refresh() {
        let mut service = Harness::new(viewing(), MockSource::new(128, 128), true);
        service.handle(DesktopClientMessage::StartStream {
            display_index: 0,
            accepted_codecs: vec![VideoCodec::TiledZstd],
            quality: QualityPreset::Balanced,
            max_fps: 30,
            interaction: InteractionMode::ViewOnly,
        });
        service.tick();  // first frame, everything changes
        assert!(service.tick().is_empty(), "a still screen sends nothing");

        service.handle(DesktopClientMessage::RequestKeyframe);
        let frames = service.tick();
        assert!(frames.iter().any(|f| f.keyframe), "the request must be honoured");
    }

    #[test]
    fn a_revoked_grant_stops_the_stream_mid_session() {
        // Matches how input_service re-checks authorization per event: a permission
        // withdrawn while streaming must take effect immediately, not at teardown.
        let mut service = Harness::new(viewing(), MockSource::new(128, 128), true);
        service.handle(DesktopClientMessage::StartStream {
            display_index: 0,
            accepted_codecs: vec![VideoCodec::TiledZstd],
            quality: QualityPreset::Balanced,
            max_fps: 30,
            interaction: InteractionMode::ViewOnly,
        });
        service.tick();
        service.revoke();
        assert!(service.tick().is_empty(), "revocation must stop frames");
    }
}
```

`Harness` exists because a `ChannelWriter` needs a live QUIC stream, and these tests are
about decisions rather than transport. It is the same split `input_service.rs` already
uses — the service's decision logic lives in `&mut self` methods that return messages,
and `run` is the only thing that writes them:

```rust
    /// The service's decisions, without a transport under them.
    struct Harness {
        session: Session,
        source: MockSource,
        enabled: bool,
        stream: Option<Stream>,
    }

    impl Harness {
        fn new(permissions: PermissionSet, source: MockSource, enabled: bool) -> Self {
            Self { session: session_with(permissions), source, enabled, stream: None }
        }

        /// One client message in, the agent's replies out.
        fn handle(&mut self, message: DesktopClientMessage) -> Vec<DesktopAgentMessage> {
            VideoService::decide(
                &mut self.stream,
                &self.session,
                &mut self.source,
                self.enabled,
                message,
            )
        }

        /// One capture-and-encode cycle, the frames it produced.
        fn tick(&mut self) -> Vec<VideoFrame> {
            VideoService::capture_once(&mut self.stream, &self.session, &mut self.source)
        }

        /// Withdraw every permission, as a revoked grant does mid-session.
        fn revoke(&mut self) {
            self.session = session_with(PermissionSet::NONE);
        }
    }
```

This dictates the shape of `VideoService`: `decide` and `capture_once` are associated
functions taking the state they touch, and `run` is a thin loop that calls them and
writes what they return. Copy `session_with` from `input_service.rs`'s test module.

**On `quality`:** `TiledZstd` is lossless, so a quality preset cannot trade fidelity for
bytes the way it would with H.264. In this milestone `quality` is accepted, stored and
reported back unchanged, and influences nothing; `max_fps` is the only knob that moves.
Say so in the field's doc comment rather than silently ignoring it — a preset that
appears to work and does nothing is worse than one that is documented as inert until
there is a lossy codec to apply it to.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rc-host-agent video_service`
Expected: FAIL — the module does not exist.

- [ ] **Step 3: Write minimal implementation**

Write `video_service.rs` mirroring `input_service.rs`. The service holds:

```rust
pub struct VideoService<S: CaptureSource> {
    writer: ChannelWriter,
    session: Session,
    source: S,
    enabled: bool,
    stream: Option<Stream>,
}

/// State that exists only while streaming.
struct Stream {
    display_index: u8,
    encoder: Encoder,
    codec: VideoCodec,
    interval: Duration,
    paused: bool,
    force_keyframe: bool,
}
```

Required behaviour:

- `ListDisplays` → `Displays(source.displays()?)`, permitted for any session that may view.
- `StartStream` → check `Permission::ViewScreen` on the *current* session state; pick the first of `accepted_codecs` that is `TiledZstd` or `RawRgba`; build an `Encoder` from the chosen display's dimensions; reply `StreamStarted { display_index, codec, width, height, hardware_accelerated: false }`. Clamp `max_fps` to `1..=60` and derive `interval`.
- `StopStream` → drop `Stream`, reply `StreamStopped`.
- `PauseStream` / `ResumeStream` → set `paused`; keep the encoder so no keyframe is needed on resume.
- `Reconfigure` → change display (rebuild the encoder, force a keyframe), quality, or `max_fps` in place.
- `RequestKeyframe` → set `force_keyframe`.
- Every failure path replies `DesktopAgentMessage::Error { code, message }` naming the real cause. Never go silent.
- The run loop is a `tokio::select!` over the reader and a `tokio::time::interval`, exactly like `input_service`'s watermark timer. Re-check permission before each capture, so revocation stops frames immediately.
- On teardown, drop the encoder and log at debug. There is no host-side state to unwind the way held keys are.

In `crates/host-agent/Cargo.toml`:

```toml
[features]
default = ["inject"]
inject = ["rc-input/inject", "rc-video/capture"]
```

and add `rc-video = { workspace = true }` to `[dependencies]`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rc-host-agent video_service -- --test-threads=1`
Expected: PASS, all seven tests.

- [ ] **Step 5: Commit**

```bash
git add crates/host-agent/src/video_service.rs crates/host-agent/src/lib.rs crates/host-agent/Cargo.toml
git commit -m "feat(agent): video service with codec negotiation and live permission checks"
```

---

### Task 9: Serve Channel::Video

**Files:**
- Modify: `crates/host-agent/src/server.rs:689` (the channel dispatch `match`), and the two sites where `display_count` is hardcoded to `0`
- Test: `crates/host-agent/tests/video_stream.rs` (create)

**Interfaces:**
- Consumes: `VideoService`, `XcapSource`, `MockSource`.
- Produces: a served `Channel::Video`.

- [ ] **Step 1: Write the failing test**

Create `crates/host-agent/tests/video_stream.rs`, following the existing
`agent_lifecycle.rs` pattern for standing up a real QUIC listener and client:

```rust
//! The video channel end to end, over a real QUIC link.

// Follow agent_lifecycle.rs for harness construction: it stands up a listener, a
// client, and a session with the permissions given.

#[tokio::test]
async fn a_client_can_start_a_stream_and_receive_a_keyframe() {
    let harness = Harness::with_view_permission().await;
    let (mut writer, mut reader) = harness.open(rc_protocol::Channel::Video).await;

    send(&mut writer, DesktopClientMessage::StartStream {
        display_index: 0,
        accepted_codecs: vec![VideoCodec::TiledZstd],
        quality: QualityPreset::Balanced,
        max_fps: 10,
        interaction: InteractionMode::ViewOnly,
    })
    .await;

    let started = recv(&mut reader).await;
    let DesktopAgentMessage::StreamStarted { codec, width, height, .. } = started else {
        panic!("expected StreamStarted, got {started:?}");
    };
    assert_eq!(codec, VideoCodec::TiledZstd);

    let frame = loop {
        if let DesktopAgentMessage::Frame(frame) = recv(&mut reader).await {
            break frame;
        }
    };
    assert!(frame.keyframe, "the first frame must stand alone");

    // The picture the agent sent must reconstruct exactly.
    let mut decoder = rc_video::decode::Decoder::new(codec, width, height).expect("decoder");
    decoder.apply(&frame).expect("apply");
    assert!(decoder.complete());
}

#[tokio::test]
async fn a_session_without_view_permission_gets_an_error_not_silence() {
    let harness = Harness::without_permissions().await;
    let (mut writer, mut reader) = harness.open(rc_protocol::Channel::Video).await;
    send(&mut writer, DesktopClientMessage::ListDisplays).await;
    assert!(matches!(recv(&mut reader).await, DesktopAgentMessage::Error { .. }));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rc-host-agent --test video_stream -- --test-threads=1`
Expected: FAIL — the channel is opened and never answered, so `recv` times out.

- [ ] **Step 3: Write minimal implementation**

In `crates/host-agent/src/server.rs`, add the arm alongside `Channel::Input`:

```rust
                    rc_protocol::Channel::Video => {
                        // Built per channel for the same reason as the input sink: a
                        // host that cannot capture tells this client so, rather than
                        // failing at startup for every client.
                        match crate::video_service::new_source() {
                            Ok(source) => {
                                let service = crate::video_service::VideoService::new(
                                    writer,
                                    session,
                                    source,
                                    server.config.features.remote_desktop,
                                );
                                tokio::spawn(async move {
                                    service.run(&mut reader).await;
                                });
                            }
                            Err(err) => {
                                tracing::warn!(%err, "video channel opened on a host that cannot capture");
                            }
                        }
                    }
```

Add to `video_service.rs` a constructor that picks the backend for the build:

```rust
/// The capture source this build uses.
///
/// # Errors
/// If no display server is reachable, or this build has no capture backend.
#[cfg(feature = "inject")]
pub fn new_source() -> rc_video::Result<rc_video::capture::xcap_source::XcapSource> {
    rc_video::capture::xcap_source::XcapSource::new()
}

/// The capture source this build uses.
///
/// # Errors
/// Always: a build without the capture backend cannot serve video, and says so rather
/// than serving black frames.
#[cfg(not(feature = "inject"))]
pub fn new_source() -> rc_video::Result<rc_video::capture::mock::MockSource> {
    Err(rc_video::VideoError::Unsupported(
        "this build has no capture backend",
    ))
}
```

Then find the two sites where `display_count` is hardcoded to `0` and populate them
from `CaptureSource::displays()`:

```bash
grep -rn "display_count" crates/ apps/
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rc-host-agent -- --test-threads=1`
Expected: PASS, including the new video stream tests.

- [ ] **Step 5: Commit**

```bash
git add crates/host-agent/src/server.rs crates/host-agent/src/video_service.rs crates/host-agent/tests/video_stream.rs
git commit -m "feat(agent): serve Channel::Video and report a real display count"
```

---

### Task 10: The client receives and decodes frames

**Files:**
- Modify: `apps/desktop-client/src-tauri/src/connection.rs` (open `Channel::Video` beside the existing `FileTransfer` at :776 and `Metrics` at :846), `apps/desktop-client/src-tauri/Cargo.toml` (add `rc-video`)
- Create: `apps/desktop-client/src-tauri/src/video_commands.rs`
- Modify: `apps/desktop-client/src-tauri/src/lib.rs` (register the commands)

**Interfaces:**
- Consumes: `rc_video::decode::Decoder`, `rc_protocol::desktop::{DesktopClientMessage, DesktopAgentMessage}`.
- Produces: Tauri commands `video_list_displays() -> Vec<DisplayInfoDto>`, `video_start_stream(display_index: u8, max_fps: u8, on_frame: tauri::ipc::Channel<tauri::ipc::InvokeResponseBody>) -> Result<StreamStartedDto, String>`, `video_stop_stream() -> Result<(), String>`, `video_request_keyframe() -> Result<(), String>`.

**Wire format into the webview**, little-endian, one message per changed region:

```
u32 x | u32 y | u32 width | u32 height | RGBA bytes (width * height * 4)
```

A frame with several damage rects produces several such messages. This is deliberately
the simplest framing that lets the frontend call `putImageData` without parsing
anything structural, and it carries no compression because zstd was already undone in
Rust.

- [ ] **Step 1: Write the failing test**

Add to `apps/desktop-client/src-tauri/src/video_commands.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_region_is_framed_with_its_position_then_its_pixels() {
        // The frontend blits straight from this, so the header has to be exact.
        let rect = Rect { x: 64, y: 128, width: 2, height: 1 };
        let pixels = [1u8, 2, 3, 4, 5, 6, 7, 8];

        let message = frame_region(&rect, &pixels);

        assert_eq!(&message[0..4], &64u32.to_le_bytes());
        assert_eq!(&message[4..8], &128u32.to_le_bytes());
        assert_eq!(&message[8..12], &2u32.to_le_bytes());
        assert_eq!(&message[12..16], &1u32.to_le_bytes());
        assert_eq!(&message[16..], &pixels);
        assert_eq!(message.len(), 16 + pixels.len());
    }

    #[test]
    fn regions_are_cut_from_the_framebuffer_at_the_right_offsets() {
        // Getting the stride wrong here shears the image, which looks like a codec
        // bug and is miserable to trace back to an arithmetic slip.
        let width = 4u32;
        let framebuffer: Vec<u8> = (0..(4 * 2 * 4)).map(|i| i as u8).collect();
        let rect = Rect { x: 2, y: 1, width: 2, height: 1 };

        let cut = cut_region(&framebuffer, width, &rect);

        // Row 1 starts at 4 px * 4 B = 16; column 2 adds 8.
        assert_eq!(cut, framebuffer[24..32]);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rc-desktop-client video`
Expected: FAIL — `cannot find function frame_region`.

- [ ] **Step 3: Write minimal implementation**

In `video_commands.rs`:

```rust
/// Header bytes before a region's pixels: x, y, width, height, each `u32` little-endian.
const REGION_HEADER: usize = 16;

/// Copy the pixels of `rect` out of an RGBA framebuffer `width` pixels wide.
fn cut_region(framebuffer: &[u8], width: u32, rect: &Rect) -> Vec<u8> {
    let stride = (width as usize) * 4;
    let run = (rect.width as usize) * 4;
    let mut out = Vec::with_capacity(run * (rect.height as usize));
    for row in 0..rect.height {
        let start = ((rect.y + row) as usize) * stride + (rect.x as usize) * 4;
        out.extend_from_slice(&framebuffer[start..start + run]);
    }
    out
}

/// Frame one region for the webview: position, size, then pixels.
fn frame_region(rect: &Rect, pixels: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(REGION_HEADER + pixels.len());
    message.extend_from_slice(&rect.x.to_le_bytes());
    message.extend_from_slice(&rect.y.to_le_bytes());
    message.extend_from_slice(&rect.width.to_le_bytes());
    message.extend_from_slice(&rect.height.to_le_bytes());
    message.extend_from_slice(pixels);
    message
}
```

Then the commands: `video_start_stream` opens `Channel::Video` through the existing
`rc_transport::open_channel` helper used at `connection.rs:776`, sends `StartStream`,
awaits `StreamStarted`, builds a `Decoder`, and spawns a task that for each incoming
`Frame` calls `decoder.apply`, then for each returned rect sends
`frame_region(&rect, &cut_region(decoder.framebuffer(), width, &rect))` down the
`tauri::ipc::Channel` as `InvokeResponseBody::Raw`.

When `decoder.needs_keyframe()` becomes true, send `RequestKeyframe` back up the
channel — the client repairs itself rather than waiting for a human to notice.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rc-desktop-client` then `cargo clippy -p rc-desktop-client --all-targets -- -D warnings`
Expected: PASS, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add apps/desktop-client/src-tauri/src/video_commands.rs apps/desktop-client/src-tauri/src/connection.rs apps/desktop-client/src-tauri/src/lib.rs apps/desktop-client/src-tauri/Cargo.toml
git commit -m "feat(client): open Channel::Video, decode frames and push regions to the webview"
```

---

### Task 11: The canvas renderer

**Files:**
- Create: `apps/desktop-client/src/video.ts`, `apps/desktop-client/src/video.test.ts`

**Interfaces:**
- Consumes: the region wire format from Task 10.
- Produces: `parseRegion(buffer: ArrayBuffer): { x: number; y: number; width: number; height: number; pixels: Uint8ClampedArray }` and `applyRegion(ctx: CanvasRenderingContext2D, buffer: ArrayBuffer): void`.

- [ ] **Step 1: Write the failing test**

Create `apps/desktop-client/src/video.test.ts`:

```typescript
import { describe, expect, it, vi } from 'vitest';
import { applyRegion, parseRegion } from './video';

function region(x: number, y: number, w: number, h: number, pixels: number[]): ArrayBuffer {
  const buffer = new ArrayBuffer(16 + pixels.length);
  const view = new DataView(buffer);
  view.setUint32(0, x, true);
  view.setUint32(4, y, true);
  view.setUint32(8, w, true);
  view.setUint32(12, h, true);
  new Uint8Array(buffer, 16).set(pixels);
  return buffer;
}

describe('parseRegion', () => {
  it('reads the little-endian header the Rust side writes', () => {
    const parsed = parseRegion(region(64, 128, 2, 1, [1, 2, 3, 4, 5, 6, 7, 8]));
    expect(parsed).toMatchObject({ x: 64, y: 128, width: 2, height: 1 });
    expect(Array.from(parsed.pixels)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  });

  it('rejects a region whose pixels do not match its dimensions', () => {
    // A truncated message must not be blitted as though it were whole; that would
    // paint uninitialised memory onto the operator's screen.
    expect(() => parseRegion(region(0, 0, 4, 4, [1, 2, 3, 4]))).toThrow();
  });
});

describe('applyRegion', () => {
  it('blits at the region position, not the origin', () => {
    // Ignoring the offset puts every update in the top-left corner — the classic
    // symptom of dropping the header.
    const putImageData = vi.fn();
    const ctx = { putImageData } as unknown as CanvasRenderingContext2D;

    applyRegion(ctx, region(64, 128, 1, 1, [9, 8, 7, 6]));

    expect(putImageData).toHaveBeenCalledTimes(1);
    const [image, x, y] = putImageData.mock.calls[0];
    expect([x, y]).toEqual([64, 128]);
    expect(image.width).toBe(1);
    expect(image.height).toBe(1);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/desktop-client && pnpm vitest run src/video.test.ts`
Expected: FAIL — cannot resolve `./video`.

- [ ] **Step 3: Write minimal implementation**

Create `apps/desktop-client/src/video.ts`:

```typescript
/**
 * Decoding the region messages the Rust side pushes down the IPC channel.
 *
 * The wire format is deliberately minimal — x, y, width, height as little-endian
 * u32, then raw RGBA — because the pixels arrive already decompressed and in the
 * exact byte order `putImageData` wants. Nothing here re-encodes or converts.
 */

/** Bytes of header before the pixels. */
const HEADER_BYTES = 16;

/** Bytes per pixel, RGBA. */
const BYTES_PER_PIXEL = 4;

/** One rectangular screen update. */
export interface Region {
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
  readonly pixels: Uint8ClampedArray;
}

/**
 * Read one region message.
 *
 * @throws if the message is too short, or its pixel count disagrees with its
 * dimensions — a truncated message must never be blitted as though it were whole.
 */
export function parseRegion(buffer: ArrayBuffer): Region {
  if (buffer.byteLength < HEADER_BYTES) {
    throw new Error(`region message of ${buffer.byteLength} bytes is shorter than its header`);
  }
  const view = new DataView(buffer);
  const x = view.getUint32(0, true);
  const y = view.getUint32(4, true);
  const width = view.getUint32(8, true);
  const height = view.getUint32(12, true);

  const expected = width * height * BYTES_PER_PIXEL;
  const actual = buffer.byteLength - HEADER_BYTES;
  if (actual !== expected) {
    throw new Error(`region ${width}x${height} needs ${expected} bytes of pixels, got ${actual}`);
  }

  return { x, y, width, height, pixels: new Uint8ClampedArray(buffer, HEADER_BYTES) };
}

/** Blit one region message onto `ctx` at the position it names. */
export function applyRegion(ctx: CanvasRenderingContext2D, buffer: ArrayBuffer): void {
  const { x, y, width, height, pixels } = parseRegion(buffer);
  ctx.putImageData(new ImageData(pixels, width, height), x, y);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd apps/desktop-client && pnpm vitest run src/video.test.ts`
Expected: PASS, all three tests.

- [ ] **Step 5: Commit**

```bash
git add apps/desktop-client/src/video.ts apps/desktop-client/src/video.test.ts
git commit -m "feat(client): parse and blit video regions onto a canvas"
```

---

### Task 12: The session screen shows the remote display

**Files:**
- Create: `apps/desktop-client/src/VideoSurface.tsx`, `apps/desktop-client/src/videoSurface.test.tsx`
- Modify: `apps/desktop-client/src/SessionScreen.tsx`, `apps/desktop-client/src/SessionToolbar.tsx:64` (wire the `fitted` toggle)

**Interfaces:**
- Consumes: `applyRegion` from Task 11; the Tauri commands from Task 10.
- Produces: `<VideoSurface displayIndex={number} fitted={boolean} />`.

- [ ] **Step 1: Write the failing test**

Create `apps/desktop-client/src/videoSurface.test.tsx`:

```tsx
import { render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { VideoSurface } from './VideoSurface';

describe('VideoSurface', () => {
  it('sizes the canvas to the stream the agent actually started', async () => {
    // A canvas left at its default size silently scales every frame, which reads as
    // a blurry remote rather than as a bug in this component.
    render(<VideoSurface displayIndex={0} fitted />);

    const canvas = await screen.findByTestId<HTMLCanvasElement>('video-surface');
    await waitFor(() => {
      expect(canvas.width).toBe(1920);
      expect(canvas.height).toBe(1080);
    });
  });

  it('says the stream failed rather than showing an empty black rectangle', async () => {
    // Indistinguishable states are the failure this project keeps guarding against:
    // a black canvas could be a locked remote screen or a dead stream.
    render(<VideoSurface displayIndex={9} fitted />);
    expect(await screen.findByRole('alert')).toHaveTextContent(/could not start/i);
  });
});
```

The test file mocks the Tauri command layer the way `remoteControl.test.tsx` already
does — read it first and follow the same mocking approach rather than inventing one.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/desktop-client && pnpm vitest run src/videoSurface.test.tsx`
Expected: FAIL — cannot resolve `./VideoSurface`.

- [ ] **Step 3: Write minimal implementation**

`VideoSurface.tsx` mounts a `<canvas data-testid="video-surface">`, calls
`video_start_stream` on mount with a `Channel` whose `onmessage` runs `applyRegion`,
sizes the canvas from the returned `StreamStarted`, and calls `video_stop_stream` on
unmount. A failure to start renders `role="alert"` naming the reason returned by the
agent — never a blank canvas.

`fitted` chooses between `object-fit: contain` within the pane and 1:1 pixels with
scrolling. This is what makes the previously dead "Fit to window" toggle in
`SessionToolbar.tsx:64` real; wire that toggle's state through to this prop.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd apps/desktop-client && pnpm vitest run && pnpm lint`
Expected: PASS, lint clean.

- [ ] **Step 5: Commit**

```bash
git add apps/desktop-client/src/VideoSurface.tsx apps/desktop-client/src/videoSurface.test.tsx apps/desktop-client/src/SessionScreen.tsx apps/desktop-client/src/SessionToolbar.tsx
git commit -m "feat(client): show the remote display and make Fit to window real"
```

---

### Task 13: End-to-end verification on real hardware

**Files:**
- Modify: `README.md`, `PROGRESS.md` (record what works and what is still unverified)

- [ ] **Step 1: Run the whole suite**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo test --workspace
cargo check -p rc-video
cd apps/desktop-client && pnpm vitest run && pnpm lint
```

Expected: all clean.

- [ ] **Step 2: Run the ignored live tests**

```bash
cargo test -p rc-video --features capture -- --ignored --nocapture
```

Expected: both monitors listed, a real frame captured at the advertised size.

- [ ] **Step 3: Drive the app**

Launch the client, connect to an agent, and confirm the remote screen appears, updates
as the remote changes, and that "Fit to window" changes the scaling.

- [ ] **Step 4: Record the truth in the docs**

Update `README.md` and `PROGRESS.md`: video works on Windows and is unverified on macOS
and Linux; input still has no controller-side capture, so the picture cannot yet be
driven; H.264, clipboard sync and adaptive quality remain unimplemented.

- [ ] **Step 5: Commit**

```bash
git add README.md PROGRESS.md
git commit -m "docs: record what the video pipeline does and does not yet do"
```
