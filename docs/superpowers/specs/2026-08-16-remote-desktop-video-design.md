# Remote desktop video — design

**Status:** approved for implementation
**Date:** 2026-08-16

## Problem

There is no video. `crates/protocol/src/desktop.rs` defines the whole vocabulary —
`VideoCodec`, `QualityPreset`, `VideoFrame`, `Rect`, and the full
`DesktopClientMessage` / `DesktopAgentMessage` pair including `StartStream`,
`Reconfigure` and `RequestKeyframe` — and nothing implements any of it. `Channel::Video`
has no arm in the agent's channel dispatch in `crates/host-agent/src/server.rs`; the
stream is opened and never served. The client opens `Control`, `FileTransfer` and
`Metrics` in `apps/desktop-client/src-tauri/src/connection.rs` and never opens `Video`.

This is the gap that makes everything else unusable. The input layer is complete and
tested, but nobody can aim a pointer at a screen they cannot see, so the input pipeline
has never been driven by a human. Two toggles in `SessionToolbar.tsx` — "Fit to window"
and "Keyboard passthrough" — set state that only their own `aria-pressed` reads, because
there is no surface to fit and nothing to pass keys through to.

Prior specs: `2026-08-15-remote-input-layer-design.md` covers input and display
enumeration. This spec covers capture, encode, transport and render. Input capture on
the video surface is milestone 2 and is scoped here but specified separately.

## Decisions taken before design

Two questions were settled with the project owner and constrain everything below.

**The stream carries text and admin work on a LAN.** Reading terminals, config files
and log output. This makes lossless the right default: compression artifacts on 9pt
text are the failure mode that matters, not bandwidth. `TiledZstd` with a `RawBgra`
fallback — both pure Rust, no system dependencies, identical on all three platforms, and
exactly what `desktop.rs` already documents as the always-supported path. H.264 and
friends stay in the enum and are refused by negotiation.

**All three platforms, Windows verified.** Capture goes through one cross-platform
crate behind a trait rather than three hand-written platform backends. Windows is
verified on real hardware; macOS and Linux compile, are covered by CI, and are
documented as unverified — the same honesty the input backends already practise.

## Capture

New crate `rc-video`, structured as a direct sibling of `rc-input`, including its
feature-flag discipline.

```rust
pub trait CaptureSource {
    fn displays(&self) -> Result<Vec<DisplayInfo>>;
    fn grab(&mut self, index: u8) -> Result<CapturedFrame>;
}

pub struct CapturedFrame {
    pub width: u32,
    pub height: u32,
    pub bgra: Vec<u8>,
}
```

`XcapSource` sits behind a `capture` feature, default off, so the encoder and every test
covering it build on a machine with no desktop — the same reason `rc-input` puts its
enigo backend behind `inject`. `MockSource` is always available and is what the test
suite runs against.

`xcap` is chosen over `scap`: scap is unmaintained and its PipeWire 0.8.0 dependency
chain no longer compiles. xcap is by the author of `display-info`, which this workspace
already depends on for display enumeration, so the two agree about what a monitor is.
xcap supports Windows 8.1+, macOS and X11, and explicitly does not support Wayland —
which matches the refusal the input layer already returns there.

**Risk to retire first.** docs.rs failed to build xcap 0.9.8; the last successful build
was 0.4.1. The real API must be confirmed against the crate before anything is built on
it. This is the first implementation step, not an assumption.

## Encode

`TiledZstd` is a tile differ, and the tiling is what produces damage rects — the OS is
never asked for dirty regions, so all three platforms behave identically.

- Split the frame into 64×64 tiles.
- Hash each tile; compare against the previous frame's hashes.
- Changed tiles become the payload, concatenated in `damage` order.
- Compress the payload with zstd.
- A keyframe is every tile.

This yields `VideoFrame { sequence, captured_at_us, keyframe, data, damage }` exactly as
already defined. No protocol change is required.

`RawBgra` is the same path with no tiling and no compression, kept as the last-resort
codec the protocol promises.

Two workspace dependencies are added: `zstd` for the codec, and `xcap` behind the
`capture` feature. Nothing else. The tile hash uses a non-cryptographic hash from a
crate already in the tree rather than pulling in another.

### Keyframes must be splittable

`MAX_VIDEO_FRAME` is 16 MiB. Raw BGRA at 1080p is 7.91 MiB (1920 × 1080 × 4) and fits.
At 4K it is 31.6 MiB and does not, and a noisy `TiledZstd` keyframe at 4K can exceed the
limit too.

So a keyframe is a tile range, not necessarily a whole screen: a large keyframe is
emitted as several frames, each carrying a contiguous slice of tiles, assembled
client-side before presentation. Building this in from the start is deliberate —
retrofitting it later touches the encoder, the wire, the client assembler and the
renderer at once. The development hardware is 1080p, so this is about not shipping
something that breaks on the first 4K desktop it meets.

## Transport

Host: `crates/host-agent/src/video_service.rs`, modelled directly on the existing
`input_service.rs` — same shape, same lifecycle, same teardown discipline. It handles
`DesktopClientMessage` on `Channel::Video`, runs a capture/encode loop bounded by
`max_fps`, and writes `DesktopAgentMessage::Frame`. It is wired into the currently
absent `Channel::Video` arm in `server.rs`.

`ListDisplays` is served from the same enumeration the input layer already uses, which
also fixes `display_count` being hardcoded to `0` in two places.

Client: `connection.rs` opens `Channel::Video` following the pattern already used for
`FileTransfer` and `Metrics`, and spawns a task that decompresses frames and applies
tiles to a persistent BGRA framebuffer.

## Reaching the webview

The existing Rust-to-webview path is `app.emit()` in `host_events.rs`, which
JSON-serialises its payload. At 1080p that is roughly 8 MiB per frame, base64-inflated by
a third again, on the main thread. It cannot carry video and is not used here.

Frames reach the webview through `tauri::ipc::Channel` carrying raw bytes — Tauri 2.11.5
supports binary natively. It is push-shaped, which matches a stream, and it opens no
port.

Rejected: a custom URI scheme protocol, which is pull-shaped and wrong for a stream; and
a localhost WebSocket, which opens a port and a new authentication surface for no gain.

**Consequence:** zstd lives entirely in Rust on both ends. The client decompresses
before the IPC boundary and hands the webview raw tiles, so the frontend needs no WASM
decoder. The IPC carries uncompressed bytes, but only for changed tiles, and the
transfer is in-process.

Render: a 2D canvas, `putImageData` per changed tile. WebGL is not needed at these
rates and would add a shader path to maintain.

## Milestone 1 scope

In:

- One display at a time, chosen via `StartStream` and changed via `Reconfigure`.
- `RawBgra` and `TiledZstd`, negotiated through `accepted_codecs`.
- `StartStream`, `StopStream`, `PauseStream`, `ResumeStream`, `Reconfigure`,
  `RequestKeyframe`, `ListDisplays`.
- Frame-rate ceiling honoured.
- Honest failures: Wayland refused, macOS Screen Recording permission reported as
  itself rather than as a black frame.
- "Fit to window" becomes wireable, since a surface now exists.

Out, deliberately:

- H.264, H.265, AV1. The variants stay; negotiation refuses them.
- Clipboard sync. `ClipboardUpdate` exists on both message types and stays unimplemented.
- Adaptive bitrate and the quality presets beyond a simple mapping to tile size and fps.
- All-displays-at-once.
- Audio, which the protocol does not model at all.

## Later milestones

**M2 — input on the surface.** The controller-side capture layer: pointer and keyboard
events on the video canvas, mapped through `PhysicalKey::from_w3c_code` and the intent
tables, written to `Channel::Input`. This is the half of the input system that was never
built; it needs a surface to aim at, which M1 provides.

**M3 — passthrough.** Wire the dead "Keyboard passthrough" toggle to a real literal-send
mode. Without it a Windows or Linux controller cannot send `Ctrl+C` to a remote macOS
terminal, because it is detected as `Copy` and rendered as `Cmd+C`. The gap is
asymmetric: a macOS controller is unaffected, since `Ctrl+C` is not in the macOS table
and falls through as a physical key.

## Testing

The load-bearing test is a property: **encode then decode reproduces the source frame
byte for byte.** That is the entire lossless claim and it is cheap to assert.

- Damage correctness in both directions: a tile that changed must appear in `damage`; a
  tile that did not must not.
- Keyframe splitting against the 16 MiB ceiling, including a synthetic 4K frame.
- Sequence gaps trigger a keyframe request.
- `MockSource` keeps all of the above headless, so it runs in CI on all three platforms.
- A real-QUIC integration test in `rc-host-agent`, following the existing pattern, with
  `MockSource` behind the agent.
- An `#[ignore]`d live test mirroring `live_injection.rs` and `live_displays.rs`, run by
  hand on real hardware.
- Frontend: canvas blit against a fake IPC channel, asserting tiles land at the right
  offsets.

## Verification

`cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo fmt --all
-- --check`, the full test suite, and `cargo check -p rc-video` to prove the crate still
builds with no capture backend — the point of the feature flag, and the check that
`rc-input` had been missing until this week.

## What this design does not do

It does not make the session usable by a human on its own. M1 delivers a picture; until
M2 lands, the input layer still has no controller-side capture, so the picture cannot be
driven. Stating the sequence plainly is preferable to implying that video alone closes
the gap.
