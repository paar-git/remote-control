# Remote input layer — design

**Status:** approved for implementation
**Date:** 2026-08-15

## Problem

The project has no remote-input pipeline. `InputEvent`, `DesktopClientMessage` and
`DesktopAgentMessage` exist in `crates/protocol/src/desktop.rs` and are referenced
nowhere else. The agent advertises `remote_desktop: false` and closes `Channel::Input`
and `Channel::Video` unread. No OS input dependency exists in the tree. `control_input`
is granted, stored and displayed, and nothing consumes it.

This spec covers the input pipeline and display enumeration. Video capture and encode
are a separate spec.

## Requirements

1. Every supported mouse and keyboard action performed on the controller reproduces
   accurately on the host.
2. A shortcut behaves according to the **host's** OS, not the controller's.
3. Physical key input and logical shortcuts are separate concerns and travel
   separately.
4. Nothing is logged as successful before the host confirms it.
5. Windows-specific key identities never reach macOS or Linux.
6. Adding an OS must not require editing existing per-OS code.

## Decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | Physical scancodes by default; a **closed** set of `Intent`s carries semantics | Typing, games and terminals need exact physical keys. Translating everything misfires on ambiguous chords. |
| 2 | New `rc-input` crate behind an `InputSink` trait | Confines OS input to one crate. `rc-platform` keeps `#![forbid(unsafe_code)]`. Agent depends on the trait, so it is mockable. |
| 3 | Backend is `enigo` initially, swappable | Mature, covers Win/mac/Linux, encapsulates the unsafe FFI. |
| 4 | X11 now; Wayland **detected and refused** | Wayland blocks synthetic input without portal/libei. Refusing honestly beats silently dropping events. |
| 5 | Tiered acknowledgement | Motion is fire-and-forget with a watermark; discrete actions are individually acked. Per-event acks on motion would add an RTT to pointer lag. |
| 6 | Controller detects intent, host renders it | 3 detect + 3 render tables cover all 9 pairs as compositions, instead of 9 tables. Host owns its own conventions, matching the project's authority model. |

## Architecture

```
crates/input/src/
  lib.rs        InputSink, InputCapability, HostOs
  keys.rs       PhysicalKey, Modifiers, KeyState        (pure)
  intent.rs     Intent, detect(), render()              (pure)
  session.rs    HeldKeys, release_all()                 (pure)
  backend/
    mock.rs     records calls; used by all tests
    enigo.rs    real injection, cfg-gated
```

### Type model

Three concepts, deliberately not collapsed:

- `PhysicalKey` — layout-independent, W3C `KeyboardEvent.code` semantics. The Tauri
  client gets `event.code` directly from the browser.
- `Modifiers` — a bitset named by **role**: `SHIFT | CONTROL | ALT | META`. `META` is
  the Win key on Windows, Command on macOS, Super on Linux. Naming by role rather than
  by vendor is what prevents a "Windows key" identity reaching macOS.
- `Intent` — a closed enum of semantic actions. Anything not on the list travels as
  `PhysicalKey` and is never remapped.

### Trait

```rust
pub trait InputSink: Send {
    fn pointer_move(&mut self, x: f64, y: f64, display: DisplayId) -> Result<()>;
    fn button(&mut self, b: MouseButton, s: KeyState)             -> Result<()>;
    fn scroll(&mut self, dx: f32, dy: f32)                        -> Result<()>;
    fn key(&mut self, k: PhysicalKey, s: KeyState)                -> Result<()>;
    fn intent(&mut self, i: Intent)                               -> Result<()>;
    fn capability(&self) -> InputCapability;
}
```

`intent()` has a default implementation: render to this host's native chord, then drive
it through `key()`. A backend implements physical injection only.

### Composition, not special cases

- A double-click is two down/up pairs. A drag is `button(Left, Down)` → moves →
  `button(Left, Up)`. The controller sends what happened; the host replays it in order.
  Nothing synthesizes gestures, so nothing can synthesize them wrongly.
- Ordering is guaranteed: `Channel::Input` is one QUIC stream, and the file-transfer
  stream cannot head-of-line block it.

### Stuck-key safety

`session.rs` tracks every key and button currently held. On session end — disconnect,
network loss, Emergency Stop — the host releases everything held before teardown.
Without this, a connection dropped during `Ctrl+C` leaves Ctrl jammed down on the
remote machine.

## Protocol

`InputEvent` gains a sequence number; `KeyDown`/`KeyUp` carry a `PhysicalKey` rather
than a raw `u32` scancode; `Intent` is new. Acks travel back on `Channel::Input`.

```rust
enum InputEvent {
    MouseMove { x: f32, y: f32 },                   // fire-and-forget
    Scroll    { delta_x: f32, delta_y: f32 },       // fire-and-forget
    MouseDown { button: MouseButton, seq: u32 },    // acked
    MouseUp   { button: MouseButton, seq: u32 },    // acked
    KeyDown   { key: PhysicalKey, repeat: bool, seq: u32 },
    KeyUp     { key: PhysicalKey, seq: u32 },
    Intent    { intent: Intent, seq: u32 },
}

enum InputAck {
    Ok       { seq: u32 },
    Failed   { seq: u32, reason: InputFailure },
    Applied  { watermark: u32 },                    // motion progress
}

enum InputFailure { NotPermitted, Blocked, Unavailable, NotSupported, ViewOnly }
```

`InputFailure` names the real cause: `NotPermitted` for macOS Accessibility/TCC,
`Blocked` for Windows UIPI, `Unavailable` for Wayland, `NotSupported` for an intent with
no host equivalent, `ViewOnly` for a session lacking `control_input`.

## Logging

The controller logs an action **only** on receipt of `Ok` or `Failed`. A pending action
that times out is logged as failed. Motion is never individually logged, so it cannot
lie. A capability probe at session start reports `InputCapability`, so a host that
cannot inject says so up front.

## Platform constraints

| Platform | Constraint |
|---|---|
| macOS | `CGEventPost` silently no-ops without Accessibility permission and still reports success. Must be probed explicitly, not inferred. |
| Windows | UIPI blocks injection into elevated windows unless the agent is elevated. Ctrl+Alt+Del cannot be sent via `SendInput`; it needs `SendSAS` from a service. |
| Linux | X11/XTest works. Wayland blocks synthetic input; detected and refused. |

## Testing

The nine platform pairs are verified as compositions: for each of 3 detect tables and 3
render tables, assert `render(detect(chord, src), dst)` yields the correct native chord,
table-driven across every `Intent`. Pure functions, no desktop required, runs in CI on
all three OSes. The `mock` backend records exact injected calls, so agent-level tests
assert on real injection sequences without a display.

## Out of scope

Video capture and encode. Wayland portal/libei injection. Clipboard sync beyond the
existing protocol messages. Multi-monitor coordinate mapping beyond `ListDisplays`.
