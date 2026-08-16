# Controller Input Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Let an operator drive the remote machine by typing and pointing at the video surface — the missing controlling half of a complete-but-unconsumed input layer.

**Architecture:** The webview captures keyboard and pointer events on the video canvas and hands them to Rust as raw W3C data. Rust owns every decision: it maps `KeyboardEvent.code` to a `PhysicalKey`, consults the *controller's own* OS chord table to decide whether a chord is a semantic `Intent`, and writes the result to `Channel::Input`. The host then renders that intent in its own native chord. Neither side models the other.

**Tech Stack:** Rust, `rc-input` (translation, already built and tested), `rc-protocol`, Tauri 2.11.5 commands, TypeScript + React.

**Spec:** `docs/superpowers/specs/2026-08-15-remote-input-layer-design.md` (the layer being consumed) and `docs/superpowers/specs/2026-08-16-remote-desktop-video-design.md` §"Later milestones".

## Global Constraints

- Rust edition 2024. `rustfmt.toml` sets `max_width = 100`; rustfmt's `fn_call_width` default of 60 also applies.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` must pass. The workspace denies warnings including `unfulfilled_lint_expectations` — prefer `#[allow]` over `#[expect]` for cfg-dependent lints.
- `cargo fmt --all -- --check` must pass; `#[rustfmt::skip]` with a comment where a hand-built table's layout is deliberate.
- Every public item needs a doc comment; the workspace denies `missing_docs`.
- **`apps/desktop-client/src/api.ts` is off-limits.** It carries the repository owner's uncommitted work. Put new client bindings in `videoApi.ts` or a new module.
- The repo has a large uncommitted working tree. Only stage files each task names. Never `git add -A`, `git add .`, or `git commit -a`.
- **Intent detection happens on the controller, using the controller's OS table.** The host renders. Neither side models the other's conventions — this is the property the whole input design rests on.

---

### Task 1: Sending input from the client

**Files:**
- Create: `apps/desktop-client/src-tauri/src/input_commands.rs`
- Modify: `apps/desktop-client/src-tauri/src/connection.rs` (open `Channel::Input` beside `Video`), `apps/desktop-client/src-tauri/src/lib.rs` (register commands), `apps/desktop-client/src-tauri/Cargo.toml` (add `rc-input`)

**Interfaces:**
- Consumes: `rc_protocol::{InputEvent, PhysicalKey, Modifiers, MouseButton, Intent, InputMessage, InputAck}`, `rc_input::intent::{Chord, HostOs, detect}`.
- Produces: Tauri commands
  - `input_pointer_move(x: f32, y: f32, display: u8) -> Result<(), String>`
  - `input_pointer_button(button: String, down: bool) -> Result<(), String>`
  - `input_scroll(delta_x: f32, delta_y: f32) -> Result<(), String>`
  - `input_key(code: String, down: bool, repeat: bool, modifiers: u8, passthrough: bool) -> Result<KeySent, String>`
  where `KeySent { as_intent: Option<String> }` reports what was actually sent, so the interface can show the operator when a chord was translated.

**The load-bearing decision:** `input_key` is where a chord becomes either a physical key or an intent. With `passthrough` true it is *always* physical — that is Task 3's escape hatch, designed in now rather than retrofitted.

- [x] **Step 1: Write the failing test**

In `input_commands.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_known_chord_travels_as_an_intent_not_as_keys() {
        // The whole point of the layer: the controller says what it *meant*, and the
        // host spells it however that OS spells it.
        let sent = classify("KeyC", Modifiers::CONTROL, false, HostOs::Windows);
        assert_eq!(sent, Sent::Intent(Intent::Copy));
    }

    #[test]
    fn ordinary_typing_travels_as_a_physical_key() {
        // Text entry, terminals and games need the exact key, never a reinterpretation.
        let sent = classify("KeyC", Modifiers::NONE, false, HostOs::Windows);
        assert_eq!(sent, Sent::Key(PhysicalKey::KeyC));
    }

    #[test]
    fn passthrough_sends_the_literal_chord_even_when_it_is_a_known_intent() {
        // Ctrl+C in a remote terminal is SIGINT, not Copy. Without this an operator on
        // Windows or Linux could never interrupt a process on a remote macOS box,
        // because the chord would be detected as Copy and rendered as Cmd+C.
        let sent = classify("KeyC", Modifiers::CONTROL, true, HostOs::Windows);
        assert_eq!(sent, Sent::Key(PhysicalKey::KeyC));
    }

    #[test]
    fn an_unrecognised_code_is_dropped_rather_than_guessed() {
        // A key this build does not carry must not be delivered as some *other* key.
        assert_eq!(classify("Unidentified", Modifiers::NONE, false, HostOs::Windows), Sent::Nothing);
    }

    #[test]
    fn a_bare_modifier_is_a_physical_key_not_an_intent() {
        // Holding Ctrl on its own is a keypress; it must reach the host so the host's
        // own modifier state stays correct.
        let sent = classify("ControlLeft", Modifiers::CONTROL, false, HostOs::Windows);
        assert_eq!(sent, Sent::Key(PhysicalKey::ControlLeft));
    }
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `cargo test -p rc-desktop-client input_commands`
Expected: FAIL — `cannot find function classify`.

- [x] **Step 3: Write minimal implementation**

```rust
/// What a key event turned into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    /// A physical key, reproduced exactly on the host.
    Key(PhysicalKey),
    /// A semantic action, spelled by the host in its own chord.
    Intent(Intent),
    /// Nothing: this build does not carry that key.
    Nothing,
}

/// Decide what a key event should become.
///
/// Detection uses the *controller's* table, because the operator typed the chord their
/// own machine's conventions taught them. The host then renders that meaning in its own
/// chord. Neither side models the other, which is what makes all nine platform pairs
/// three tables rather than nine.
fn classify(code: &str, modifiers: Modifiers, passthrough: bool, os: HostOs) -> Sent {
    let Some(key) = PhysicalKey::from_w3c_code(code) else {
        return Sent::Nothing;
    };
    if passthrough {
        return Sent::Key(key);
    }
    match detect(Chord::new(key, modifiers), os) {
        Some(intent) => Sent::Intent(intent),
        None => Sent::Key(key),
    }
}
```

The commands then hold a monotonic `seq` counter, build the matching `InputEvent`, and write it to the input channel. Follow how `video_commands.rs` holds its writer and maps transport errors.

- [x] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rc-desktop-client` then `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: PASS, clippy clean.

- [x] **Step 5: Commit**

```bash
git add apps/desktop-client/src-tauri/src/input_commands.rs apps/desktop-client/src-tauri/src/connection.rs apps/desktop-client/src-tauri/src/lib.rs apps/desktop-client/src-tauri/Cargo.toml
git commit -m "feat(client): send keyboard and pointer input to the remote machine"
```

---

### Task 2: Capturing on the video surface

**Files:**
- Create: `apps/desktop-client/src/inputCapture.ts`, `apps/desktop-client/src/inputCapture.test.ts`
- Modify: `apps/desktop-client/src/VideoSurface.tsx`, `apps/desktop-client/src/videoSurface.test.tsx`

**Interfaces:**
- Consumes: the Task 1 commands.
- Produces: `pointerFraction(event: {clientX,clientY}, rect: DOMRect): {x,y}` and `modifierBits(event: KeyboardEvent | MouseEvent): number`; `<VideoSurface capturing={boolean} …>`.

- [x] **Step 1: Write the failing test**

```typescript
describe('pointerFraction', () => {
  it('maps a click to a fraction of the surface, not to raw pixels', () => {
    // The host multiplies this by its own resolution, so sending pixels would put the
    // pointer somewhere else entirely on any machine with a different screen.
    const rect = { left: 100, top: 50, width: 800, height: 400 } as DOMRect;
    expect(pointerFraction({ clientX: 500, clientY: 250 }, rect)).toEqual({ x: 0.5, y: 0.5 });
  });

  it('clamps a drag that leaves the surface', () => {
    // Releasing outside the canvas must not send a fraction above 1.0, which would
    // land the remote pointer off-screen.
    const rect = { left: 0, top: 0, width: 100, height: 100 } as DOMRect;
    expect(pointerFraction({ clientX: 250, clientY: -40 }, rect)).toEqual({ x: 1, y: 0 });
  });
});

describe('modifierBits', () => {
  it('names modifiers by role so a Mac Command key is META, not a Windows key', () => {
    const event = { ctrlKey: false, altKey: false, shiftKey: false, metaKey: true };
    expect(modifierBits(event as KeyboardEvent)).toBe(0b0000_1000);
  });
});
```

- [x] **Step 2: Run test to verify it fails**

Run: `cd apps/desktop-client && pnpm vitest run src/inputCapture.test.ts`
Expected: FAIL — cannot resolve `./inputCapture`.

- [x] **Step 3: Write minimal implementation**

`pointerFraction` clamps into `0..=1`. `modifierBits` mirrors `Modifiers`' bit layout exactly: SHIFT `0b0001`, CONTROL `0b0010`, ALT `0b0100`, META `0b1000` — **verify these against `crates/protocol/src/input.rs` rather than trusting this list**, since a mismatch silently sends the wrong modifier.

`VideoSurface` gains focus handling: the canvas is focusable, captures `keydown`/`keyup`/`pointermove`/`pointerdown`/`pointerup`/`wheel` **only while focused**, and calls `event.preventDefault()` so the browser does not act on the operator's keystrokes locally. Release capture on blur, and release it explicitly when the component unmounts — a session that ends mid-chord must not leave the operator's own machine believing a key is held.

- [x] **Step 4: Run tests to verify they pass**

Run: `cd apps/desktop-client && pnpm test:run && pnpm typecheck` and `pnpm lint` from the repo root.
Expected: PASS, clean.

- [x] **Step 5: Commit**

```bash
git add apps/desktop-client/src/inputCapture.ts apps/desktop-client/src/inputCapture.test.ts apps/desktop-client/src/VideoSurface.tsx apps/desktop-client/src/videoSurface.test.tsx
git commit -m "feat(client): capture keyboard and pointer on the video surface"
```

---

### Task 3: The passthrough escape hatch

**Files:**
- Modify: `apps/desktop-client/src/SessionToolbar.tsx`, `apps/desktop-client/src/SessionScreen.tsx`, `apps/desktop-client/src/VideoSurface.tsx`, `apps/desktop-client/src/sessionToolbar.test.tsx`, `apps/desktop-client/src/sessionScreen.test.tsx`

**Why this exists.** Intent translation is right for shortcuts and wrong for terminals. A Windows or Linux operator pressing `Ctrl+C` against a remote macOS host has it detected as `Copy` and rendered as `Cmd+C`, so SIGINT never arrives — and the same for `Ctrl+Z`, `Ctrl+A`, `Ctrl+S`. The gap is asymmetric: a macOS operator is unaffected, because `Ctrl+C` is not in the macOS table and already falls through as a physical key. There is no way to say "send this literally", and the toolbar has carried a dead "Keyboard passthrough" toggle since before any of this existed.

- [x] **Step 1: Write the failing test**

```tsx
it('keyboard passthrough sends the literal chord instead of the intent', async () => {
  // Ctrl+C in a remote terminal is SIGINT. Without passthrough it is detected as Copy
  // and arrives as Cmd+C on a macOS host, so the operator can never interrupt.
  renderSession();
  await userEvent.click(screen.getByRole('button', { name: /keyboard passthrough/i }));

  const surface = await screen.findByTestId('video-surface');
  surface.focus();
  await userEvent.keyboard('{Control>}c{/Control}');

  expect(inputKey).toHaveBeenCalledWith(expect.objectContaining({ passthrough: true }));
});
```

- [x] **Step 2: Run test to verify it fails**

Run: `cd apps/desktop-client && pnpm vitest run src/sessionScreen.test.tsx`
Expected: FAIL — the toggle does not reach the capture layer.

- [x] **Step 3: Write minimal implementation**

Wire `passthrough` from `SessionToolbar` through `SessionScreen` into `VideoSurface`, and from there into every `input_key` call. Make the props **required**, matching the decision already taken for `fitted` — an optional prop here would let a caller ship a toggle that looks live and does nothing, which is the exact defect this toggle already had once.

Show the state plainly: while passthrough is on, the surface should say shortcuts are being sent literally. An operator who forgets it is on will wonder why Copy stopped working.

- [x] **Step 4: Run tests to verify they pass**

Run: `cd apps/desktop-client && pnpm test:run && pnpm typecheck`, `pnpm lint` from the root.
Expected: PASS, clean.

- [x] **Step 5: Commit**

```bash
git add apps/desktop-client/src/SessionToolbar.tsx apps/desktop-client/src/SessionScreen.tsx apps/desktop-client/src/VideoSurface.tsx apps/desktop-client/src/sessionToolbar.test.tsx apps/desktop-client/src/sessionScreen.test.tsx
git commit -m "feat(client): let an operator send a chord literally"
```

---

### Task 4: Verification and honest documentation

- [x] **Step 1: Full suite**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo test --workspace -- --test-threads=1
cd apps/desktop-client && pnpm test:run && pnpm typecheck
```

- [x] **Step 2: Update `README.md` and `PROGRESS.md`**

The screen can now be driven. Record what is still missing: `Alt+Tab` is intercepted by the operator's own OS before the app sees it and needs low-level keyboard hooking that is not built; character keys inject by US-layout character, so a non-US *host* layout may produce a different character for letter keys; clipboard sync does not exist.

- [x] **Step 3: Commit**

```bash
git add README.md PROGRESS.md
git commit -m "docs: the remote screen can now be driven"
```
