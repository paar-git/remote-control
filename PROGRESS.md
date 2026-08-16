# Progress

What works today, measured rather than remembered. Every figure below came from running
the command next to it against the current tree.

There is no phase numbering here any more. The old document tracked a nine-phase plan
that the product no longer follows: the plan assumed a pairing exchange, an owner
account, a role hierarchy, a coordination server, mDNS discovery, a privileged helper
and a remote terminal, and all seven have been deleted. Tracking progress against a plan
that has been abandoned describes the plan, not the product.

## What works

**Two machines can connect to each other.** One types the address the other displays.
The connection runs over QUIC with mutually-authenticated TLS 1.3, and completing that
handshake admits nothing on its own — the machine being connected to then decides.

**The admission decision is real and is enforced.** Incoming access must be on,
then a trusted device identity, an unattended password, or a person clicking
Accept, checked in that order. Trust is keyed on the identity the peer proved
through TLS, not the address it was typed at.
A stranger answering at a trusted device's address is refused as `IdentityChanged`
rather than prompted. A wrong password is a refusal rather than a fallback to the
dialog. Accepting with no permissions ticked is a refusal. See
[`docs/access-model.md`](docs/access-model.md).

**The window is four categories, and each one leads somewhere.** Remote Control is
connect plus this device. My Devices is the trust list with a real presence probe.
Sessions separates what is happening now from what already happened, and a banner
sits above every page while someone is controlling this machine. Settings is
sections, not more navigation.

**A session holds exactly what it was granted.** Fixed at admission, carried on the
session, and re-checked on every request rather than once at connect. Both machines
enforce it; the one being controlled is the authority. Six permissions, five of them
offered on the Accept dialog; `Administer` is reachable only from a trusted device's own
settings.

**Over a live session:** the remote screen, file browsing and chunked, resumable
transfer in both directions, and live system metrics. Each is gated on the permission
that covers it, and a tool whose permission was withheld is absent from the interface
rather than present and failing.

**The remote screen arrives losslessly.** The host tiles each frame at 64×64, hashes
every tile, and sends only the ones that changed, compressed with zstd — so a still
desktop costs nothing and a moving one costs what actually moved. Lossless is a
deliberate choice rather than a stopgap: this stream carries terminals and log output,
where compression artifacts on small text are the failure that matters, not bandwidth.
Encode and decode are covered by a property test asserting the picture comes back
byte-for-byte identical.

A refresh too large for one frame is split across several and reassembled, because a 4K
screen exceeds the channel's frame ceiling before a single pixel of overhead. Damage is
computed from the frames themselves rather than asked of the operating system, which is
why all three platforms behave identically. A dropped frame is noticed by its sequence
gap and repaired by requesting a keyframe, rather than leaving a permanently wrong
picture for a human to spot.

**Watching a screen is its own permission.** Not implied by being allowed to move the
pointer, and not granted by unattended access that was given for something else.

**The remote machine can be driven.** The surface forwards keys, pointer motion, clicks
and the wheel while it holds focus — only while focused, so the operator can still use
their own machine during a session. Shortcuts cross by *meaning* rather than by key: the
controller recognises the chord its own OS taught the operator, and the host spells that
meaning in its own chord, so Copy is Copy in either direction. A toggle sends a chord
literally where a program needs the raw keys instead, because `Ctrl+C` in a remote
terminal is SIGINT rather than Copy. Keys still held are released explicitly on blur and
on unmount, since the host has no other way to learn a key came up.

**A refusal is visible, and so is a host that falls behind.** A revoked `control_input`
grant reads as a refusal naming its reason rather than as a frozen screen, and a host too
busy to apply input says so — a round-trip ping stays healthy while the machine at the
other end does not.

**Multi-monitor hosts are navigable.** The picker draws the host's real arrangement from
its reported geometry, and the pointer reaching an edge with a monitor beyond it carries
across to the corresponding point rather than stopping at the seam. The layout is kept
current by the host's own unsolicited pushes, because a monitor plugged in mid-session
moves where every later coordinate lands.

**Clipboard text is shared, and it is its own permission.** A clipboard carries whatever
its owner last copied — routinely a password or a key that was never on screen — so it
is not implied by being allowed to type. Both ends hold the state that stops the two
echoing a value back and forth forever, and the relaying side keeps a digest rather than
the text.

**The application updates itself** from a signed release manifest, verifying a SHA-256
checksum before anything is installed and never installing without confirmation.

## What does not work yet

**Desktop shortcut grabbing is written but has never run on a real desktop.** `Alt+Tab`
and its kin are intercepted by the *operator's* own OS before this app sees them, so a
low-level keyboard hook takes them back and forwards each as the intent it means —
`SwitchApp`, `ShowDesktop`, `LockScreen`. The policy deciding which chords to take, when
to hold the grab, and what to do with one that was caught is pure and tested on every
platform. The hook itself exists for **Windows only**, compiles, and has never been
installed on a running desktop. macOS and Linux report `Unsupported` rather than taking
nothing quietly: macOS needs a `CGEventTap` with the Accessibility grant, X11 needs
`XGrabKey`, and Wayland has no portable equivalent at all.

**`Ctrl+Alt+Del` cannot be forwarded, and says so.** It is dispatched on the Secure
Desktop, above every hook an ordinary process may install. It is named unreachable
rather than offered, because a switch that quietly did nothing would leave an operator
believing they had sent it to a machine they cannot see.

**Character keys are injected by position on Windows and macOS, by character on Linux.**
Windows uses virtual-key codes and macOS `kVK_ANSI_*` `CGKeyCode`s, so the physical key
travels and the host's own layout decides what it types. Linux still goes by character,
because enigo's escape hatch there is a *keysym*, which names a character rather than a
position — so a Linux host on a non-US layout may still type something other than what
the operator pressed. None of these tables has injected a keystroke on real hardware.

Also absent from the video path: H.264 and every other lossy codec (the variants exist
and negotiation refuses them), adaptive quality, and viewing more than one display at
once — a session shows one display at a time, though it can now switch between them and
carry the pointer across their edges. `QualityPreset` is accepted and reported back but
changes nothing, because the only codecs implemented are lossless.

**Screen capture is verified on Windows only.** macOS and Linux compile and are covered
by CI, but no frame has ever been captured on either. Wayland is refused outright rather
than returning black frames.

**Cross-machine use has not been confirmed by hand.** Everything below is verified by
automated tests, including twelve cases driven against the real `rc-agent` binary in
its own process. A run between two *physical* machines on a real network has not been
recorded.

## Deleted, and why the test count fell

Seven subsystems were removed. This is the largest single change in the project's
history and it is the reason the Rust suite is smaller than it was:

| Removed | Why |
|---|---|
| Pairing protocol | Replaced by the Accept dialog. It was the single largest obstacle to the product being usable. |
| Owner account and login | There is no account. The desktop session lock is the boundary. |
| Role hierarchy | Reduced to four permissions with no roles above them. |
| Coordination server | Nothing routed through it; machines are reached by address. |
| mDNS discovery | Announced the application to the whole network to save reading an address off a screen. |
| Privileged helper | Service and power control went with it. |
| Remote terminal | Out of scope for this product. |

**Rust tests: 814 → 582.** Every one of the removed tests belonged to deleted code,
and each drop was reconciled against what was deleted at the time it happened. The
largest single fall was 156 tests when the pairing protocol went, which had been the
most heavily tested subsystem in the tree.

This is a smaller product, not a less tested one. Read the number as deletion rather
than decay.

**TypeScript tests: 129 → 265**, because the interface was rewritten rather than
removed, then rebuilt around four categories.

## Verification

Run against the current tree. Reproduce with `pnpm verify`.

| Command | Result |
|---|---|
| `cargo test --workspace` | **876 passed**, 0 failed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean, exit 0 |
| `cargo fmt --all --check` | clean |
| `pnpm -r test:run` | **388 passed**, 0 failed (337 desktop + 51 shared-types) |
| `pnpm -r typecheck` | clean |
| `pnpm run lint` | clean |
| `pnpm run format:check` | clean |
| `pnpm verify` | clean, exit 0 |
| `node scripts/check-version-sync.mjs` | `Version sync OK: 0.2.0` |

Clippy runs at pedantic with `-D warnings` across all targets and all features. A
warning is a build failure.

## The tests worth knowing about

Not a list of everything, but the ones that pin a property rather than a behaviour:

- **A granted peer is admitted with exactly what was granted**, over two real QUIC
  endpoints, asserted on both sides against a strict subset rather than "everything" —
  so a wholesale replacement anywhere in the exchange would fail it.
- **A refused peer receives nothing identifying**, asserted against the raw frame bodies
  that actually crossed the wire rather than against a struct's shape.
- **The dialled address reaches the decision**, with the complement asserted too: the
  dialled port is checked to differ from the peer's ephemeral source port, so the test
  cannot pass by coincidence.
- **The lockout holds under concurrency.** Five simultaneous attempts, asserting an
  exact split of three refusals and two lockouts rather than "some were blocked". The
  pre-fix code produced five refusals.
- **An over-long password takes the same time** whether or not unattended access is
  configured, asserted with a wall-clock bound rather than only on the outcome.
- **The two address parsers agree.** `address.ts` re-implements `PeerAddress::from_str`
  so a typo is reported under the field instead of arriving as a timeout;
  `crates/transport/tests/address_cross_check.rs` is the table both must satisfy.
- **The access model, against the real binary.** Twelve cases in
  `crates/host-agent/tests/access_e2e.rs` spawn `rc-agent` as its own process with a
  seeded database and drive a real client at it over QUIC: dismissal, a refusal
  never retried, not-accepting, wrong password, a stranger at a trusted address, a
  correct password, a trusted identity admitted without a prompt, a withheld
  permission refused per request, a grant surviving a restart, a revoked device
  refused after restart, a suspended device refused while keeping its settings,
  and a second device unable to reuse the first's grant.

## Known loose ends

- **Existing address-keyed certificate pins are not migrated.** They record a
  certificate digest whose identity was never stored, so the new trust key cannot be
  derived from them. Machines that were "always allowed" under the old pin must be
  accepted again.
- **The four-page UI and the TypeScript IPC wrappers were implemented in the same
  session that finished them.** They have tests; they have not had a separate review
  pass.
- **The unattended verification uses a hard-coded production hashing policy** for the
  dummy hash, while a stored credential is verified at whatever policy its PHC string
  encodes. If a credential were ever stored under a weaker policy, the timing
  distinction that was closed for over-long passwords would reopen for normal ones.
