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

**The admission decision is real and is enforced.** A trusted device identity, an
unattended password, or a person clicking Accept, checked in that order. Trust is
keyed on the identity the peer proved through TLS, not the address it was typed at.
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
enforce it; the one being controlled is the authority.

**Over a live session:** file browsing and chunked, resumable transfer in both
directions, and live system metrics. Both are gated on the permission that covers them,
and a tool whose permission was withheld is absent from the interface rather than
present and failing.

**The application updates itself** from a signed release manifest, verifying a SHA-256
checksum before anything is installed and never installing without confirmation.

## What does not work yet

**There is no remote display.** No screen capture, no input injection. The session
screen says so in a sentence rather than rendering an empty frame that would look like a
picture that had not loaded yet. `control_input` exists as a permission and is granted
and enforced, but nothing consumes it yet.

**Cross-machine use has not been confirmed by hand.** Everything below is verified by
automated tests, including nine cases driven against the real `rc-agent` binary in its
own process. A run between two *physical* machines on a real network has not been
recorded.

## Deleted, and why the test count fell

Seven subsystems were removed. This is the largest single change in the project's
history and it is the reason the Rust suite is smaller than it was:

| Removed | Why |
|---|---|
| Pairing protocol | Replaced by the Accept dialog. It was the single largest obstacle to the product being usable. |
| Owner account and login | There is no account. The desktop session lock is the boundary. |
| Role hierarchy | Reduced to three permissions with no roles above them. |
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

**TypeScript tests: 129 → 256**, because the interface was rewritten rather than
removed, then rebuilt around four categories.

## Verification

Run against the current tree. Reproduce with `pnpm verify`.

| Command | Result |
|---|---|
| `cargo test --workspace` | **662 passed**, 0 failed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean, exit 0 |
| `cargo fmt --all --check` | clean |
| `pnpm -r test:run` | **256 passed**, 0 failed (205 desktop + 51 shared-types) |
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
- **The access model, against the real binary.** Nine cases in
  `crates/host-agent/tests/access_e2e.rs` spawn `rc-agent` as its own process with a
  seeded database and drive a real client at it over QUIC: dismissal, not-accepting,
  wrong password, a stranger at a trusted address, a correct password, a trusted
  identity admitted without a prompt, a withheld permission refused per request, a
  grant surviving a restart, a revoked device refused after restart, and a second
  device unable to reuse the first's grant.

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
