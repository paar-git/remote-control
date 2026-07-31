# Progress

Last updated: 2026-07-31 · **Phase 2 of 9 complete.**

This document is the honest record of what runs today. Anything not listed as done is
not built — there are no mock implementations or placeholder handlers anywhere in the
tree.

## Verification status

All figures below were produced by running the commands, not estimated.

| Check | Command | Result |
|---|---|---|
| Rust format | `cargo fmt --all -- --check` | clean |
| Rust lint | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean (pedantic enabled) |
| Rust tests | `cargo test --workspace` | **343 passed**, 0 failed |
| TS typecheck | `pnpm -r typecheck` | clean (strict, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`) |
| TS lint | `pnpm lint` | clean |
| TS format | `pnpm format:check` | clean |
| TS tests | `pnpm -r test:run` | **75 passed**, 0 failed |
| Frontend build | `pnpm --filter @rc/desktop-client build` | succeeds |
| Full gate | `scripts/verify.ps1` | `All checks passed.` |

Rust test distribution: security 173, protocol 54, storage 49, host-agent 31,
platform 23, desktop-client backend 7, coordination-server 6.
TypeScript: shared-types 51, desktop-client 24.

## Phase 1 — Foundation ✅

- **Monorepo**: Cargo workspace (resolver 3, edition 2024) + pnpm workspace, shared
  lint/format/test configuration, workspace-wide dependency pinning.
- **`rc-protocol`**: length-prefixed framing with per-channel size ceilings enforced
  from the header before allocation; six channels; version negotiation; typed
  identifiers; bounded sliding-window replay guard; message types for control,
  pairing, terminal, files, system and desktop.
- **`rc-storage`**: SQLite schema with 9 tables, `STRICT` typing, `CHECK` constraints,
  foreign keys, WAL, embedded migrations, additive-only policy that refuses to open a
  schema newer than the binary.
- **`rc-platform`**: per-OS directory resolution, host inventory, and the
  privileged-command allowlist with a protected-services deny-list.
- **`rc-host-agent`**: `run` / `check` / `print-config` / `write-config`; validated
  TOML configuration; rotating JSON + console logging; SIGTERM and Ctrl+C handling.
  **Verified booting**, migrating its database and shutting down cleanly.
- **`rc-coordination-server`**: axum service, loopback-by-default binding, request
  body limit, `/health`.
- **`@rc/shared-types`**: Zod mirror of the protocol; branded identifiers; the
  reconnection decision policy and backoff with jitter.
- **Desktop client**: Tauri 2 + React 19 + Vite 8 + Tailwind 4; strict CSP; minimal
  capability grant; validated IPC boundary; real status panel driven by a working
  `client_info` command.

### Security decisions made in Phase 1

1. **mTLS over QUIC with pinned self-signed certificates**, rather than a hand-rolled
   handshake. Mutual authentication, forward secrecy and TLS 1.3 come from reviewed
   implementations; the project's own crypto surface is limited to the pairing proof.
2. **External serde tagging on the wire.** Postcard is not self-describing, so serde's
   internally-tagged representation silently fails to decode. Caught before it could
   become a runtime bug.
3. **Command allowlist resolves to `(program, argv)`, never a string.** Injection is
   structurally impossible rather than filtered. 18 injection payloads are tested.
4. **Fail-closed on unknown enum variants.** A power or service action from a newer
   peer is rejected, not approximated.
5. **Sanitising untrusted text strips bidirectional overrides** as well as control
   characters, so a file named `cod<U+202E>txt.exe` cannot render as `codexe.txt`.
6. **`OwnerAccountRow` deliberately does not derive `Serialize`**, so a password hash
   cannot reach the frontend by accident. Pinned by a test.
7. **Coordinator binds loopback by default**; exposure requires an explicit flag and
   logs a warning.
8. **Fingerprint comparison rejects malformed input on both sides**, so two invalid
   values never compare equal.

### Known limitations after Phase 1

- **Sidebar sections other than Home are disabled**, each labelled with the phase that
  implements it. They are inert, not fake.
- `is_elevated()` on Windows probes an Administrator-only directory rather than
  querying the token, to keep `unsafe_code` forbidden. Correct in practice; will be
  revisited if a safe binding is added.

## Phase 2 — Secure pairing ✅

### `rc-security`

A new crate holding the security core. `#![forbid(unsafe_code)]` throughout — the DPAPI
path goes through the maintained `windows-dpapi` wrapper rather than raw FFI.

- **Device identity**: Ed25519 long-term keys; TLS certificates via `rcgen`; SHA-256
  certificate and public-key fingerprints; device ids *derived* from the identity public
  key, so an id cannot be claimed without the key. Certificate renewal preserves the
  device id and identity fingerprint, so trust survives it.
- **Keystore**: versioned JSON envelope; DPAPI (`CurrentUser` scope, with
  application-specific secondary entropy) on Windows; mode `0600` in a `0700` directory
  on Unix, where unsafe permissions are a hard error rather than a warning; atomic
  write-and-rename; BLAKE3 keyed integrity hash; a file from a newer format version is
  refused rather than guessed at.
- **Pairing codes**: 9 characters over a 30-symbol unambiguous alphabet (≈44 bits),
  rejection-sampled so the mapping stays uniform; stored only as `Argon2id(code, salt)`;
  180-second default TTL; single-use; 5-attempt cap. `PairingCode` implements neither
  `Serialize` nor `Display` and redacts its `Debug`; the sole exposure path is
  `expose_for_display()`.
- **Pairing protocol**: length-prefixed transcript committing to protocol version,
  session id, both device ids, both identity and certificate fingerprints, both nonces,
  the code verifier, the expiry and the requested permissions. Three domain-separated
  labels so the client's proof cannot be echoed back as the agent's. Consumption is
  atomic under one mutex.
- **Owner passwords**: Argon2id at m=19 MiB, t=2, p=1 (OWASP first recommendation);
  unique 16-byte salt; 12–1024 byte inputs; no normalisation; `Zeroizing` buffers;
  parameters carried inside the PHC string so hashes upgrade transparently on the next
  successful login.
- **Throttle**: injected-clock lockout with a bounded tracked-key map that prefers
  keeping locked entries, so key-cycling can neither exhaust memory nor clear someone
  else's lockout.
- **Permissions**: 10 typed capabilities across `Owner` / `Operator` / `ViewOnly`.
  `Capability` is `#[non_exhaustive]` and the grant table is an exhaustive `match`, so
  adding a capability without assigning it is a compile error.

### `rc-storage`

- Migration `0002_pairing_and_trust.sql` (additive only): trust metadata, pairing-code
  outcomes, Argon2 parameter columns.
- `TrustRepository`: list, find, find-by-identity, rename, revoke, record
  authentication, record certificate rotation, favourite. Revocation is immediate at the
  repository layer. Registering one identity under two device ids is rejected.
- `OwnerRepository`: create (no default password, exactly one owner), authenticate,
  throttle, persist lockout across restarts, detect and apply hash upgrades.
- `AuditRepository`: typed key/value metadata with a secret-looking-key redaction
  backstop.

### `rc-host-agent`

- `identity` and `pair` subcommands. Identity is created on first run and never silently
  regenerated.
- `complete_pairing` verifies a proof, records trust before returning the confirmation,
  and audits completion, rejection and throttling as three distinct events. It is fully
  implemented and tested; Phase 3 supplies the network path that reaches it.
- Pairing rows left `open` by a previous run are swept to `expired` on startup, so the
  trail never implies a live code.

### Desktop client

- Real **Devices screen**: empty state, trusted-device list, device name / id /
  fingerprint / role / first-paired / last-authenticated, rename, revoke with
  confirmation, copy fingerprint, and a separate section for revoked devices explaining
  they are retained for history and cannot connect.
- Owner setup and login flow.
- All data crosses the IPC boundary through typed, schema-validated commands returning
  DTOs — never database rows. No private key, password hash, or pairing verifier has a
  path to the frontend.
- The pairing panel states plainly that completing an exchange needs Phase 3. **There is
  no Connect button.**

### Security decisions made in Phase 2

1. **DPAPI at `CurrentUser` scope, not machine scope.** Machine scope would let every
   process on the host decrypt the key. The cost is that changing the service account
   requires re-running setup, reported as a specific `KeystoreWrongIdentity` error.
2. **Secondary DPAPI entropy.** Not a secret, but it raises the bar from "any process
   running as this user" to "a process written against this application".
3. **Length-prefixed transcript fields.** With naive concatenation, shifting a character
   between adjacent fields leaves the bytes unchanged — an attacker could move meaning
   between fields without altering the proof.
4. **Three domain-separation labels**, so an observed client proof cannot be replayed as
   the agent's confirmation.
5. **Clients pin the identity fingerprint, not the certificate fingerprint**, so routine
   renewal is not indistinguishable from identity substitution.
6. **Unsafe Unix permissions are a hard error.** A world-readable private key is already
   compromised; continuing would only hide it.
7. **No password normalisation.** Normalisation silently changes what the user typed,
   and the set of strings that normalise together is not something a user can reason
   about.
8. **Wrong code and wrong transcript return the identical error**, so failure is not an
   oracle. A missing owner account performs a full dummy hash and returns the identical
   error, so login is not an enumeration oracle.
9. **Throttle checked before hashing**, so lockout cannot be turned into a
   work-amplification vector.
10. **Capabilities over role checks.** `Capability` is `#[non_exhaustive]` with an
    exhaustive grant table, making an undecided capability a compile error.

### Known limitations after Phase 2

- **No network path exists yet.** The agent does not bind a QUIC listener; the client
  cannot connect to anything. Two devices can be paired cryptographically but cannot
  communicate. This is Phase 3.
- **`complete_pairing` is reachable only from tests.** It is fully implemented and
  covered, but nothing calls it in production until the Phase 3 listener exists. It
  carries a scoped `#[allow(dead_code)]` with that rationale rather than being deleted
  and rewritten later without its tests.
- **Pairing sessions do not survive a restart, by design.** A code whose window the
  operator has lost track of is worse than making them start again.
- **The Unix permission paths are enforced in code and tested, but this workspace was
  verified on Windows**, so the `#[cfg(unix)]` tests did not execute here. They are not
  claimed as passing on Linux until CI runs there — Phase 9.
- Windows data-directory ACLs rely on the installer; the requirement is documented in
  `docs/keystore-format.md`. Phase 9.
- Session tokens are not implemented; they belong with the transport in Phase 3.
- No integration tests yet — they need two processes that can talk, so they arrive with
  Phase 3.

## Remaining phases

| Phase | Scope | Status |
|---|---|---|
| 3 | QUIC transport, mDNS discovery, connect/disconnect/reconnect lifecycle, connection-state UI | next |
| 4 | Real PTY sessions, system metrics, dashboard, privilege separation | pending |
| 5 | File manager: browsing, resumable transfers, checksums, transfer queue | pending |
| 6 | Screen capture, encoding, streaming, input forwarding, monitor and quality controls | pending |
| 7 | Process and service management, power actions, confirmations, audit events | pending |
| 8 | Coordination service signalling, NAT traversal, relay fallback, E2E verification | pending |
| 9 | Installers, update architecture, full threat model, security review, documentation | pending |

## Next: Phase 3 — Networking

1. QUIC transport with mutually-authenticated TLS 1.3, using the Phase 2 device
   certificates and pinned fingerprints.
2. Bind the agent listener; wire `complete_pairing` to a real pairing endpoint that is
   reachable only while the operator has a window open.
3. Connection lifecycle: connect, disconnect, reconnect with the existing backoff
   policy; `DisconnectReason::permits_auto_reconnect` already governs whether a retry is
   allowed.
4. mDNS discovery on the local network.
5. Connection-state UI, replacing the disabled Phase 3 affordances on the Devices
   screen.
6. Session tokens: issued on authentication, stored hashed, short-lived, rotating.
7. Integration tests across two real processes — the first phase where they are
   possible.

The security assumptions this phase must preserve are listed in
[`docs/threat-model.md`](docs/threat-model.md#security-assumptions-phase-3-networking-must-preserve).
The two that are easiest to break by accident: the transcript's certificate
fingerprints must come from the observed TLS connection rather than the message body,
and revocation must be re-checked per connection rather than trusted from cached state.
