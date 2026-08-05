# Progress

Last updated: 2026-08-05 · **Phases 1–3 of 9 complete; phase 4 partly done.**

This document is the honest record of what runs today. Anything not listed as done is
not built — there are no mock implementations or placeholder handlers anywhere in the
tree.

## Verification status

All figures below were produced by running the commands, not estimated.

| Check | Command | Result |
|---|---|---|
| Rust format | `cargo fmt --all -- --check` | clean |
| Rust lint | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean (pedantic enabled) |
| Rust tests | `cargo test --workspace` | **574 passed**, 0 failed |
| TS typecheck | `pnpm -r typecheck` | clean (strict, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`) |
| TS lint | `pnpm lint` | clean |
| TS format | `pnpm format:check` | clean |
| TS tests | `pnpm -r test:run` | **85 passed**, 0 failed |
| Frontend build | `pnpm --filter @rc/desktop-client build` | succeeds |
| Full gate | `scripts/verify.ps1` | `All checks passed.` |

Rust test distribution: security 185, transport 61 + 15 end-to-end, protocol 62,
host-agent 66 + 10 two-process integration, storage 49, desktop-client backend 45,
terminal 26, monitoring 24, platform 23, coordination-server 6.
TypeScript: shared-types 51, desktop-client 34.

The 8 integration tests spawn the **real `rc-agent` binary** as a separate process and
drive a real client against it over QUIC. They are what makes the claims below about
pairing, connecting and restarting statements of fact rather than of intent.

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

## Phase 3 — Networking ✅

The agent listens, a client pairs with it over the network, and the two connect,
disconnect and reconnect. Verified by spawning the real agent binary.

### `rc-transport`

- **QUIC + mutually-authenticated TLS 1.3**, ALPN `rc/1`, self-signed device
  certificates pinned by fingerprint. Hostname verification is deliberately absent -
  peers are identified by key, not by name. Certificate chains are refused under every
  policy, because a chain implies a CA there is none of.
- **`peer_certificate_fingerprint`** reads the peer's certificate from the *connection*.
  The endpoint-wide `ObservedPeer` is shared by every concurrent handshake, so
  authorizing against it could match one client against another client's certificate.
  Pinned by a concurrency test that runs two clients at once.
- **Channels**: one bidirectional QUIC stream per channel, tagged with a channel byte,
  frame ceilings enforced from the header before allocation.
- **Handshake**: `Opening` states whether a connection is a session or a pairing
  exchange. Postcard is not self-describing, so inferring it by attempting two decodes
  would let the peer choose the branch. `TrustDirectory` is async and reads through to
  the database on every connection, which is what makes revocation immediate.
- **Pairing over the wire**: the four-message exchange, with both certificate
  fingerprints taken from TLS and never from a message body. Trust is persisted
  *before* the confirmation is sent, so a storage failure cannot leave a client
  believing in a pairing the agent has no record of.
- **Discovery**: mDNS advertise and browse. Everything discovered is an untrusted hint
  about where to dial; nothing is ever pinned from it, and discovery being unavailable
  never prevents connecting.

### `rc-host-agent`

- Binds the listener, accepts connections, and routes each by its `Opening`.
- **Session cap as a reservation released on `Drop`**, so no error path can leak a slot
  and leave the agent refusing everything until it is restarted.
- **Loopback control endpoint**: `GET /health` unauthenticated, `POST /pairing` behind a
  local-control token. The token is a *filesystem capability* - it lives in the agent's
  data directory under the same protection as the keystore - so the set of callers that
  can create trust is exactly the set that could already read the keystore.
- `rc-agent pair` is a client of that endpoint. It previously opened a window in its own
  process, which no client could ever have completed: the proof arrives at the agent,
  whose manager had never heard of it.
- Audit records for every connection outcome, with unknown and revoked reported
  identically on the wire and distinctly in the local trail.

### Desktop client

- **Connection manager** with the full state machine - offline, discovering, connecting,
  authenticating, connected, disconnecting, reconnecting, waiting-to-retry, refused,
  failed - exponential backoff with full jitter, and address selection that tries the
  last working address first.
- **Automatic reconnect happens only after an accident.** Pressing Disconnect sets a
  flag that every retry path checks. Refusals are never retried at all.
- Real pairing and connect/disconnect/reconnect commands, and a Devices screen where
  every button performs the operation it names.

### The bug the integration test found

`DeviceIdentity::from_pkcs8` **reissued the certificate on every load**. The key was
stable, so the device id and identity fingerprint were stable - but the certificate DER
was not, and peers pin the certificate fingerprint at the TLS layer. Every paired client
would have refused the agent after an ordinary reboot, reporting an identity change:
the loudest failure the system has, firing on a routine restart.

Phase 2 could not have caught this, because nothing connected. The two-process restart
test caught it on its first run.

The fix persists the certificate in the keystore and reuses it verbatim, with a one-time
in-place upgrade for keystores written before this. A stored certificate that does not
carry the stored key's public key is refused, so a file assembled from two identities
cannot present a fingerprint peers pin while holding a different key.

### Security decisions made in Phase 3

1. **The listener pins nothing.** It serves many paired clients and a single pin could
   only ever match one. Admission is the handshake's job, and the handshake reads live
   trust state on every connection.
2. **Fingerprints in the pairing transcript come from TLS, never from a message.** This
   is the whole anti-relay property; a fingerprint a peer can choose binds nothing.
3. **The local pairing route is gated by a file, not a password.** The operating
   system's permissions make the access decision; the token only carries it over a
   socket, and is regenerated on every start.
4. **A refusal ends a reconnect loop.** Retrying would turn a loud failure into a quiet
   loop nobody sees - the exact failure mode a fingerprint mismatch exists to prevent.
5. **Session ids are identifiers, not credentials.** A session is authenticated by its
   TLS connection, which cannot be transplanted; nothing is authorized by presenting an
   id, and the UI never displays one as though it were a secret.

### Known limitations after Phase 3

- **Certificate renewal breaks pinning until the client pairs again.** Clients pin the
  certificate fingerprint at the TLS layer, so when an agent renews - after roughly 398
  days - its peers will refuse it. The stored `identity_fingerprint` and
  `record_certificate_rotation` exist for exactly this, but nothing yet performs the
  rotation over the network. Phase 9.
- **Sessions carry no application traffic yet.** The control channel answers `Ping`;
  metrics, terminal, files and video return a typed `Unsupported` rather than an empty
  answer that would put unmeasured figures on a dashboard. Phases 4 to 6.
- **Automatic reconnect is driven by the UI, not by a background supervisor.** The
  policy, the backoff and the intentional-disconnect suppression are implemented and
  tested; nothing yet watches a dropped connection and starts the loop unprompted.
- **Wake-on-LAN, favourites and per-server reconnect preferences** have database columns
  and are read back, but nothing writes them yet. Phase 7.
- The `#[cfg(unix)]` permission tests still did not execute, since this workspace was
  verified on Windows.

## Phase 4 — Terminal and monitoring ⚠ partly complete

Terminals and metrics work end to end. The privileged-operation split does not exist
yet, so this phase is **not** finished; see the limitations below.

### `rc-monitoring`

- CPU (aggregate and per core), memory, swap, disks, network rates, temperatures and
  processes, read from the operating system.
- **Nothing unmeasurable is reported as zero.** No GPU backend is linked, so the GPU
  list is empty rather than showing an idle adapter. Windows has no load average, so it
  is `None` rather than three zeros. A rate over a zero-length interval does not exist,
  so the first snapshot after start carries none.
- One collector for the whole agent. CPU utilisation is measured *across an interval*,
  so a collector per connection would multiply the sampling cost on the machine being
  watched and none of them would agree with the others.
- Sampling intervals are clamped. A client asking for 10 ms would cost a full process
  enumeration a hundred times a second on the server it is supposed to be observing.

### `rc-terminal`

- Real pseudo-terminals: ConPTY on Windows, `openpty` on Unix. Not a simulated shell —
  a child process reading a real terminal device, which is why colour, line editing and
  interactive prompts work without this crate knowing they exist.
- A blocking reader thread feeds a bounded channel, so a shell printing faster than the
  network can carry it applies backpressure rather than growing a buffer.
- A session kills its shell in `Drop`, so no path out — including a dropped connection,
  which is the common case rather than an exotic one — leaves a shell running.
- Shells are chosen by *kind*, never by path. A field accepting a path would be an
  arbitrary-execution API wearing a terminal's clothes.

### Agent and client

- `SystemSnapshot` and `HostInfo` control requests, and the terminal channel served on
  its own task per connection.
- Every request is authorized against the **live** session, not once at connect, so a
  device revoked mid-session stops being answered immediately.
- The client renders terminals with xterm.js. A real emulator rather than escape-stripped
  text, because a shell will not draw a prompt until something answers its `ESC[6n`
  cursor query — stripped output would look like a terminal until asked to be one.
- A Monitoring screen with live readings, sparklines on a fixed 0–100 scale, and sections
  that are absent rather than zeroed when the server could not measure them.

### Security decisions made in Phase 4

1. **Unmeasurable is absent, never zero.** An operator cannot distinguish a cold machine
   from a missing sensor if both read `0 °C`, and will eventually trust the wrong one.
2. **Terminal traffic is never recorded** — not in the log, the audit trail, application
   state or the database. The trail records that a terminal opened, which program it
   launched, and when it closed.
3. **Ctrl+C is a control character, not a signal.** Signalling the shell would kill the
   shell; writing ETX to the terminal interrupts what the shell is running, which is what
   the person pressing it meant.
4. **Elevation is refused, not downgraded.** Opening an unprivileged shell and labelling
   it elevated would be worse than saying no.

### Known limitations after Phase 4

- **The privileged-operation split is not built.** There is no separate privileged
  service on Windows and no sudoers/polkit path on Linux, so elevated terminals are
  refused with a specific error. This is the largest remaining piece of Phase 4.
- **Metrics are polled by the screen showing them**, not pushed on a subscription. The
  `SubscribeMetrics` request is accepted and clamped but no periodic push exists yet, so
  a dashboard costs nothing while nobody is looking at it and updates only while someone
  is.
- **A terminal does not survive a reconnect.** Keeping a PTY alive with nobody watching
  needs an explicit lifetime and a way for the operator to see and end orphaned sessions
  before it is safe to offer.
- **No GPU, battery or disk-health readings.** Each needs a platform-specific backend
  that has not been written; all three are reported as absent.
- Command history, terminal search, output export and the destructive-command
  confirmation templates from the specification are not built.

## Remaining phases

| Phase | Scope | Status |
|---|---|---|
| 3 | QUIC transport, mDNS discovery, connect/disconnect/reconnect lifecycle, connection-state UI | done |
| 4 | Real PTY sessions, system metrics, dashboard, privilege separation | partly done |
| 5 | File manager: browsing, resumable transfers, checksums, transfer queue | pending |
| 6 | Screen capture, encoding, streaming, input forwarding, monitor and quality controls | pending |
| 7 | Process and service management, power actions, confirmations, audit events | pending |
| 8 | Coordination service signalling, NAT traversal, relay fallback, E2E verification | pending |
| 9 | Installers, update architecture, full threat model, security review, documentation | pending |

## Next: finish Phase 4, then Phase 5 — File manager

Remaining in Phase 4:

1. The privileged-operation split: a separate privileged service on Windows reached over
   authenticated local IPC, and a restricted sudoers/polkit path on Linux. Elevated
   terminals depend on it, as does every later phase that changes host state.
2. Pushed metrics on the metrics channel, for a dashboard that updates without polling.

Then Phase 5: browsing, resumable transfers with checksums, a transfer queue, conflict
handling, and path-traversal and symlink-escape protection.

The security assumptions these must preserve are in
[`docs/threat-model.md`](docs/threat-model.md). The one most easily broken by accident:
the privileged helper must validate every request against the allowlist *itself* rather
than trusting that its caller already did.
