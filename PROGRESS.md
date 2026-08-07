# Progress

Last updated: 2026-08-07 · **Phases 1–4 complete; phase 5 mostly complete.**

This document is the honest record of what runs today. Anything not listed as done is
not built — there are no mock implementations or placeholder handlers anywhere in the
tree.

## Verification status

All figures below were produced by running the commands, not estimated.

| Check | Command | Result |
|---|---|---|
| Rust format | `cargo fmt --all -- --check` | clean |
| Rust lint | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean (pedantic enabled) |
| Rust tests | `cargo test --workspace` | **727 passed**, 0 failed |
| TS typecheck | `pnpm -r typecheck` | clean (strict, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`) |
| TS lint | `pnpm lint` | clean |
| TS format | `pnpm format:check` | clean |
| TS tests | `pnpm -r test:run` | **107 passed**, 0 failed |
| Frontend build | `pnpm --filter @rc/desktop-client build` | succeeds |
| Full gate | `scripts/verify.ps1` | `All checks passed.` |

Rust test distribution: security 185, transport 61 + 15 end-to-end, file-transfer 72,
protocol 66, host-agent 89 + 16 two-process integration, storage 49,
desktop-client backend 50, privileged 31 + 11 cross-process, monitoring 27, terminal 26,
platform 23, coordination-server 6.
TypeScript: shared-types 51, desktop-client 56.

The 16 agent integration tests spawn the **real `rc-agent` binary** as a separate process
and drive a real client against it over QUIC. They are what makes the claims below about
pairing, connecting, restarting, terminals, file transfers and pushed metrics statements
of fact rather than of intent.

The 11 privileged tests run a **real helper on a real loopback socket**. Every test that
asks for a refusal sends raw bytes rather than going through the client, precisely so
what is measured is the helper's own enforcement and not the client's convenience checks.

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

## Phase 4 — Terminal and monitoring ✅

Terminals and metrics work end to end, metrics are pushed rather than polled, and the
privileged-operation split exists as a separate elevated process.

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

### `rc-privileged` — the privilege split

A separate elevated process. The agent runs unelevated and *asks*; the helper runs as
`LocalSystem` or root and *decides*. Compromising the network-facing agent yields the
ability to request operations from a closed list, not to run arbitrary code as root.

- **The helper re-validates every request itself**, never trusting that its caller
  already did. The agent checks too, so a mistake is reported immediately without a round
  trip, but that check is a convenience; the helper's is the control. Every refusal test
  sends raw bytes past the client to prove it.
- **An operation crosses the wire, never a command.** There is no field for a program, an
  argument vector or a shell string, so there is nothing for an injection to inject into.
  Resolution to `(program, argv)` happens inside the helper, from constants.
- **Authorization is a file.** A 32-byte token, regenerated at every start and written
  with the same atomic mode-0600 write the keystore uses. Being able to read it *is* the
  authorization — the same model as the agent's own local control endpoint.
- **Loopback only, and the address is not configurable**, so no configuration mistake can
  put a privileged endpoint on the network. Bounded request size, request deadline and
  command deadline.
- **A helper is optional.** `network.privileged_port = 0` says none is installed. Without
  a reachable, elevated helper the agent does not advertise `service_management` or
  `power_control` at all, so the client never offers a button that would fail when
  pressed. The state is probed with a `Ping` at startup and logged once.

Documented in [`docs/privileged-operations.md`](docs/privileged-operations.md).

### Pushed metrics

`SubscribeMetrics` arrives on the control channel; readings go out on the metrics
channel. The two are joined by a per-session `watch` handle created before either exists,
so a client that subscribes before opening the channel does not lose the subscription.

- **`MetricsUpdate` is deliberately lighter than `SystemSnapshot`**: only what changes
  between samples. No process list, no CPU model, no core counts. A tick therefore skips
  the process walk, which is the expensive part of sampling, and static facts are not
  resent every two seconds looking like live readings.
- **Authorization is re-checked every tick**, not captured at subscribe time. A dashboard
  is the longest-lived thing a session holds; capturing the decision once would let a
  device revoked at nine o'clock keep receiving readings all evening.
- **Missed ticks are skipped, not queued.** A client that stops reading receives a current
  sample when it resumes, never a burst of stale ones.
- **A stream that ends says why.** `Stopped { reason }` rather than going quiet, because a
  dashboard that silently stops updating cannot be told apart from an idle server and
  would keep presenting its last reading as current.
- **The client falls back to polling** if the subscription is refused — an older agent, or
  a session that may not watch — so a downgraded pair still shows live figures. The badge
  states which is in use and the interval the server actually accepted after clamping.
- Idle when nobody is subscribed: an open metrics channel with no subscription costs a
  parked task and no sampling at all.

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
5. **The helper is the decision-maker, and the agent's matching check is a convenience.**
   If the client half were deleted entirely, nothing the helper permits would change.
   This is the assumption `docs/threat-model.md` names as the one most easily broken by
   accident, so it is pinned by tests that bypass the client deliberately.
6. **A capability that cannot be performed is not advertised.** Service and power control
   disappear from the agent's capabilities when no helper is reachable, rather than being
   offered and failing.
7. **A refusal from the helper carries a message.** An empty one would be a silent failure
   wearing an error's clothes — the operator sees only the message.
8. **A metrics stream that ends announces itself.** Silence is indistinguishable from an
   idle server, and a frozen dashboard that still looks live is the worse failure.

### Known limitations after Phase 4

- **Elevated terminals are still refused.** The helper performs power and service
  operations; it does not yet spawn an elevated PTY, which needs a token-duplication path
  rather than a command allowlist. Refused with a specific error rather than downgraded.
- **The agent does not yet audit privileged requests.** The helper logs every one; the
  agent's own audit trail gains the corresponding entries with the Phase 7 handlers that
  call it.
- **No installer packaging for the helper.** It runs correctly when started by hand or by
  a service definition, but neither the Windows service registration nor the systemd unit
  is generated yet, and the data-directory ACLs it depends on are still the installer's
  job. Phase 9.
- **A terminal does not survive a reconnect.** Keeping a PTY alive with nobody watching
  needs an explicit lifetime and a way for the operator to see and end orphaned sessions
  before it is safe to offer.
- **No GPU, battery or disk-health readings.** Each needs a platform-specific backend
  that has not been written; all three are reported as absent.
- Command history, terminal search, output export and the destructive-command
  confirmation templates from the specification are not built.

## Phase 5 — File manager ⚠ mostly complete

Browsing, uploading and downloading work end to end and are verified against a real
agent. Folder transfers, a transfer queue and previews are not built; see below.

### `rc-file-transfer`

- **Path resolution against three attack classes.** Traversal is closed by lexical
  normalisation before any I/O; symlink escape by canonicalising and re-checking; and
  Windows device names (`CON`, `NUL`, and any name ending in a space or dot) by an
  explicit refusal list. `CON.txt` does not create a file — it opens the console — so a
  transfer to one would appear to succeed and write nowhere.
- **The check runs twice, and both passes are necessary.** The lexical pass alone misses
  a symlink pointing out of a root. The canonical pass alone cannot run on a path that
  does not exist yet, which is every upload destination — for those the *parent* is
  canonicalised and checked instead, so a file cannot be planted through a symlinked
  parent.
- **Traversal and symlink escape report the identical error.** Distinguishing them would
  tell a peer whether a path exists and whether it is a link: a map of a filesystem it
  was just refused access to.
- **Listings report symlinks, never follow them.** A link to a 40 GB file elsewhere would
  otherwise be listed as a 40 GB file sitting in the directory, which is not what is
  there.
- **Transfers are verified, not assumed.** A completed transfer whose BLAKE3 digest does
  not match is *discarded*, in both directions. A file that is silently wrong is worse
  than a transfer that failed: the failure is found now, by whoever can retry it; the
  corruption is found later, by whoever depended on it.
- **Resuming verifies the prefix** against a digest over the same range. A resume that
  trusted the offset alone would splice two different files together and pass no check
  until the final digest.
- **Written aside and renamed in** after verification, so a failed transfer leaves the
  original file intact and leaves a partial with an obviously incomplete name.

### Agent

- Serves the file channel: list, stat, checksum a range, create, rename, copy, delete,
  upload and download.
- **Two capabilities, checked per message against the live session.** Reading needs
  `FileRead`; anything that changes the filesystem needs `FileWrite`. Which one a message
  needs comes from an explicit list of read-only operations, so an operation added later
  falls through to the write half — the safe side to default to.
- Confinement comes from `features.file_transfer_roots`. An empty list means the whole
  filesystem, which is the right default for a server the operator administers and is
  stated rather than assumed. Roots that cannot be applied fail closed to *no* file
  access.
- Deletion never infers recursion, and removes a symlink as a link rather than following
  it to a target that may be outside the roots.

### Client

- Two-pane file manager: this machine on the left, the server on the right, with
  navigation, hidden-file toggle, conflict policy, new folder and delete.
- **File bytes never enter the webview.** The backend reads and streams them. Passing a
  gigabyte through a JavaScript string would be slow, would double its memory, and would
  put file contents somewhere a rendering bug could reach.
- Names are rendered as inert text after the schema strips control characters and
  bidirectional overrides — without which `co<U+202E>gnp.exe` displays as `codexe.png`.
- Deleting shows the full resolved path and says plainly that there is no recycle bin.

### Security decisions made in Phase 5

1. **Unmeasurable and unresolvable both fail closed.** A path that cannot be resolved is
   refused; roots that cannot be applied permit nothing.
2. **A failed checksum discards the file**, on both sides, rather than keeping it with a
   warning.
3. **An unrecognised conflict policy means "stop and ask".** Every other option
   overwrites or renames something, so defaulting to one of those would make a UI bug
   destructive.
4. **The local pane is resolved too.** It is not "safe because it is local": paths still
   arrive from a webview, and a NUL or a reserved name is refused before it reaches an
   `open`.

### Known limitations after Phase 5

- **No folder upload or download.** Only individual files; a recursive transfer needs a
  queue with progress and a cancel path.
- **No transfer queue, pause, or per-transfer progress in the UI.** The library resumes
  correctly and the agent offers a resume point, but nothing drives it from the
  interface yet — a transfer is one blocking call that reports when it finishes.
- **No recycle bin, previews, archive handling, drag-and-drop, or disk-space
  validation.** A full disk is reported when the write fails rather than predicted.
- Copying a directory is refused rather than partially performed.

## Remaining phases

| Phase | Scope | Status |
|---|---|---|
| 3 | QUIC transport, mDNS discovery, connect/disconnect/reconnect lifecycle, connection-state UI | done |
| 4 | Real PTY sessions, system metrics, dashboard, privilege separation | done |
| 5 | File manager: browsing, resumable transfers, checksums, transfer queue | mostly done |
| 6 | Screen capture, encoding, streaming, input forwarding, monitor and quality controls | next |
| 7 | Process and service management, power actions, confirmations, audit events | pending |
| 8 | Coordination service signalling, NAT traversal, relay fallback, E2E verification | pending |
| 9 | Installers, update architecture, full threat model, security review, documentation | pending |

## Next: Phase 6 — Remote desktop

1. Screen capture on both platforms, with a software encoder and a hardware path where
   one is available.
2. Video streaming over the video channel, with adaptive quality driven by measured
   throughput rather than a fixed guess.
3. Input forwarding, gated on `RemoteInput` and disabled the moment authorization is
   lost.
4. Monitor enumeration and switching, and the connection statistics the specification
   asks for.

Still outstanding from earlier phases, and worth doing before or alongside Phase 6:

- **A transfer queue** with progress and pause/resume in the file manager UI, plus folder
  transfers (Phase 5).
- **Phase 7's service and power handlers**, which are now unblocked: the privileged helper
  is built, reachable and proven, but nothing on the control channel calls it yet.
- **A background reconnect supervisor** (Phase 3), so a dropped connection starts the
  retry loop without the UI driving it.

The security assumptions these must preserve are in
[`docs/threat-model.md`](docs/threat-model.md). The one most easily broken by accident is
now built and pinned by tests: the privileged helper validates every request against the
allowlist *itself* rather than trusting that its caller already did. Phase 7 will add the
handlers that call it, and the temptation there will be to let the agent's check stand in
for the helper's. It must not — see
[`docs/privileged-operations.md`](docs/privileged-operations.md).
