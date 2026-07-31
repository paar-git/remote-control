# Progress

Last updated: 2026-07-31 · **Phase 1 of 9 complete.**

This document is the honest record of what runs today. Anything not listed as done is
not built — there are no mock implementations or placeholder handlers anywhere in the
tree.

## Verification status

All figures below were produced by running the commands, not estimated.

| Check | Command | Result |
|---|---|---|
| Rust format | `cargo fmt --all -- --check` | clean |
| Rust lint | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean (pedantic enabled) |
| Rust tests | `cargo test --workspace` | **122 passed**, 0 failed |
| TS typecheck | `pnpm -r typecheck` | clean (strict, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`) |
| TS lint | `pnpm lint` | clean |
| TS format | `pnpm format:check` | clean |
| TS tests | `pnpm -r test:run` | **62 passed**, 0 failed |
| Frontend build | `pnpm --filter @rc/desktop-client build` | succeeds |

Rust test distribution: protocol 54, host-agent 23, platform 23, storage 12,
coordination-server 6, desktop-client backend 4.

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

- **No network path exists yet.** The agent does not bind a QUIC listener; the client
  cannot connect to anything. This is Phase 3.
- **No pairing, no device identity generation.** Phase 2.
- **Sidebar sections other than Home are disabled**, each labelled with the phase that
  implements it. They are inert, not fake.
- Windows file permissions on the data directory rely on the installer setting the
  parent ACL; the Unix `0700` path is enforced in code and tested. Phase 9.
- `is_elevated()` on Windows probes an Administrator-only directory rather than
  querying the token, to keep `unsafe_code` forbidden. Correct in practice; will be
  revisited if a safe binding is added.
- No integration tests yet — they need two processes that can talk, so they arrive
  with Phase 3.

## Remaining phases

| Phase | Scope | Status |
|---|---|---|
| 2 | Device identities, pairing codes, trusted-device storage, mutual auth, saved-device screen | next |
| 3 | QUIC transport, mDNS discovery, connect/disconnect/reconnect lifecycle, connection-state UI | pending |
| 4 | Real PTY sessions, system metrics, dashboard, privilege separation | pending |
| 5 | File manager: browsing, resumable transfers, checksums, transfer queue | pending |
| 6 | Screen capture, encoding, streaming, input forwarding, monitor and quality controls | pending |
| 7 | Process and service management, power actions, confirmations, audit events | pending |
| 8 | Coordination service signalling, NAT traversal, relay fallback, E2E verification | pending |
| 9 | Installers, update architecture, full threat model, security review, documentation | pending |

## Next: Phase 2 — Secure pairing

1. Create `crates/security`: Ed25519 device identity, certificate generation via
   `rcgen`, SHA-256 fingerprints, OS keystore integration (DPAPI / `0600` file).
2. Pairing codes: CSPRNG over an unambiguous alphabet, hashed at rest, TTL,
   single-use, attempt-capped.
3. Transcript-bound pairing proof committing to **both** certificate fingerprints, so
   a relayed exchange cannot succeed.
4. Trusted-device repository over `rc-storage`, including revocation.
5. Argon2id owner account with login throttling.
6. Devices screen in the client: pair, list, rename, favourite, copy fingerprint,
   revoke.
7. Tests: code expiry, single use, attempt cap, wrong-code rejection, fingerprint
   mismatch, persistence across restart, throttling.
