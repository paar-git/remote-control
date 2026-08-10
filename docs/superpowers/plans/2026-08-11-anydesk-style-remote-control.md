# AnyDesk-style Remote Control Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Strip the terminal, privileged-helper, coordination-server, owner-account and pairing subsystems out of the product, replace authorisation with AnyDesk's connect-and-accept model plus an optional unattended password, fold host and client into one binary, and rebuild the interface on a light AnyDesk-style palette.

**Architecture:** `rc-host-agent` becomes a library plus a thin service binary, so the Tauri desktop application can embed the host side and be both controller and controlled. A connection is authorised by one of three paths, checked in order: a pinned always-allow peer, a correct unattended password, or a human pressing Accept. Authorisation is a `PermissionSet` carried on the live session and re-checked on every request. The frontend collapses from an eleven-section sidebar shell to two states — main window and session — with session tools on a floating toolbar.

**Tech Stack:** Rust (edition 2024, workspace resolver 3), tokio, QUIC via quinn, rustls, postcard, SQLite via sqlx, Argon2id; TypeScript 5.9, React 19, Vite 8, Tailwind 4, Zod 4, Vitest 4, Tauri 2.

**Spec:** `docs/superpowers/specs/2026-08-11-anydesk-style-remote-control-design.md`

## Global Constraints

- Rust edition 2024, `rust-version = "1.90"`, workspace resolver 3. Never bump these.
- `crates/security` keeps `#![forbid(unsafe_code)]`. Never relax it.
- Clippy runs pedantic with `-D warnings` across all targets and all features. A warning is a failure.
- TypeScript is pinned to 5.9 (not 7.x) because `typescript-eslint` requires `typescript <6.1.0`. Never bump it.
- TypeScript is strict with `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`.
- No mock implementations, no placeholder handlers, no stub returns anywhere in the tree. If something cannot be measured or performed, it is **absent**, never zero and never faked.
  - **Ruled 2026-08-11:** this bans code that pretends to work. Interface copy that states plainly a feature is not in this version — such as the session screen's display panel in Task 17 — is the opposite of a stub and satisfies the constraint rather than violating it. Do not flag it.
- **Ruled 2026-08-11:** address parsing is implemented twice, in `crates/transport/src/address.rs` and in `apps/desktop-client/src/address.ts`. This is deliberate, not drift. The backend's copy is the authority and re-validates every address; the frontend's exists only so a typo is reported under the field rather than as a connection failure seconds later. Do not flag it as duplication, and do not collapse it to one implementation.
- Every value crossing the Tauri IPC boundary is validated by a Zod schema in `apps/desktop-client/src/api.ts`. Database rows never cross it; DTOs do.
- No secret gets a `Serialize` impl or a plain `Debug`. Password hashes never reach the frontend.
- Argon2id parameters are m=19 MiB, t=2, p=1 (`HashingPolicy::PRODUCTION`). Tests use `HashingPolicy::FAST_FOR_TESTS`.
- Password inputs are 12–1024 bytes and are **not** normalised.
- The full gate is `pnpm verify`. On Windows, `scripts/verify.ps1`.
- Commit after every task. Never use `--no-verify`.

## Version sync

`scripts/check-version-sync.mjs` runs as part of `pnpm verify` and asserts the version is identical across `package.json`, every workspace `package.json`, `Cargo.toml` and the Tauri config. When a task deletes a crate or an app, that script's expected file list must be updated in the same task or `pnpm verify` fails.

---

## File Structure

**Crates deleted entirely:** `crates/terminal`, `crates/privileged`, `apps/coordination-server`.

**Crates modified:**

| Path | Responsibility after this plan |
|---|---|
| `crates/protocol/src/control.rs` | `Opening`, `Hello`, `HelloAck`, plus new `Authenticate` and `SessionAuthorization` |
| `crates/protocol/src/pairing.rs` | **deleted** |
| `crates/protocol/src/terminal.rs` | **deleted** |
| `crates/security/src/permissions.rs` | `Permission` (3 variants) and `PermissionSet` |
| `crates/security/src/pairing/` | **deleted** |
| `crates/security/src/password.rs` | `PasswordCredential` (renamed from `OwnerCredential`), unchanged logic |
| `crates/security/src/throttle.rs` | unchanged; now guards unattended-password attempts |
| `crates/transport/src/address.rs` | **new** — `PeerAddress` parsing and display |
| `crates/transport/src/discovery.rs` | **deleted** |
| `crates/transport/src/pairing.rs` | **deleted** |
| `crates/transport/src/handshake.rs` | session handshake only; authorisation moved out |
| `crates/storage/src/owner.rs` | **deleted** |
| `crates/storage/src/audit.rs` | **deleted** |
| `crates/storage/src/trust.rs` | **deleted**, replaced by `recent.rs` |
| `crates/storage/src/recent.rs` | **new** — `RecentConnection`, `RecentRepository` |
| `crates/storage/src/settings.rs` | **new** — `HostSettings`, `SettingsRepository` |
| `crates/storage/migrations/0003_anydesk_model.sql` | **new** — drops the old tables, adds the new ones |
| `crates/host-agent/src/lib.rs` | **new** — the host, as a library |
| `crates/host-agent/src/access.rs` | **new** — `AcceptPrompt`, `AcceptRequest`, `AcceptDecision`, `authorize_session` |
| `crates/host-agent/src/terminal_service.rs` | **deleted** |
| `crates/host-agent/src/main.rs` | thin service wrapper over the library |

**Frontend deleted:** `AuthScreen.tsx`, `TerminalScreen.tsx`, `RemoteAccessScreen.tsx`, `RemoteSupportScreen.tsx`, `ThisComputerScreen.tsx`, the whole `shell/` directory, `ui/QuickAction.tsx`, `ui/Kbd.tsx`, `ui/PageHeader.tsx`.

**Frontend created:**

| Path | Responsibility |
|---|---|
| `src/MainWindow.tsx` | This Desk + Remote Desk cards, Recent list |
| `src/ThisDeskCard.tsx` | Own addresses, machine name, accepting-connections state |
| `src/RemoteDeskCard.tsx` | Address field, validation, Connect |
| `src/RecentList.tsx` | Recent rows, always-allow, remove |
| `src/AcceptDialog.tsx` | The incoming-connection prompt |
| `src/SessionScreen.tsx` | Rewritten: remote screen area + floating toolbar |
| `src/SessionToolbar.tsx` | The auto-hiding toolbar |
| `src/SettingsDialog.tsx` | Four sections including the updates pane |
| `src/address.ts` | Address parsing/validation mirroring `PeerAddress` |
| `src/permissions.ts` | The three permissions, mirrored for the UI |

---

## Task order and why

Tasks 1–4 delete subsystems with no dependants, so the tree stays green throughout. Task 5 deletes pairing, which breaks connecting; Tasks 6–13 rebuild it under the new model. Tasks 14–20 are the interface. Task 21 is documentation. Run `cargo test --workspace` and `pnpm test:run` at the end of every task — a task is not done until both pass.

---

### Task 1: Delete the terminal subsystem

**Files:**
- Delete: `crates/terminal/` (whole directory)
- Delete: `crates/host-agent/src/terminal_service.rs`
- Delete: `crates/protocol/src/terminal.rs`
- Delete: `apps/desktop-client/src/TerminalScreen.tsx`
- Modify: `Cargo.toml` (workspace members, workspace dependencies)
- Modify: `crates/protocol/src/lib.rs:48` (remove `pub mod terminal;`)
- Modify: `crates/protocol/src/ids.rs` (remove `TerminalId`), `crates/protocol/src/lib.rs:53` (remove it from the `pub use`)
- Modify: `crates/protocol/src/frame.rs` (remove the `Terminal` channel variant)
- Modify: `crates/protocol/src/limits.rs` (remove the terminal frame ceiling)
- Modify: `crates/host-agent/src/main.rs`, `crates/host-agent/src/server.rs`, `crates/host-agent/src/sessions.rs`
- Modify: `apps/desktop-client/src-tauri/Cargo.toml`, `apps/desktop-client/src-tauri/src/lib.rs:349-352`, `apps/desktop-client/src-tauri/src/session_commands.rs`
- Modify: `apps/desktop-client/src/api.ts` (remove `openTerminal`, `sendTerminalInput`, `resizeTerminal`, `closeTerminal`, `listenTerminalOutput`, `listenTerminalExit` and their schemas)
- Modify: `apps/desktop-client/package.json` (remove `@xterm/xterm`, `@xterm/addon-fit`)
- Modify: `scripts/check-version-sync.mjs` (drop `crates/terminal` from its file list)
- Delete: `docs/terminal-architecture.md`

**Interfaces:**
- Consumes: nothing.
- Produces: a workspace with no `rc-terminal`, a `Channel` enum with no `Terminal` variant, and an `api.ts` with no terminal functions.

- [ ] **Step 1: Confirm the current state is green before deleting anything**

```bash
cargo test --workspace 2>&1 | tail -5
pnpm -r test:run 2>&1 | tail -5
```

Expected: Rust `727 passed`-scale totals with `0 failed`; TypeScript `107 passed`. If anything already fails, stop and report — do not start deleting on a red tree.

- [ ] **Step 2: Delete the terminal crate and its consumers**

```bash
rm -rf crates/terminal
rm -f crates/host-agent/src/terminal_service.rs
rm -f crates/protocol/src/terminal.rs
rm -f apps/desktop-client/src/TerminalScreen.tsx
rm -f docs/terminal-architecture.md
```

- [ ] **Step 3: Remove the workspace entries**

In `Cargo.toml`, delete the line `    "crates/terminal",` from `[workspace] members` and the line `rc-terminal = { path = "crates/terminal" }` from `[workspace.dependencies]`.

In `crates/host-agent/Cargo.toml` and `apps/desktop-client/src-tauri/Cargo.toml`, delete the `rc-terminal.workspace = true` dependency lines.

- [ ] **Step 4: Remove the protocol surface**

In `crates/protocol/src/lib.rs`, delete `pub mod terminal;` and remove `TerminalId` from the `pub use ids::{...}` list.

In `crates/protocol/src/ids.rs`, delete the `TerminalId` declaration and any test referring to it.

In `crates/protocol/src/frame.rs`, delete the `Terminal` variant from `Channel` and its arms in every `match`. The compiler will point at each one — `Channel` is matched exhaustively by design, so there is no silent miss.

In `crates/protocol/src/limits.rs`, delete the terminal ceiling constant and its entry in the per-channel limit table.

- [ ] **Step 5: Remove the agent and client wiring**

In `crates/host-agent/src/main.rs` delete `mod terminal_service;`. In `server.rs` and `sessions.rs` delete every terminal task spawn, channel route and session field. Follow the compiler.

In `apps/desktop-client/src-tauri/src/lib.rs`, delete lines 349–352 (`session_commands::open_terminal` through `session_commands::close_terminal`) from the `generate_handler!` list. In `session_commands.rs` delete the four command functions and their helper state.

- [ ] **Step 6: Remove the frontend surface**

In `apps/desktop-client/src/api.ts` delete the six terminal exports listed in **Files** together with their Zod schemas and any types only they used.

In `apps/desktop-client/package.json` delete the `"@xterm/addon-fit"` and `"@xterm/xterm"` dependency lines, then run:

```bash
pnpm install
```

In `apps/desktop-client/src/shell/navigation.ts` delete the `terminal` entry from the `session` group's `items` array. In `apps/desktop-client/src/App.tsx` delete the `import TerminalScreen` line and the `case 'terminal':` arm of `Section`.

- [ ] **Step 7: Delete the terminal tests that no longer have a subject**

```bash
grep -rln "terminal\|Terminal" crates/host-agent/tests/ apps/desktop-client/src/*.test.ts
```

Delete the terminal cases from the files that match. Where a whole test file is about terminals, delete the file. Do not delete a test that also covers something surviving — split it instead.

- [ ] **Step 8: Update the version-sync script**

In `scripts/check-version-sync.mjs`, remove `crates/terminal/Cargo.toml` from the list of files it checks.

- [ ] **Step 9: Verify the tree is green again**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
pnpm -r typecheck && pnpm -r test:run
```

Expected: all four succeed. The Rust total drops by roughly 26 (the terminal crate) plus whatever agent tests covered terminals. That fall is the point of the task.

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "refactor: delete the terminal subsystem

The product is a remote-desktop tool. A PTY is not part of that, and the
crate, its protocol channel, its agent service, its four IPC commands and
its xterm.js screen were the largest subsystem nobody asked for."
```

---

### Task 2: Delete the privileged helper

**Files:**
- Delete: `crates/privileged/` (whole directory)
- Delete: `docs/privileged-operations.md`
- Modify: `Cargo.toml`, `crates/host-agent/Cargo.toml`, `crates/host-agent/src/config.rs` (the `network.privileged_port` setting), `crates/host-agent/src/server.rs`
- Modify: `crates/platform/src/` — the privileged-command allowlist and protected-services deny-list module
- Modify: `scripts/check-version-sync.mjs`
- Modify: `installers/` — any reference to installing or registering the helper

**Interfaces:**
- Consumes: Task 1's workspace.
- Produces: a workspace with no `rc-privileged` and a host config with no `privileged_port`.

- [ ] **Step 1: Confirm nothing outside the helper depends on it**

```bash
grep -rn "rc_privileged\|rc-privileged\|privileged_port" --include=*.rs --include=*.toml --include=*.ts . | grep -v "^./target" | grep -v "^./crates/privileged"
```

Expected: hits only in `Cargo.toml`, `crates/host-agent/`, `crates/platform/`, and `installers/`. If anything else appears — particularly in `file-transfer` or `monitoring` — stop and report it, because the spec assumed no other consumer.

- [ ] **Step 2: Delete the crate and its documentation**

```bash
rm -rf crates/privileged
rm -f docs/privileged-operations.md
```

- [ ] **Step 3: Remove the workspace and agent wiring**

In `Cargo.toml` delete `    "crates/privileged",` from members and `rc-privileged = { path = "crates/privileged" }` from workspace dependencies.

In `crates/host-agent/Cargo.toml` delete `rc-privileged.workspace = true`.

In `crates/host-agent/src/config.rs` delete the `privileged_port` field, its default, its validation and its documentation comment.

In `crates/host-agent/src/server.rs` delete the startup `Ping` probe for the helper, the "helper reachable" log line, and the code that adds or withholds `service_management` and `power_control` from the advertised capabilities.

- [ ] **Step 4: Remove the platform allowlist**

In `crates/platform/src/`, delete the privileged-command allowlist module and the protected-services deny-list, remove its `pub mod` from `lib.rs`, and delete its tests — including the 18 injection-payload cases, which have no subject once the allowlist is gone.

Keep per-OS directory resolution and host inventory. They are used by the agent and the client.

- [ ] **Step 5: Remove it from the installers**

```bash
grep -rn "privileged\|helper" installers/
```

Delete every service registration, systemd unit fragment, file copy and ACL rule for the helper from the files that match.

- [ ] **Step 6: Update the version-sync script and verify**

Remove `crates/privileged/Cargo.toml` from `scripts/check-version-sync.mjs`, then:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Expected: all succeed. The Rust total drops by roughly 42 (31 unit + 11 cross-process).

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor: delete the privileged helper

The helper existed to serve power actions and service management. Both are
being removed, and nothing else called it, so the elevated process, its
loopback endpoint, its token file and the platform command allowlist go
with them."
```

---

### Task 3: Delete the coordination server

**Files:**
- Delete: `apps/coordination-server/` (whole directory)
- Modify: `Cargo.toml`, `pnpm-workspace.yaml`, `scripts/check-version-sync.mjs`, `README.md` (layout table)

**Interfaces:**
- Consumes: Task 2's workspace.
- Produces: a workspace whose only app is the desktop client.

- [ ] **Step 1: Confirm nothing depends on it**

```bash
grep -rn "coordination" --include=*.rs --include=*.toml --include=*.ts --include=*.yaml . | grep -v "^./target" | grep -v "^./apps/coordination-server"
```

Expected: hits only in `Cargo.toml`, `README.md`, `PROGRESS.md`, `scripts/`, and the spec. No crate should import it.

- [ ] **Step 2: Delete it**

```bash
rm -rf apps/coordination-server
```

- [ ] **Step 3: Remove the workspace entries**

In `Cargo.toml` delete `    "apps/coordination-server",` from members. Check `pnpm-workspace.yaml` for an `apps/*` glob — if it lists the app explicitly, remove that line. Remove its `Cargo.toml` from `scripts/check-version-sync.mjs`.

In `README.md`, delete the `coordination-server` row from the repository-layout block and the sentence describing an optional self-hosted signalling service.

- [ ] **Step 4: Verify**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
pnpm install && pnpm -r test:run
```

Expected: all succeed. The Rust total drops by 6.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: delete the coordination server

Addresses are typed in by hand, so a rendezvous service has no role. It
answered /health and nothing else."
```

---

### Task 4: Delete mDNS discovery

**Files:**
- Delete: `crates/transport/src/discovery.rs`
- Modify: `crates/transport/src/lib.rs`, `crates/transport/Cargo.toml` (drop the mdns dependency)
- Modify: `apps/desktop-client/src-tauri/src/connect_commands.rs` (remove `discover_agents`), `apps/desktop-client/src-tauri/src/lib.rs:338`
- Modify: `apps/desktop-client/src/api.ts` (remove `discoverAgents`, `DiscoveredAgent`, its schema)
- Modify: `apps/desktop-client/src/useConnection.ts`, `apps/desktop-client/src/connection.test.ts` (remove the `discovering` state)

**Interfaces:**
- Consumes: Task 3's workspace.
- Produces: a `ConnectionState` union with no `discovering` variant.

- [ ] **Step 1: Write the failing test for the reduced state machine**

In `apps/desktop-client/src/connection.test.ts`, replace the discovery cases with:

```typescript
import { describe, expect, it } from 'vitest';
import { describeConnectionState, isBusy, isConnected } from './api.js';

describe('connection state', () => {
  it('has no discovering state', () => {
    // `discovering` existed only for mDNS. Typing an address cannot discover.
    expect(() => describeConnectionState({ kind: 'discovering' } as never)).toThrow();
  });

  it('describes every state a typed address can reach', () => {
    for (const kind of [
      'offline',
      'connecting',
      'authenticating',
      'connected',
      'disconnecting',
      'reconnecting',
      'waitingToRetry',
      'refused',
      'failed',
    ] as const) {
      expect(describeConnectionState({ kind } as never)).toBeTruthy();
    }
  });
});
```

- [ ] **Step 2: Run it and watch it fail**

```bash
pnpm --filter @rc/desktop-client test:run -- connection
```

Expected: FAIL — `describeConnectionState({kind:'discovering'})` currently returns a string instead of throwing.

- [ ] **Step 3: Delete discovery**

```bash
rm -f crates/transport/src/discovery.rs
```

In `crates/transport/src/lib.rs` delete `pub mod discovery;` and any re-export from it. In `crates/transport/Cargo.toml` delete the mdns dependency, and delete it from `[workspace.dependencies]` in the root `Cargo.toml` if nothing else uses it.

In `apps/desktop-client/src-tauri/src/connect_commands.rs` delete `discover_agents`; in `lib.rs` delete line 338 from the handler list.

In `apps/desktop-client/src/api.ts` delete `discoverAgents`, the `DiscoveredAgent` type and its schema, and remove `'discovering'` from the `connectionState` Zod union and from `describeConnectionState` and `isBusy`.

In `apps/desktop-client/src/useConnection.ts` remove every `discovering` branch.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
pnpm --filter @rc/desktop-client test:run -- connection
cargo test -p rc-transport
```

Expected: both PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: delete mDNS discovery

The address is typed, so there is nothing to discover. The 'discovering'
connection state goes with it."
```

---

### Task 5: Delete pairing

This is the task that breaks connecting. The tree compiles and its remaining tests pass at the end of it, but no two machines can authorise a session until Task 11. That is expected and is why Tasks 6–13 follow immediately.

**Files:**
- Delete: `crates/security/src/pairing/` (whole directory)
- Delete: `crates/transport/src/pairing.rs`
- Delete: `crates/protocol/src/pairing.rs`
- Delete: `crates/host-agent/src/local_api.rs` (the loopback `POST /pairing` endpoint and its token file)
- Delete: `apps/desktop-client/src/RemoteSupportScreen.tsx`
- Delete: `docs/pairing-protocol.md`
- Modify: `crates/security/src/lib.rs`, `crates/protocol/src/lib.rs`, `crates/transport/src/lib.rs`, `crates/transport/src/handshake.rs`, `crates/protocol/src/control.rs`
- Modify: `crates/host-agent/src/main.rs` (drop the `pair` subcommand), `server.rs`
- Modify: `apps/desktop-client/src-tauri/src/lib.rs`, `commands.rs`, `connect_commands.rs`
- Modify: `apps/desktop-client/src/api.ts` (remove `pairWithServer`, `checkPairingCodeFormat`)

**Interfaces:**
- Consumes: Task 4's workspace.
- Produces: `Opening` with a single `Hello` variant; no `PairingCode`, `PairingManager`, `PairingClient`, `PairingPolicy`, `PairingState`, `RequestedPermissions`, `PairingSessionId`.

- [ ] **Step 1: Delete the pairing modules**

```bash
rm -rf crates/security/src/pairing
rm -f crates/transport/src/pairing.rs
rm -f crates/protocol/src/pairing.rs
rm -f crates/host-agent/src/local_api.rs
rm -f apps/desktop-client/src/RemoteSupportScreen.tsx
rm -f docs/pairing-protocol.md
```

- [ ] **Step 2: Remove the re-exports**

In `crates/security/src/lib.rs` delete `pub mod pairing;` and the whole `pub use pairing::{...}` block (lines 35–37).

In `crates/protocol/src/lib.rs` delete `pub mod pairing;` and remove `PairingSessionId` from the `pub use ids::{...}` list. In `crates/protocol/src/ids.rs` delete `PairingSessionId`.

In `crates/transport/src/lib.rs` delete `pub mod pairing;` and its re-exports.

- [ ] **Step 3: Collapse `Opening`**

In `crates/protocol/src/control.rs`, replace the `Opening` enum at line 115 with:

```rust
/// The first message on a new connection.
///
/// This is a single-variant enum on purpose. Postcard is not self-describing, so a
/// bare struct here would leave a future second kind of opening indistinguishable
/// except by attempting two decodes — which would let the peer choose the branch.
/// Keeping the discriminant costs one byte and keeps that door shut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Opening {
    /// The peer wants a session.
    Hello(Box<Hello>),
}
```

In the same file, delete the `already_paired` field from `HelloAck` (line 135) and its documentation. Whether a peer may proceed is now decided by Task 11's authorisation step, not announced in the acknowledgement.

- [ ] **Step 4: Strip the handshake**

In `crates/transport/src/handshake.rs` delete the pairing branch of `accept_handshake` (line 175), the pairing arm of `read_opening` (line 210), and the `already_paired` assignment in `finish_accept` (line 231). Delete the `authorize` function (line 114) and the `TrustRecord` struct (line 75) — Task 11 replaces both.

`AuthenticatedPeer` (line 56) stays. It carries the peer's certificate fingerprint read from the connection, which is the anti-relay property the whole design rests on.

- [ ] **Step 5: Strip the agent**

In `crates/host-agent/src/main.rs` delete `mod local_api;` and the `pair` subcommand from the CLI enum and its dispatch arm. In `server.rs` delete the loopback control endpoint, its token generation and its `/pairing` route. Keep `GET /health`.

Delete the startup sweep that expires stale pairing rows — there are no pairing rows.

- [ ] **Step 6: Strip the client**

In `apps/desktop-client/src-tauri/src/lib.rs` delete `commands::check_pairing_code_format` (line 337) and `connect_commands::pair_with_server` (line 339) from the handler list, and delete both functions from their modules.

In `apps/desktop-client/src/api.ts` delete `checkPairingCodeFormat` and `pairWithServer` and their schemas.

In `apps/desktop-client/src/shell/navigation.ts` delete the `remote-support` item. In `App.tsx` delete the `RemoteSupportScreen` import and its `case`. Change `DEFAULT_SECTION` to `'remote-access'` if it was not already.

- [ ] **Step 7: Delete the pairing tests**

```bash
grep -rln "pair\|Pairing" crates/*/tests/ crates/*/src/ apps/desktop-client/src/*.test.ts
```

Delete every test whose subject was pairing, including the transport pairing tests and the agent integration tests that ran a pairing exchange. Task 13 writes the integration tests that replace them.

- [ ] **Step 8: Verify**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
pnpm -r typecheck && pnpm -r test:run
```

Expected: all succeed. This is the largest single drop in the test count in the plan.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "refactor: delete the pairing protocol

Codes, verifiers, the transcript, the four-message exchange and the local
pairing endpoint are replaced by connect-and-accept in the tasks that
follow. Nothing can authorise a session between here and the task that
adds the accept path."
```

---

### Task 6: Reduce the permission model to three permissions

**Files:**
- Rewrite: `crates/security/src/permissions.rs`
- Modify: `crates/security/src/lib.rs`
- Test: `crates/security/src/permissions.rs` (inline `#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: Task 5's workspace.
- Produces:
  - `Permission` — `ControlInput`, `TransferFiles`, `ViewMetrics`; `Permission::name(self) -> &'static str`; `Permission::ALL: [Permission; 3]`
  - `PermissionSet` — `NONE`, `ALL`, `with(self, Permission) -> Self`, `without(self, Permission) -> Self`, `contains(self, Permission) -> bool`, `is_empty(self) -> bool`, `iter(self) -> impl Iterator<Item = Permission>`
  - `PermissionSet` is `Copy`, `Serialize`, `Deserialize`, and round-trips through `u8` via `bits()`/`from_bits()`

- [ ] **Step 1: Write the failing tests**

Replace the entire contents of `crates/security/src/permissions.rs` tests with this module, leaving the old production code in place for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_set_grants_nothing() {
        let set = PermissionSet::NONE;
        assert!(set.is_empty());
        for permission in Permission::ALL {
            assert!(!set.contains(permission));
        }
    }

    #[test]
    fn all_grants_every_permission() {
        for permission in Permission::ALL {
            assert!(PermissionSet::ALL.contains(permission));
        }
    }

    #[test]
    fn with_grants_only_the_named_permission() {
        let set = PermissionSet::NONE.with(Permission::TransferFiles);
        assert!(set.contains(Permission::TransferFiles));
        assert!(!set.contains(Permission::ControlInput));
        assert!(!set.contains(Permission::ViewMetrics));
    }

    #[test]
    fn without_revokes_only_the_named_permission() {
        let set = PermissionSet::ALL.without(Permission::ControlInput);
        assert!(!set.contains(Permission::ControlInput));
        assert!(set.contains(Permission::TransferFiles));
        assert!(set.contains(Permission::ViewMetrics));
    }

    #[test]
    fn with_is_idempotent() {
        let once = PermissionSet::NONE.with(Permission::ViewMetrics);
        assert_eq!(once, once.with(Permission::ViewMetrics));
    }

    #[test]
    fn iter_yields_exactly_the_granted_permissions() {
        let set = PermissionSet::NONE
            .with(Permission::ControlInput)
            .with(Permission::ViewMetrics);
        let granted: Vec<Permission> = set.iter().collect();
        assert_eq!(granted, vec![Permission::ControlInput, Permission::ViewMetrics]);
    }

    #[test]
    fn bits_round_trip() {
        let set = PermissionSet::NONE.with(Permission::TransferFiles);
        assert_eq!(PermissionSet::from_bits(set.bits()), Some(set));
    }

    #[test]
    fn unknown_bits_are_refused_rather_than_masked() {
        // A newer peer sending a permission this build does not know must not have it
        // silently dropped — the set would then mean something different on each side.
        assert_eq!(PermissionSet::from_bits(0b1000_0000), None);
    }

    #[test]
    fn names_are_stable() {
        assert_eq!(Permission::ControlInput.name(), "control_input");
        assert_eq!(Permission::TransferFiles.name(), "transfer_files");
        assert_eq!(Permission::ViewMetrics.name(), "view_metrics");
    }
}
```

- [ ] **Step 2: Run the tests and watch them fail**

```bash
cargo test -p rc-security permissions
```

Expected: FAIL to compile — `Permission`, `PermissionSet` and their members do not exist.

- [ ] **Step 3: Replace the production code**

Replace everything above the test module in `crates/security/src/permissions.rs` with:

```rust
//! What a session is allowed to do.
//!
//! Three permissions, chosen by a human on the Accept dialog or pre-selected for
//! unattended access. There are no roles: a role is an indirection that only pays for
//! itself when there are many permissions and many kinds of user, and this product has
//! three of one and one of the other.
//!
//! A permission is granted for the lifetime of a session and cannot be escalated
//! within it. Widening requires a new connection, which means a new decision by a
//! human — so a compromised session cannot talk its way into more than it was given.

use serde::{Deserialize, Serialize};

/// A discrete thing a session may be permitted to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Move the pointer and type on the remote machine.
    ControlInput,
    /// List, download and upload files.
    TransferFiles,
    /// Read CPU, memory, disk and network readings.
    ViewMetrics,
}

impl Permission {
    /// Every permission, in the order the interface presents them.
    pub const ALL: [Self; 3] = [Self::ControlInput, Self::TransferFiles, Self::ViewMetrics];

    /// Stable name used in errors, logs and the interface.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ControlInput => "control_input",
            Self::TransferFiles => "transfer_files",
            Self::ViewMetrics => "view_metrics",
        }
    }

    /// This permission's bit in a [`PermissionSet`].
    const fn bit(self) -> u8 {
        match self {
            Self::ControlInput => 0b0000_0001,
            Self::TransferFiles => 0b0000_0010,
            Self::ViewMetrics => 0b0000_0100,
        }
    }
}

/// The permissions a session holds.
///
/// A bitset rather than a collection so it is `Copy` and can be carried on a session
/// without an allocation or a lock, and so an authorisation check is one instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PermissionSet(u8);

impl PermissionSet {
    /// Every bit that any known permission uses.
    const KNOWN: u8 = 0b0000_0111;

    /// Grants nothing. What a connection holds before a human has decided.
    pub const NONE: Self = Self(0);

    /// Grants everything. The Accept dialog's default selection.
    pub const ALL: Self = Self(Self::KNOWN);

    /// This set with `permission` added.
    #[must_use]
    pub const fn with(self, permission: Permission) -> Self {
        Self(self.0 | permission.bit())
    }

    /// This set with `permission` removed.
    #[must_use]
    pub const fn without(self, permission: Permission) -> Self {
        Self(self.0 & !permission.bit())
    }

    /// Whether this set grants `permission`.
    #[must_use]
    pub const fn contains(self, permission: Permission) -> bool {
        self.0 & permission.bit() != 0
    }

    /// Whether this set grants nothing at all.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The granted permissions, in [`Permission::ALL`] order.
    pub fn iter(self) -> impl Iterator<Item = Permission> {
        Permission::ALL
            .into_iter()
            .filter(move |permission| self.contains(*permission))
    }

    /// The raw bits, for storage.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// A set from raw bits, or `None` if any unknown bit is set.
    ///
    /// Refusing rather than masking is deliberate. A peer or a database row carrying a
    /// permission this build does not know is not a set with one fewer permission — it
    /// is a value this build cannot interpret, and quietly reinterpreting it would make
    /// the same bytes mean different things on either side.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::KNOWN != 0 {
            None
        } else {
            Some(Self(bits))
        }
    }
}
```

- [ ] **Step 4: Update the re-exports and follow the compiler**

In `crates/security/src/lib.rs` replace `pub use permissions::{AuthorizationContext, Capability, Role};` with `pub use permissions::{Permission, PermissionSet};`.

```bash
cargo build --workspace 2>&1 | grep -E "^error" | head -40
```

Every remaining reference to `Capability`, `Role` or `AuthorizationContext` is now an error. Replace each with the corresponding `Permission`: file operations take `Permission::TransferFiles`, metrics take `Permission::ViewMetrics`, and anything that referenced `RemoteDesktopView`, `RemoteInput` or a deleted capability takes `Permission::ControlInput` or is deleted along with its handler.

- [ ] **Step 5: Run the tests and verify they pass**

```bash
cargo test -p rc-security permissions
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(security): reduce the permission model to three permissions

Ten capabilities across three roles become control input, transfer files
and view metrics — the three checkboxes on the Accept dialog. A set is a
Copy bitset so an authorisation check costs one instruction, and unknown
bits are refused rather than masked."
```

---

### Task 7: Rename `OwnerCredential` to `PasswordCredential`

A small, mechanical task on its own so the rename does not hide inside a behavioural change.

**Files:**
- Modify: `crates/security/src/password.rs`, `crates/security/src/lib.rs`, and every call site

**Interfaces:**
- Consumes: Task 6's workspace.
- Produces: `PasswordCredential` with the identical API — `create(&str, HashingPolicy, &dyn RandomSource) -> Result<Self>`, `from_phc(impl Into<String>) -> Result<Self>`, `expose_phc_for_storage(&self) -> &str`, `verify(&self, &str) -> Result<()>`, `policy(&self) -> Result<HashingPolicy>`, `needs_rehash(&self, HashingPolicy) -> bool`, `is_argon2id(&self) -> bool`.

- [ ] **Step 1: Rename the type and its documentation**

```bash
grep -rln "OwnerCredential" --include=*.rs . | grep -v "^./target" | xargs sed -i 's/OwnerCredential/PasswordCredential/g'
```

In `crates/security/src/password.rs`, update the doc comment on the type: it no longer protects an owner account, it protects the optional unattended-access password.

- [ ] **Step 2: Verify nothing else calls it by the old name**

```bash
grep -rn "OwnerCredential" --include=*.rs --include=*.md . | grep -v "^./target" | grep -v "docs/superpowers"
```

Expected: no output.

- [ ] **Step 3: Run the tests**

```bash
cargo test -p rc-security password
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: PASS. The password tests are unchanged apart from the type name — the hashing, the validation bounds, the `Zeroizing` buffers and the transparent parameter upgrade are all kept exactly as they are.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor(security): rename OwnerCredential to PasswordCredential

There is no owner account. The same Argon2id code now protects the
optional unattended-access password."
```

---

### Task 8: Replace the storage schema

**Files:**
- Delete: `crates/storage/src/owner.rs`, `crates/storage/src/audit.rs`, `crates/storage/src/trust.rs`
- Create: `crates/storage/migrations/0003_anydesk_model.sql`
- Create: `crates/storage/src/recent.rs`
- Create: `crates/storage/src/settings.rs`
- Modify: `crates/storage/src/lib.rs`, `crates/storage/src/models.rs`, `crates/storage/src/repo_tests.rs`

**Interfaces:**
- Consumes: `PermissionSet` and `PasswordCredential` from Tasks 6 and 7; `Fingerprint` from `rc_security`.
- Produces:
  - `RecentConnection { address: String, machine_name: String, last_connected_ms: i64, pinned_fingerprint: Option<Fingerprint>, pinned_permissions: PermissionSet }`
  - `RecentRepository::new(&Database) -> Self`, and async `list() -> Result<Vec<RecentConnection>>`, `find(&str) -> Result<Option<RecentConnection>>`, `record(&str, &str, i64) -> Result<()>`, `set_always_allow(&str, Option<Fingerprint>, PermissionSet) -> Result<()>`, `remove(&str) -> Result<()>`
  - `HostSettings { accepting: bool, listen_port: u16, machine_name: String, unattended_permissions: PermissionSet }`
  - `SettingsRepository::new(&Database) -> Self`, and async `load() -> Result<HostSettings>`, `set_accepting(bool) -> Result<()>`, `set_listen_port(u16) -> Result<()>`, `set_machine_name(&str) -> Result<()>`, `set_unattended(Option<&PasswordCredential>, PermissionSet) -> Result<()>`, `unattended_credential() -> Result<Option<PasswordCredential>>`

- [ ] **Step 1: Write the migration**

Create `crates/storage/migrations/0003_anydesk_model.sql`:

```sql
-- The AnyDesk access model.
--
-- This migration is deliberately destructive, and it is the only one that is. The
-- owner account, the pairing history, the audit trail and the trusted-device table
-- describe a model the product no longer has; carrying them forward would leave rows
-- that nothing reads and that imply guarantees nothing enforces.
--
-- The additive-only policy resumes after this migration. Nothing has shipped, so no
-- installed database is being destroyed.

DROP TABLE IF EXISTS owner_accounts;
DROP TABLE IF EXISTS pairing_codes;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS trusted_devices;

-- Machines this one has connected to.
--
-- The address is the key because the address is what the user types. A machine that
-- moves to a new address is a new row, which is correct: the user reaches it by a
-- different name and its pinned fingerprint has to be re-decided.
CREATE TABLE recent_connections (
    address              TEXT    NOT NULL PRIMARY KEY,
    machine_name         TEXT    NOT NULL,
    last_connected_ms    INTEGER NOT NULL,
    -- Set only when the user ticked "always allow". NULL means every connection to
    -- this machine still raises the Accept dialog.
    pinned_fingerprint   TEXT,
    -- The permissions an always-allow connection receives. Meaningless, and required
    -- to be zero, when pinned_fingerprint is NULL.
    pinned_permissions   INTEGER NOT NULL DEFAULT 0,

    CHECK (length(address) BETWEEN 1 AND 255),
    CHECK (length(machine_name) BETWEEN 1 AND 255),
    CHECK (last_connected_ms > 0),
    CHECK (pinned_permissions BETWEEN 0 AND 7),
    CHECK (pinned_fingerprint IS NOT NULL OR pinned_permissions = 0)
) STRICT;

CREATE INDEX idx_recent_connections_last_connected
    ON recent_connections (last_connected_ms DESC);

-- This machine's own settings. Exactly one row, pinned by the CHECK on id.
CREATE TABLE host_settings (
    id                     INTEGER NOT NULL PRIMARY KEY,
    accepting              INTEGER NOT NULL DEFAULT 1,
    listen_port            INTEGER NOT NULL DEFAULT 7443,
    machine_name           TEXT    NOT NULL,
    -- Argon2id PHC string. NULL means unattended access is not configured, which is
    -- a different state from "configured with a weak password" and is the default.
    unattended_phc         TEXT,
    unattended_permissions INTEGER NOT NULL DEFAULT 0,

    CHECK (id = 1),
    CHECK (accepting IN (0, 1)),
    CHECK (listen_port BETWEEN 1 AND 65535),
    CHECK (length(machine_name) BETWEEN 1 AND 255),
    CHECK (unattended_permissions BETWEEN 0 AND 7),
    CHECK (unattended_phc IS NOT NULL OR unattended_permissions = 0)
) STRICT;
```

- [ ] **Step 2: Write the failing repository tests**

Create `crates/storage/src/recent.rs` containing only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use rc_security::{Fingerprint, Permission, PermissionSet};

    use super::*;
    use crate::test_support::temp_database;

    #[tokio::test]
    async fn an_empty_database_lists_nothing() {
        let database = temp_database().await;
        let repository = RecentRepository::new(&database);
        assert!(repository.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn recording_a_connection_makes_it_findable() {
        let database = temp_database().await;
        let repository = RecentRepository::new(&database);
        repository.record("192.168.1.77", "WORK-LAPTOP", 1_700_000_000_000).await.unwrap();

        let found = repository.find("192.168.1.77").await.unwrap().unwrap();
        assert_eq!(found.machine_name, "WORK-LAPTOP");
        assert_eq!(found.last_connected_ms, 1_700_000_000_000);
        assert!(found.pinned_fingerprint.is_none());
        assert!(found.pinned_permissions.is_empty());
    }

    #[tokio::test]
    async fn recording_the_same_address_twice_updates_rather_than_duplicates() {
        let database = temp_database().await;
        let repository = RecentRepository::new(&database);
        repository.record("192.168.1.77", "OLD-NAME", 1_000).await.unwrap();
        repository.record("192.168.1.77", "NEW-NAME", 2_000).await.unwrap();

        let all = repository.list().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].machine_name, "NEW-NAME");
        assert_eq!(all[0].last_connected_ms, 2_000);
    }

    #[tokio::test]
    async fn the_list_is_most_recent_first() {
        let database = temp_database().await;
        let repository = RecentRepository::new(&database);
        repository.record("10.0.0.1", "OLDEST", 1_000).await.unwrap();
        repository.record("10.0.0.2", "NEWEST", 3_000).await.unwrap();
        repository.record("10.0.0.3", "MIDDLE", 2_000).await.unwrap();

        let names: Vec<String> = repository
            .list()
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.machine_name)
            .collect();
        assert_eq!(names, vec!["NEWEST", "MIDDLE", "OLDEST"]);
    }

    #[tokio::test]
    async fn always_allow_stores_the_pin_and_the_permissions() {
        let database = temp_database().await;
        let repository = RecentRepository::new(&database);
        repository.record("10.0.0.1", "BOX", 1_000).await.unwrap();

        let fingerprint = Fingerprint::from_bytes([7u8; 32]);
        let granted = PermissionSet::NONE.with(Permission::TransferFiles);
        repository
            .set_always_allow("10.0.0.1", Some(fingerprint.clone()), granted)
            .await
            .unwrap();

        let found = repository.find("10.0.0.1").await.unwrap().unwrap();
        assert_eq!(found.pinned_fingerprint, Some(fingerprint));
        assert_eq!(found.pinned_permissions, granted);
    }

    #[tokio::test]
    async fn clearing_always_allow_clears_the_permissions_too() {
        // A row with permissions but no pin would be a grant nothing can match, which
        // the schema refuses. Clearing must clear both or the write fails.
        let database = temp_database().await;
        let repository = RecentRepository::new(&database);
        repository.record("10.0.0.1", "BOX", 1_000).await.unwrap();
        repository
            .set_always_allow("10.0.0.1", Some(Fingerprint::from_bytes([7u8; 32])), PermissionSet::ALL)
            .await
            .unwrap();

        repository.set_always_allow("10.0.0.1", None, PermissionSet::ALL).await.unwrap();

        let found = repository.find("10.0.0.1").await.unwrap().unwrap();
        assert!(found.pinned_fingerprint.is_none());
        assert!(found.pinned_permissions.is_empty());
    }

    #[tokio::test]
    async fn removing_an_entry_removes_its_pin() {
        let database = temp_database().await;
        let repository = RecentRepository::new(&database);
        repository.record("10.0.0.1", "BOX", 1_000).await.unwrap();
        repository.remove("10.0.0.1").await.unwrap();
        assert!(repository.find("10.0.0.1").await.unwrap().is_none());
    }
}
```

Create `crates/storage/src/settings.rs` containing only this test module for now:

```rust
#[cfg(test)]
mod tests {
    use rc_security::{HashingPolicy, OsRandom, PasswordCredential, Permission, PermissionSet};

    use super::*;
    use crate::test_support::temp_database;

    #[tokio::test]
    async fn defaults_accept_connections_with_no_unattended_password() {
        let database = temp_database().await;
        let repository = SettingsRepository::new(&database);
        let settings = repository.load().await.unwrap();

        assert!(settings.accepting);
        assert_eq!(settings.listen_port, 7443);
        assert!(settings.unattended_permissions.is_empty());
        assert!(repository.unattended_credential().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn setting_a_password_stores_a_verifiable_credential() {
        let database = temp_database().await;
        let repository = SettingsRepository::new(&database);
        let credential =
            PasswordCredential::create("correct horse battery", HashingPolicy::FAST_FOR_TESTS, &OsRandom)
                .unwrap();

        repository
            .set_unattended(Some(&credential), PermissionSet::NONE.with(Permission::ViewMetrics))
            .await
            .unwrap();

        let stored = repository.unattended_credential().await.unwrap().unwrap();
        assert!(stored.verify("correct horse battery").is_ok());
        assert!(stored.verify("wrong").is_err());
        assert_eq!(
            repository.load().await.unwrap().unattended_permissions,
            PermissionSet::NONE.with(Permission::ViewMetrics)
        );
    }

    #[tokio::test]
    async fn clearing_the_password_clears_its_permissions() {
        let database = temp_database().await;
        let repository = SettingsRepository::new(&database);
        let credential =
            PasswordCredential::create("correct horse battery", HashingPolicy::FAST_FOR_TESTS, &OsRandom)
                .unwrap();
        repository.set_unattended(Some(&credential), PermissionSet::ALL).await.unwrap();

        repository.set_unattended(None, PermissionSet::ALL).await.unwrap();

        assert!(repository.unattended_credential().await.unwrap().is_none());
        assert!(repository.load().await.unwrap().unattended_permissions.is_empty());
    }

    #[tokio::test]
    async fn the_password_hash_is_not_part_of_the_loaded_settings() {
        // HostSettings is the type that reaches the frontend. A password is configured
        // first, so this fails if the hash ever gains a path into the DTO — the test
        // would pass trivially against an empty database.
        let database = temp_database().await;
        let repository = SettingsRepository::new(&database);
        let credential =
            PasswordCredential::create("correct horse battery", HashingPolicy::FAST_FOR_TESTS, &OsRandom)
                .unwrap();
        repository.set_unattended(Some(&credential), PermissionSet::ALL).await.unwrap();

        let json = serde_json::to_string(&repository.load().await.unwrap()).unwrap();

        let phc = credential.expose_phc_for_storage();
        assert!(!json.contains(phc), "the stored hash reached the settings DTO");
        assert!(!json.contains("argon2"));
    }

    #[tokio::test]
    async fn a_port_outside_the_valid_range_is_refused() {
        let database = temp_database().await;
        let repository = SettingsRepository::new(&database);
        assert!(repository.set_listen_port(0).await.is_err());
    }
}
```

- [ ] **Step 3: Run the tests and watch them fail**

```bash
cargo test -p rc-storage recent settings
```

Expected: FAIL to compile — `RecentRepository`, `SettingsRepository`, `HostSettings` and `temp_database` do not exist.

- [ ] **Step 4: Delete the old repositories and write the new ones**

```bash
rm -f crates/storage/src/owner.rs crates/storage/src/audit.rs crates/storage/src/trust.rs
```

In `crates/storage/src/lib.rs` replace `pub mod owner; pub mod audit; pub mod trust;` with `pub mod recent; pub mod settings;` and update the re-exports to `pub use recent::{RecentConnection, RecentRepository}; pub use settings::{HostSettings, SettingsRepository};`.

Add a `test_support` module to `crates/storage/src/lib.rs`, exposing `pub(crate) async fn temp_database() -> Database` built on the existing `Database::open_in_memory()` (used throughout `crates/storage/src/lib.rs`'s own tests), which runs every migration on open. Do not write a second way to build a test database.

Write the production code above each new file's test module. `RecentRepository::record` is an `INSERT ... ON CONFLICT(address) DO UPDATE SET machine_name = excluded.machine_name, last_connected_ms = excluded.last_connected_ms` — note it deliberately leaves the pin alone, so reconnecting does not silently re-grant. `set_always_allow` writes `PermissionSet::NONE` whenever the fingerprint argument is `None`, which is what makes the schema's `CHECK` unreachable from the repository rather than merely guarded by it.

`SettingsRepository::load` inserts the default row on first read, using the operating system's hostname from `rc_platform` as the machine name. `HostSettings` derives `Serialize` but has no field that could hold a hash — `unattended_credential()` is a separate call returning `PasswordCredential`, which has no `Serialize` impl at all.

- [ ] **Step 5: Run the tests and verify they pass**

```bash
cargo test -p rc-storage
```

Expected: PASS, including the migration tests. Update `repo_tests.rs` to drop the owner, trust and audit cases and to assert the new schema's table list.

- [ ] **Step 6: Verify the whole workspace still builds**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Expected: PASS. Every reference to `TrustRepository`, `OwnerRepository` and `AuditRepository` must be gone by now; follow the compiler for any that remain.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(storage): replace trust, owner and audit with recent and settings

Migration 0003 drops the tables describing a model the product no longer
has, and adds the two it does: machines you have connected to, with an
optional pinned fingerprint, and this machine's own settings including the
optional unattended password."
```

---

### Task 9: Parse peer addresses

**Files:**
- Create: `crates/transport/src/address.rs`
- Modify: `crates/transport/src/lib.rs`, `crates/transport/src/error.rs`

**Interfaces:**
- Consumes: Task 8's workspace.
- Produces: `PeerAddress { host: String, port: u16 }`, `PeerAddress::DEFAULT_PORT: u16 = 7443`, `impl FromStr for PeerAddress { type Err = TransportError }`, `impl Display for PeerAddress`, `PeerAddress::to_socket_addrs(&self) -> Result<Vec<SocketAddr>>`.

- [ ] **Step 1: Write the failing tests**

Create `crates/transport/src/address.rs` with only this test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_ipv4_address_takes_the_default_port() {
        let address: PeerAddress = "192.168.1.77".parse().unwrap();
        assert_eq!(address.host, "192.168.1.77");
        assert_eq!(address.port, PeerAddress::DEFAULT_PORT);
    }

    #[test]
    fn an_explicit_port_is_honoured() {
        let address: PeerAddress = "192.168.1.77:9000".parse().unwrap();
        assert_eq!(address.host, "192.168.1.77");
        assert_eq!(address.port, 9000);
    }

    #[test]
    fn a_bare_ipv6_address_takes_the_default_port() {
        let address: PeerAddress = "fe80::1".parse().unwrap();
        assert_eq!(address.host, "fe80::1");
        assert_eq!(address.port, PeerAddress::DEFAULT_PORT);
    }

    #[test]
    fn a_bracketed_ipv6_address_with_a_port_is_parsed() {
        let address: PeerAddress = "[fe80::1]:9000".parse().unwrap();
        assert_eq!(address.host, "fe80::1");
        assert_eq!(address.port, 9000);
    }

    #[test]
    fn a_hostname_is_accepted() {
        let address: PeerAddress = "work-laptop.local".parse().unwrap();
        assert_eq!(address.host, "work-laptop.local");
        assert_eq!(address.port, PeerAddress::DEFAULT_PORT);
    }

    #[test]
    fn a_hostname_with_a_port_is_accepted() {
        let address: PeerAddress = "work-laptop.local:9000".parse().unwrap();
        assert_eq!(address.host, "work-laptop.local");
        assert_eq!(address.port, 9000);
    }

    #[test]
    fn surrounding_whitespace_is_ignored() {
        // People paste addresses. A trailing space is not a different machine.
        let address: PeerAddress = "  192.168.1.77  ".parse().unwrap();
        assert_eq!(address.host, "192.168.1.77");
    }

    #[test]
    fn an_empty_address_is_refused() {
        assert!("".parse::<PeerAddress>().is_err());
        assert!("   ".parse::<PeerAddress>().is_err());
    }

    #[test]
    fn port_zero_is_refused() {
        // Port 0 means "any free port" to the operating system, which is not something
        // a peer can be listening on.
        assert!("192.168.1.77:0".parse::<PeerAddress>().is_err());
    }

    #[test]
    fn a_port_above_the_range_is_refused() {
        assert!("192.168.1.77:70000".parse::<PeerAddress>().is_err());
    }

    #[test]
    fn a_url_is_refused_rather_than_half_understood() {
        // Accepting a scheme would imply the transport honours it. It does not; this
        // is always QUIC.
        assert!("https://192.168.1.77".parse::<PeerAddress>().is_err());
    }

    #[test]
    fn a_path_is_refused() {
        assert!("192.168.1.77/admin".parse::<PeerAddress>().is_err());
    }

    #[test]
    fn an_unbracketed_ipv6_address_keeps_the_default_port_rather_than_guessing() {
        // "fe80::1:9000" cannot be told from an address whose last group is 9000, so
        // the whole string is the host. Brackets are how the user says otherwise.
        let address: PeerAddress = "fe80::1:9000".parse().unwrap();
        assert_eq!(address.port, PeerAddress::DEFAULT_PORT);
        assert_eq!(address.host, "fe80::1:9000");
    }

    #[test]
    fn display_round_trips_through_parse() {
        for text in ["192.168.1.77:9000", "work-laptop.local:7443", "[fe80::1]:9000"] {
            let address: PeerAddress = text.parse().unwrap();
            assert_eq!(address.to_string(), text);
            assert_eq!(address.to_string().parse::<PeerAddress>().unwrap(), address);
        }
    }
}
```

- [ ] **Step 2: Run the tests and watch them fail**

```bash
cargo test -p rc-transport address
```

Expected: FAIL to compile — `PeerAddress` does not exist.

- [ ] **Step 3: Write the implementation**

Above the test module in `crates/transport/src/address.rs`:

```rust
//! The address a user types to reach another machine.
//!
//! An IPv4 address, an IPv6 address or a hostname, each with an optional `:port`. No
//! scheme, no path, no query. Accepting a URL would imply the transport honours the
//! scheme, and it does not — this is always QUIC.
//!
//! An unbracketed IPv6 address with a trailing `:9000` is genuinely ambiguous: it is
//! indistinguishable from an address whose final group is `9000`. Rather than guess,
//! the whole string is taken as the host and the default port applies. Brackets are
//! how the user says otherwise, and [`Display`] always emits them.

use std::fmt;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;

use crate::error::{Result, TransportError};

/// A machine to dial.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerAddress {
    /// An IP address or a hostname. IPv6 addresses are stored unbracketed.
    pub host: String,
    /// The QUIC port.
    pub port: u16,
}

impl PeerAddress {
    /// The port used when the address does not name one.
    pub const DEFAULT_PORT: u16 = 7443;

    /// The longest address accepted, matching the database column's `CHECK`.
    const MAX_LEN: usize = 255;

    /// Resolve to socket addresses.
    ///
    /// A hostname may resolve to several; all are returned in the order the resolver
    /// gave them, and the caller tries each. Resolution failure is an error, never an
    /// empty list, so "no such host" cannot be mistaken for "nothing to try".
    pub fn to_socket_addrs(&self) -> Result<Vec<SocketAddr>> {
        let resolved: Vec<SocketAddr> = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|source| TransportError::UnresolvableAddress {
                address: self.to_string(),
                source,
            })?
            .collect();

        if resolved.is_empty() {
            return Err(TransportError::UnresolvableAddress {
                address: self.to_string(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "the name resolved to no addresses",
                ),
            });
        }
        Ok(resolved)
    }
}

impl FromStr for PeerAddress {
    type Err = TransportError;

    fn from_str(text: &str) -> Result<Self> {
        let trimmed = text.trim();
        if trimmed.is_empty() || trimmed.len() > Self::MAX_LEN {
            return Err(TransportError::InvalidAddress(text.to_owned()));
        }
        if trimmed.contains("://") || trimmed.contains('/') || trimmed.contains('?') {
            return Err(TransportError::InvalidAddress(text.to_owned()));
        }

        let (host, port) = if let Some(rest) = trimmed.strip_prefix('[') {
            // Bracketed IPv6, with or without a port.
            let (inside, after) = rest
                .split_once(']')
                .ok_or_else(|| TransportError::InvalidAddress(text.to_owned()))?;
            let port = match after {
                "" => Self::DEFAULT_PORT,
                _ => parse_port(after.strip_prefix(':').ok_or_else(|| {
                    TransportError::InvalidAddress(text.to_owned())
                })?)?,
            };
            if inside.parse::<IpAddr>().is_err() {
                return Err(TransportError::InvalidAddress(text.to_owned()));
            }
            (inside.to_owned(), port)
        } else if trimmed.matches(':').count() > 1 {
            // More than one colon and no brackets: an unbracketed IPv6 address. The
            // whole string is the host; a trailing group cannot be told from a port.
            if trimmed.parse::<IpAddr>().is_err() {
                return Err(TransportError::InvalidAddress(text.to_owned()));
            }
            (trimmed.to_owned(), Self::DEFAULT_PORT)
        } else if let Some((host, port)) = trimmed.split_once(':') {
            (host.to_owned(), parse_port(port)?)
        } else {
            (trimmed.to_owned(), Self::DEFAULT_PORT)
        };

        if host.is_empty() || !is_plausible_host(&host) {
            return Err(TransportError::InvalidAddress(text.to_owned()));
        }
        Ok(Self { host, port })
    }
}

impl fmt::Display for PeerAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(formatter, "[{}]:{}", self.host, self.port)
        } else {
            write!(formatter, "{}:{}", self.host, self.port)
        }
    }
}

/// A port that a peer could actually be listening on.
///
/// Zero means "any free port" to the operating system, so it is never something to
/// dial.
fn parse_port(text: &str) -> Result<u16> {
    match text.parse::<u16>() {
        Ok(0) | Err(_) => Err(TransportError::InvalidAddress(text.to_owned())),
        Ok(port) => Ok(port),
    }
}

/// Whether a host could be a hostname or an IP literal.
///
/// Deliberately permissive about what a resolver will accept and strict about what
/// cannot possibly be a host, so an obviously wrong entry is reported in the interface
/// rather than as a resolution failure seconds later.
fn is_plausible_host(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    !host.starts_with('-')
        && !host.ends_with('-')
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-' || character == '.')
}
```

Add the two error variants to `crates/transport/src/error.rs`:

```rust
    /// The text the user typed is not an address this transport can dial.
    #[error("`{0}` is not a valid address")]
    InvalidAddress(String),

    /// The address is well formed but names nothing reachable.
    #[error("`{address}` could not be resolved")]
    UnresolvableAddress {
        address: String,
        #[source]
        source: std::io::Error,
    },
```

Add `pub mod address;` and `pub use address::PeerAddress;` to `crates/transport/src/lib.rs`.

- [ ] **Step 4: Run the tests and verify they pass**

```bash
cargo test -p rc-transport address
cargo clippy -p rc-transport --all-targets --all-features -- -D warnings
```

Expected: PASS, 13 tests.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(transport): parse the address a user types

IPv4, IPv6 and hostnames with an optional port. A URL is refused rather
than half-understood, and an unbracketed IPv6 address with a trailing
group keeps the default port rather than guessing which half is the port."
```

---

### Task 10: The accept decision

The authorisation logic, with no user interface and no network, so it can be tested exhaustively before either exists.

**Files:**
- Modify: `crates/host-agent/Cargo.toml` (add a `[lib]` target)
- Create: `crates/host-agent/src/lib.rs`
- Create: `crates/host-agent/src/access.rs`
- Modify: `crates/host-agent/src/main.rs`

**Interfaces:**
- Consumes: `PermissionSet`, `PasswordCredential`, `Throttle`, `Clock` from `rc_security`; `RecentRepository`, `SettingsRepository` from `rc_storage`; `Fingerprint`.
- Produces:
  - `AcceptRequest { address: String, fingerprint: Fingerprint, machine_name: String }`
  - `AcceptDecision::Accept(PermissionSet)` / `AcceptDecision::Dismiss`
  - `#[async_trait] pub trait AcceptPrompt: Send + Sync { async fn ask(&self, request: AcceptRequest) -> AcceptDecision; }`
  - `Authorization::Granted(PermissionSet)` / `Authorization::Refused(RefusalReason)`
  - `RefusalReason::{Dismissed, NotAccepting, IdentityChanged, WrongPassword, TooManyAttempts}`
  - `async fn authorize_connection(request: &ConnectionRequest, deps: &AccessDeps<'_>) -> Result<Authorization>`
  - `ConnectionRequest { address: PeerAddress, fingerprint: Fingerprint, machine_name: String, unattended_password: Option<String> }`

- [ ] **Step 1: Make the agent a library**

In `crates/host-agent/Cargo.toml` add, above `[dependencies]`:

```toml
[lib]
name = "rc_host_agent"
path = "src/lib.rs"

[[bin]]
name = "rc-agent"
path = "src/main.rs"
```

Create `crates/host-agent/src/lib.rs`:

```rust
//! The host side of the product, as a library.
//!
//! Both the desktop application and the optional service run this code. There is one
//! implementation of accepting a connection, deciding what it may do and serving it —
//! a second would be a second set of authorisation bugs.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod access;
pub mod config;
pub mod file_service;
pub mod identity;
pub mod logging;
pub mod metrics_service;
pub mod server;
pub mod sessions;

pub use access::{
    AcceptDecision, AcceptPrompt, AcceptRequest, AccessDeps, Authorization, ConnectionRequest,
    RefusalReason, authorize_connection,
};
```

In `crates/host-agent/src/main.rs` delete every `mod` declaration and replace the references with `use rc_host_agent::...`. `main.rs` becomes the CLI and the service lifetime only.

- [ ] **Step 2: Write the failing tests**

Create `crates/host-agent/src/access.rs` with only this test module:

```rust
#[cfg(test)]
mod tests {
    use rc_security::{
        Clock, HashingPolicy, OsRandom, PasswordCredential, Permission, PermissionSet, Throttle,
    };
    use rc_storage::{RecentRepository, SettingsRepository};
    use rc_transport::PeerAddress;

    use super::*;

    /// A prompt that answers however the test says, and counts how often it was asked.
    struct ScriptedPrompt {
        answer: AcceptDecision,
        asked: std::sync::atomic::AtomicUsize,
    }

    impl ScriptedPrompt {
        fn new(answer: AcceptDecision) -> Self {
            Self { answer, asked: std::sync::atomic::AtomicUsize::new(0) }
        }
        fn asked(&self) -> usize {
            self.asked.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl AcceptPrompt for ScriptedPrompt {
        async fn ask(&self, _request: AcceptRequest) -> AcceptDecision {
            self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.answer
        }
    }

    fn request(password: Option<&str>) -> ConnectionRequest {
        ConnectionRequest {
            address: "192.168.1.77".parse::<PeerAddress>().unwrap(),
            fingerprint: Fingerprint::from_bytes([7u8; 32]),
            machine_name: "WORK-LAPTOP".to_owned(),
            unattended_password: password.map(str::to_owned),
        }
    }

    #[tokio::test]
    async fn a_dismissed_connection_is_refused_and_grants_nothing() {
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        let outcome = harness.authorize(request(None)).await.unwrap();
        assert_eq!(outcome, Authorization::Refused(RefusalReason::Dismissed));
    }

    #[tokio::test]
    async fn an_accepted_connection_gets_exactly_what_the_human_ticked() {
        let granted = PermissionSet::NONE.with(Permission::ViewMetrics);
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept(granted))).await;
        let outcome = harness.authorize(request(None)).await.unwrap();
        assert_eq!(outcome, Authorization::Granted(granted));
    }

    #[tokio::test]
    async fn a_machine_not_accepting_connections_is_never_prompted() {
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept(PermissionSet::ALL))).await;
        harness.settings().set_accepting(false).await.unwrap();

        let outcome = harness.authorize(request(None)).await.unwrap();
        assert_eq!(outcome, Authorization::Refused(RefusalReason::NotAccepting));
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn an_always_allow_peer_skips_the_prompt() {
        let granted = PermissionSet::NONE.with(Permission::TransferFiles);
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness.recent().record("192.168.1.77:7443", "WORK-LAPTOP", 1_000).await.unwrap();
        harness
            .recent()
            .set_always_allow("192.168.1.77:7443", Some(Fingerprint::from_bytes([7u8; 32])), granted)
            .await
            .unwrap();

        let outcome = harness.authorize(request(None)).await.unwrap();
        assert_eq!(outcome, Authorization::Granted(granted));
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn a_pinned_peer_presenting_a_different_fingerprint_is_refused_not_prompted() {
        // This is the loudest failure the system has. Falling back to the Accept
        // dialog would turn an identity change into a routine click.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept(PermissionSet::ALL))).await;
        harness.recent().record("192.168.1.77:7443", "WORK-LAPTOP", 1_000).await.unwrap();
        harness
            .recent()
            .set_always_allow(
                "192.168.1.77:7443",
                Some(Fingerprint::from_bytes([99u8; 32])),
                PermissionSet::ALL,
            )
            .await
            .unwrap();

        let outcome = harness.authorize(request(None)).await.unwrap();
        assert_eq!(outcome, Authorization::Refused(RefusalReason::IdentityChanged));
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn a_correct_unattended_password_skips_the_prompt() {
        let granted = PermissionSet::NONE.with(Permission::ControlInput);
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness.set_unattended("correct horse battery", granted).await;

        let outcome = harness.authorize(request(Some("correct horse battery"))).await.unwrap();
        assert_eq!(outcome, Authorization::Granted(granted));
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn a_wrong_unattended_password_is_refused_without_falling_back_to_the_prompt() {
        // Falling back would make a wrong password indistinguishable from no password
        // and would let an attacker convert a guess into a prompt on someone's screen.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept(PermissionSet::ALL))).await;
        harness.set_unattended("correct horse battery", PermissionSet::ALL).await;

        let outcome = harness.authorize(request(Some("wrong password here"))).await.unwrap();
        assert_eq!(outcome, Authorization::Refused(RefusalReason::WrongPassword));
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn a_password_offered_when_none_is_configured_is_refused_identically() {
        // The answer must not disclose whether unattended access exists.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept(PermissionSet::ALL))).await;
        let outcome = harness.authorize(request(Some("anything at all"))).await.unwrap();
        assert_eq!(outcome, Authorization::Refused(RefusalReason::WrongPassword));
    }

    #[tokio::test]
    async fn repeated_wrong_passwords_lock_out_before_hashing() {
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness.set_unattended("correct horse battery", PermissionSet::ALL).await;

        for _ in 0..5 {
            let _ = harness.authorize(request(Some("wrong password here"))).await.unwrap();
        }
        let outcome = harness.authorize(request(Some("correct horse battery"))).await.unwrap();
        assert_eq!(outcome, Authorization::Refused(RefusalReason::TooManyAttempts));
    }

    #[tokio::test]
    async fn no_password_offered_still_reaches_the_prompt_when_unattended_is_configured() {
        // Configuring unattended access adds a second way in; it does not remove the
        // first.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept(PermissionSet::ALL))).await;
        harness.set_unattended("correct horse battery", PermissionSet::ALL).await;

        let outcome = harness.authorize(request(None)).await.unwrap();
        assert_eq!(outcome, Authorization::Granted(PermissionSet::ALL));
        assert_eq!(harness.prompt().asked(), 1);
    }

    #[tokio::test]
    async fn accepting_with_nothing_ticked_is_a_refusal_not_an_empty_session() {
        // A session that may do nothing is a connection nobody can use and nobody can
        // see. Saying no is clearer.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept(PermissionSet::NONE))).await;
        let outcome = harness.authorize(request(None)).await.unwrap();
        assert_eq!(outcome, Authorization::Refused(RefusalReason::Dismissed));
    }
}
```

Write a `Harness` in the same test module that builds a `temp_database`, a `SettingsRepository`, a `RecentRepository`, a `Throttle::with_defaults()`, a fixed test `Clock`, and holds the `ScriptedPrompt`; `Harness::authorize` assembles an `AccessDeps` and calls `authorize_connection`. Expose `settings()`, `recent()`, `prompt()`, and `set_unattended(&str, PermissionSet)` which builds a `PasswordCredential` with `HashingPolicy::FAST_FOR_TESTS`.

- [ ] **Step 3: Run the tests and watch them fail**

```bash
cargo test -p rc-host-agent access
```

Expected: FAIL to compile — nothing in `access` exists.

- [ ] **Step 4: Write the implementation**

Above the test module in `crates/host-agent/src/access.rs`:

```rust
//! Deciding what an incoming connection may do.
//!
//! Three ways in, checked in a fixed order, and the order is the design:
//!
//! 1. **A pinned peer.** The user has already decided about this machine. If the
//!    fingerprint does not match the pin, the connection is refused outright — never
//!    handed to the Accept dialog, because an identity change must not be reachable by
//!    a routine click.
//! 2. **An unattended password**, if the connection offered one. A wrong password is a
//!    refusal, not a fallback to the dialog: falling back would let anyone with the
//!    address raise a prompt on someone's screen by guessing, and would make a wrong
//!    password indistinguishable from no password.
//! 3. **A human.** The dialog, with the timeout and the default both set to Dismiss.
//!
//! Nothing here talks to a network or a window. The prompt is a trait so the whole
//! decision can be tested against a scripted answer, and so the desktop application
//! and the service can present it differently without either owning the rule.

use async_trait::async_trait;
use rc_security::{Clock, Fingerprint, PermissionSet, Throttle};
use rc_storage::{RecentRepository, SettingsRepository};
use rc_transport::PeerAddress;
use tokio::sync::Mutex;

use crate::error::Result;

/// What the person at the keyboard is shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptRequest {
    /// Correlates the dialog with the connection waiting on it.
    ///
    /// The answer arrives from a window, not from the connection, so without this an
    /// answer could be applied to whichever request happened to be open.
    pub request_id: String,
    /// The address the connection came from, as it will be displayed.
    pub address: String,
    /// The peer's certificate fingerprint, taken from the TLS connection.
    pub fingerprint: Fingerprint,
    /// The name the peer reported. Untrusted, and displayed as such.
    pub machine_name: String,
}

/// What they decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptDecision {
    /// Accept, granting exactly these permissions.
    Accept(PermissionSet),
    /// Refuse. Also what a timeout, an Escape and a closed window mean.
    Dismiss,
}

/// Asks a human.
#[async_trait]
pub trait AcceptPrompt: Send + Sync {
    /// Show the request and return the answer.
    ///
    /// Implementations must return [`AcceptDecision::Dismiss`] on a timeout rather than
    /// blocking forever: a connection held open waiting for someone who went home is a
    /// resource leak with an authorisation decision attached.
    async fn ask(&self, request: AcceptRequest) -> AcceptDecision;
}

/// An incoming connection, after TLS and before any authorisation.
#[derive(Debug, Clone)]
pub struct ConnectionRequest {
    pub address: PeerAddress,
    pub fingerprint: Fingerprint,
    pub machine_name: String,
    /// The unattended password the peer offered, if it offered one.
    pub unattended_password: Option<String>,
}

/// Why a connection was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// A human said no, or said nothing for long enough.
    Dismissed,
    /// This machine is not accepting connections at all.
    NotAccepting,
    /// A pinned peer presented a different certificate.
    IdentityChanged,
    /// An unattended password was offered and was wrong, or none is configured.
    WrongPassword,
    /// Too many wrong passwords; the lockout is in force.
    TooManyAttempts,
}

/// The outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorization {
    /// Proceed, holding exactly these permissions for the whole session.
    Granted(PermissionSet),
    /// Do not proceed.
    Refused(RefusalReason),
}

/// Everything the decision reads or writes.
pub struct AccessDeps<'a> {
    pub settings: &'a SettingsRepository,
    pub recent: &'a RecentRepository,
    pub prompt: &'a dyn AcceptPrompt,
    pub throttle: &'a Mutex<Throttle>,
    pub clock: &'a dyn Clock,
}

/// Decide what an incoming connection may do.
pub async fn authorize_connection(
    request: &ConnectionRequest,
    deps: &AccessDeps<'_>,
) -> Result<Authorization> {
    // Read once. Two reads could straddle a settings change and decide against two
    // different configurations within one connection.
    let settings = deps.settings.load().await?;
    if !settings.accepting {
        return Ok(Authorization::Refused(RefusalReason::NotAccepting));
    }

    let key = request.address.to_string();

    // 1. A decision the user already made about this machine.
    if let Some(entry) = deps.recent.find(&key).await? {
        if let Some(pinned) = entry.pinned_fingerprint {
            // `ct_eq`, not `==`. The crate provides it precisely so no comparison of an
            // identity anywhere in the tree is the one that leaks a timing signal.
            return Ok(if pinned.ct_eq(&request.fingerprint) {
                Authorization::Granted(entry.pinned_permissions)
            } else {
                Authorization::Refused(RefusalReason::IdentityChanged)
            });
        }
    }

    // 2. An unattended password, if one was offered.
    if let Some(offered) = request.unattended_password.as_deref() {
        // Checked before hashing, so a lockout cannot be turned into a
        // work-amplification vector.
        {
            let throttle = deps.throttle.lock().await;
            if throttle.check(&key, deps.clock).is_err() {
                return Ok(Authorization::Refused(RefusalReason::TooManyAttempts));
            }
        }

        let stored = deps.settings.unattended_credential().await?;
        let permitted = settings.unattended_permissions;

        let verified = match &stored {
            Some(credential) => credential.verify(offered).is_ok(),
            None => {
                // A full dummy hash, so "no unattended access configured" and "wrong
                // password" cost the same and answer the same. Otherwise the timing
                // discloses whether unattended access exists.
                let _ = rc_security::password::verify_against_nothing(
                    offered,
                    rc_security::HashingPolicy::PRODUCTION,
                );
                false
            }
        };

        let mut throttle = deps.throttle.lock().await;
        return Ok(if verified {
            throttle.record_success(&key, deps.clock);
            Authorization::Granted(permitted)
        } else {
            throttle.record_failure(&key, deps.clock);
            Authorization::Refused(RefusalReason::WrongPassword)
        });
    }

    // 3. Ask a human.
    let decision = deps
        .prompt
        .ask(AcceptRequest {
            address: key,
            fingerprint: request.fingerprint.clone(),
            machine_name: request.machine_name.clone(),
        })
        .await;

    Ok(match decision {
        // Accepting with nothing ticked is a session that can do nothing and that
        // nobody can see. Refusing says the same thing more clearly.
        AcceptDecision::Accept(granted) if !granted.is_empty() => Authorization::Granted(granted),
        _ => Authorization::Refused(RefusalReason::Dismissed),
    })
}
```

- [ ] **Step 5: Run the tests and verify they pass**

```bash
cargo test -p rc-host-agent access
cargo clippy -p rc-host-agent --all-targets --all-features -- -D warnings
```

Expected: PASS, 11 tests.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(host-agent): the accept decision

Three ways in, checked in order: a pinned peer, an unattended password, a
human. A pin mismatch is refused rather than handed to the dialog, and a
wrong password does not fall back to it. The prompt is a trait, so the
whole rule is tested against scripted answers with no window and no
network."
```

---

### Task 11: Carry the decision over the wire

**Files:**
- Modify: `crates/protocol/src/control.rs`
- Modify: `crates/transport/src/handshake.rs`
- Modify: `crates/host-agent/src/server.rs`, `crates/host-agent/src/sessions.rs`
- Test: `crates/protocol/src/control.rs`, `crates/transport/tests/`

**Interfaces:**
- Consumes: Task 10's `Authorization`, `RefusalReason`.
- Produces:
  - `control::Authenticate { unattended_password: Option<String> }`
  - `control::SessionAuthorization::Granted { permissions: PermissionSet, machine_name: String }` / `::Refused { reason: WireRefusal }`
  - `WireRefusal::{Dismissed, NotAccepting, IdentityChanged, Rejected}`
  - `finish_accept` returns the `PermissionSet` the session holds
  - `Session::permissions() -> PermissionSet` and `Session::require(Permission) -> Result<()>`

- [ ] **Step 1: Write the failing protocol test**

In `crates/protocol/src/control.rs`, add to the test module:

```rust
    #[test]
    fn a_wire_refusal_does_not_distinguish_a_wrong_password_from_a_dismissal() {
        // Both must look the same to the peer, or the answer becomes an oracle for
        // whether unattended access is configured. They are distinguished only in the
        // receiving machine's own log.
        assert_eq!(WireRefusal::from(RefusalReason::Dismissed), WireRefusal::Rejected);
        assert_eq!(WireRefusal::from(RefusalReason::WrongPassword), WireRefusal::Rejected);
        assert_eq!(WireRefusal::from(RefusalReason::TooManyAttempts), WireRefusal::Rejected);
    }

    #[test]
    fn not_accepting_and_identity_changed_are_reported_distinctly() {
        // These two need different remedies, so telling them apart helps the person
        // connecting and discloses nothing they could not already observe.
        assert_eq!(WireRefusal::from(RefusalReason::NotAccepting), WireRefusal::NotAccepting);
        assert_eq!(
            WireRefusal::from(RefusalReason::IdentityChanged),
            WireRefusal::IdentityChanged
        );
    }

    #[test]
    fn session_authorization_round_trips_through_postcard() {
        let granted = SessionAuthorization::Granted {
            permissions: PermissionSet::ALL,
            machine_name: "WORK-LAPTOP".to_owned(),
        };
        let bytes = postcard::to_stdvec(&granted).unwrap();
        assert_eq!(postcard::from_bytes::<SessionAuthorization>(&bytes).unwrap(), granted);
    }

    #[test]
    fn an_authenticate_message_carrying_no_password_is_the_common_case() {
        let message = Authenticate { unattended_password: None };
        let bytes = postcard::to_stdvec(&message).unwrap();
        assert_eq!(postcard::from_bytes::<Authenticate>(&bytes).unwrap(), message);
    }
```

- [ ] **Step 2: Run it and watch it fail**

```bash
cargo test -p rc-protocol control
```

Expected: FAIL to compile — `Authenticate`, `SessionAuthorization` and `WireRefusal` do not exist.

- [ ] **Step 3: Add the messages**

In `crates/protocol/src/control.rs`:

```rust
/// Sent by the initiator immediately after [`HelloAck`].
///
/// The password travels inside the already-established mutually-authenticated TLS
/// connection, so it is never on the wire in the clear, and it is never part of
/// [`Hello`] — a peer that has not yet seen who it is talking to should not have sent
/// a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authenticate {
    /// The unattended-access password, when the user supplied one.
    pub unattended_password: Option<String>,
}

/// What a peer is told about its own connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionAuthorization {
    /// Proceed. These permissions hold for the whole session and cannot be widened.
    Granted {
        permissions: PermissionSet,
        /// The responder's machine name, for the initiator's Recent list.
        machine_name: String,
    },
    /// Do not proceed.
    Refused { reason: WireRefusal },
}

/// Why a peer was refused, as the peer is told it.
///
/// Deliberately coarser than the receiving machine's own reason. A dismissal, a wrong
/// password and a lockout are one value here: distinguishing them would tell a caller
/// whether unattended access is configured and whether its guesses are landing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum WireRefusal {
    /// The machine is not accepting connections at all.
    NotAccepting,
    /// A pinned peer presented a different certificate.
    IdentityChanged,
    /// Refused. Says nothing about which of the several ways it was refused.
    Rejected,
}
```

Add `impl From<RefusalReason> for WireRefusal` in `crates/host-agent/src/access.rs` — the mapping lives with the reasons it narrows, and the protocol crate must not depend on the agent. Move the two mapping tests there and leave the round-trip tests in the protocol crate.

- [ ] **Step 4: Wire it into the handshake**

In `crates/transport/src/handshake.rs`, change `finish_accept` to take an `authorize: impl AsyncFnOnce(&AuthenticatedPeer) -> Authorization`-shaped callback (a boxed async closure or a small trait, whichever the surrounding code already uses), read the `Authenticate` frame, call the callback, write the `SessionAuthorization`, and return `Result<PermissionSet>` — closing the connection when refused.

Change `begin_handshake` to take `unattended_password: Option<String>`, send `Authenticate`, read `SessionAuthorization`, and return the granted `PermissionSet` and the responder's machine name, or a typed error carrying the `WireRefusal`.

- [ ] **Step 5: Carry the permissions on the session**

In `crates/host-agent/src/sessions.rs`, add `permissions: PermissionSet` to the session record and:

```rust
impl Session {
    /// What this session may do. Fixed for its lifetime.
    #[must_use]
    pub const fn permissions(&self) -> PermissionSet {
        self.permissions
    }

    /// Refuse unless this session holds `permission`.
    ///
    /// Called on every request rather than once at connect, so a session whose
    /// permissions are withdrawn stops being answered immediately rather than at its
    /// next reconnection.
    pub fn require(&self, permission: Permission) -> Result<()> {
        if self.permissions.contains(permission) {
            Ok(())
        } else {
            Err(AgentError::PermissionDenied { permission: permission.name() })
        }
    }
}
```

Replace every existing authorisation check in `file_service.rs` and `metrics_service.rs` with `session.require(Permission::TransferFiles)` and `session.require(Permission::ViewMetrics)`. Keep the existing rule that the set of read-only file operations is an explicit list and anything not on it needs write access — with one file permission now, that list collapses, so delete it and require `TransferFiles` for every file operation. Record that change in the file-service doc comment so the next reader does not think the distinction was lost by accident.

- [ ] **Step 6: Run the tests and verify they pass**

```bash
cargo test -p rc-protocol -p rc-transport -p rc-host-agent
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: carry the accept decision over the wire

Authenticate and SessionAuthorization join the control channel. The wire
refusal is coarser than the local reason on purpose: a dismissal, a wrong
password and a lockout are one value, so the answer is not an oracle for
whether unattended access is configured."
```

---

### Task 12: Embed the host in the desktop application

**Files:**
- Modify: `apps/desktop-client/src-tauri/Cargo.toml` (depend on `rc-host-agent`)
- Modify: `apps/desktop-client/src-tauri/src/lib.rs`
- Create: `apps/desktop-client/src-tauri/src/host.rs` — the embedded listener and the Tauri-backed `AcceptPrompt`
- Create: `apps/desktop-client/src-tauri/src/host_commands.rs`
- Modify: `apps/desktop-client/src-tauri/src/commands.rs`, `connect_commands.rs`
- Modify: `apps/desktop-client/src/api.ts`

**Interfaces:**
- Consumes: `rc_host_agent::{AcceptPrompt, AcceptRequest, AcceptDecision, authorize_connection}`, `PeerAddress`.
- Produces these Tauri commands, each mirrored by a Zod-validated function in `api.ts`:
  - `host_status() -> HostStatusDto { accepting: bool, addresses: Vec<String>, machine_name: String, listen_port: u16 }`
  - `set_accepting(accepting: bool) -> HostStatusDto`
  - `pending_accept_request() -> Option<AcceptRequestDto>`
  - `answer_accept_request(request_id: String, granted: Vec<String>) -> ()`
  - `connect_to_address(address: String, unattended_password: Option<String>) -> ConnectionStateDto`
  - `list_recent() -> Vec<RecentDto>`, `set_always_allow(address: String, always: bool) -> ()`, `remove_recent(address: String) -> ()`
  - `host_settings() -> SettingsDto`, `set_unattended_password(password: Option<String>, permissions: Vec<String>) -> ()`

- [ ] **Step 1: Write the failing frontend contract test**

Create `apps/desktop-client/src/host.test.ts`:

```typescript
import { describe, expect, it } from 'vitest';
import { acceptRequestSchema, hostStatusSchema, recentSchema } from './api.js';

describe('host DTO schemas', () => {
  it('accepts a well-formed host status', () => {
    const parsed = hostStatusSchema.parse({
      accepting: true,
      addresses: ['192.168.1.42:7443'],
      machineName: 'KOREN-PC',
      listenPort: 7443,
    });
    expect(parsed.addresses).toHaveLength(1);
  });

  it('refuses a host status with no machine name', () => {
    expect(() =>
      hostStatusSchema.parse({ accepting: true, addresses: [], machineName: '', listenPort: 7443 }),
    ).toThrow();
  });

  it('accepts an accept request and keeps the fingerprint intact', () => {
    const parsed = acceptRequestSchema.parse({
      requestId: 'r1',
      address: '192.168.1.77:7443',
      fingerprint: 'a'.repeat(64),
      machineName: 'WORK-LAPTOP',
    });
    expect(parsed.fingerprint).toHaveLength(64);
  });

  it('strips control characters and bidi overrides from an untrusted machine name', () => {
    // The peer chooses this string. Without stripping, a name can be made to render
    // as a different one.
    const parsed = acceptRequestSchema.parse({
      requestId: 'r1',
      address: '192.168.1.77:7443',
      fingerprint: 'a'.repeat(64),
      machineName: 'WORK‮POTAL',
    });
    expect(parsed.machineName).toBe('WORKPOTAL');
  });

  it('refuses a recent entry whose pinned permissions are unknown', () => {
    expect(() =>
      recentSchema.parse({
        address: '192.168.1.77:7443',
        machineName: 'WORK-LAPTOP',
        lastConnectedMs: 1,
        alwaysAllow: true,
        pinnedPermissions: ['control_input', 'launch_missiles'],
      }),
    ).toThrow();
  });
});
```

- [ ] **Step 2: Run it and watch it fail**

```bash
pnpm --filter @rc/desktop-client test:run -- host
```

Expected: FAIL — the three schemas are not exported from `api.ts`.

- [ ] **Step 3: Write the schemas and the sanitiser**

In `apps/desktop-client/src/api.ts`, add a shared `untrustedText` helper that strips C0/C1 control characters and the Unicode bidirectional overrides (`‪`–`‮`, `⁦`–`⁩`), reusing the existing sanitiser if `api.ts` already has one for file names — do not write a second. Then export `hostStatusSchema`, `acceptRequestSchema`, `recentSchema` and `settingsSchema`, and the functions listed under **Interfaces**, each parsing its result through its schema.

- [ ] **Step 4: Write the embedded host**

Create `apps/desktop-client/src-tauri/src/host.rs`. It:

- starts `rc_host_agent::server` on the configured port when `accepting` is true, and stops it when set to false;
- implements `AcceptPrompt` by storing the request in shared state, emitting a `rc://accept-request` Tauri event, and awaiting a `tokio::sync::oneshot` resolved by `answer_accept_request`;
- wraps that await in `tokio::time::timeout(Duration::from_secs(30), ..)`, mapping elapsed time to `AcceptDecision::Dismiss`;
- holds at most one pending request at a time and answers any further incoming connection with `AcceptDecision::Dismiss` while one is open, so a flood cannot stack dialogs.

Register `host_commands::*` in the `generate_handler!` list in `lib.rs`.

- [ ] **Step 5: Write the timeout test**

In `apps/desktop-client/src-tauri/src/host.rs`:

```rust
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rc_host_agent::{AcceptDecision, AcceptPrompt};

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_prompt_nobody_answers_becomes_a_dismissal() {
        let prompt = TauriPrompt::for_tests();
        let request = test_request();

        let decision = prompt.ask(request).await;

        assert_eq!(decision, AcceptDecision::Dismiss);
    }

    #[tokio::test]
    async fn a_second_request_while_one_is_open_is_dismissed_immediately() {
        // Stacking dialogs would let anyone with the address bury the machine in
        // prompts until one is clicked by accident.
        let prompt = TauriPrompt::for_tests();
        let first = tokio::spawn({
            let prompt = prompt.clone();
            async move { prompt.ask(test_request()).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(prompt.ask(test_request()).await, AcceptDecision::Dismiss);
        first.abort();
    }
}
```

- [ ] **Step 6: Run everything**

```bash
cargo test -p rc-desktop-client
pnpm --filter @rc/desktop-client test:run
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(client): embed the host side in the desktop application

One program is now both controller and controlled. The Accept prompt is a
Tauri-backed implementation of the trait from the agent library, with the
30-second timeout mapping to Dismiss and at most one dialog open at a time
so a flood cannot stack prompts until one is clicked by accident."
```

---

### Task 13: Two-process integration tests for the access model

**Files:**
- Modify: `crates/host-agent/tests/` — adapt the existing harness that spawns the real binary
- Create: `crates/host-agent/tests/access_e2e.rs`

**Interfaces:**
- Consumes: everything from Tasks 9–12.
- Produces: no new API; this task exists to make the earlier tasks' claims statements of fact.

- [ ] **Step 1: Find the existing harness**

```bash
ls crates/host-agent/tests/
grep -rn "fn spawn_agent\|Command::new" crates/host-agent/tests/ | head
```

Reuse whatever spawns the real `rc-agent` binary. Do not write a second harness — the whole value of these tests is that they drive the real process.

- [ ] **Step 2: Write the failing end-to-end tests**

Create `crates/host-agent/tests/access_e2e.rs` covering exactly these cases, each against a spawned real agent with a scripted prompt supplied through its configuration:

1. Connect and accept with all three permissions → the client reaches `connected` and a metrics request succeeds.
2. Connect and dismiss → the client reaches `refused` and does **not** retry.
3. Nobody answers → after 30 seconds the client reaches `refused`. Drive the clock rather than sleeping.
4. Unattended password correct → connected with the pre-selected permissions, and the prompt was never shown.
5. Unattended password wrong → refused, and the prompt was never shown.
6. Always-allow peer → connected with no prompt.
7. Always-allow peer presenting a changed certificate → refused with `IdentityChanged`, no prompt, no retry.
8. Accepted with `TransferFiles` unticked → a file request is refused while a metrics request succeeds, proving the permission is enforced per request and not merely hidden in the interface.
9. The agent restarts and the always-allow peer reconnects → still connected with no prompt, proving the pin survived and the certificate did not change across a restart. This is the regression test for the Phase 3 bug where the certificate was reissued on every load; it must not be dropped.

- [ ] **Step 3: Run them and watch them fail, then pass**

```bash
cargo test -p rc-host-agent --test access_e2e -- --test-threads=1
```

The CI configuration already serialises the agent end-to-end tests (commit `71f66ac`); keep `--test-threads=1` and whatever serialisation attribute the existing tests use, because two agents binding ports concurrently is a flake, not a finding.

- [ ] **Step 4: Run the full gate**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
pnpm -r typecheck && pnpm -r test:run
```

Expected: all PASS. At this point the access model is complete and proven; the remaining tasks are interface and documentation.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "test(host-agent): prove the access model against a real agent

Nine cases driven against the spawned binary: accept, dismiss, timeout,
correct and wrong unattended password, always-allow, a changed certificate
on a pinned peer, a withheld permission refused per request, and a pin
surviving an agent restart."
```

---

### Task 14: Rewrite the design tokens

**Files:**
- Rewrite: `apps/desktop-client/src/index.css`
- Modify: every surviving component that names a deleted token

**Interfaces:**
- Consumes: nothing.
- Produces: the token names `--color-page`, `--color-card`, `--color-border`, `--color-text`, `--color-text-secondary`, `--color-accent`, `--color-accent-hover`, `--color-success`, `--color-danger`.

- [ ] **Step 1: Replace the `@theme` block**

In `apps/desktop-client/src/index.css`, replace the entire `@theme { ... }` block with:

```css
/*
 * Design tokens.
 *
 * One light theme, matching the product this is modelled on. There is no dark
 * variant and no `data-theme` opt-in: a token defined for a theme nobody can select
 * is dead code, and this file previously carried a whole second palette for one.
 *
 * The accent is used for exactly two things — the primary action and the current
 * state of a control. Status colours mean the state they name and are never
 * decorative.
 */
@theme {
  --color-page: #f5f6f8;
  --color-card: #ffffff;
  --color-border: #e3e5e9;

  --color-text: #1a1a1a;
  --color-text-secondary: #6b7280;

  --color-accent: #ef443b;
  --color-accent-hover: #d93a32;
  --color-accent-soft: rgb(239 68 59 / 10%);
  --color-accent-text: #ffffff;

  --color-success: #2e9e4f;
  --color-success-soft: rgb(46 158 79 / 12%);
  --color-danger: #c62828;
  --color-danger-soft: rgb(198 40 40 / 10%);

  --radius-card: 8px;
  --shadow-card: 0 1px 2px rgb(16 24 40 / 6%), 0 1px 3px rgb(16 24 40 / 4%);

  --ease-ui: cubic-bezier(0.2, 0, 0.2, 1);
}
```

- [ ] **Step 2: Replace the base layer**

In the same file, delete `:root { color-scheme: dark; }`, both `:root[data-theme=...]` blocks and every token they define. Set `color-scheme: light` on `:root`, and set `body`'s background to `var(--color-page)` and colour to `var(--color-text)`.

Keep, unchanged: the `html, body, #root { height: 100% }` rule, `overflow: hidden` on `body`, `font-variant-numeric: tabular-nums`, the monospace stack for `code`/`pre`/`.font-mono`, the `:focus-visible` outline, the `user-select: none` rule on buttons, the scrollbar styling, and the `prefers-reduced-motion` block.

Change the font stack's first family to `'Segoe UI Variable Text', 'Segoe UI', 'Inter', system-ui, sans-serif`.

- [ ] **Step 3: Delete the shimmer**

Delete the `rc-shimmer` keyframes and the `.animate-skeleton` utility. Keep `rc-pulse`/`.animate-status-pulse`, `rc-fade-in`/`.animate-fade-in` and `rc-toast-in`/`.animate-toast-in`.

- [ ] **Step 4: Find every reference to a deleted token**

```bash
grep -rn "color-surface\|color-text-primary\|color-text-muted\|color-border-subtle\|color-border-strong\|color-warning\|animate-skeleton" apps/desktop-client/src/
```

Replace each: `--color-surface` and `--color-surface-sunken` become `--color-page`; `--color-surface-raised` and `--color-surface-overlay` become `--color-card`; `--color-text-primary` becomes `--color-text`; `--color-text-muted` becomes `--color-text-secondary`; `--color-border-subtle` and `--color-border-strong` become `--color-border`; `--color-warning*` becomes `--color-danger*` where it marked a problem and is deleted where it was decorative.

- [ ] **Step 5: Verify nothing references a token that no longer exists**

```bash
grep -rn "color-surface\|color-text-primary\|color-text-muted\|color-border-subtle\|color-border-strong\|color-warning\|animate-skeleton\|data-theme" apps/desktop-client/src/
pnpm --filter @rc/desktop-client build
```

Expected: no grep output, and a successful build.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(ui): rewrite the design tokens for a light theme

Four dark surface levels and a whole unreachable light palette become one
light theme with a single red accent. The focus outline, reduced-motion
block, tabular figures and scrollbar styling are kept unchanged."
```

---

### Task 15: The main window

**Files:**
- Create: `apps/desktop-client/src/MainWindow.tsx`, `ThisDeskCard.tsx`, `RemoteDeskCard.tsx`, `RecentList.tsx`, `address.ts`, `permissions.ts`
- Create: `apps/desktop-client/src/address.test.ts`, `mainWindow.test.tsx`
- Delete: `apps/desktop-client/src/RemoteAccessScreen.tsx`, `ThisComputerScreen.tsx`, `AuthScreen.tsx`, `shell/`
- Rewrite: `apps/desktop-client/src/App.tsx`

**Interfaces:**
- Consumes: the Tauri commands from Task 12.
- Produces: `parseAddress(text: string): { ok: true; value: string } | { ok: false; reason: string }` in `address.ts`, mirroring `PeerAddress` exactly.

- [ ] **Step 1: Write the failing address tests**

Create `apps/desktop-client/src/address.test.ts`:

```typescript
import { describe, expect, it } from 'vitest';
import { parseAddress } from './address.js';

describe('parseAddress', () => {
  it('accepts a bare IPv4 address and applies the default port', () => {
    expect(parseAddress('192.168.1.77')).toEqual({ ok: true, value: '192.168.1.77:7443' });
  });

  it('accepts an explicit port', () => {
    expect(parseAddress('192.168.1.77:9000')).toEqual({ ok: true, value: '192.168.1.77:9000' });
  });

  it('accepts a bracketed IPv6 address', () => {
    expect(parseAddress('[fe80::1]:9000')).toEqual({ ok: true, value: '[fe80::1]:9000' });
  });

  it('accepts a hostname', () => {
    expect(parseAddress('work-laptop.local')).toEqual({
      ok: true,
      value: 'work-laptop.local:7443',
    });
  });

  it('trims surrounding whitespace', () => {
    expect(parseAddress('  192.168.1.77  ')).toEqual({ ok: true, value: '192.168.1.77:7443' });
  });

  it('reports an empty address rather than silently doing nothing', () => {
    const result = parseAddress('');
    expect(result.ok).toBe(false);
  });

  it('refuses a URL', () => {
    expect(parseAddress('https://192.168.1.77').ok).toBe(false);
  });

  it('refuses port zero', () => {
    expect(parseAddress('192.168.1.77:0').ok).toBe(false);
  });

  it('refuses a port above the range', () => {
    expect(parseAddress('192.168.1.77:70000').ok).toBe(false);
  });

  it('gives a reason a person can act on', () => {
    const result = parseAddress('https://192.168.1.77');
    if (result.ok) throw new Error('expected a refusal');
    expect(result.reason).toMatch(/address/i);
    expect(result.reason).not.toMatch(/undefined|error|null/i);
  });
});
```

- [ ] **Step 2: Run it and watch it fail**

```bash
pnpm --filter @rc/desktop-client test:run -- address
```

Expected: FAIL — `./address.js` does not exist.

- [ ] **Step 3: Write `address.ts`**

Implement `parseAddress` to the same rules as `PeerAddress::from_str` in Task 9, including the unbracketed-IPv6 behaviour. This is a deliberate second implementation: the backend's is the authority and re-validates everything, and this one exists so the user is told about a typo before a connection is attempted. Say so in the file's doc comment, so nobody later "removes the duplication" by trusting only one of them.

- [ ] **Step 4: Write the failing main-window test**

Create `apps/desktop-client/src/mainWindow.test.tsx` with React Testing Library, covering:

- the This Desk card renders each address returned by `host_status` with a copy button;
- the accepting-connections dot reads *Accepting connections* when true and *Not accepting connections* when false;
- typing an invalid address and pressing Connect shows the reason under the field and **does not clear the field**;
- typing a valid address and pressing Connect calls `connect_to_address` once with the canonical form;
- an empty Recent list renders its one-sentence empty state rather than a bare list;
- a Recent row shows the machine name, the address and a relative time, and clicking it calls `connect_to_address`.

Mock the Tauri IPC with the existing helper in `apps/desktop-client/src/test-setup.ts`; do not introduce a second mocking approach.

- [ ] **Step 5: Build the components**

Write `ThisDeskCard.tsx`, `RemoteDeskCard.tsx`, `RecentList.tsx` and `MainWindow.tsx` to the layout in the spec: two cards side by side above a Recent list, a slim title bar with a gear on the right. Addresses render in the monospace stack. An address the backend could not determine is absent from the list rather than shown as a placeholder.

Delete `RemoteAccessScreen.tsx`, `ThisComputerScreen.tsx`, `AuthScreen.tsx` and the whole `shell/` directory.

Rewrite `App.tsx` as a two-state root: `MainWindow` or `SessionScreen`, plus the toast bar and the accept dialog. Delete the `Gate` type, `useServiceStatus`, the collapsed-sidebar state and its `localStorage` key, the keyboard-shortcut effect and the update banner's section check — the banner now sits under the title bar unconditionally when an update is pending.

- [ ] **Step 6: Run the tests and verify they pass**

```bash
pnpm --filter @rc/desktop-client test:run
pnpm --filter @rc/desktop-client typecheck
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(ui): the main window

Two cards and a Recent list replace an eleven-section sidebar, four shell
components, a navigation table, seven keyboard shortcuts and the owner
login gate."
```

---

### Task 16: The accept dialog

**Files:**
- Create: `apps/desktop-client/src/AcceptDialog.tsx`, `apps/desktop-client/src/acceptDialog.test.tsx`
- Modify: `apps/desktop-client/src/App.tsx`

**Interfaces:**
- Consumes: the `rc://accept-request` Tauri event and `answer_accept_request` from Task 12.
- Produces: no exported API beyond the component.

- [ ] **Step 1: Write the failing tests**

Create `apps/desktop-client/src/acceptDialog.test.tsx` covering:

- it renders the incoming address, the machine name and the fingerprint;
- all three permission checkboxes are ticked by default;
- pressing Escape calls `answer_accept_request` with an empty grant;
- clicking Dismiss calls `answer_accept_request` with an empty grant;
- clicking Accept with all three ticked calls it with all three;
- unticking *Transfer files* and clicking Accept calls it with the other two only;
- the Dismiss button is the one focused on open, so a stray Enter refuses rather than accepts;
- the dialog renders the machine name as inert text — a name containing `<img src=x onerror=...>` appears as those literal characters and creates no element.

- [ ] **Step 2: Run and watch fail**

```bash
pnpm --filter @rc/desktop-client test:run -- acceptDialog
```

Expected: FAIL — the component does not exist.

- [ ] **Step 3: Build the component**

Write `AcceptDialog.tsx` as a modal with `role="alertdialog"`, focus trapped inside it, initial focus on Dismiss, Escape wired to dismiss. Mount it from `App.tsx` on the `rc://accept-request` event.

Do not render a countdown. The backend owns the 30-second timeout; a second timer in the interface would be a number that can disagree with the decision.

- [ ] **Step 4: Run and verify**

```bash
pnpm --filter @rc/desktop-client test:run -- acceptDialog
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(ui): the accept dialog

Names the address, the machine and the fingerprint. Dismiss takes initial
focus and Escape dismisses, so a stray keystroke refuses rather than
grants control of the machine."
```

---

### Task 17: The session screen and its toolbar

**Files:**
- Rewrite: `apps/desktop-client/src/SessionScreen.tsx`
- Create: `apps/desktop-client/src/SessionToolbar.tsx`, `apps/desktop-client/src/sessionToolbar.test.tsx`

**Interfaces:**
- Consumes: `PermissionSet` as a `string[]` from the session state.
- Produces: `SessionToolbar` taking `permissions: readonly string[]` and callbacks per tool.

- [ ] **Step 1: Write the failing tests**

Create `apps/desktop-client/src/sessionToolbar.test.tsx` covering:

- with all three permissions, Files, Monitoring, fit-to-window, keyboard passthrough, fullscreen and Disconnect are all present;
- with `transfer_files` withheld, the Files button is **absent from the document** — not present-and-disabled;
- with `view_metrics` withheld, the Monitoring button is absent;
- Disconnect is always present regardless of permissions, because leaving is not a permission;
- the toolbar is visible on mount and hidden after three seconds of no pointer movement;
- moving the pointer near the top edge shows it again.

- [ ] **Step 2: Run and watch fail**

```bash
pnpm --filter @rc/desktop-client test:run -- sessionToolbar
```

Expected: FAIL — the component does not exist.

- [ ] **Step 3: Build the toolbar and the session screen**

`SessionToolbar.tsx`: a centred floating bar, visible on mount, hidden after 3000 ms without pointer movement, shown again when the pointer is within 80 px of the top edge. Disconnect is the only control using the accent.

`SessionScreen.tsx`: the remote screen area fills the window. Until the video work lands, render an honest panel — a single sentence stating that the remote display is not available in this version and that the session tools below still work. Do not render a grey rectangle that looks like a screen that has not loaded.

Files opens the existing `FilesScreen` as a full-window overlay with a close button. Monitoring opens the reduced `MonitoringScreen` as a bottom strip.

- [ ] **Step 4: Run and verify**

```bash
pnpm --filter @rc/desktop-client test:run
pnpm --filter @rc/desktop-client typecheck
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(ui): the session screen and its floating toolbar

A tool whose permission was withheld is absent from the toolbar rather
than present and failing when pressed. The display area says plainly that
video is not in this version instead of rendering an empty screen."
```

---

### Task 18: Shrink the monitoring screen

**Files:**
- Rewrite: `apps/desktop-client/src/MonitoringScreen.tsx`
- Modify: `apps/desktop-client/src/monitoring.test.ts`

**Interfaces:**
- Consumes: the existing `subscribeMetrics` / `listenMetricsUpdate` / `listenMetricsStopped` API, unchanged.
- Produces: a `MonitoringStrip` component rendering CPU, memory, disk and network only.

- [ ] **Step 1: Update the failing tests**

In `apps/desktop-client/src/monitoring.test.ts`, keep every test covering the subscription lifecycle, the polling fallback, the clamped interval badge and the `Stopped { reason }` handling — none of that behaviour changes. Add:

```typescript
  it('renders no process table', () => {
    render(<MonitoringStrip />);
    expect(screen.queryByRole('table')).toBeNull();
  });

  it('omits a reading the server could not measure rather than showing zero', () => {
    // An operator cannot tell a cold machine from a missing sensor if both read 0.
    render(<MonitoringStrip snapshot={{ cpuPercent: 12, memoryPercent: 44 }} />);
    expect(screen.getByText(/12/)).toBeInTheDocument();
    expect(screen.queryByText(/disk/i)).toBeNull();
  });
```

- [ ] **Step 2: Run and watch fail**

```bash
pnpm --filter @rc/desktop-client test:run -- monitoring
```

Expected: FAIL — `MonitoringStrip` does not exist.

- [ ] **Step 3: Rewrite the component**

Keep the sparklines and their fixed 0–100 scale. Delete the process table, the temperature section, the per-core breakdown and the page header. A section whose reading is absent renders nothing at all — never a zero, never a dash, never a placeholder.

- [ ] **Step 4: Run and verify**

```bash
pnpm --filter @rc/desktop-client test:run -- monitoring
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(ui): shrink monitoring to a session strip

CPU, memory, disk and network with their sparklines. The process table,
temperatures and per-core breakdown go. An absent reading stays absent."
```

---

### Task 19: The settings dialog

**Files:**
- Create: `apps/desktop-client/src/SettingsDialog.tsx`, `apps/desktop-client/src/settings.test.tsx`
- Rewrite: `apps/desktop-client/src/UpdateScreen.tsx` as `UpdatesPane.tsx`
- Modify: `apps/desktop-client/src/App.tsx`

**Interfaces:**
- Consumes: `host_settings`, `set_accepting`, `set_unattended_password` from Task 12; the existing update API unchanged.
- Produces: no exported API beyond the components.

- [ ] **Step 1: Write the failing tests**

Create `apps/desktop-client/src/settings.test.tsx` covering:

- the four sections render: This computer, Incoming connections, Updates, About;
- unattended access is off by default and the password field is not rendered until it is switched on;
- switching it on and saving a password shorter than 12 bytes shows an error and does not call `set_unattended_password`;
- saving a valid password calls `set_unattended_password` once with the chosen permissions;
- switching unattended access off calls `set_unattended_password` with a null password;
- the password field's value never appears in any DOM attribute after save;
- a failed save reverts the control to its stored value and shows the error, rather than leaving the interface showing a state the machine is not in;
- the About section shows the version and the identity fingerprint.

- [ ] **Step 2: Run and watch fail**

```bash
pnpm --filter @rc/desktop-client test:run -- settings
```

Expected: FAIL — the component does not exist.

- [ ] **Step 3: Build it**

Write `SettingsDialog.tsx` with the four sections. Move `UpdateScreen.tsx` to `UpdatesPane.tsx`, keeping its check, download, pause, resume, cancel and install logic untouched — only the header, the page chrome and the layout shrink. Delete the update-banner section check in `App.tsx`.

- [ ] **Step 4: Run and verify**

```bash
pnpm --filter @rc/desktop-client test:run
pnpm --filter @rc/desktop-client typecheck
pnpm --filter @rc/desktop-client build
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(ui): one settings dialog

This computer, incoming connections, updates and about. Unattended access
is off by default, and a save that fails reverts the control rather than
showing a state the machine is not in."
```

---

### Task 20: Delete the dead UI kit and run the full gate

**Files:**
- Delete: `apps/desktop-client/src/ui/QuickAction.tsx`, `Kbd.tsx`, `PageHeader.tsx`
- Modify: `apps/desktop-client/src/ui/index.ts`

- [ ] **Step 1: Find what is genuinely unused**

```bash
for component in QuickAction Kbd PageHeader Tooltip CopyButton Status Field Feedback Card Button; do
  echo -n "$component: "
  grep -rl "$component" apps/desktop-client/src --include=*.tsx --include=*.ts | grep -v "/ui/" | wc -l
done
```

Delete every component whose count is 0. Do not delete one that still has a consumer just because this plan listed it — the plan predicted the outcome, the grep measures it.

- [ ] **Step 2: Delete and update the barrel**

Delete the files with no consumers and remove their lines from `apps/desktop-client/src/ui/index.ts`.

- [ ] **Step 3: Run the full gate**

```bash
pnpm version:check
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test:run
pnpm release:smoke
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Expected: every command succeeds. If `pnpm version:check` fails, a deleted crate is still listed in `scripts/check-version-sync.mjs` — fix that rather than the version.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore(ui): delete the components nothing renders any more"
```

---

### Task 21: Rewrite the documentation

**Files:**
- Rewrite: `README.md`, `PROGRESS.md`, `docs/threat-model.md`, `docs/network-protocol.md`
- Create: `docs/access-model.md`
- Modify: `docs/permission-model.md` → delete; `docs/reconnection.md` → update

- [ ] **Step 1: Write `docs/access-model.md`**

One document replacing the three deleted ones. It must state, in this order: the three ways in and why they are checked in that order; why a pin mismatch is refused rather than prompted; why a wrong password does not fall back to the dialog; why the wire refusal is coarser than the local reason; why accepting with nothing ticked is a refusal; and why permissions cannot be widened within a session.

- [ ] **Step 2: Rewrite `docs/threat-model.md`**

Per the spec's *Threat model changes* section. State plainly what got weaker: an attacker now needs mTLS plus a human click or the unattended password, rather than needing to defeat a pairing exchange. Name the social-engineering exposure and list the four mitigations built into the dialog. Say that anyone at an unlocked keyboard can use the application, and that this matches every other application on that desktop.

- [ ] **Step 3: Rewrite `PROGRESS.md`**

Delete the phase numbering — it describes a plan the product no longer follows. Describe what works. Include a short section explaining that the test count fell because subsystems were deleted, with the before and after figures, so a future reader does not read the drop as decay.

Re-run every command in its verification table and record the actual output. Do not carry a figure forward from the old document.

- [ ] **Step 4: Rewrite `README.md`**

The repository layout table, with the three deleted crates and the deleted app removed. The one-paragraph design description, rewritten for one program that is both sides. The getting-started section, with the `pair` subcommand gone.

- [ ] **Step 5: Update `docs/network-protocol.md` and `docs/reconnection.md`**

Remove the pairing exchange from the protocol document and describe `Authenticate` and `SessionAuthorization`. In the reconnection document, confirm the existing rule still holds and now covers the new refusals: an accidental drop retries with backoff; a `WireRefusal` of any kind never does.

- [ ] **Step 6: Check every internal link still resolves**

```bash
grep -rhoE "\]\([^)]+\.md[^)]*\)" README.md PROGRESS.md docs/*.md | sed -E 's/^\]\(//; s/\)$//' | sort -u | while read -r link; do
  case "$link" in http*) continue;; esac
  target="${link%%#*}"
  [ -f "$target" ] || [ -f "docs/$target" ] || echo "broken: $link"
done
```

Expected: no output.

- [ ] **Step 7: Run the full gate and commit**

```bash
pnpm verify
```

```bash
git add -A
git commit -m "docs: rewrite for the AnyDesk access model

One access-model document replaces the pairing, owner-authentication and
permission-model documents. The threat model states plainly what got
weaker and why that trade was made. PROGRESS.md drops the phase numbering
and explains the fall in the test count as deletion rather than decay."
```

---

## Self-Review

**Spec coverage.** Every section of the spec maps to a task: deletions → Tasks 1–5; permission reduction → Task 6; `PasswordCredential` → Task 7; schema → Task 8; address → Task 9; the accept decision, the ordering rules, the oracle properties → Task 10; the wire → Task 11; one binary → Task 12; the integration proof → Task 13; tokens → Task 14; main window → Task 15; accept dialog → Task 16; session and toolbar → Task 17; monitoring → Task 18; settings including updates → Task 19; dead UI kit → Task 20; every named document → Task 21.

**Two gaps found and closed while reviewing:** the spec's requirement that a resolution failure is an error rather than an empty list was unstated in the original Task 9 and is now in `to_socket_addrs`; and the spec's rule that recording a reconnection must not silently re-grant a cleared pin was unstated in Task 8 and is now explicit in the `record` implementation note.

**Type consistency.** `PermissionSet` is spelled identically in Tasks 6, 8, 10, 11 and 12. `PasswordCredential` is introduced in Task 7 and used under that name in Tasks 8 and 10. `RefusalReason` (local, five variants) and `WireRefusal` (wire, three variants) are deliberately different types, and the `From` impl between them is placed in Task 11 in the crate that may depend on both. `PeerAddress::DEFAULT_PORT` is 7443 in Task 9, in the `0003` migration's default in Task 8, and in `address.ts` in Task 15.

**One known duplication, kept deliberately:** address parsing exists in Rust and again in TypeScript. Task 15 requires this to be documented in the file so it is not later "deduplicated" by trusting only the frontend copy.
