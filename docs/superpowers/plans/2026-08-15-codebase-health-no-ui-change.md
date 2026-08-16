# Codebase Health Implementation Plan (no UX/UI change)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix real bugs, dead wiring, and stale leftovers across Rust and TypeScript so the product behaves as the access model already describes, without changing the approved visual design.

**Architecture:** Keep the current chrome, pages, and session screen. Fix IPC shapes, permission gates, default ports, admission/reconnect, and shared state behind those surfaces. Delete unused config and comments after the behavior is correct. Do not add screens, move navigation, or restyle components.

**Tech Stack:** Rust 2024 (sqlx/SQLite, quinn/QUIC, rustls, tokio), TypeScript + React 19 + Zod + Vitest, Tauri 2.

**Spec:** Current product docs are `docs/access-model.md`, `docs/network-protocol.md`, `docs/reconnection.md`, `PROGRESS.md`. Historical plans in `docs/superpowers/` are archive, not requirements.

## Global Constraints

- **Do not change UX/UI.** No layout, color, typography, spacing, or navigation changes. Existing components stay. Copy may change only when it is factually false (for example “enter a device ID” when IDs cannot be dialed).
- **Clippy is pedantic with `-D warnings`.** A warning is a build failure.
- **Migrations are additive only** unless a header documents a sanctioned exception.
- **Fingerprints are lowercase hex, compared with `Fingerprint::ct_eq`.**
- **No secret is logged, returned to the webview, or placed in an error message.**
- **Desktop IPC is camelCase.** Every response is validated by a Zod schema. Nothing type-asserts.
- **Red is reserved for destructive actions and failures.** Connect stays the RC accent.
- **Verification after each task:** the commands named in that task. Full tree: `pnpm test:run` and `cargo test --workspace` before calling a phase done.
- **Do not implement remote display / input injection in this plan.** That is a later product spec. `control_input` stays a granted, unused permission.

---

## What the audit found

A full read of crates, `src-tauri`, the desktop client, shared-types, docs, and scripts. No TODO/FIXME markers exist. The problems are wiring, leftover deleted-product surface, and docs that still describe pairing / three permissions / a coordination server.

### Critical (breaks real use)

1. **Default ports disagree.** Desktop listen/dial default is **7443**. Standalone `rc-agent` default is **47811** (`rc_protocol::DEFAULT_AGENT_PORT`). Typing an IP without a port cannot reach a stock agent.
2. **Outgoing identity pin is never written.** Incoming `IdentityChanged` works. Outgoing always uses `PinPolicy::TrustOnFirstUse`. A substitute at a known address is accepted.
3. **`subscribe_metrics` IPC shape is wrong.** Frontend sends `{ input: { intervalMs } }`. Rust expects top-level `intervalMs`. Live metrics never subscribe.
4. **Disconnect and ping require `control_input`.** A files/metrics-only session cannot hang up. The toolbar still offers Disconnect.
5. **Inbound banner is hidden during an outbound session.** `SessionScreen` replaces `AppShell`, so someone controlling *this* machine can become invisible.
6. **`accepting=1` does not start the listener on launch.** After restart the machine is not reachable until the toggle is flipped again.
7. **`std::mem::forget(connector)` leaks a QUIC endpoint on every successful connect.**
8. **Auto-reconnect is implemented and never started.** Dropped links stay “connected” until the next command fails.

### High

9. Suspend / permission shrink do not end or re-check the live session (revoke does disconnect).
10. Session monitoring button mounts `MonitoringStrip` with no snapshot; `MonitoringScreen` is unused.
11. Outgoing connect always sends `unattendedPassword: null`. The host password exists; the client never uses it.
12. “See all” on Recent opens trusted devices, a different store.
13. Host snapshot is fetched twice and never refreshed after accept-toggle or connect.
14. IPC errors from `{ code, message }` become `[object Object]`.
15. `SessionScreen` is always given `deviceName={null}`.
16. Fit / keyboard / fullscreen on the session toolbar are local no-ops.

### Medium / dead

17. Unused deps: `zustand`. Unused CSS token `--color-sidebar`. Unused APIs: `removeRecent`, `connectionTone`, `connectionLabel`, `getServerFacts`.
18. `portable-pty` workspace dep. `DEFAULT_COORDINATION_PORT`. Agent config still validates coordination/relay URLs and session-token TTLs.
19. Unused SQLite tables: `app_setting`, `connection_event`, `local_identity`, `transfer_state`.
20. `packages/shared-types` is version `0.1.0` and still models pairing-era devices the UI does not use.
21. Docs say three permissions, certificate pins, `installers/`, `UpdateScreen.tsx`, `docs/installation.md`. None of those match the tree.
22. `README.md` lists Rust 1.96; `Cargo.toml` is `rust-version = "1.90"`; toolchain is unpinned `stable`.
23. Duplicate inbound polling (App + Sessions). History is one-shot. No outgoing session rows are written.
24. `ReplayGuard` is unused. Control `sent_at_ms` / `nonce` are not checked.
25. `FeatureConfig.remote_desktop` defaults true; the server always advertises `remote_desktop: false`.
26. Stale comments: pairing, owner account, lock screen, “accept path is not here yet”.

---

## File map

| Area | Files |
|---|---|
| Ports | `crates/protocol/src/lib.rs`, `crates/transport/src/address.rs`, `crates/storage/src/settings.rs`, `crates/host-agent/src/config.rs`, `apps/desktop-client/src/address.ts`, tests that hard-code either 7443 or 47811 |
| Outgoing pin | `apps/desktop-client/src-tauri/src/connection.rs`, `crates/storage/src/recent.rs` |
| IPC | `apps/desktop-client/src/api.ts`, `apps/desktop-client/src/ipc.ts`, `apps/desktop-client/src/ipc.test.ts`, `session_commands.rs`, `connect_commands.rs` |
| Session safety | `apps/desktop-client/src/App.tsx`, `SessionScreen.tsx`, `MonitoringScreen.tsx`, `SessionToolbar.tsx` |
| Host start | `apps/desktop-client/src-tauri/src/lib.rs`, `host.rs`, `host_commands.rs` |
| Reconnect / leak | `connection.rs`, `connect_commands.rs` |
| Trust live sessions | `trust_commands.rs`, `crates/host-agent/src/sessions.rs` |
| Shared host state | `useHostSnapshot.ts`, `RemoteControlPage.tsx`, `SettingsPage.tsx`, `App.tsx` |
| Dead config / docs | `host-agent/src/config.rs`, `protocol/src/lib.rs`, `PROGRESS.md`, `README.md`, `docs/*.md`, `tauri.conf.json` |
| Dead TS | `package.json`, `index.css`, `useConnection.ts`, `api.ts`, `navigation.ts` comments |

---

### Task 1: Unify the default listen/dial port

**Files:**
- Modify: `crates/protocol/src/lib.rs`
- Modify: `crates/host-agent/src/config.rs`
- Modify: `crates/host-agent` tests that assume 47811 as the *default*
- Test: `crates/transport/tests/address_cross_check.rs` (already 7443)
- Test: `apps/desktop-client/src/address.test.ts` (already 7443)

**Decision (locked):** The product default is **7443**, matching `PeerAddress::DEFAULT_PORT`, SQLite `host_settings`, the TypeScript parser, and `docs/network-protocol.md`. Change `DEFAULT_AGENT_PORT` to 7443. An existing `agent.toml` that sets `listen_port = 47811` must keep working (explicit config wins).

- [ ] **Step 1: Write/adjust the protocol constant test**

In `crates/protocol/src/lib.rs` the existing const asserts compare ports. After the change they must still pass with one number.

- [ ] **Step 2: Change the constant**

```rust
pub const DEFAULT_AGENT_PORT: u16 = 7443;
```

Leave `DEFAULT_AGENT_HEALTH_PORT` as 47813 unless it now collides; it does not. Keep `DEFAULT_COORDINATION_PORT` only until Task 10 deletes it.

- [ ] **Step 3: Run**

```
cargo test -p rc-protocol
cargo test -p rc-host-agent --lib
cargo test -p rc-transport
```

Expected: pass. Any fixture that assumed the *default* is 47811 is updated to 7443. Fixtures that *explicitly* set 47811 stay.

- [ ] **Step 4: Commit**

```
git commit -m "fix: use 7443 as the single default listen and dial port"
```

---

### Task 2: Parse Tauri `{ code, message }` errors

**Files:**
- Modify: `apps/desktop-client/src/ipc.ts`
- Test: `apps/desktop-client/src/ipc.test.ts`

- [ ] **Step 1: Extend the existing test** so a rejection of `{ code: 'not_authorized', message: 'That machine refused.' }` becomes an `IpcError` whose `.message` is `That machine refused.`

- [ ] **Step 2: Implement** in `call()`:

```ts
function messageFromIpc(cause: unknown): string {
  if (cause instanceof Error) return cause.message;
  if (typeof cause === 'string' && cause !== '') return cause;
  if (cause !== null && typeof cause === 'object' && 'message' in cause) {
    const message = (cause as { message: unknown }).message;
    if (typeof message === 'string' && message !== '') return message;
  }
  return 'The backend rejected the command.';
}
```

Never stringify the whole object. Never put `code` alone on screen if `message` exists.

- [ ] **Step 3: Run** `pnpm --filter @rc/desktop-client exec vitest run src/ipc.test.ts`

- [ ] **Step 4: Commit** `fix: surface Tauri command error messages instead of [object Object]`

---

### Task 3: Fix `subscribe_metrics` and `unsubscribe_metrics` IPC

**Files:**
- Modify: `apps/desktop-client/src/api.ts` **or** `session_commands.rs` — pick one side. Prefer changing the frontend call to `{ intervalMs }` so it matches every other scalar command. Do not invent a new UI.
- Test: `apps/desktop-client/src/api.test.ts` if a helper is tested; otherwise add a unit test next to session command tests if they exist, or a small `api.ts` test that the args object is `{ intervalMs }`.

- [ ] **Step 1: Change**

```ts
export function subscribeMetrics(intervalMs: number): Promise<number> {
  return call('subscribe_metrics', z.number().int().positive(), { intervalMs });
}

export function unsubscribeMetrics(): Promise<null> {
  return call('unsubscribe_metrics', z.null());
}
```

- [ ] **Step 2: Run** `pnpm --filter @rc/desktop-client exec vitest run src/api.test.ts src/monitoring.test.tsx`

- [ ] **Step 3: Commit** `fix: align metrics subscribe/unsubscribe with the Tauri command shape`

---

### Task 4: Disconnect and ping must not require `control_input`

**Files:**
- Modify: `apps/desktop-client/src-tauri/src/connect_commands.rs`
- Modify: `apps/desktop-client/src-tauri/src/file_commands.rs` (`list_local_directory` — drop remote-grant gate; keep “must be connected” only if the command truly needs a session)
- Test: add a Rust test or extend existing connect command tests: a manager with only `view_metrics` can `disconnect_from_server` and `ping_server`.

- [ ] **Step 1: Remove** `state.require_permission(Permission::ControlInput)?` from `disconnect_from_server` and `ping_server`. Keep the “manager must exist” check.

- [ ] **Step 2: Update the doc comments** that still say “if the application is locked”.

- [ ] **Step 3: Run** `cargo test -p rc-desktop-client`

- [ ] **Step 4: Commit** `fix: allow disconnect and ping without the input permission`

---

### Task 5: Keep the inbound banner visible inside a session

**Files:**
- Modify: `apps/desktop-client/src/App.tsx`
- Test: add `src/app.test.tsx` or extend an existing App-level test: when `inSession` and inbound sessions are non-empty, `has been controlling this machine` is in the document.

**UI rule:** Reuse `InboundSessionBanner` as-is. Do not restyle it. Render it as a sibling above both `SessionScreen` and `AppShell` (or pass it into `SessionScreen` as the existing banner node). Emergency disconnect stays the same handler.

- [ ] **Step 1: Write the failing test** (render with inbound sessions + connected state).

- [ ] **Step 2: Hoist the banner** so it is not unmounted when `SessionScreen` replaces `AppShell`.

- [ ] **Step 3: Run** the new test + `src/sessions.test.tsx`

- [ ] **Step 4: Commit** `fix: show inbound control while an outbound session is open`

---

### Task 6: Start the host listener from stored `accepting`

**Files:**
- Modify: `apps/desktop-client/src-tauri/src/lib.rs` (`initialise`)
- Test: `apps/desktop-client/src-tauri/src/host.rs` / host command tests if they cover start-up

- [ ] **Step 1:** After DB + identity are ready, if `settings.accepting` is true, call the same `HostRuntime::start` path `set_accepting(true)` already uses.

- [ ] **Step 2:** If start fails, leave accepting as stored but log the error; do not flip the row to 0 silently.

- [ ] **Step 3: Run** `cargo test -p rc-desktop-client`

- [ ] **Step 4: Commit** `fix: honour persisted accepting and listen on startup`

---

### Task 7: Stop leaking the QUIC connector; actually reconnect

**Files:**
- Modify: `apps/desktop-client/src-tauri/src/connection.rs`
- Modify: `apps/desktop-client/src-tauri/src/connect_commands.rs` if a watcher must be spawned
- Test: existing connection tests; add a test that `ActiveConnection` owns the connector (drop closes cleanly) and that `reconnect` is invoked when the live connection ends unintentionally.

- [ ] **Step 1:** Store `ClientConnector` (or the `Endpoint`) on `ActiveConnection`. Delete `std::mem::forget(connector)`.

- [ ] **Step 2:** On unintentional drop of the live QUIC connection, call the existing `reconnect` path. Do not retry refusals or intentional disconnects (`permits_auto_reconnect` already encodes this).

- [ ] **Step 3: Run** `cargo test -p rc-desktop-client --lib`

- [ ] **Step 4: Commit** `fix: own the QUIC connector and start automatic reconnect`

---

### Task 8: Write and honour the outgoing identity pin

**Files:**
- Modify: `apps/desktop-client/src-tauri/src/connection.rs`
- Modify: `crates/storage/src/recent.rs` (already has `set_known_identity`)
- Test: storage repo tests already cover the pin write; add a connection-level test that a second connect to the same address uses `PinPolicy::Pinned` when `known_identity` is set, and that a different cert is refused.

- [ ] **Step 1:** After a granted, authenticated connect, persist `observed` fingerprint via `RecentRepository::set_known_identity`.

- [ ] **Step 2:** Before dialling, if `known_identity` is present, use `PinPolicy::Pinned`. Otherwise `TrustOnFirstUse`.

- [ ] **Step 3: Run** `cargo test -p rc-storage` and `cargo test -p rc-desktop-client --lib`

- [ ] **Step 4: Commit** `fix: pin outgoing peers by the identity they proved`

---

### Task 9: Suspend and permission changes must affect the live session

**Files:**
- Modify: `apps/desktop-client/src-tauri/src/trust_commands.rs`
- Modify: `crates/host-agent/src/sessions.rs` if `Session::require` should re-read trust
- Test: extend `access_e2e.rs` or trust command tests: suspend a device that has an inbound session → session ends. Narrow permissions → next request is refused (or session ends; pick one and document it in `docs/access-model.md`).

**Locked decision:** Match `revoke_device`: walking live inbound sessions and disconnecting the matching identity on suspend. For permission shrink, re-check the live trust row inside `Session::require` so comments stop lying.

- [ ] **Step 1: Write the failing e2e/unit test**

- [ ] **Step 2: Implement disconnect-on-suspend** using the same identity walk as revoke.

- [ ] **Step 3: Implement live re-check** on `Session::require` (or disconnect on shrink — do not do both in a confusing mix).

- [ ] **Step 4: Run** `cargo test -p rc-host-agent --test access_e2e`

- [ ] **Step 5: Commit** `fix: apply suspend and permission changes to live sessions`

---

### Task 10: Wire session monitoring to the real subscriber

**Files:**
- Modify: `apps/desktop-client/src/SessionScreen.tsx` only as much as swapping `MonitoringStrip` for the existing `MonitoringScreen` default export (already built and tested).
- Test: `apps/desktop-client/src/monitoring.test.tsx` already exists. Add a SessionScreen test that opening Monitoring calls `system_snapshot` or `subscribe_metrics`.

**UI rule:** Use the existing monitoring pane. Do not redesign it.

- [ ] **Step 1:** Mount `MonitoringScreen` when the toolbar Monitoring tool is on.

- [ ] **Step 2: Run** `pnpm --filter @rc/desktop-client exec vitest run src/monitoring.test.tsx src/sessionToolbar.test.tsx`

- [ ] **Step 3: Commit** `fix: load live metrics when Monitoring is opened`

Fit / keyboard / fullscreen: **do not restyle**. Either leave them (known no-ops until remote display exists) or make the existing buttons no-op *and* keep the tests. This plan does **not** remove them; removing them is a UX change. Add a one-line code comment that they are local-only until capture exists.

---

### Task 11: One host snapshot, kept current

**Files:**
- Modify: `apps/desktop-client/src/useHostSnapshot.ts`
- Modify: `apps/desktop-client/src/App.tsx`
- Modify: `apps/desktop-client/src/RemoteControlPage.tsx`
- Modify: `apps/desktop-client/src/SettingsPage.tsx` (read snapshot props instead of fetching the same four calls)

**UI rule:** Same chrome, same pages. Only the data source is shared.

- [ ] **Step 1:** Add `refresh()` to `useHostSnapshot`. Call it after `setAccepting`, after a successful connect, and after emergency disconnect (`hostEpoch` already exists).

- [ ] **Step 2:** Pass `status`, `identity`, `os`, `hostname`, `recent` into `RemoteControlPage` so it stops duplicating the four fetches. Keep its presence-probe loop.

- [ ] **Step 3:** Fix the inverted `listRecent` catch (`if (cancelled) setRecent([])` → `if (!cancelled) setRecent([])`).

- [ ] **Step 4: Run** `pnpm --filter @rc/desktop-client exec vitest run src/remoteControl.test.tsx src/thisDevice.test.tsx src/settingsPage.test.tsx src/appShell.test.tsx`

- [ ] **Step 5: Commit** `fix: share host snapshot and refresh it after real state changes`

---

### Task 12: Session name, My Devices connect, inbound poll

**Files:**
- Modify: `apps/desktop-client/src-tauri/src/connection.rs` — put `ack.descriptor.display_name` on `ConnectionState::Connected`
- Modify: `apps/desktop-client/src/api.ts` connection schema
- Modify: `apps/desktop-client/src/App.tsx` — pass that name into `SessionScreen`
- Modify: `apps/desktop-client/src/MyDevicesPage.tsx` — dial through the same `connectToAddress` + `connection.set` path as the home form (no new controls)
- Modify: `apps/desktop-client/src/SessionsPage.tsx` — do not start a second inbound poll if App already owns inbound; or accept App’s list as a prop. History: reload when inbound list changes.

**UI rule:** Toolbar still looks the same; it finally shows the real machine name instead of the fallback “Connected machine”.

- [ ] **Step 1:** Extend the Zod `connected` variant with `deviceName: string | null` (or required string). Update `connection.test.ts`.

- [ ] **Step 2:** Wire My Devices connect through `onConnection` from App (same as home).

- [ ] **Step 3: Run** `pnpm --filter @rc/desktop-client exec vitest run src/connection.test.ts src/myDevices.test.tsx src/sessions.test.tsx`

- [ ] **Step 4: Commit** `fix: show the remote name and share one connect path`

---

### Task 13: Copy that is factually wrong (not a redesign)

**Files:**
- Modify: `apps/desktop-client/src/chrome/ConnectionBar.tsx` placeholder — “Enter hostname or IP address” (IDs still rejected; tests already cover that).
- Modify: `apps/desktop-client/src/chrome/DeviceIdentityBar.tsx` info tooltip if it implies the ID is dialable (keep “Your Address” layout).
- Modify: `apps/desktop-client/src/FilesScreen.tsx` hint — “My Devices” / “Remote Control”, not “paired server from Devices”.
- Modify: `apps/desktop-client/src/chrome/QuickAccessPanel.tsx` invite subtitle only if it claims a request is sent. The row stays. Subtitle should describe the real action (clipboard invitation).

**Do not** change layout, colors, or component structure.

- [ ] **Step 1: Update** `connectionBar.test.tsx` if it queries the old placeholder.

- [ ] **Step 2: Run** `pnpm --filter @rc/desktop-client exec vitest run src/chrome/connectionBar.test.tsx src/thisDevice.test.tsx`

- [ ] **Step 3: Commit** `fix: stop describing device IDs and pairing as how you connect`

---

### Task 14: Unattended password on the existing connect path

**Constraint:** No new page, no new chrome region. The Connect split button already has a menu. Add one real item: “Connect with password…” that uses a small existing dialog pattern (`ConfirmDialog` / a password `TextField`) and calls `connectToAddress(address, password)`.

If that is judged a UX change, **stop after documenting the gap** and skip the dialog. Default: implement via the existing split menu + existing field/dialog primitives.

- [ ] **Step 1: Test** that choosing the menu item calls `connectToAddress` with a non-null password.

- [ ] **Step 2: Implement** using `useConnectForm` (add an optional password argument to `connect`).

- [ ] **Step 3: Run** `pnpm --filter @rc/desktop-client exec vitest run src/chrome/connectionBar.test.tsx`

- [ ] **Step 4: Commit** `fix: send an unattended password when the operator provides one`

---

### Task 15: Recent “See all” must list recents

**Files:**
- Modify: `apps/desktop-client/src/MyDevicesPage.tsx` **or** `App.tsx` navigation target

**Locked decision (no new visual language):** Keep the My Devices page. Add a compact **Recent** list *above or below* trusted devices using the same row component already used for trusted machines / recent home rows. Empty trusted + non-empty recent is allowed. Do not invent a fifth nav item.

Alternatively, if adding a section is rejected as UX: change “See all” to stay on Remote Control and simply not claim a different store. Prefer the first option.

- [ ] **Step 1: Test** that a recent-only address appears after “See all”.

- [ ] **Step 2: Implement** `listRecent` on My Devices as a second list.

- [ ] **Step 3: Run** `pnpm --filter @rc/desktop-client exec vitest run src/myDevices.test.tsx src/remoteControl.test.tsx`

- [ ] **Step 4: Commit** `fix: See all shows recent connections, not only trusted devices`

---

### Task 16: Dead TypeScript and dependency cleanup

**Files:**
- Modify: `apps/desktop-client/package.json` — remove `zustand` if still unused
- Modify: `apps/desktop-client/src/index.css` — remove `--color-sidebar` if unused
- Modify: comments in `navigation.ts`, `useConnection.ts`, `ui/Tooltip.tsx` (sidebar language)
- Modify: `api.ts` — keep `removeRecent` (backend exists); either use it from a recent-row overflow later or leave the wrapper. Do not delete a working command just because the UI has no trash icon (that would be a UX add).
- Do not delete `CopyButton` if Settings/other screens still import it.

- [ ] **Step 1: Grep** `zustand`, `--color-sidebar`, `connectionTone`, `connectionLabel`.

- [ ] **Step 2: Remove only unused items.** Run typecheck.

- [ ] **Step 3: Run** `pnpm --filter @rc/desktop-client typecheck` and `pnpm --filter @rc/desktop-client test:run`

- [ ] **Step 4: Commit** `chore: remove unused client dependencies and leftover sidebar comments`

---

### Task 17: Dead Rust config and crates leftovers

**Files:**
- Modify: `crates/protocol/src/lib.rs` — delete `DEFAULT_COORDINATION_PORT` and its const tests
- Modify: `crates/host-agent/src/config.rs` — stop requiring `coordination_url` / `relay_url` / session-token TTLs as if those products exist. Keep listen/health/max_sessions/auth throttle.
- Modify: root `Cargo.toml` — remove `portable-pty`
- Modify: `crates/security/Cargo.toml` description (no pairing/owner)
- Modify: `crates/host-agent/src/server.rs` module docs (“accept is not here yet” is false)
- Modify: `crates/host-agent/tests/agent_lifecycle.rs` comments
- Modify: `apps/desktop-client/src-tauri/tauri.conf.json` `longDescription` — drop “terminal”; do not invent remote-desktop claims
- Test: update `remote_access_without_a_coordination_url_is_rejected` — delete or rewrite to the new rule

**Do not delete** `protocol/src/desktop.rs` in this plan. It is reserved for the future remote-display spec.

- [ ] **Step 1: Run the coordination-url test, then delete/rewrite it**

- [ ] **Step 2: Implement config + comment cleanup**

- [ ] **Step 3: Run** `cargo test -p rc-host-agent --lib` and `cargo clippy --workspace --all-targets --all-features -- -D warnings`

- [ ] **Step 4: Commit** `chore: remove coordination-server and pairing leftovers from config`

---

### Task 18: Unused SQLite tables

**Files:**
- Create: `crates/storage/migrations/0005_drop_unused_legacy_tables.sql`
- Modify: `crates/storage/src/repo_tests.rs` if it pins those tables as present

**Sanctioned exception:** these tables have no readers. Document the drop in the migration header the same way 0003 did.

Drop only: `app_setting`, `connection_event`, `local_identity`, `transfer_state`. Do **not** drop `recent_connections` or `trusted_devices`.

- [ ] **Step 1: Write a storage test** that opens a migrated DB and asserts those four names are absent.

- [ ] **Step 2: Add the migration**

- [ ] **Step 3: Run** `cargo test -p rc-storage`

- [ ] **Step 4: Commit** `chore: drop unused SQLite tables with no readers`

---

### Task 19: shared-types and version sync

**Files:**
- Modify: `packages/shared-types/package.json` version → `0.2.0`
- Modify: `scripts/check-version-sync.mjs` to include `packages/shared-types/package.json`
- Modify: `packages/shared-types/src/devices.ts` — either delete unused pairing-era `SavedDevice` or mark it unused and stop claiming it is the protocol mirror. Prefer deleting what the desktop client does not import, and keep `fingerprintSchema` / `protocolVersionSchema` / `untrustedText`.
- Test: `packages/shared-types` tests that only exist for the deleted model go with it.

- [ ] **Step 1: Run** `pnpm version:check` (expect fail on 0.1.0)

- [ ] **Step 2: Bump + trim unused schemas**

- [ ] **Step 3: Run** `pnpm version:check` and `pnpm --filter @rc/shared-types test:run`

- [ ] **Step 4: Commit** `chore: sync shared-types to 0.2.0 and drop unused pairing schemas`

---

### Task 20: Docs match the product

**Files:**
- Modify: `PROGRESS.md` — four permissions; correct Rust test count after running `cargo test --workspace -- --list`; “nine cases” → actual `access_e2e` count
- Modify: `README.md` — four ways in; identity pin not certificate pin; remove `installers/`; Rust version from `Cargo.toml` / toolchain
- Modify: `docs/threat-model.md` — trusted identity is the first door
- Modify: `docs/keystore-format.md` — renewal vs identity substitution
- Modify: `docs/reconnection.md` — pin language = identity fingerprint
- Modify: `docs/network-protocol.md` — Input ceiling 4 KiB (match `frame.rs`) or change the constant to 256 KiB if the doc is the intended contract. **Locked:** change the doc to 4 KiB unless a remote-display spec says otherwise.
- Modify: `docs/update-manager.md` — `UpdatesPane.tsx`, no unlock, no Updates sidebar
- Modify: `crates/host-agent/src/main.rs` — drop or replace `docs/installation.md` reference
- Modify: `release-notes.md` if it still says three permissions as *current* (historical “reduced to three” can stay as history if dated)

Add a one-line banner at the top of `docs/superpowers/specs/*` and `docs/superpowers/plans/*` that are historical: `> Historical. Not current product documentation.`

- [ ] **Step 1: Run** `cargo test --workspace -- --list` and `pnpm --filter @rc/desktop-client exec vitest run --reporter=json` (or count from the last `pnpm test:run`) and write the real numbers.

- [ ] **Step 2: Edit the docs**

- [ ] **Step 3: Commit** `docs: align product docs with four permissions, identity pins, and current files`

---

### Task 21: Verify scripts and CI comments

**Files:**
- Modify: `scripts/verify.sh`, `scripts/verify.ps1` — call the same steps as `pnpm verify`, or invoke `pnpm verify` and drop “phase” wording
- Modify: `.github/workflows/ci.yml` comment about “sixteen” e2e tests if the count is wrong
- Modify: `clippy.toml` allow-list leftovers (`ConPTY`, etc.) only if unused

- [ ] **Step 1: Diff `pnpm verify` vs `verify.ps1` and make them match**

- [ ] **Step 2: Commit** `chore: make verify scripts match pnpm verify`

---

### Task 22: Final verification (no UI pass)

- [ ] **Step 1: Run**

```
pnpm test:run
cargo test --workspace
pnpm --filter @rc/desktop-client typecheck
```

- [ ] **Step 2: Confirm by reading the output** that counts match `PROGRESS.md`

- [ ] **Step 3: Do not restyle anything.** If a test failed because a visual class changed, revert that change.

- [ ] **Step 4: Commit** only if the last tasks left uncommitted docs/test count updates.

---

## Explicitly out of scope

- Remote display, input injection, video/input protocol implementation (`protocol/src/desktop.rs` stays).
- Adding a tray, About window chrome, or new nav items.
- Visual fidelity, theming, title-bar restyle.
- Rewriting session toolbar tools until there is a display to attach them to.
- Casual rewrite of signed updater fixtures (`release-manifest.json` is signed).
- Deleting historical SQL migrations 0001/0002.

---

## Suggested execution order

Tasks 1–9 are correctness and safety. Tasks 10–15 are client wiring. Tasks 16–21 are hygiene. Task 22 is the gate.

If this is too large for one execution session, split after Task 9 (backend/safety) and after Task 15 (client wiring).
