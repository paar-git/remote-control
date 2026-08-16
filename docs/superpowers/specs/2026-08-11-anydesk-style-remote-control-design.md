> Historical. Not current product documentation.

# AnyDesk-style remote control — design

Date: 2026-08-11
Status: approved, not yet implemented

## Why

The application has grown five subsystems — terminal, file manager, monitoring,
privileged operations, updates — a pairing protocol, an owner account with a password
gate, and a ten-capability permission model. It does not have the one thing it exists
for: **you cannot see or control another computer's screen.** `crates/remote-desktop/src/`
is an empty directory.

This document specifies the first of two pieces of work:

1. **This spec.** Strip the subsystems that are not wanted, replace the account and
   pairing model with AnyDesk's connect-and-accept model, and rebuild the interface in
   AnyDesk's visual language.
2. **A later spec.** Screen capture, encoding, streaming and input forwarding — the
   actual remote desktop, which lands in the shell this spec builds.

Doing them in this order means the shell is coherent before the video fills it, and the
session screen has a defined place to arrive.

## Scope

In scope: deletion of unwanted subsystems, the new access model, the single-binary app
shape, and the complete visual rebuild.

Out of scope, deliberately: screen capture, video encoding, input forwarding, internet
rendezvous, NAT traversal, and relay fallback. Each is named here only where this design
must leave room for it.

## Decisions

These were settled during design and are not open questions.

| Decision | Choice |
|---|---|
| Sequencing | Strip and restyle first; remote desktop in a second spec |
| Subsystems kept | File transfer, monitoring, updates |
| Subsystems deleted | Terminal, processes, services, power, activity log |
| Authorisation | Connect, then a human clicks Accept on the remote machine |
| Unattended access | Optional password, off by default |
| App shape | One binary that is both host and client |
| Address | An IP address or hostname — no numeric ID, no directory |
| Discovery | None; the address is typed |
| Navigation | No sidebar; session tools live on a floating in-session toolbar |
| Visual design | Light surfaces, AnyDesk red accent, single theme |

## Part 1 — Deletions

### Crates removed entirely

- **`crates/terminal`** — pseudo-terminal sessions, ConPTY and `openpty`. Removed with
  the Terminal screen. Its 26 tests go with it.
- **`crates/privileged`** — the separate elevated helper process and its command
  allowlist. It exists solely to serve power actions and service management, both of
  which are being deleted, and nothing else calls it. Its 31 unit tests and 11
  cross-process tests go with it.
- **`apps/coordination-server`** — a rendezvous service with no role once addresses are
  typed in manually.

Their entries are removed from `Cargo.toml`, `pnpm-workspace.yaml` and the README's
repository-layout table.

### Removed from `crates/security`

The crate survives. Device identity, TLS certificate issuance and the keystore are what
make a connection encrypted and are load-bearing for everything below.

Removed:

- **The pairing-code system**: code generation over the 30-symbol alphabet, the Argon2
  code verifier, the length-prefixed pairing transcript, the three domain-separation
  labels, the single-use consumption path, the 180-second window and the five-attempt
  cap.
- **The owner account**: username, password creation, login, logout, and the client's
  startup gate.
- **The capability model**: ten typed capabilities across three roles, and the
  exhaustive grant table.

Kept and repurposed:

- **Argon2id hashing** (m=19 MiB, t=2, p=1) and its `Zeroizing` buffers now protect the
  unattended-access password.
- **The lockout throttle** with its injected clock and bounded key map now rate-limits
  unattended-password attempts.
- **Device identity, certificate persistence and fingerprints** are unchanged. The bug
  fixed in Phase 3 — reissuing the certificate on every load — must stay fixed; the
  regression test for it is kept.

### Removed from `crates/transport`

- **mDNS advertise and browse.** Addresses are typed, so discovery has no consumer.
- The **`discovering`** state and its transitions in the client connection state
  machine.

The pairing branch of the `Opening` handshake is removed; a connection is now always a
session. The discriminated `Opening` type itself is kept, because inferring the branch
by attempting two postcard decodes would let a peer choose it — the original reason for
its existence, which still holds if a second branch is ever added.

### Removed from `crates/storage`

An additive migration adds the tables below and the old ones are dropped in the same
migration. The additive-only policy is relaxed exactly once, here, and the migration is
documented as breaking: an existing database loses its trusted devices, owner account,
pairing history and audit trail. This is acceptable because the product has not shipped.

Dropped: the owner account table, the pairing-code outcome table, the audit table, and
the capability columns on trust rows.

### Frontend deletions

Deleted files:

- `src/AuthScreen.tsx`
- `src/TerminalScreen.tsx`
- `src/RemoteAccessScreen.tsx`
- `src/RemoteSupportScreen.tsx`
- `src/ThisComputerScreen.tsx`
- `src/shell/AppShell.tsx`, `src/shell/Sidebar.tsx`, `src/shell/TopBar.tsx`,
  `src/shell/navigation.ts`
- `src/ui/QuickAction.tsx`, `src/ui/Kbd.tsx`, `src/ui/PageHeader.tsx`
- The xterm.js dependencies from `apps/desktop-client/package.json`

Substantially rewritten:

- `MonitoringScreen.tsx` — 628 lines become a compact in-session panel showing CPU,
  memory, disk and network only. The sparklines and the fixed 0–100 scale are kept; the
  process table, the temperature section and the per-core breakdown are removed.
- `UpdateScreen.tsx` — 525 lines become a pane inside Settings plus a small prompt. The
  download, pause, resume, cancel and install machinery is unchanged; only its
  presentation shrinks.
- `App.tsx` — 448 lines become a two-state root: main window, or session.

Removed from `src/api.ts`: `getOwnerStatus`, `createOwner`, `ownerLogin`, `ownerLogout`,
`listTrustedDevices`, `renameTrustedDevice`, `revokeTrustedDevice`,
`getRecentAuditEvents`, `checkPairingCodeFormat`, `discoverAgents`, `pairWithServer`,
`openTerminal`, `sendTerminalInput`, `resizeTerminal`, `closeTerminal`,
`listenTerminalOutput`, `listenTerminalExit`.

The corresponding Tauri commands are removed from `src-tauri/src/commands.rs` and
`src-tauri/src/session_commands.rs`.

### Documentation deletions

`docs/pairing-protocol.md`, `docs/owner-authentication.md`, `docs/permission-model.md`,
`docs/privileged-operations.md`, `docs/terminal-architecture.md`.

`docs/threat-model.md` is rewritten rather than deleted — see Part 2.

### Effect on the test suite

Several hundred passing Rust tests are deleted along with the code they cover. This is
correct, not a regression, and `PROGRESS.md` must say so explicitly rather than letting
a falling number read as decay. Every test covering code that survives must still pass.

## Part 2 — Access model

### One binary, two roles

The Tauri application embeds the host side. On launch it starts a QUIC listener on a
configured port and displays its own address. The same window dials outward. A user
installs one program and can both control and be controlled.

`rc-host-agent` remains in the tree as an optional system service for machines that must
be reachable with nobody signed in. It shares the same transport and the same
authorisation code paths; it is not a second implementation.

Because the host side now runs inside an unelevated desktop application, capturing the
screen of a locked machine or a machine at the login screen is not possible from the app
alone. That is what the optional service is for, and the interface must not imply
otherwise.

### Connecting

1. The user types an address — an IPv4 address, an IPv6 address, or a hostname —
   optionally with a port, and presses Connect.
2. The client dials over QUIC. Mutually-authenticated TLS 1.3 completes. Both sides now
   hold the other's certificate fingerprint, read from the connection rather than from
   any message body.
3. If the peer is marked *always allow* and its pinned fingerprint matches, the session
   is authorised immediately with the permissions stored alongside the pin.
4. Otherwise, if the client supplied an unattended password and one is configured, it is
   verified. Success authorises the session with the remote machine's pre-selected
   permissions.
5. Otherwise the remote machine raises the Accept dialog. Until a human acts, the
   connection is established but authorised for nothing.

### The Accept dialog

Raised on the machine being connected *to*. It shows the incoming address, the peer's
certificate fingerprint, and three checkboxes:

- **Control keyboard and mouse** — default on
- **Transfer files** — default on
- **View system metrics** — default on

Two buttons: **Dismiss** and **Accept**. Rules:

- Dismiss is the default action. Pressing Escape, closing the dialog, or a 30-second
  timeout all count as Dismiss.
- The dialog is raised to the foreground and the window is brought to attention, but it
  does not steal keyboard focus, so a keystroke in flight cannot accept a connection.
- A dismissal closes the connection. It is not retried by the client — a refusal ends a
  reconnect loop, which is an existing decision this design keeps.
- Unchecking a box withholds that permission for the whole session. Permissions cannot be
  escalated later without a new connection.

Authorisation is checked against the live session on every request, not captured once at
connect time. This is an existing property of the agent and must survive the rewrite: a
session whose permissions are revoked mid-flight stops being answered immediately.

### Unattended access

Off by default. There is no default password, and no password means the unattended path
does not exist — a connecting client is told the machine requires someone to accept,
which is the same answer it gets for a wrong password, so the presence of a password is
not disclosed.

When enabled in Settings, the user sets a password (12–1024 bytes, no normalisation) and
pre-selects which of the three permissions an unattended connection receives. The
password is stored as an Argon2id PHC string with a unique 16-byte salt, using the
existing hashing code and its transparent parameter upgrade on successful verification.

Attempts are rate-limited by the existing throttle, checked *before* hashing so lockout
cannot be turned into a work-amplification vector. Lockout persists across restarts.

### Recent connections

Replaces the trusted-device list. Each entry holds: address, the machine name the peer
reported, when it was last connected, and an optional pinned fingerprint.

- Clicking a row reconnects to that address.
- **Always allow** pins the peer's fingerprint and the permissions granted, so future
  connections from it skip the Accept dialog. Unticking it clears the pin.
- If a pinned peer presents a different fingerprint, the connection is **refused** and
  the user is told the machine's identity changed. It is never silently re-accepted and
  never retried — this is the loudest failure the system has and it must stay loud.
- Removing an entry deletes it and its pin.

### Threat model changes

`docs/threat-model.md` is rewritten to state plainly what changed:

- Before: reaching the port was not enough; an attacker had to defeat a pairing exchange
  bound to fingerprints taken from TLS.
- After: an attacker must defeat mutually-authenticated TLS **and** either persuade a
  human to click Accept or know the unattended password.
- The new exposure is social: a user who clicks Accept on an unexpected connection grants
  control. The dialog is designed against this — it names the address, defaults to
  Dismiss, times out to Dismiss, and does not take focus — but it cannot eliminate it.
  This is the model AnyDesk uses and it is an accepted, deliberate trade.
- Anyone at the keyboard of an unlocked machine can use the application, since the client
  password gate is gone. This matches every other application on that desktop.

## Part 3 — Interface

### Main window

No sidebar. No navigation model. Two states only: main window, or session.

A slim title bar carries the application name on the left and a gear on the right. Below
it, two cards side by side:

**This Desk** — the address other people type to reach this machine, in a large
monospaced line with a copy button; the machine name beneath it; and a status dot with a
label reading *Accepting connections* or *Not accepting connections*.

Where the machine has several addresses, all are listed, most-likely-reachable first,
each individually copyable. An address that could not be determined is absent rather than
shown as a placeholder — an existing principle of this codebase that applies here.

**Remote Desk** — a single text field for the remote address and a red Connect button.
The field accepts an IPv4 address, an IPv6 address in brackets, or a hostname, each with
an optional `:port`. Validation happens on submit, and an invalid address is reported
under the field without clearing it.

Beneath both cards, **Recent** — a plain list of rows: machine name, address, relative
time, and a row menu with *Always allow* and *Remove*. Empty state: one sentence
explaining that machines appear here after you connect to them.

### Session

The remote screen fills the window. Until the second spec builds video, this is a
placeholder panel stating that the display stream is not yet available and offering the
session tools — honest, not a fake screen.

A floating toolbar, centred at the top, fully visible on entry and auto-hiding after
three seconds of no pointer movement; it returns when the pointer nears the top edge. It
holds: fit-to-window, keyboard passthrough, Files, Monitoring, fullscreen, and
Disconnect. Disconnect is the only red control.

- **Files** opens the existing two-pane manager as a full-window overlay with a close
  button. Its logic is unchanged: local pane left, remote pane right, resolved paths,
  checksummed transfers.
- **Monitoring** opens a compact strip along the bottom: CPU, memory, disk and network
  with the existing sparklines. It does not cover the screen.
- A tool whose permission was withheld is **not shown** on the toolbar, rather than shown
  and failing when pressed. This is an existing principle — a capability that cannot be
  performed is not advertised — and it applies unchanged.

### Settings

One dialog, reached by the gear. Four sections:

1. **This computer** — machine name and listening port.
2. **Incoming connections** — accept connections on or off; unattended password on or
   off; when on, the password field and the three pre-selected permissions.
3. **Updates** — the existing check, download and install controls, presented compactly.
4. **About** — version, identity fingerprint.

### Visual system

`src/index.css` is rewritten. The four-surface dark palette and every `--color-*` token
it defines are replaced by a single light theme. The `data-theme` opt-in is removed —
there is one theme, and a token defined for a theme nobody can select is dead code.

| Token | Value | Use |
|---|---|---|
| `--color-page` | `#F5F6F8` | Window background |
| `--color-card` | `#FFFFFF` | Cards, dialogs, overlays |
| `--color-border` | `#E3E5E9` | Hairlines |
| `--color-text` | `#1A1A1A` | Primary text |
| `--color-text-secondary` | `#6B7280` | Metadata, labels |
| `--color-accent` | `#EF443B` | The single accent |
| `--color-accent-hover` | `#D93A32` | Accent hover |
| `--color-success` | `#2E9E4F` | Connected, accepting |
| `--color-danger` | `#C62828` | Refusals, identity change |

Type is Segoe UI at a 14px base, with the existing monospace stack retained for
addresses and file paths. Radii are 8px. Cards carry one soft shadow; nothing else does.
Tabular figures stay, because live metrics must not shift sideways as digits change.

The accent is reserved for the primary action — Connect — and for the current state of
a control. Status colours mean the state they name and are never decorative. These are
existing rules in the codebase and they carry over unchanged; only the values change.

Retained from `index.css`: the focus-visible outline, the reduced-motion block, the
scrollbar styling, and the fade and pulse animations. The skeleton shimmer is removed
along with the screens that used it.

## Components and boundaries

| Unit | Responsibility | Depends on |
|---|---|---|
| `crates/security` | Device identity, certificates, keystore, unattended-password hashing and throttle | — |
| `crates/transport` | QUIC, mTLS, channels, session handshake | `security`, `protocol` |
| `crates/protocol` | Wire messages, framing, limits | — |
| `crates/storage` | Recent connections, pins, settings | — |
| Host side (in-app) | Listener, Accept-dialog arbitration, per-request authorisation | `transport`, `storage` |
| Client side (in-app) | Dial, connection state machine, session lifetime | `transport`, `storage` |
| `src/` frontend | Main window, session, settings | Tauri commands only |

The authorisation decision lives on the host side and is reached through one function
that takes a session and a permission and returns a boolean. Every request path calls it.
The frontend never makes an authorisation decision; it only renders the outcome and hides
controls for permissions it was not granted.

## Error handling

- A connection that cannot be established reports why in the Remote Desk card:
  unreachable, refused, timed out, or identity changed. Each is distinct, because each
  has a different remedy.
- A dismissal and a wrong unattended password return the same answer to the connecting
  client, so failure is not an oracle for whether a password is configured. They are
  distinguished in the local log on the receiving machine.
- A dropped session returns to the main window with a message saying the connection was
  lost, and the Recent entry stays. Accidental drops may be retried with the existing
  backoff; a refusal or an identity change is never retried.
- A settings change that cannot be saved is reported and the control reverts to its
  stored value, rather than showing a state the machine is not in.

## Testing

- **Rust, unit**: address parsing and rejection; unattended-password verification,
  throttle and lockout persistence; fingerprint pinning including the mismatch refusal;
  the permission function for each of the three permissions in both directions.
- **Rust, two-process**: the existing integration harness that spawns a real binary is
  kept and adapted. It must cover: connect and Accept; connect and Dismiss; timeout as
  dismissal; unattended password accepted; unattended password refused; always-allow
  skipping the dialog; a pinned peer presenting a changed fingerprint being refused; and
  a permission withheld at accept time being refused for the whole session.
- **TypeScript**: address field validation; connection state rendering for each terminal
  state; Recent list behaviour; toolbar hiding controls for withheld permissions.
- The existing file-transfer and monitoring tests are kept unchanged, since that code is
  not being modified.

## Documentation to update

- `README.md` — repository layout, what the product is, how to run one app rather than
  two.
- `PROGRESS.md` — rewritten. The phase numbering is abandoned; it describes what works.
  The fall in test count is explained as deletion, not decay.
- `docs/threat-model.md` — rewritten per Part 2.
- `docs/network-protocol.md` — the pairing exchange removed, the session handshake and
  the accept flow described.
- A new `docs/access-model.md` replacing the three deleted authorisation documents.

## What this leaves for the second spec

`crates/remote-desktop` stays empty and stays in the workspace. The session screen has a
defined placeholder, the video channel already exists in the protocol, and the
*control keyboard and mouse* permission is already defined and enforced. The second spec
fills in capture, encoding, streaming and input forwarding, and replaces the placeholder.
