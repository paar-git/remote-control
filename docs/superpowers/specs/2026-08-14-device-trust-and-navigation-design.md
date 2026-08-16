> Historical. Not current product documentation.

# Device trust, unattended access and a four-category interface

Design for the change that moves persistent access off the address it was typed at and
onto the device it was granted to, and that rebuilds the window around four categories
instead of one scrolling page.

This document extends `2026-08-11-anydesk-style-remote-control-design.md`. That design
established the Accept dialog, the three permissions and the address-keyed pin. The
first two survive. The third is what this document replaces.

## The problem with the current model

Trust today is a row in `recent_connections`, keyed by the address the user typed,
holding a pinned **certificate** fingerprint and three permission bits. Two things are
wrong with it.

**It is keyed on the address.** A machine reached at a new address is a new row with no
pin, and an address is not an identity. `docs/access-model.md` is careful to key the
lookup on the *dialled* address rather than the peer's ephemeral socket address, which
closes the worst version of this — but the remaining version is still "the thing I
trusted is whatever answers at this name".

**It pins a rotatable credential.** `crates/security/src/identity.rs` documents the
distinction it wants: the identity key is the trust anchor, the certificate is a
credential the identity signs for itself, and renewal must not break trust. Nothing
implements that. `set_always_allow` pins `certificate_fingerprint`, so the first
certificate renewal on the far side makes every pinned peer fail with
`IdentityChanged` — the loudest refusal the system has, fired by an ordinary
maintenance event. This is a latent bug, not only a design shortcoming.

## The trust anchor

Every device generates an Ed25519 identity key and a **self-signed certificate whose
subject public key is that identity key** (`DeviceIdentity::from_key_pair`). The peer
proves possession of the private half by completing the TLS handshake. `rc-transport`
already retains the peer's full certificate DER on `ObservedCertificate`, not merely its
fingerprint.

Therefore the receiving side can compute, for every connection, a **TLS-verified
identity fingerprint**:

```
identity_fingerprint = Fingerprint::of_public_key(spki_ed25519_key(peer_certificate_der))
```

That value is the trust key. It is stable across certificate renewal, independent of
address, and cannot be presented by a device that does not hold the private key. It
requires no protocol change: nothing new crosses the wire, and no self-reported field is
believed. In particular, `DeviceDescriptor::device_id` is **not** used for trust — it is
a claim the peer makes about itself, and it is treated as display text like
`display_name`.

A new function in `rc-security`, `identity_fingerprint_of_certificate(der) -> Result<Fingerprint>`,
performs the extraction and is the only sanctioned source. It fails rather than guesses
when the certificate is not a well-formed Ed25519 end-entity certificate; a connection
whose certificate cannot yield an identity is refused.

### What is not carried forward

Existing address-keyed pins cannot be migrated. They record a certificate fingerprint,
and the identity behind it was never stored, so the new key cannot be derived from the
old row. Anything currently pinned must be trusted once more.

There is deliberately **no** address-based fallback path for old pins. A fallback would
reintroduce "the address is the authentication", which is the entire defect being
removed, and it would be reachable by any peer that could occupy a saved address.

## Data model

Migration `crates/storage/migrations/0004_device_trust.sql`, following
`0003_anydesk_model.sql`.

### `trusted_devices`

One row per trusted device identity.

| Column | Meaning |
|---|---|
| `identity_fingerprint` | PK. Lowercase hex of the verified identity fingerprint. |
| `device_id` | The peer's self-reported device id. Display only. |
| `display_name` | Last reported name. Untrusted text. |
| `os_family` | Last reported OS family. Untrusted. |
| `last_address` | Where it last connected from. **Never authenticates.** |
| `added_ms` | When the human first trusted it. |
| `last_connected_ms` | Last admitted connection, or NULL. |
| `unattended` | May reconnect without anyone approving. |
| `suspended` | Temporarily disabled; the row and its settings are retained. |
| `permissions` | What an admitted session receives, including `Administer`. |

`CHECK` constraints mirror the existing style: fingerprint exactly 64 hex characters,
`unattended`/`suspended` in `(0, 1)`, `permissions BETWEEN 0 AND 15`, and
`CHECK (suspended = 0 OR unattended IN (0, 1))` is *not* added — suspension is
orthogonal to how the device gets in and constraining them together would encode a rule
the code does not have.

### The separation §6 asks for is structural

`unattended` answers **how the device gets in**. `permissions` answers **what it may do
once in**. They are different columns, written by different commands, and neither
implies the other. Granting a laptop unattended access to a desktop sets one boolean and
touches no permission bit. Granting Administrator sets one bit and touches no access
column. There is no code path that widens one because the other was widened.

### `session_history`

| Column | Meaning |
|---|---|
| `id` | PK, autoincrement. |
| `session_id` | The id assigned at admission, or NULL for a connection never admitted. |
| `identity_fingerprint` | NULL for a device that was never trusted. |
| `device_name` | Name as displayed at the time. Untrusted text. |
| `direction` | `incoming` or `outgoing`. |
| `address` | The address dialled or connected from. |
| `started_ms`, `ended_ms` | `ended_ms` NULL while live. |
| `permissions` | What the session held. |
| `outcome` | `completed`, `refused` or `failed`. |
| `end_reason` | A `DisconnectReason` name, or NULL. |

History is capped at 500 rows, trimmed oldest-first on insert, so an unattended machine
does not accumulate an unbounded table.

### `recent_connections`

Retained. It is the *outgoing* dial history and the address is the correct key for it —
the address is what the user types to reach a machine. Two changes:

- `pinned_fingerprint` and `pinned_permissions` are dropped. Incoming trust lives in
  `trusted_devices` now, and leaving these would be two tables claiming to hold the same
  decision.
- `known_identity` is added, nullable. Recorded on the first successful outgoing
  connection and verified on every subsequent one, so the *client* also pins an identity
  rather than a certificate. This is what stops the far side's certificate renewal from
  looking like a substituted machine, and it is what makes a substituted machine visible.

### Migration numbering

The file is `crates/storage/migrations/0004_device_trust.sql`. It is additive except for
dropping the two pin columns, which is the deliberate break described above. The
additive-only policy that `0003` reinstated is broken exactly once more, for exactly one
reason, and that reason is written into the migration's header comment.

## Permissions

A fourth permission, `Permission::Administer`.

```
ControlInput   0b0001
TransferFiles  0b0010
ViewMetrics    0b0100
Administer     0b1000
```

`PermissionSet::KNOWN` widens from `0b0111` to `0b1111`. `from_bits` continues to refuse
unknown bits rather than masking them, so a build that does not know `Administer`
refuses a set containing it rather than silently dropping it — the existing behaviour,
now load-bearing across a version boundary. The protocol minor version is bumped
accordingly.

Database `CHECK` bounds widen from `0 AND 7` to `0 AND 15` for
`host_settings.unattended_permissions` and for the new `trusted_devices.permissions`.

### What Administer authorizes

Four new control-channel requests, each gated by `Session::require(Permission::Administer)`
on every request like the other three:

| Request | Effect |
|---|---|
| `ListTrustedDevices` | Read the controlled machine's trusted devices. |
| `SetDevicePermissions { identity, permissions }` | Change what a trusted device may do. |
| `SetUnattendedAccess { identity, enabled }` | Turn unattended reconnection on or off. |
| `RevokeDevice { identity }` | Remove the trust relationship entirely. |

The response payload is `ControlResponsePayload::TrustedDevices(Box<Vec<TrustedDeviceSummary>>)`,
boxed for the same reason `Snapshot` is: it is far larger than `Pong`, and an un-boxed
variant would set the size of every control response.

**No self-modification.** A session may not target its own `identity_fingerprint` with
any of the three mutating requests. Without this, an admin session could grant itself
unattended access it was never given, or make itself un-revokable. This is enforced in
one place, in the service, by comparing the request's target against the identity the
session was admitted under, and it is refused as `PermissionDenied` rather than silently
ignored.

`TrustedDeviceSummary` carries no secret: names, ids, timestamps, flags and permission
bits. There is no credential associated with a trust relationship to leak — a device is
authenticated by holding its identity private key, not by presenting a stored token.

## Admission

`authorize_connection` gains a step and keeps everything else. The new order:

```
0. Not accepting                                → Refused(NotAccepting)
1. Derive verified identity from the certificate
     malformed                                  → Refused(Rejected)
2. trusted_devices lookup by identity
     suspended                                  → Refused(Suspended)
     unattended                                 → grant_or_refuse(stored permissions)
     trusted, not unattended                    → fall through to 4, marked trusted
   no row, but dialled address is a trusted
   device's last_address                        → Refused(IdentityChanged)
3. Unattended password, if offered              → unchanged
4. A human                                      → unchanged
```

Everything the current implementation guarantees is preserved unchanged: the settings
read happens once, the throttle guard is held across the whole check-hash-record
sequence, the dummy hash still runs when no credential is configured, an over-long
password is still rejected before hashing, at most one dialog is open at a time, the
correlation id still gates the answer, and an empty grant is still a refusal through
`grant_or_refuse`.

### `IdentityChanged` is retained, re-anchored

Under identity-keyed trust, a changed certificate carrying the same identity key is
ordinary renewal and is admitted — that is the point. A changed *identity* is an unknown
device, which would normally mean the Accept dialog.

But the property `access-model.md` exists to protect is that a machine substituted at a
trusted address must not arrive as a routine click. So: if the dialled address equals a
trusted device's `last_address` and the presenting identity is not that device, the
connection is refused as `IdentityChanged` and never reaches the prompt. The remedy is
the same as today — remove the entry and connect again — and it is stated in the
interface.

`RefusalReason::Suspended` is added and collapses to `WireRefusal::Rejected`, joining
`Dismissed`, `WrongPassword` and `TooManyAttempts`. A peer that could distinguish
"suspended" from "rejected" would learn that it is known to the machine, which is
precisely what a revoked or suspended device must not learn.

### The Accept dialog

Three answers, plus one behind a second step.

- **Reject** — keeps initial focus. Timeout, Escape and closing the window all mean
  this, as today.
- **Accept Once** — grants the ticked permissions for this session and **persists
  nothing**. No `trusted_devices` row is written.
- **Accept & Trust** — writes a `trusted_devices` row with the ticked permissions and
  `unattended = 0`. The device is remembered, and it still raises this dialog next time.
- **Allow unattended access** — a checkbox revealed only after Accept & Trust is chosen,
  requiring a second deliberate act, with the consequence spelled out in a sentence. It
  sets `unattended = 1`.

**Administrator is never offered here.** It is granted only from My Devices → device
detail → a confirmation dialog that names the device and enumerates the privileges. A
permission that lets a device rewrite the trust database must not be reachable from the
control people click several times a day.

The dialog shows: name, device id, OS, the address, the verified identity fingerprint in
display groups, whether the device is already trusted, and the permissions being
requested.

## Outgoing connections

The client records the server's verified identity fingerprint in
`recent_connections.known_identity` on first successful connection, and verifies it on
every subsequent connection to that address. A mismatch is surfaced as a refusal naming
an identity change, not as a generic failure — the client side of the same property the
host side enforces.

`TrustPolicy::Pinned` in `rc-transport` continues to pin at the TLS layer for the
certificate it has seen, and the identity check happens above it, on the observed DER.

## Interface

### Navigation

A typed `View` union — `remote-control`, `my-devices`, `sessions`, `settings` — held in
`App`, with a sidebar that labels all four, marks the current one with a filled
background and `aria-current="page"`, and animates page changes with a short opacity and
translate transition honouring `prefers-reduced-motion`.

The uncommitted `AppSidebar` (a Devices item that scrolls the page, and Sessions and
File-transfer items permanently disabled) is replaced by this. In-session tools remain
reachable from the session screen, where they apply.

### Remote Control

`Connect to a device` is the visual centre: one field accepting a device address, one
primary `Connect` button in the accent colour — never red. Below it, `This Device`, and
below that a compact recent list of at most five entries with a `View all devices →`
link.

`This Device` shows the machine name, a status line, the **address** as the value to
connect with, and the **Device ID** beneath it as the identity to verify. Copy and Share
act on both. `Allow incoming connections` is a real toggle over the existing
`set_accepting` command. IPv4, IPv6, hostname, listen port, connection method and
reachability move into a collapsed `Advanced network information` disclosure.

The Device ID is labelled as an identity to verify, not as something to dial, because
there is no rendezvous service and it cannot dial. Nothing in the interface implies
otherwise.

### My Devices

Cards over `trusted_devices`: name, OS, presence dot, trust level, last connected,
`Connect`, and a menu. Clicking a card opens a detail view with three sections — Access
(trusted, connect without approval, administrator), Permissions (the four real ones), and
Security (added, last connection, device identity) — and a destructive `Revoke Access`.

**Presence** is a real reachability probe: a QUIC connection attempt to the saved address
that is dropped before `Authenticate` is sent, so the far side never raises a prompt and
never records a session. Three states — online, offline, checking — and never a
fabricated one. Probes run concurrently with a short timeout when the page opens.

### Sessions

Active sessions (device, connected since, direction, permissions in use, latency from
the existing `ping_server`, Disconnect) over the live registry, and recent sessions over
`session_history` with a compact empty state rather than a large empty container.

### Settings

Sections on one page, not new navigation categories: Remote Access, Security, Network,
Appearance. The existing `SettingsDialog` logic is reused rather than rewritten.

**General is omitted.** "Start with system", "Start minimized" and "Minimize to tray" do
not exist — no autostart plugin, no tray. Three switches that change nothing would be
exactly the placeholder this work is removing.

### Connection states

The existing discriminated union already covers offline, connecting, authenticating,
connected, disconnecting, reconnecting, waiting to retry, refused and failed. Each gets
a distinct message and indicator, and `Connect` shows progress rather than appearing
inert.

**No wire signal is added for "waiting for remote approval."** Telling an
unauthenticated peer that a human is being asked discloses that unattended access is not
configured on that machine — the oracle `access-model.md` closes deliberately. The
client instead shows "Waiting for the remote device…" after several seconds in
`authenticating`, which is true, useful, and leaks nothing.

### Active-session visibility

An inbound session registry on the desktop host side, mirroring
`rc_host_agent::SessionRegistry`. While any inbound session is live, a banner is present
on every page showing the controlling device, the duration and the permissions in use,
with `Disconnect` and `Emergency Disconnect`. The latter drops every inbound session
immediately and sets `accepting` to false, so the door closes as well as the session.

## Testing

Beyond the existing suites, which must continue to pass unchanged where the behaviour is
unchanged:

- Allow Once writes no `trusted_devices` row.
- Accept & Trust writes one, and the device still reaches the dialog next time.
- A device with `unattended` is admitted with exactly its stored permissions, no prompt.
- A different identity presenting a trusted device's *address* is refused as
  `IdentityChanged`, never prompted.
- A different identity cannot be admitted under another device's row: the lookup is by
  identity, and a second key produces no row.
- Administrator is absent from every admission path that does not have it stored, and is
  not settable from the Accept dialog.
- Removing Administrator takes effect on the next request within a live session, because
  permissions are re-checked per request.
- Revoking prevents a subsequent unattended connection, asserted by connecting again
  rather than by reading the table.
- A suspended device is refused, and its row and settings survive.
- An admin session cannot modify its own trust row.
- Certificate renewal does not break trust: the same identity with a new certificate is
  still admitted.
- Session history records outcome, duration and direction, including a refused
  connection.
- Trust and revocation both survive a restart, asserted against the real `rc-agent`
  binary in `access_e2e.rs` alongside the existing nine cases.

## Verification

`pnpm verify` in full: version sync, format, lint, typecheck, TypeScript tests, release
smoke, `cargo fmt --check`, clippy pedantic with `-D warnings` across all targets and
features, and `cargo test --workspace`.

## What this design does not do

- No rendezvous or relay service, so a Device ID cannot be dialled.
- No screen capture, input injection, clipboard, audio or microphone. `ControlInput`
  remains granted and enforced with nothing consuming it, as today.
- No autostart or tray integration.
- No migration of existing address-keyed pins.
