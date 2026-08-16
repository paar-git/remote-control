# Connection, pairing and trusted access — design

**Date:** 2026-08-07
**Status:** approved, not yet implemented
**Scope:** subsystem 2 of 4 (see "Decomposition" below)

## Problem

Connecting one computer to another must be simple enough for someone with no
technical knowledge: read a code off one screen, type it into another, approve the
request. It must stay simple on the second connection — a device the owner has
trusted should connect without another prompt — without giving that device silent,
unbounded, permanent access.

The pieces underneath this already exist. Device identity, connection codes, the
capability model and the encrypted transport were built in Phases 2–4. What is
missing is the layer that turns them into a flow a person can follow, and the
approval semantics that let a connection happen *without* creating permanent trust.

## Decomposition

The original request spans four independent subsystems. They are listed here so a
later reader knows what this document deliberately excludes.

| # | Subsystem | Status |
|---|---|---|
| 1 | Internet rendezvous: connect by code across networks, no IP shown | Not started. `apps/coordination-server` is a health-check stub. Phase 8. |
| 2 | **Connection and trust UX** | **This document.** |
| 3 | Guest mode: no account required to use the app | Included here (§5), because it blocks the flow at first launch. |
| 4 | Cloud accounts, Google OAuth, sync, extra themes | Not started. Needs a hosted backend and a registered OAuth client. |

This document covers subsystem 2 and the part of 3 that stands in its way.

### What already exists

Not rebuilt by this design:

- **Device identity** — Ed25519 keypair, device UUID, self-signed pinned certificate,
  keystore protected by DPAPI on Windows and `0600`/`0700` on Unix. The private key
  never leaves the machine.
- **Connection codes** — nine characters over a 30-symbol confusable-free alphabet
  (~44 bits), 3-minute expiry, single-use, stored only as an Argon2id verifier, with
  a hard cap of five attempts.
- **Capabilities** — ten typed capabilities, enforced host-side. Adding one without
  deciding which roles hold it is a compile error.
- **Session security** — mutually authenticated TLS 1.3 over QUIC, fingerprint
  pinning, replay guard, fresh per-session keys.

## Reach

Machines on the same local network, found via the existing mDNS discovery.
Connecting to a computer on another network needs subsystem 1 and is out of scope.
No address or hostname is shown to the user anywhere in the normal UI.

## Architecture

A new crate, `crates/access` (`rc-access`), depending on `rc-security`,
`rc-storage` and `rc-protocol`. It orchestrates existing primitives; it implements
no cryptography of its own.

| Module | Responsibility |
|---|---|
| `code.rs` | Connection-code lifecycle: current code, expiry countdown, regeneration, disabling incoming connections. Wraps `rc_security::pairing::code`. |
| `request.rs` | Approval state machine: `Pending → Accepted{scope} \| Rejected \| Expired`. Pure logic, no I/O. |
| `trust.rs` | `TrustScope`, promotion from session to permanent, revocation, revoke-all. |
| `permissions.rs` | Per-device capability edits and the narrow/widen rule. |
| `presence.rs` | Online/offline state for saved devices, fed by mDNS discovery. |

`request.rs` holds no I/O deliberately: the approval semantics are the part most
worth testing exhaustively, and they should be testable without a network, a
database or a UI.

The agent wires approval into its admission path. `host-agent/src/server.rs` is
already ~1500 lines; the state machine does not go there.

Client UI: `DevicesScreen.tsx` (~800 lines) splits into `src/devices/` —
`RequestPrompt`, `SavedComputers`, `DeviceDetail`, `PermissionEditor` — over a small
state module.

## Data model

`TrustedDevice` gains two fields:

- `trust_scope: TrustScope` — `Session` or `Permanent`.
- `operating_system: String` — recorded at pairing, shown in the saved-computer list.

Schema migration 2 → 3.

Everything else the saved-computer list and management page need is already on
`TrustedDevice`: `display_name` (the nickname), `hostname`, `last_connected_at_ms`,
`paired_at_ms` (when trust was created), `revoked`, `granted_capabilities`,
`favorite`.

Session-scoped records are deleted when the session ends **and** on agent startup.
The startup sweep is what makes a crash safe: without it, a killed agent would leave
a one-time grant behind that behaves like permanent trust.

The global "Allow Trusted Devices to Connect Automatically" switch lives in agent
config, not per device.

## Connection and approval flow

**First connection.** Computer B surfaces the code it already generates, with a live
countdown, **Generate New Code**, and **Disable incoming connections**. Computer A
enters the code. The existing pairing exchange runs unchanged — same transcript, same
domain separation — but on completion it raises a **pending request** instead of
writing permanent trust.

Computer B sees the requesting device's name, hostname and the permissions being
requested, and chooses:

- **Reject** — nothing is written.
- **Accept Once** — trust record with `Session` scope. The device must ask again next
  time.
- **Accept & Trust** — `Permanent` scope, and Computer A is then asked to confirm
  saving Computer B.

That last confirmation is what makes the two-sided approval real rather than
cosmetic: either side declining leaves no permanent record on either machine.

**Later connections.** A permanently trusted device connects without prompting B.
B always sees a visible notice — "Koren-PC connected using Trusted Access" — and an
audit event is written. The owner is never unaware that someone is connected.

When the global automatic-connection switch is off, even trusted devices prompt.

**Emergency disconnect.** The existing `Disconnect` control message backs a
host-side control that is reachable whenever a session is active. The local user
always outranks the remote one.

## Permissions

Each trusted device has a permission editor covering the ten existing capabilities.

- **Narrowing** — applies immediately, no authentication.
- **Widening** — requires the owner password and writes an audit record.

Enforcement is unchanged. `TrustedDevice::holds()` still requires that a capability
be granted by the role *and* present in `granted_capabilities`, so the property that
widening a role cannot retroactively widen an existing device survives. Widening
becomes an explicit, authenticated, audited mutation rather than a side effect.

Permissions are always enforced by the machine being controlled, never by the
machine asking.

## Guest mode

The app opens straight into its normal UI. No account is required to generate codes,
connect, accept connections, create trusted devices, transfer files, or configure
permissions.

The owner password is created on first use of a privileged action:

- Accept & Trust
- Widening a device's permissions
- Revoke all trusted devices
- Power control

The existing `owner` module is reused unchanged; only the point at which the gate
applies moves. The password protects *local* privilege — it is not a cloud account
and never leaves the machine.

## Protocol

New `ControlRequestPayload` variants: `ListTrustedDevices`, `RenameTrustedDevice`,
`RevokeTrustedDevice`, `RevokeAllTrustedDevices`, `SetDevicePermissions`,
`SetUnattendedAccess`.

The pairing protocol gains the request/approval round trip. `protocol_major` stays
at 1; this is additive.

## Errors

| Condition | What the user sees |
|---|---|
| Code expired | The code is no longer valid, with a button to ask for a new one. |
| Five failed attempts | The code is destroyed; B must generate another. |
| Request rejected | "The other computer declined the connection." No reason is given — B's reason is B's business. |
| Request timed out | Distinguished from rejection, so A knows to try again rather than give up. |
| Revoked device connects | Refused as an unknown device; it falls back to the code flow. |

## UX wording

Per the requirement to avoid jargon: the normal UI says **Connection Code**,
**Trusted Device**, **Saved Computer**, **Ask Before Connecting**, **Allow Automatic
Connection**, **Remove Access**. Fingerprints, key details and certificate
information live behind an Advanced section for operators who want them.

The distinction a user must understand without help is one-time access versus
trusted access. The three-button prompt carries that: Reject / Accept Once /
Accept & Trust.

## Testing

- **State machine** — every transition in `request.rs`, including expiry racing
  acceptance.
- **Scope lifecycle** — a session-scoped record does not survive session end; and
  does not survive an agent restart that skipped the clean shutdown path.
- **Permission rules** — narrowing needs no authentication; widening without the
  owner password fails; a widened capability takes effect only after both role and
  grant allow it.
- **Revoke** — revoking a device invalidates its credentials immediately and it
  returns to the code flow; revoke-all does so for every device at once.
- **Two-agent integration** — Accept Once requires a fresh approval on the next
  connection; Accept & Trust does not.
- **Two-sided trust** — A declining to save B leaves no permanent record on either
  machine.
- **Component tests** — the request prompt and the permission editor.

## Out of scope

Internet rendezvous, Google OAuth, cloud accounts, cloud sync, extra themes, and
guest-to-account migration. Each belongs to subsystem 1 or 4.
