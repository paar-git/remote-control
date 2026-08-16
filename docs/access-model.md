# Access model

How this application decides whether an incoming connection may have a session, and
what it may do once it has one.

This document replaces `pairing-protocol.md`, `owner-authentication.md` and
`permission-model.md`. All three described a mechanism that no longer exists: there is
no pairing exchange, no owner account and no role hierarchy.

The rule lives in one place — `crates/host-agent/src/access.rs`, in
`authorize_connection`. Everything below is a property of that function.

## The four ways in, in this order

A connection that has completed mutual TLS arrives here with a verified device identity
(the Ed25519 subject public key of the certificate it presented), the address the
caller dialled, a self-reported machine name and, if it offered one, an unattended
password. Completing TLS proves possession of that identity key. Nothing about the
caller is trusted yet.

**0. Is this machine accepting at all?** If not, the connection is refused before
anything else is read. The setting is read once per connection, not twice: two reads
could straddle a change and decide against two different configurations.

**1. A trusted device.** If the presenting identity has a row in `trusted_devices` and
that row is not suspended, the stored grant is applied. Unattended devices skip the
dialog; trusted-but-attended devices still raise it. The key is the identity, not the
address it was typed at: a device reached at a new address keeps its grant, and a
renewed certificate is not an identity change.

**2. An unattended password**, if the connection offered one and no trust row admitted
it. Verified with Argon2id against the stored PHC string, under a per-address lockout.

**3. A human.** The Accept dialog, with the timeout and the default both set to refuse,
and at most one dialog open at a time. The three answers are Accept Once (persists
nothing), Accept & Trust (remembers, still asks next time), and unattended access
behind a second deliberate step. Administrator is never offered here.

The order is the design. A stored identity grant is checked before a password because
it is the stronger statement; a password is checked before the dialog because a
machine configured for unattended access should not raise a prompt nobody is there to
answer.

## A stranger at a trusted address is refused, not prompted

`IdentityChanged` is now an address-versus-identity mismatch: the dialled address
equals a trusted device's `last_address`, but the presenting identity is not that
device. The connection is refused outright. It is never handed to the dialog.

A substituted machine at a familiar address is either a reinstall or an attacker. Both
need a human decision, but the *dialog* is the wrong place to take it: the dialog is a
thing users click through many times a day, and an identity change that arrives as a
routine Accept prompt will be accepted by reflex. Refusing it forces the question
somewhere deliberate — removing the entry and connecting again.

An ordinary certificate renewal does not trigger this. The trust key is the identity
behind the certificate, which renewal leaves unchanged.

`RefusalReason::Suspended` collapses to `WireRefusal::Rejected`. A peer that could
distinguish "suspended" from "rejected" would learn that it is known to the machine,
which is precisely what a revoked or suspended device must not learn.

## A wrong password is a refusal, not a fallback to the dialog

Falling back would mean anyone with the address could raise a prompt on someone's screen
by guessing, and would make a wrong password indistinguishable from no password at all.

The attempt is counted against a per-address lockout, and the lockout is held across the
whole check — the throttle guard is taken before the stored credential is read and
released after the failure is recorded. Taking it twice would let N concurrent attempts
all pass the check before any of them recorded a failure, so the bound would hold only
for a caller that was polite enough to try one at a time.

When no unattended password is configured, the verification still runs against a dummy
hash at full cost. Returning early would make "no password configured" measurably faster
than "wrong password", which is an oracle for whether unattended access exists.

## The peer is told less than the log records

There are two refusal types, and the difference between them is the point:

| Local (`RefusalReason`) | On the wire (`WireRefusal`) |
| --- | --- |
| `Dismissed` | `Rejected` |
| `WrongPassword` | `Rejected` |
| `TooManyAttempts` | `Rejected` |
| `NotAccepting` | `NotAccepting` |
| `IdentityChanged` | `IdentityChanged` |

A caller that could tell a dismissal from a wrong password from a lockout could use the
answer as an oracle: for whether unattended access is configured at all, and for whether
its guesses were landing. Those three collapse into one value.

`NotAccepting` and `IdentityChanged` stay distinct because they need different remedies
and disclose nothing a caller could not already observe.

This is enforced by the type system rather than by convention: `WireRefusal` is a
separate type in `rc-protocol`, `RefusalReason` lives in `rc-host-agent` and derives no
`Serialize`, and the `From` impl between them is the only crossing.

## The acknowledgement discloses nothing either

`HelloAck` is sent before the admission decision, to anyone who completes TLS — which,
under trust-on-first-use, is anyone who can reach the port. It therefore carries the
negotiated protocol version and nothing else.

The machine's name, hostname, OS version, application version, device id, capabilities
and session id all ride on `SessionAuthorization::Granted`, which only an admitted peer
receives. A peer that is refused learns that it was refused and nothing about what it
reached.

Adding a field to `HelloAck` moves it from "disclosed to admitted peers" to "disclosed
to anyone who can reach the port".

## Accepting with nothing ticked is a refusal

A session that may do nothing is a connection nobody can use and nobody can see.
Refusing says the same thing more clearly, and it keeps the "active sessions" list
meaningful.

Every door that can grant something funnels through one function, `grant_or_refuse`,
rather than each re-deriving the check. This very nearly stayed specific to the human
branch alone, which is exactly how a fourth way in would have missed it.

## Permissions are fixed for the life of a session

What was granted at admission is what the session holds until it ends. There is no
mechanism to widen it: doing so requires a new connection, which means a new decision by
a human.

They are **re-checked on every request**, not once when the channel opens. A permission
decided once at handshake and then trusted forever is the failure this design exists to
prevent — a session whose permissions are withdrawn stops being answered immediately
rather than at its next reconnection.

The check is `Session::require`, and both sides apply it. The controlled machine's copy
is the authority. The controlling machine keeps its own copy so it can refuse locally
and so it can show controls that will actually work, rather than buttons that will be
denied — but nothing on the controlling side can widen what the controlled side
enforces.

## The four permissions

| Name | What it allows |
| --- | --- |
| `control_input` | Move the pointer and type on the remote machine |
| `transfer_files` | Browse and transfer files, in both directions |
| `view_metrics` | Read system information and live metrics |
| `administer` | Manage this machine's trusted devices over the control channel |

`administer` is never conferrable from the Accept dialog. It is granted only from My
Devices, after a confirmation that names the device and the privileges. A session may
not modify its own trust row.

How a device gets in (`unattended`) and what it may do (`permissions`) are separate
columns, written by separate commands. Turning on unattended access touches no
permission bit.

There is no separate read and write file permission. There used to be, as an explicit
list of read-only operations with everything else needing write access; with one file
permission the list collapsed into a single check. If a second file permission is ever
reintroduced, the split belongs back in `file_service.rs`.

## What the dialog is arranged to prevent

The Accept dialog is the one place a person decides something that cannot be undone by
closing a window, so the *careless* answer is the safe one:

- **Reject takes initial focus**, so a held Enter or a stray keystroke refuses.
- **Escape refuses**, and so does closing the window.
- **It times out to a refusal** after thirty seconds. An unattended machine closes its
  own door.
- **Only one can be open at a time.** A second connection arriving while one is pending
  is refused without ever reaching the prompt, so nobody can be buried in prompts until
  one is clicked by accident.

The timeout is owned by the backend. The interface renders no countdown, because a
second timer would be a number on screen that can disagree with the decision actually
being made.

## The address is the one the user dialled

Trust itself is keyed on the presenting identity. The address still matters in two
places: it is what the user types to reach a machine (`recent_connections`), and it is
what `IdentityChanged` compares against a trusted device's `last_address`. Both use
the address as typed, carried across the wire on `Authenticate`, **not** the peer's
remote socket address from the QUIC connection, whose source port is ephemeral.

Getting this wrong would mean the identity-change branch was never entered, and a
stranger at a familiar address fell through to the human dialog — the outcome that
comparison exists to prevent.

Existing address-keyed certificate pins are not migrated. They record a certificate
digest whose identity was never stored, so the new key cannot be derived from them.
No address-based fallback was added, because that is the defect being removed.
