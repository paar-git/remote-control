# Threat model

Written for the current design: one application that is both the machine being
controlled and the machine controlling, admitting connections by a trusted
identity, an unattended password, or a human clicking Accept, and remembering a
device by the identity it proved.

The access rules themselves are in [`access-model.md`](access-model.md). This document is
about who can attack them and what happens when they do.

## What is being protected

1. **Confidentiality and integrity of sessions** — screen contents, keystrokes,
   transferred files.
2. **Control of a machine** — nothing may act on it without a decision by the person at
   it, or a password they set.
3. **Machine identity** — a caller must be certain which machine it reached, and a
   machine must be certain which caller it admitted.
4. **The unattended password at rest.**

## Assets

| Asset | Where it lives | Protection |
| --- | --- | --- |
| Device private key | Versioned keystore file (DPAPI `CurrentUser` / `0600` in a `0700` dir), never the database | Implemented — see [`keystore-format.md`](keystore-format.md) |
| Unattended password | Argon2id (m=19 MiB, t=2, p=1) PHC string in `host_settings.unattended_phc` | Implemented — never leaves the database, never crosses IPC |
| Trusted-device identities | `trusted_devices.identity_fingerprint` | Integrity of the local database; the key is proved by TLS and cannot be claimed |
| Session traffic | In flight only | mTLS 1.3 over QUIC |

There are no session tokens. A session is authenticated by the mutually-authenticated
TLS connection it runs on, which cannot be transplanted onto another connection, so
there is no bearer value to steal. The session id exists only so both sides' logs name
the same session.

## What got weaker, stated plainly

The previous design required an attacker to defeat a pairing exchange: a short-lived,
single-use, attempt-capped code, with the proof bound to both certificate fingerprints.
Without it, no connection was possible at all.

The current design requires **mutual TLS plus a trusted identity, the unattended
password, or a human clicking Accept**. Completing TLS is not a barrier — the
listener is trust-on-first-use and any well-formed self-signed client certificate
passes it.

So the first door is a trusted identity. Without that grant, the barrier is a
person, or a password.

This is a real reduction, and it was made deliberately: the pairing exchange was the
single largest obstacle to the product being usable, and a remote-control tool nobody
can set up protects nothing. What replaces it is the model AnyDesk, TeamViewer and
Chrome Remote Desktop all use, and the exposure it creates is the one they all have.

## The exposure that replaces it: social engineering

An attacker who can reach the port can raise a dialog on someone's screen and ask them
to click Accept. That is the attack, and no cryptography addresses it. It is why the
support-scam industry exists.

Four mitigations are built into the dialog, and all four are about making the
*careless* answer the safe one:

1. **Dismiss takes initial focus**, so a held Enter or a stray keystroke refuses rather
   than grants.
2. **It times out to a refusal.** An unattended machine closes its own door after thirty
   seconds rather than leaving a prompt open indefinitely.
3. **Only one dialog can be open at a time.** A second connection arriving while one is
   pending is refused without reaching the prompt, so nobody can be buried in prompts
   until one is clicked by accident.
4. **The grant is itemised and reducible.** The dialog says what the caller will be able
   to do and lets each item be taken away, so accepting is not all-or-nothing.

What is *not* mitigated: a person who is talked into clicking Accept has admitted the
caller, and the application did what it was told. The remaining defences are the session
being visible while it runs and endable at any moment, and the permission set bounding
what an admitted caller can reach.

## Anyone at an unlocked keyboard can use this application

There is no login. Someone sitting at an unlocked machine can open the application,
connect out, change the unattended password and turn incoming connections on or off.

This is deliberate and it matches every other application on that desktop: the operating
system's session lock is the boundary that protects the desktop, and adding a second
password in front of one application would be security theatre — it would be bypassed by
reading the database file, and it would train the user to type a password that protects
nothing.

The consequence to be aware of: the previous design's "application is locked" state was
the only thing standing between physical access and remote-access configuration. It is
gone.

## Trust boundaries

1. **Network → this machine.** Everything crossing it is hostile until the connection
   has been admitted. Completing TLS admits nothing.
2. **Webview → backend.** The webview is untrusted. Every IPC response is
   schema-validated, and every value that originated on another machine is stripped of
   control characters and bidirectional overrides before it is rendered.
3. **Controlling machine → controlled machine.** An admitted session is authorised for
   what it was granted and nothing else, re-checked on every request. The controlling
   side is never the authority on what the controlled side permits.

## Adversaries and controls

### A1. Attacker who can reach the port

*Can:* complete TLS, learn that something is listening and what protocol version it
speaks, and cause an Accept dialog to appear on the screen — once. Attempt unattended
passwords, at the rate the lockout allows.

*Cannot:* learn the machine's name, hostname, OS version, application version or
capabilities without being admitted — none of it travels before the decision. Tell a
dismissal from a wrong password from a lockout. Learn whether unattended access is
configured at all, by answer or by timing. Stack dialogs. Get a session without a human
click, the password, or a stored trusted-identity grant.

*Residual:* denial of service by flooding the port; the one-dialog rule also means an
attacker can occupy the dialog slot and stop a legitimate connection from raising one
while it is open. Bounded by the thirty-second timeout, not eliminated. Repeated dialogs
are a nuisance the user must respond to by turning off incoming connections.

### A2. Attacker who knows the address and guesses the password

*Can:* try passwords. Each attempt costs a full Argon2id verification on the target.

*Cannot:* exceed the lockout. The throttle guard is held across the check, the stored
credential read, the hash and the record of failure, so concurrent attempts cannot all
pass the check before any of them counts. Distinguish a wrong password from any other
refusal.

*Residual:* a weak password. The floor is 12 bytes, stricter than AnyDesk's, and the
interface says so rather than silently enforcing it. A user who chooses a guessable
12-character password is not protected by the lockout alone.

### A3. Stolen machine

*Can:* obtain the database with trusted-device identities and the unattended password hash,
and the encrypted device key.

*Cannot:* recover the unattended password from its Argon2id hash at those parameters,
cheaply. Use the device key without the OS user account it is bound to (DPAPI
`CurrentUser` on Windows, file mode on Unix).

*Residual:* the trusted-device list discloses which machines this one will admit.
An attacker with the unlocked desktop has the application, per the section above.

### A4. Malicious peer that was admitted

*Can:* do exactly what it was granted, for as long as the session lasts.

*Cannot:* widen its permissions — there is no mechanism, and every request is re-checked
against the live set rather than a set captured at connect. Escape the configured file
roots: every path from the wire is resolved and checked before any filesystem call.
Reach anything requiring a permission that was not ticked. Grant itself unattended
access or make itself un-revokable: a session may not target its own trust row, and
revocation is immediate because there is no bearer credential to invalidate.

*Residual:* what was granted. A session granted `control_input` can do anything the
logged-in user can do on that machine. That is what remote control is.

### A5. Compromised webview

*Can:* call any exposed command.

*Cannot:* obtain the unattended password or its hash — neither has a route across the
IPC boundary, and the settings DTO is hand-written so a new database column cannot start
sending one. Obtain the device private key. Widen a session's permissions.

*Residual:* it can do what the person at the keyboard can do, which is the same set.
