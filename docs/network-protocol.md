# Network protocol

How two machines reach each other, decide whether to admit a connection, and hold a
session.

## Transport

QUIC over UDP, with mutually-authenticated TLS 1.3 and ALPN `rc/1`. Default port
**7443/UDP**.

QUIC rather than TCP for three reasons that matter to this application specifically:

- **Independent streams.** Each channel is its own stream, so a multi-gigabyte file
  transfer cannot delay a keystroke. Over a single TCP connection it would.
- **Connection migration.** A laptop that moves from Wi-Fi to Ethernet keeps its
  connection instead of dropping it.
- **Address validation is built in.** QUIC's retry mechanism costs one round trip on a
  first connection and removes an amplification-reflection vector from a service that
  may face the internet.

TLS 1.2 is not offered. There is no legacy peer to accommodate, and 1.3 removes whole
categories of downgrade and cipher negotiation.

## Certificates are containers, not credentials

Both peers hold self-signed certificates over their long-term Ed25519 identity keys.
There is no certificate authority, because both machines are administered by the same
person and there is no third party whose opinion about their names is worth anything.

The verifiers therefore check very little:

| Check | Why |
|---|---|
| The certificate parses as X.509 | Anything else cannot carry a key |
| Exactly one certificate, no chain | A chain would imply a CA we do not have |
| SHA-256 of the DER matches the pin | This is the trust decision |
| The handshake signature verifies | Proves possession of the private key |

Hostname verification is **deliberately absent**. A peer is identified by key, not by
name, and a machine dialled by address on a home network has no stable name to verify
anyway.

### Where a fingerprint comes from

Always from the connection, via `peer_certificate_fingerprint`. Never from a message
body, and never from the endpoint-wide `ObservedPeer` — that value is shared by every
concurrent handshake on a listener, so reading it could attribute one client's
certificate to another.

## Channels

One bidirectional QUIC stream per channel. The opener writes a single byte naming the
channel before any frame; the accepting side reads it and knows what the stream is
before parsing anything.

| Channel | Byte | Frame ceiling | Carries |
|---|---|---|---|
| Control | 1 | 256 KiB | Handshake, admission, requests |
| File transfer | 3 | 8 MiB | Directory listings, chunks |
| Video | 4 | 16 MiB | Encoded frames |
| Input | 5 | 256 KiB | Mouse and keyboard events |
| Metrics | 6 | 256 KiB | Periodic system metrics |

Frames are `RC` magic, channel byte, and a big-endian `u32` length, then a postcard
body. The ceiling is checked **from the header**, before the body is allocated, so an
oversized length is refused without the allocation ever happening. A reader
additionally caps how much unparsed data it will buffer, so a peer that sends a valid
header and then stalls cannot make it hold memory.

## Opening a connection

The first message on a control stream states what the connection is for:

```
Opening::Hello(..)     a machine asking for a session
```

A single-variant enum rather than a bare struct, on purpose. Postcard is not
self-describing, so a second kind of opening added later would be indistinguishable
except by attempting two decodes -- and which branch succeeded would be chosen by the
peer rather than by the responder. The discriminant costs one byte and keeps that door
shut.

## Session handshake

```
initiator                                     responder
  |---- Opening::Hello ------------------------>|
  |        version, role, descriptor,           |- version and role checks
  |        capabilities, timestamp              |
  |<--- HelloAck -------- or ---- Reject -------|
  |        negotiated version, and nothing else |
  |---- Authenticate --------------------------->|
  |        dialled address,                     |- fingerprint from *this* connection
  |        unattended password (optional)       |- admission decision
  |<--- SessionAuthorization -------------------|
  |        Granted { permissions, descriptor,   |
  |                  capabilities, session id } |
  |        or Refused { reason }                |
```

Version negotiation: majors must match exactly, and the two settle on the lower minor.
A differing major is refused rather than approximated.

The exchange is split into two legs so the password travels **after** the peer has been
seen. A secret does not belong in `Hello`, which is sent before the initiator knows what
it is talking to.

The handshake deadline applies to each leg separately rather than once for the whole
exchange, so a peer that is merely slow to decide on a password is not penalised for
time already spent.

### `HelloAck` carries the version and nothing else

It is sent before the admission decision, to anyone who completes TLS. Since the
listener is trust-on-first-use, that is anyone who can reach the port.

Everything identifying the responder -- its name, hostname, OS version, application
version, device id, capabilities and the session id -- travels on
`SessionAuthorization::Granted`, which only an admitted peer receives. A refused peer
learns that it was refused and nothing about what it reached.

Adding a field to `HelloAck` moves it from "disclosed to admitted peers" to "disclosed
to anyone who can reach the port".

### Refusals are coarse on the wire

`WireRefusal` has three values: `NotAccepting`, `IdentityChanged` and `Rejected`. A
dismissal, a wrong unattended password and a lockout are all `Rejected`, because
distinguishing them would tell a caller whether unattended access is configured and
whether its guesses were landing.

The responder's own five-way reason is recorded locally and never serialised. See
[`access-model.md`](access-model.md).

### Permissions on the wire

`SessionAuthorization::Granted` carries `WirePermissions`, a `u8` bitset mirroring
`PermissionSet`. A bit this build does not recognise is **refused, not masked**:
silently dropping an unknown permission would make the same wire value mean different
things on either side of the connection.

It is a separate type from `PermissionSet` because `rc-security` already depends on
`rc-protocol`, so the protocol crate depending back would be a cycle. `rc-transport`
depends on both and converts at the boundary.

### The session id is not a credential

It exists so both peers and both logs name the same session. It authorizes nothing:
authentication is the mutually-authenticated TLS connection, which cannot be
transplanted. Presenting a session id over a different connection achieves nothing.

## Why admission is separate from TLS

TLS answers *which key is on the other end*. It cannot answer *may that key have a
session*, because in this design that is a decision the machine being controlled makes
-- usually by asking its user.

A connection that trusted the TLS result alone would admit whoever completed a handshake
with a self-signed certificate, which is a remote-control agent with no authorisation at
all. So the decision is made per connection, after `Authenticate`, from the fingerprint
the TLS verifier observed.

## The dialled address, not the socket address

`Authenticate` carries the address the user typed. The responder keys its pinned
identities on that string.

It is carried rather than read off the QUIC connection because the peer's remote socket
address has an ephemeral source port: keying on it would make every reconnection look
like a new, unpinned peer, so the pin would never match and a changed certificate would
fall through to the human dialog.

## Discovery

There is none. A machine is reached by typing the address it displays.

mDNS was removed: it announced the presence of the application to everyone on the
network, and its only benefit was saving the user from reading an address off a screen
-- which is the interaction this product is built around anyway.

## Connecting: which address is tried

The address the user typed, resolved. A hostname may resolve to several addresses; all
are tried in the order the resolver returned them, because the first is not reliably the
reachable one.

A refusal ends the attempt rather than moving to the next address: it is a decision by
the machine on the other end, and the same machine answers on every address it has.

## Timeouts

| Timeout | Value | Why |
|---|---|---|
| Connection attempt | 8 s | Long enough for a slow link, short enough to try the next address |
| Application handshake | 15 s | A peer past TLS that says nothing holds agent resources |
| Accept dialog | 30 s | A human is deciding; an unattended machine closes its own door |
| QUIC idle | 30 s | Survives a Wi-Fi handover; notices a dead peer before the operator does |
| QUIC keep-alive | 10 s | Under the idle timeout, and under most home routers' NAT rebinding window |
| Session idle | 30 min | A session left open on an unattended desk is one someone else can use |

## Ports

| Port | Protocol | Bound to | Purpose |
|---|---|---|---|
| 7443 | UDP | Configurable, `0.0.0.0` by default | The QUIC listener for incoming connections |
| 47813 | TCP | `127.0.0.1`, not configurable | The standalone service's health endpoint |

The health endpoint's address is deliberately not configurable, so no configuration
mistake can put an unauthenticated route on the network.

On Windows, the first run with incoming connections enabled raises the firewall prompt.
It is left to appear rather than being pre-authorised by an installer: a remote-access
application that silently opens a port is doing the thing the prompt exists to reveal.
