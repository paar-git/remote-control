# Network protocol

How a client and an agent find each other, authenticate, and hold a session.

## Transport

QUIC over UDP, with mutually-authenticated TLS 1.3 and ALPN `rc/1`. Default port
**47811/UDP**.

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
name, and an agent reached through a coordinator has no stable name to verify anyway.

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
| Control | 1 | 256 KiB | Handshake, pairing, requests |
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
Opening::Hello(..)     a device that claims to be trusted already
Opening::Pairing(..)   a device that wants to run the pairing exchange
```

This is a tag rather than something inferred. Postcard is not self-describing, so
"try decoding as A, else as B" would frequently succeed either way — and which branch
the agent took would be chosen by the peer rather than by the agent.

## Session handshake

```
client                                        agent
  │──── Opening::Hello ────────────────────────►│
  │        version, role, descriptor,           ├─ fingerprint from *this* connection
  │        capabilities, timestamp              ├─ TrustDirectory lookup (live)
  │                                             ├─ revoked?      → refuse
  │                                             ├─ id mismatch?  → refuse
  │◄──── HelloAck ─────── or ──── Reject ───────│
  │        negotiated version, session id,      │
  │        capabilities, idle timeout           │
```

Version negotiation: majors must match exactly, and the two settle on the lower minor.
A differing major is refused rather than approximated.

**Every refusal looks identical on the wire** — `RejectReason::NotAuthorized`. Unknown,
revoked and fingerprint-changed are recorded distinctly in the agent's own audit trail
and are indistinguishable to the peer, so the port cannot be used to enumerate which
devices an agent knows.

### The session id is not a credential

`HelloAck` carries a `SessionId`. It exists so both peers, the audit trail and the
operator's session list name the same session. It authorizes nothing: authentication is
the mutually-authenticated TLS connection, which cannot be transplanted onto another
connection. Presenting a session id over a different connection achieves nothing.

## Why authorization is separate from TLS

TLS answers *which key is on the other end*. It cannot answer *is that key still
trusted*, because revocation happens in a database minutes or months after a
certificate was pinned.

A connection that trusted the TLS result alone would notice a revocation only if the
certificate happened to change — which is to say, never. So the agent performs a fresh
trust lookup, against the authoritative store, on **every** connection.
Implementations of `TrustDirectory` must not cache.

## Discovery

mDNS, service type `_remotectl._udp.local.`. The agent publishes a TXT record with its
device id, display name, identity fingerprint and protocol major.

**Nothing announced is trusted.** Anyone on the network can broadcast a record claiming
any device id. A discovered address is only ever a hint about where to dial; the
connection that follows pins the agent's certificate, so a spoofed announcement costs
one failed dial and nothing more. A discovered device is never added to the trusted list
and a discovered fingerprint is never pinned.

Discovery can be turned off, and being unable to discover never prevents connecting: the
last successful address, a configured endpoint and a typed address all still work.

## Connecting: which address is tried

In order, stopping at the first that works:

1. The address the last successful connection used.
2. An address discovered over mDNS for this device id.
3. The operator-configured endpoint.

The saved address comes first because on a home network it is nearly always still right,
and trying it first avoids a discovery round trip on every connect.

## Timeouts

| Timeout | Value | Why |
|---|---|---|
| Connection attempt | 8 s | Long enough for a slow link, short enough to try the next address |
| Application handshake | 15 s | A peer past TLS that says nothing holds agent resources |
| Pairing step | 60 s | A human is typing a code somewhere in this loop |
| QUIC idle | 30 s | Survives a Wi-Fi handover; notices a dead peer before the operator does |
| QUIC keep-alive | 10 s | Under the idle timeout, and under most home routers' NAT rebinding window |
| Session idle | 30 min | A session left open on an unattended desk is one someone else can use |

## Ports

| Port | Protocol | Bound to | Purpose |
|---|---|---|---|
| 47811 | UDP | Configurable, `0.0.0.0` by default | The agent's QUIC listener |
| 47813 | TCP | `127.0.0.1`, not configurable | The agent's local health and control endpoint |
| 47812 | TCP | Configurable, loopback by default | The optional coordination server |

The local endpoint's address is deliberately not configurable, so no configuration
mistake can put an unauthenticated route on the network.
