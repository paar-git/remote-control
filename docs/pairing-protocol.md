# Pairing protocol

How two devices that have never met establish mutual, long-lived trust, using a short
code the operator carries out-of-band.

Implemented in `crates/security/src/pairing/`. This document describes the protocol as
built; the module documentation carries the same detail alongside the code.

## Why pairing exists

The agent and the client authenticate each other with self-signed, fingerprint-pinned
certificates. Self-signed means there is no certificate authority to appeal to, so the
very first exchange has to establish which fingerprint is the right one. That is what
pairing does, and it is the only moment in the system's life where trust is created
rather than checked.

The out-of-band channel is the operator: they read a code off the server's console and
type it into the client. An attacker on the network does not see it.

## The exchange

```text
 Operator                Agent                                   Client
    │                      │                                        │
    │  starts pairing ────►│  begin_pairing()                       │
    │◄── code shown ───────│  generates code, stores only verifier  │
    │                      │                                        │
    │──────────────── types the code ───────────────────────────────►
    │                      │                                        │
    │                      │◄── 1. ClientIdentityClaim ─────────────│
    │                      │                                        │
    │                      │─── 2. PairingChallenge ───────────────►│
    │                      │    (agent identity, nonce, salt)       │
    │                      │                                        │
    │                      │            both sides build the same transcript
    │                      │                                        │
    │                      │◄── 3. ClientProof ─────────────────────│
    │                      │    (MAC + Ed25519 signature)           │
    │                      │                                        │
    │                      │─── 4. AgentConfirmation ──────────────►│
    │                      │    (MAC + Ed25519 signature)           │
    │                      │                                        │
    │                  records trust                          pins agent identity
```

### Why each step exists

| Step | Purpose |
|---|---|
| **Claim** | Binds the client's device id to its public key. The id is *derived* from the key, so a client cannot claim an identity it does not hold. |
| **Challenge** | Gives the client the agent's fingerprints and the verifier salt. Nothing secret is disclosed — without the code, the salt is useless. |
| **Proof** | Two independent assertions: a MAC keyed by the code verifier (the operator's code was entered correctly) and an Ed25519 signature (the client holds the key behind its claimed fingerprint). Either alone would be insufficient. |
| **Confirmation** | Proves the *agent* also knew the code and holds the key behind the fingerprint the client is about to pin. This is what stops an attacker who guessed the code from impersonating the server. |

## Pairing codes

Nine characters from a 30-symbol alphabet, displayed as `XXX-XXX-XXX`.

* **Alphabet**: `23456789ABCDEFGHJKMNPQRSTVWXYZ`. Digits `0`/`1` and letters `I`/`L`/`O`/`U`
  are excluded — they are the pairs people actually mistype reading a code off a console.
* **Entropy**: 30⁹ ≈ 2×10¹³, about **44 bits**.
* **Parsing**: case-insensitive, separators ignored. Characters outside the alphabet are
  rejected with a clear message rather than silently folded, because a silent mapping
  could turn one valid code into another.

44 bits is not enough on its own. It is enough *in combination with* the controls around
it: a 3-minute default window, a hard cap of 5 attempts, and single-use consumption. An
online attacker gets 5 guesses out of 2×10¹³ before the code is destroyed.

### Storage

The raw code is **never stored**. What is persisted is `verifier = Argon2id(code, salt)`
with a per-code random salt, so:

* Reading the database does not yield a usable code.
* Recovering a live code from a stolen database means running Argon2id at production
  cost over a 44-bit space — expensive, and pointless after three minutes.

The verifier is also what keys the pairing MAC, so the agent never needs to retain the
raw code after displaying it.

### Display

`PairingCode` implements neither `Serialize` nor `Display`, and its `Debug` is redacted.
The only way to obtain the characters is `expose_for_display()`, named so that every call
site is obvious in review. It is called exactly once, by the `pair` subcommand, writing
to the operator's own console. The code never reaches a log, an audit record, or the
network.

## The transcript

Both peers independently build a byte string committing to every value that matters, then
prove they can key a MAC over it. Anything that differs between the two — a swapped
fingerprint, an edited permission role, a different expiry, a downgraded protocol version
— produces a different transcript and therefore a proof that does not verify.

```text
"rc.pairing.transcript.v1"
  || len||protocol_major  || len||protocol_minor
  || len||pairing_session_id
  || len||agent_device_id        || len||client_device_id
  || len||agent_identity_fp      || len||client_identity_fp
  || len||agent_certificate_fp   || len||client_certificate_fp
  || len||agent_nonce            || len||client_nonce
  || len||code_verifier
  || len||expires_at_ms
  || len||requested_role
  || len||requested_capabilities (sorted, comma-joined)
```

Every field is written as a `u64` big-endian length followed by its bytes, in fixed order.
**Length-prefixing is essential**: with naive concatenation, moving a character from one
field into the next leaves the bytes unchanged, which would let an attacker shift meaning
between fields without altering the proof.

### Domain separation

Three distinct labels are derived from the transcript, so no value produced for one
purpose can be replayed as another:

| Label | Used for |
|---|---|
| `rc.pairing.v1.mac` | deriving the MAC key from the code verifier |
| `rc.pairing.v1.client-proof` | the client's MAC and Ed25519 signature |
| `rc.pairing.v1.agent-proof` | the agent's MAC and Ed25519 signature |

The client's and agent's proofs are therefore *different values over the same transcript*.
An attacker who observes the client's proof cannot echo it back as the agent's
confirmation.

### Why this resists relaying

An attacker who forwards messages between a real client and a real agent cannot make both
sides agree, because the transcript names both endpoints' certificate fingerprints, and
the attacker's own TLS connection to each side carries a different one.

## Security properties and what enforces each

| Property | Enforced by |
|---|---|
| Expiry | `PairingSession::refresh` against an injected clock |
| Single use | atomic `Challenged → Consumed` under one mutex |
| Attempt cap | failure counter, terminal `AttemptsExhausted` state |
| No replay across sessions | session id and both nonces in the transcript |
| No relay to another endpoint | both certificate fingerprints in the transcript |
| No permission tampering | requested role and capabilities in the transcript |
| No downgrade | protocol version in the transcript, floor in `Transcript::build` |
| Raw code never stored | only `Argon2id(code, salt)` is retained |
| Not an oracle | wrong code and wrong transcript both yield `ProofRejected` |

### Atomicity

Consumption happens under a single mutex covering the state check and the state change.
Eight threads racing with an identical valid proof produce exactly one success — this is
asserted by a test, not assumed.

### No downgrade

Pairing establishes *long-lived* trust, so it refuses to negotiate downwards. A peer
offering an older major version than `MIN_PAIRING_VERSION` is rejected rather than
accommodated.

### Not an oracle

A wrong code and a well-formed proof over a wrong transcript both return the identical
`ProofRejected` error. An attacker cannot use the error to learn which part they got
wrong.

## Session lifetime

Pairing sessions live **in memory only** and die with the process. This is deliberate: a
code that survives a restart is a code whose window the operator has lost track of.

On startup the agent sweeps `pairing_code` rows still marked `open` and records them as
`expired`, so the persisted trail never implies a live code that no longer exists.

## What Phase 3 must preserve

The transport does not get to relax any of this.

1. **The certificate fingerprints in the transcript must be the ones actually observed on
   the TLS connection**, not values copied from the message body. If Phase 3 fills them in
   from what the peer *claims*, the anti-relay property is lost entirely.
2. **Revocation must be re-checked on every connection**, against the repository, not
   against cached frontend state.
3. **`complete_pairing` is the only sanctioned completion path.** It records trust before
   returning the confirmation, so a client can never believe it is paired while the agent
   has no record of it.
4. **Pairing must not be reachable without the operator having opened a window.** There is
   no ambient pairing endpoint; a session must exist first.
5. The proof must never be logged in full. The audit trail records a short transcript
   digest for correlation, which is not enough to reconstruct the exchange.
