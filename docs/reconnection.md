# Reconnection

What happens when a connection ends, and — more importantly — when it must *not* come
back on its own.

## The rule

**Automatic reconnect happens only after an accident.**

Pressing Disconnect sets a flag that every retry path checks. Without it, Disconnect
would be a button that disconnects for half a second, which is worse than no button at
all.

Two further cases must not retry, for a different reason. A refused connection —
unknown device, revoked device, changed identity — and an incompatible peer both fail
for reasons that retrying cannot fix. Retrying them would turn a loud, visible failure
into a quiet loop that nobody sees, which is precisely the failure mode a fingerprint
mismatch exists to make noisy.

`TransportError::permits_auto_reconnect` is the single place that distinction is
decided.

| Situation | Retried automatically? |
|---|---|
| Network dropped, agent restarted, handshake timed out | yes |
| The operator pressed Disconnect | **no** |
| The agent refused this device | **no** |
| The agent presented a different certificate | **no** |
| Protocol or version mismatch | **no** |
| The agent is rate-limiting this client | **no** |

## Connection states

The client reports a precise state rather than a spinner, because "reconnecting,
attempt 3" and "the server refused this device" call for completely different responses
from the operator.

```
  Offline ──connect──► Discovering ──► Connecting ──► Authenticating ──► Connected
     ▲                      │              │                │               │
     │                      └──────────────┴────────────────┘               │
     │                                   failure                            │
     │                                      │                               │
     │                          ┌───────────┴────────────┐                  │
     │                          │                        │                  │
     └────── refused ───────────┘              WaitingToRetry ◄─────lost ────┘
        (identity changed,                        │
         revoked, not paired)                     └──► Reconnecting ──► …
```

## Backoff

Exponential, doubling from 500 ms to a 30-second ceiling, with **full jitter** — the
delay is drawn uniformly from `[0, capped]` rather than from the upper half.

The jitter is not politeness. Without it, a client and an agent that restart together
retry in lockstep indefinitely, and several clients on one network synchronise their
retries into a thundering herd against a machine that is already struggling. Halving
the range instead of using the full one keeps a synchronised herd synchronised, just
more slowly.

Ten attempts by default, after which the client stops and says so. `0` means keep
trying.

## What is *not* replayed

Reconnecting re-establishes a connection. It does not re-run what the previous session
was doing.

- **Destructive and privileged commands are never repeated automatically.** A power
  action, a service stop or a process kill that was in flight when the link dropped is
  not retried; the operator issues it again if they still want it.
- **Terminal input is never resent.** A half-delivered command line reaching a shell
  twice is its own kind of disaster.
- **Interrupted file transfers may resume**, because a transfer is idempotent by
  construction: it has a checksum, an offset, and a defined result.

## Identity is verified again, every time

A reconnect is a new connection and goes through the whole handshake: the certificate
is pinned again, and the agent performs a fresh trust lookup against its database.

This is what makes revocation immediate. A device revoked while it was connected is
refused on its very next attempt, without waiting for a cache to expire or for either
side to restart.

## Where the client reconnects *to*

The same order as a first connection: the last address that worked, then discovery,
then the configured endpoint. A server that changed address after a power cut is found
by discovery on the second candidate.

## Known limitation

The reconnect policy, the backoff and the intentional-disconnect suppression are
implemented and tested, and the client exposes a Reconnect action. What does not yet
exist is a background supervisor that notices a dropped connection and starts the loop
without being asked. Until that lands, an accidental drop is visible in the UI and
reconnecting is one click.
