# Reconnection

What happens when a connection ends, and — more importantly — when it must *not* come
back on its own.

## The rule

**Automatic reconnect happens only after an accident.**

Pressing Disconnect sets a flag that every retry path checks. Without it, Disconnect
would be a button that disconnects for half a second, which is worse than no button at
all.

Two further cases must not retry, for a different reason. A **refusal** and an
incompatible peer both fail for reasons that retrying cannot fix. Retrying them would
turn a loud, visible failure into a quiet loop that nobody sees, which is precisely the
failure mode a fingerprint mismatch exists to make noisy.

A refusal now arrives as `TransportError::SessionRefused`, carrying a `WireRefusal`.
**No value of it is ever retried**, and that is deliberate for each one:

- `Rejected` means a person said no, a password was wrong, or the address is locked out.
  Retrying a refusal by a human is pestering them; retrying a wrong password walks into
  the lockout; and the three are indistinguishable here by design, so the safe reading
  of an ambiguous value is the one that does not retry.
- `NotAccepting` means the other machine has incoming connections switched off. Nothing
  changes until someone turns them on.
- `IdentityChanged` is the loudest failure this application has. Retrying it would
  reduce an active-attacker signal to a background hum.

`TransportError::permits_auto_reconnect` is the single place that distinction is
decided.

| Situation | Retried automatically? |
|---|---|
| Network dropped, the other machine restarted, handshake timed out | yes |
| The address did not resolve | yes |
| The operator pressed Disconnect | **no** |
| The connection was refused, for any reason | **no** |
| The other machine presented a different identity | **no** |
| Protocol or version mismatch | **no** |
| The other machine is rate-limiting this one | **no** |
| The address is malformed | **no** |
| The other machine sent a permission this build does not know | **no** |

A name that does not resolve **is** retried, which looks like an exception and is not.
Resolution runs fresh on every attempt, so a machine that went to sleep and a resolver
that blipped both produce exactly the same error as a permanently bad name — and both
heal without anyone touching anything. Filing it as permanent would mean a saved machine
that went to sleep stopped being reachable until the operator intervened, with nothing
mistyped and nothing wrong. A *malformed* address is permanent, because that text does
not change between attempts.

## Connection states

The client reports a precise state rather than a spinner, because "reconnecting,
attempt 3" and "the server refused this device" call for completely different responses
from the operator.

```
  Offline ──connect──► Connecting ──► Authenticating ──► Connected
     ▲                      │                │               │
     │                      └────────────────┘               │
     │                            failure                    │
     │                               │                       │
     │                   ┌───────────┴────────────┐          │
     │                   │                        │          │
     └────── refused ────┘              WaitingToRetry ◄──lost┘
        (identity changed,                  │
         not accepting, rejected)           └──► Reconnecting ──► …
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
- **Interrupted file transfers may resume**, because a transfer is idempotent by
  construction: it has a checksum, an offset, and a defined result.
- **The permission grant is not carried over.** A reconnection is a new admission
  decision, so the new session holds what that decision granted and not what the
  previous one held. The grant is cleared the moment the connection leaves the connected
  state.

## The decision is made again, every time

A reconnect is a new connection and goes through the whole handshake, including the
admission decision. The identity is observed again and checked against the pin again.

This is what makes withdrawing access immediate. A machine whose pin is removed while it
is connected is asked about again on its very next attempt, and one whose identity
changed is refused outright rather than being handed to the dialog.

It also means the permissions can differ between one session and the next, because a
different human may answer differently. Nothing caches the previous answer.

## Where it reconnects *to*

The same address that was dialled. There is no discovery and no configured endpoint to
fall back to: a machine is reached by the address its user read off their screen, and if
that address changed, its user has to say so.

## Known limitation

The reconnect policy, the backoff and the intentional-disconnect suppression are
implemented and tested, and the client exposes a Reconnect action. What does not yet
exist is a background supervisor that notices a dropped connection and starts the loop
without being asked. Until that lands, an accidental drop is visible in the UI and
reconnecting is one click.
