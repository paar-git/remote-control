# Privileged operations

How the agent restarts a service or shuts a machine down without itself being able to run
arbitrary code as root.

## Why there are two processes

The agent is the process exposed to the network — the one an attacker reaches first. It
needs to *cause* a handful of privileged operations. It does not need the ability to do
anything else with those privileges.

So privilege is split. The agent runs unelevated and asks; a small helper runs elevated
and decides.

```
  client ──QUIC──► rc-agent ──loopback JSON──► rc-privileged-helper ──► (program, argv)
                 (unelevated)                    (LocalSystem / root)
                        │                              │
                   asks for an                   re-validates and
                   operation                     resolves it itself
```

Compromising the agent yields the ability to *request* operations from a closed list. It
does not yield the ability to run arbitrary code as root.

## The rule the design rests on

> **The helper re-validates every request against the allowlist itself.**
> It never trusts that its caller already did.

The agent validates too — `PrivilegedClient::power` and `PrivilegedClient::service` refuse
a protected service without a round trip, so an operator gets an immediate answer. That
check is a convenience. The helper's check is the control. If `client.rs` were deleted
entirely, nothing about what the helper permits would change.

This is enforced by tests that deliberately bypass the client: every refusal test in
`crates/privileged/tests/split_e2e.rs` sends raw bytes to the socket, because that is what
a compromised agent could do.

## An operation crosses the wire, never a command

A request names a `PowerAction`, or a service name plus a `ServiceAction`. There is no
field for a program, an argument vector or a shell string — so there is nothing for an
injection to inject into. A request shaped like `{"program":"/bin/sh","args":["-c","id"]}`
does not parse as an operation at all.

The resolution from operation to `(program, argv)` happens inside the helper, from
constants in `rc_platform::privileged`. Every path through it:

1. Validates the service name (`validate_service_name`).
2. Consults the protected-services deny-list (`is_protected_service`).
3. Returns a fixed program with an explicit argument vector.

The only caller-supplied value that ever reaches an argv element is a service name, and by
then it has survived steps 1 and 2. Arguments are passed as separate values, so quoting,
`&&`, `|`, `;`, `$(…)` and newlines are inert data rather than syntax.

A malformed name and a protected service return the **identical** error. Distinguishing
them would tell a caller which services exist on a host it was just refused access to.

## Authorization is a file

The helper generates a fresh 32-byte token at every start and writes it to
`<data-dir>/privileged-helper.token`, using the same atomic, mode-0600 write the keystore
uses. The agent reads it and presents it with each request; the helper compares in constant
time.

Being able to read that file **is** the authorization. The operating system's permissions
make the access decision; the token only carries it over a socket. This is deliberately the
same model as the agent's own local control endpoint: the set of callers that can request a
privileged operation is exactly the set that could already read the agent's keystore.

The token is regenerated on every start and removed on shutdown, so a copy taken from a
previous run is useless.

**The installer must create the data directory such that only the agent's account and
administrators can read it.** On Unix this is a `0700` directory; on Windows it is an ACL
grant to the agent's service account and `Administrators`, with inheritance broken. Getting
this wrong is the one deployment mistake that defeats the split — anyone who can read the
token can ask for any operation on the list.

## The socket

Loopback only, on `127.0.0.1`, at `DEFAULT_PRIVILEGED_PORT` (47814). The address is not
configurable, so no configuration mistake can put a privileged endpoint on the network.
Only the port can be changed, and only to another port above 1023 that does not collide
with the agent's own.

Bounds, so a local process that can reach the port cannot exhaust the helper:

| Bound | Value | Why |
|---|---|---|
| Request size | 8 KiB | A request is a few hundred bytes. A larger read would be an allocation chosen by whoever connected. |
| Request deadline | 10 s | A connection that opens and says nothing holds a slot. |
| Command deadline | 60 s | A service restart can be slow; neither it nor a hung command may hold the helper forever. |

Command output is not captured. It would carry operating-system text into the agent's log
and from there to a client, and there is nothing in it the operator needs that the exit code
does not already say.

## Running with no helper

**A helper is optional.** Setting `network.privileged_port = 0` states that none is
installed.

With no helper — or with one that is configured but does not answer — the agent does not
advertise `service_management` or `power_control` in its capabilities at all. The client
therefore never offers a button for them. A capability advertised but unavailable is a
button that fails when pressed.

The agent probes the helper once at startup with a `Ping` rather than assuming a token file
means a working helper, and logs the outcome:

| Situation | Logged as | Effect |
|---|---|---|
| `privileged_port = 0` | info | Capabilities withheld |
| Token unreadable | warning | Capabilities withheld |
| Helper does not answer | warning | Capabilities withheld |
| Running, not elevated | warning | Capabilities withheld |
| Running and elevated | info | Capabilities advertised |

An operator finds out here, at startup, rather than when a power button does nothing.

## Installing the helper

```
rc-privileged-helper --data-dir <the agent's data directory> [--port 47814]
```

Install it as a **Windows service running as `LocalSystem`**, or a **systemd unit running as
root**. It must start before the agent, or the agent's startup probe will find no token and
withhold the capabilities until it is restarted.

The helper refuses to start if the data directory does not exist; it does not create it,
because creating it would mean choosing its permissions, and that choice belongs to the
installer that knows the agent's account.

## Status

Built and tested: the transport, the token, the allowlist re-validation, the capability
gating and the startup probe. The service and power *handlers* on the agent's control
channel arrive with Phase 7 — the helper is reachable and proven, but nothing in the UI
calls it yet.

Not yet built: an audit record on the agent side for each privileged request (the helper
logs every one), and installer packaging for either platform (Phase 9).

## Related

- [`threat-model.md`](threat-model.md) — where this sits among the trust boundaries.
- [`permission-model.md`](permission-model.md) — the application-level capabilities, which
  are a separate question from OS privilege and never become it.
- [`keystore-format.md`](keystore-format.md) — the same file-protection model, applied to
  the device key.
