# Terminal architecture

How a keystroke in the client reaches a shell on the server, and how its output comes
back.

## The path

```
  xterm.js  ──► Tauri command ──► terminal channel ──► TerminalService ──► PTY ──► shell
  (client)          (IPC)            (QUIC stream)        (agent)
     ▲                                                                            │
     └──── Tauri event ◄──── terminal channel ◄──── reader thread ◄────────────────┘
```

Bytes cross unaltered in both directions. Nothing along this path parses, rewrites or
interprets the stream — which is exactly why colours, line editing, interactive prompts
and full-screen programs work without any of it knowing they exist.

## A pseudo-terminal, not a pipe

The agent allocates a real PTY: ConPTY on Windows, `openpty` on Unix, through
`portable-pty`.

This is not an implementation detail. A program behaves differently when it detects a
terminal: it enables colour, enables line editing, draws prompts, and buffers by line
rather than by block. Running a shell on pipes produces something that looks superficially
similar and then fails on the first `sudo` password prompt, the first `less`, and the
first progress bar.

A consequence worth stating: **a PTY has one output stream.** stdout and stderr are
merged by the kernel before anything can separate them. The protocol therefore carries
one stream, and a client that wanted them apart could not have them without giving up
everything above.

## The client must answer the shell's questions

A shell interrogates its terminal before it will draw a prompt. The most visible is
`ESC[6n` — *where is the cursor?* — to which a terminal replies `ESC[row;colR`.

A client that does not answer leaves the shell waiting forever, and the session looks
like it hung during startup. This is not hypothetical: it is what happens, on the first
connection, every time.

xterm.js answers these as part of processing the stream. That is the reason the client
uses a real terminal emulator rather than rendering the bytes into a `<pre>` with escape
codes stripped — the stripped version would look like a terminal until the moment it was
asked to be one.

## Shells are chosen by kind, never by path

The client asks for `PowerShell`, `Cmd`, `Bash` or `SystemDefault`. The agent resolves
that to a program on the host.

A field that accepted a path would be an arbitrary-program-execution API wearing a
terminal's clothes: the capability check would read "may open a terminal" and the effect
would be "may run any program on the server". Keeping the choice to a closed set means
the worst a client can do with this API is get a shell — which is what the capability
grants.

Inside the shell the operator can of course run anything. The difference is that the
session is *recorded as a terminal session* rather than as an opaque command, and the
audit trail says which program was launched.

## Threads, not tasks

Reading a PTY blocks, and there is no portable async equivalent. Each session gets one
blocking reader thread that pushes into a bounded channel; the async side reads that.

Polling with a timeout from an async task would either burn CPU while idle or add latency
to every keystroke. A parked thread costs a stack.

## Backpressure

The output channel is bounded. A shell printing faster than the network can carry it
blocks its reader thread rather than growing a buffer.

That is the correct behaviour: the alternative is an agent whose memory use is decided by
whatever the operator happened to `cat`.

Input is bounded too. A quarter of a megabyte is a generous paste; a megabyte of
"keystrokes" is not a paste, it is an attempt to make the agent allocate.

## Sessions never outlive their connection

The terminal registry belongs to the connection handler. When the connection ends —
cleanly, or because the network dropped, or because the client crashed — the registry is
dropped, and dropping it kills every shell it holds.

`TerminalSession` also kills its child in `Drop`, so there is no path out of a session,
including a panic, that leaves a shell running.

Without this, closing a laptop lid would leave shells running on the server indefinitely,
and the operator would have no way to see or stop them.

## Authorization is re-checked per message

`Capability::Terminal` is checked before a PTY is spawned **and** before every message
that touches an existing one.

Checking only at open would mean a device revoked mid-connection kept its shell — which
is precisely the state revocation exists to prevent.

## Signals

Ctrl+C is delivered as the control character `0x03` written to the terminal, not as a
process signal to the shell.

This matters: signalling the shell would kill the shell. Writing ETX to the terminal lets
the shell's own line discipline interrupt whatever it is running, which is what Ctrl+C
means to the person pressing it.

`Kill` is the exception, and is explicit: it ends the session and reaps the child.

## What is never recorded

Terminal input and output. Not in the log, not in the audit trail, not in application
state, not in the database.

A terminal is where passwords are typed and where secrets are printed. The audit trail
records that a terminal was opened, which program it launched, and when it closed — not
what happened inside it.

## Limits

| Limit | Value | Why |
|---|---|---|
| Terminals per connection | 8 | A client wanting more opens a second connection, which is visible in the session list |
| Output chunk | 16 KiB | Large enough not to fragment a burst, far inside the channel ceiling |
| Queued output chunks | 64 | Bounded; see backpressure |
| Input per message | 256 KiB | A generous paste, not an allocation vector |
| Terminal grid | 2–1000 cells | Clamped rather than refused, so a maximised window still resizes |

## Not implemented

**Elevated sessions.** Requesting one is refused with a specific error rather than
silently downgraded — opening an unprivileged shell and labelling it elevated would be
considerably worse than saying no. The privileged-agent split that would provide this is
Phase 4's remaining work; see `PROGRESS.md`.

**Reconnecting to an existing terminal.** A dropped connection ends its sessions. Keeping
a PTY alive across reconnects means keeping a shell running with nobody watching it,
which needs an explicit lifetime and an explicit way for the operator to see and end
orphaned sessions before it is safe to offer.
