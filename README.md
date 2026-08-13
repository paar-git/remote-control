# Remote Control

Private remote access between machines **you own**. You type an address, the person at
the other machine clicks Accept, and you are connected. No account, no sign-in, no
third-party cloud in the path.

> **Status: the access model is built; the remote display is not.** Two machines can
> find each other by address, admit each other by a human clicking Accept or by an
> unattended password, and hold a session with file transfer and system monitoring over
> it. There is no screen capture and no input injection yet, and the session screen says
> so rather than showing an empty frame. See [`PROGRESS.md`](PROGRESS.md) for exactly
> what works today.

## Design in one paragraph

One program is both sides. It listens for incoming connections and it makes outgoing
ones, and the same binary does both — there is no separate agent to install and no
client to pair with it. Two machines authenticate each other with mutually-authenticated
TLS 1.3 over QUIC using self-signed certificates, and then, because completing TLS
proves only *which key* is on the other end, the machine being connected to makes a
separate admission decision: a pinned identity it already trusts, an unattended password
its owner set, or a person clicking Accept. What that session may then do is fixed at
admission and re-checked on every single request.

## Repository layout

```text
.
├─ apps/
│  └─ desktop-client/          Tauri 2 + React + TypeScript application
│     └─ src-tauri/            Its backend: connections in and out
├─ crates/
│  ├─ protocol/                Wire protocol, framing, limits, replay guard
│  ├─ security/                Identity, keystore, passwords, permissions
│  ├─ transport/               QUIC, mutual TLS, the handshake, addresses
│  ├─ storage/                 SQLite schema, migrations, repositories
│  ├─ platform/                OS abstraction: paths, host facts, addresses
│  ├─ monitoring/              System metrics collection
│  ├─ file-transfer/           Chunked, resumable transfers
│  ├─ updater/                 Signed release manifests and installation
│  └─ host-agent/              The admission decision, and a standalone service
├─ packages/
│  └─ shared-types/            Zod mirror of the protocol
├─ installers/                 Windows and Linux packaging
├─ docs/                       Access model, threat model, protocol
└─ scripts/                    Verification and development helpers
```

`crates/host-agent` is both a library and a binary. The library holds the admission rule
and the session server, and the desktop application depends on it so that the two cannot
drift into deciding differently. The binary is a headless service for a machine with
nobody sitting at it, where every connection request is dismissed unless an unattended
password or a pin admits it.

## Requirements

| Tool | Version used | Notes |
|---|---|---|
| Rust | 1.96 (edition 2024) | `rustup` installs the pinned toolchain automatically |
| Node | ≥ 20.19 | 24.x verified |
| pnpm | 11.x | `packageManager` field pins it |
| MSVC Build Tools | 2022 | Windows only, for linking |
| WebView2 | current | Windows only, preinstalled on Windows 11 |

TypeScript is pinned to **5.9**, not 7.x: `typescript-eslint` currently requires
`typescript <6.1.0`.

## Getting started

```bash
pnpm install

# Everything: format, lint, typecheck, JS tests, clippy, Rust tests
pnpm verify
```

### Run the application

```bash
pnpm --filter @rc/desktop-client tauri:dev
```

Opening `http://127.0.0.1:1420` in a browser instead will show an explicit
"backend unavailable" message — the UI has no mock mode.

The window shows the addresses this machine can be reached on. Type one of them into
another machine's window and press Connect; a dialog appears here asking whether to
allow it, and what it may do.

On Windows, the first time incoming connections are enabled the firewall prompt appears.
Allow it for private networks. Nothing pre-authorises it, deliberately: an application
that silently opens a port is doing the thing that prompt exists to reveal.

### Run the headless service

For a machine nobody is sitting at:

```bash
cargo run -p rc-host-agent -- --root ./local/agent write-config   # seed a config file
cargo run -p rc-host-agent -- --root ./local/agent check          # validate it
cargo run -p rc-host-agent -- --root ./local/agent identity       # show this machine's identity
cargo run -p rc-host-agent -- --root ./local/agent run            # start it
```

There is no window, so there is nobody to click Accept: every connection request is
dismissed unless an unattended password or a pinned identity admits it. That is the
fail-closed direction, and it is deliberate.

Omit `--root` to use the production locations (`%ProgramData%\remote-control` on
Windows, `/etc` + `/var/lib` + `/var/log` on Linux).

## Security posture

The rules the codebase is built to, each enforced by tests:

- **Completing TLS admits nothing.** It answers which key is on the other end, not
  whether that key may have a session. The admission decision is separate and happens
  per connection.
- **A refused peer learns only that it was refused.** A dismissal, a wrong unattended
  password and a lockout are one value on the wire, so the answer is not an oracle for
  whether unattended access is configured.
- **Nothing identifying travels before the decision.** The acknowledgement sent to
  everyone who completes TLS carries the protocol version and nothing else.
- **Permissions are fixed at admission and re-checked on every request.** A permission
  decided once and trusted forever is the failure this design exists to prevent.
- **Accepting with nothing ticked is a refusal**, decided in one place that every
  admission path funnels through.
- **A pinned machine presenting a different certificate is refused outright**, never
  handed to the Accept dialog — an identity change must not be reachable by a routine
  click.
- **Nothing off the wire is trusted.** Frames are rejected on the header alone if they
  exceed a per-channel limit, before any allocation. Every path is resolved and checked
  before any filesystem call.
- **No plaintext secrets at rest.** The unattended password is an Argon2id hash that
  never crosses the IPC boundary; private keys live in a protected keystore (DPAPI on
  Windows, `0600` in a `0700` directory on Linux), not the database.
- **An intentional disconnect never auto-reconnects**, and neither does a refusal.
- **The application is not elevated.** It warns if you run it as administrator.

### Documentation

| Document | Covers |
|---|---|
| [`docs/access-model.md`](docs/access-model.md) | The three ways in, the ordering, the oracle properties, what a session may do |
| [`docs/threat-model.md`](docs/threat-model.md) | Assets, boundaries, adversaries, what got weaker and why |
| [`docs/network-protocol.md`](docs/network-protocol.md) | QUIC, mutual TLS, the two-leg handshake, channels, ports |
| [`docs/reconnection.md`](docs/reconnection.md) | What is retried, what is never retried, and why |
| [`docs/keystore-format.md`](docs/keystore-format.md) | Keystore envelope, DPAPI and Unix protection, installer requirements |
| [`docs/file-transfer-protocol.md`](docs/file-transfer-protocol.md) | Chunking, resumption, conflict policies, verification |
| [`docs/update-manager.md`](docs/update-manager.md) | Release manifests, resumable downloads, verification and install flow |

Read [`docs/threat-model.md`](docs/threat-model.md) before exposing anything beyond your
LAN. It states plainly what this design gives up relative to a pairing exchange, and why.

## Not supported, deliberately

Stealth or hidden installation, antivirus evasion, unattended access to machines you do
not administer, consent bypasses, or any form of covert operation. The application shows
a dialog before admitting anyone, shows the session while it runs, and can be
disconnected from either end at any moment.

## Licence

MIT OR Apache-2.0.
