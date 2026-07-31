# Remote Control

A private remote-access platform for servers **you own and administer**: remote
desktop, a real terminal, file management, monitoring and power control, with strong
device identity and no third-party cloud in the path.

> **Status: Phase 2 of 9 complete.** The foundation and the security core — device
> identity, protected keystore, secure pairing, trusted devices, owner authentication
> and the capability model — are built, tested and verified. **Networking is not built
> yet**: two devices can be paired cryptographically but cannot yet connect. That lands
> in Phase 3. See [`PROGRESS.md`](PROGRESS.md) for exactly what works today and what
> does not.

## Design in one paragraph

A **host agent** runs as a system service on the machine being controlled. A
**desktop client** runs unelevated on your main PC. They authenticate each other with
mutually-authenticated TLS 1.3 over QUIC using self-signed, **fingerprint-pinned**
device certificates established during a short, single-use pairing exchange. An
optional **self-hosted coordination service** helps them find each other across
networks but never terminates encryption and never sees session contents. Privileged
operating-system work happens only in the agent, only through a closed allowlist of
fixed program paths and explicit argument vectors.

## Repository layout

```text
.
├─ apps/
│  ├─ desktop-client/          Tauri 2 + React + TypeScript client
│  │  └─ src-tauri/            Client backend (unelevated)
│  └─ coordination-server/     Optional self-hosted signalling service
├─ crates/
│  ├─ protocol/                Wire protocol, framing, limits, replay guard
│  ├─ security/                Identity, keystore, pairing, passwords, permissions
│  ├─ storage/                 SQLite schema, migrations, repositories, audit log
│  ├─ platform/                OS abstraction, privileged-command allowlist
│  └─ host-agent/              The agent service
├─ packages/
│  └─ shared-types/            Zod mirror of the protocol, reconnection policy
├─ installers/                 Windows and Linux packaging
├─ docs/                       Threat model, installation, operations
└─ scripts/                    Verification and development helpers
```

Crates for `remote-desktop`, `file-transfer`, `terminal` and `monitoring` are created in
the phases that implement them, rather than sitting empty.

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

### Run the agent

```bash
cargo run -p rc-host-agent -- --root ./local/agent write-config   # seed a config file
cargo run -p rc-host-agent -- --root ./local/agent check          # validate it
cargo run -p rc-host-agent -- --root ./local/agent identity       # show this device's identity
cargo run -p rc-host-agent -- --root ./local/agent pair           # open a pairing window
cargo run -p rc-host-agent -- --root ./local/agent run            # start it
```

`identity` creates the device identity on first use and prints the fingerprint a client
pins. `pair` prints a single-use code that expires in 180 seconds — the one sanctioned
path by which a code becomes visible. Completing a pairing over the network requires the
transport from Phase 3.

Omit `--root` to use the production locations (`%ProgramData%\remote-control` on
Windows, `/etc` + `/var/lib` + `/var/log` on Linux).

### Run the client

```bash
pnpm --filter @rc/desktop-client tauri:dev
```

Opening `http://127.0.0.1:1420` in a browser instead will show an explicit
"backend unavailable" message — the UI has no mock mode.

### Run the coordination service

```bash
cargo run -p rc-coordination-server         # binds 127.0.0.1:47812 by default
curl http://127.0.0.1:47812/health
```

## Security posture

The rules the codebase is built to, each enforced by tests:

- **Nothing off the wire is trusted.** Frames are rejected on the header alone if they
  exceed a per-channel limit, before any allocation.
- **No shell, ever.** Privileged operations resolve to a fixed program path plus an
  explicit `argv`; caller-supplied values are validated and can never become flags,
  separators or commands. See `crates/platform/src/privileged.rs`.
- **An intentional disconnect never auto-reconnects.** Encoded identically in Rust
  (`DisconnectReason::permits_auto_reconnect`) and TypeScript (`permitsAutoReconnect`),
  with paired tests on both sides.
- **Device identity is pinned.** A changed fingerprint is a hard, user-visible failure,
  never a silent re-trust.
- **No plaintext secrets at rest.** Passwords are Argon2id hashes; tokens are stored
  hashed; private keys live in a protected keystore (DPAPI on Windows, `0600` in a
  `0700` directory on Linux), not the database. Pairing codes are stored only as an
  Argon2id verifier.
- **The client is not elevated.** It warns if you run it as administrator.
- **Authorization is by typed capability.** No `if is_owner` conditionals; adding a
  capability without deciding which roles get it is a compile error.
- **Application permission is not OS privilege.** An owner cannot use application
  permissions to bypass UAC, polkit, or the protected-services deny-list.

### Security documentation

| Document | Covers |
|---|---|
| [`docs/threat-model.md`](docs/threat-model.md) | Assets, boundaries, adversaries, residual risk |
| [`docs/pairing-protocol.md`](docs/pairing-protocol.md) | The pairing exchange, transcript construction, domain separation |
| [`docs/keystore-format.md`](docs/keystore-format.md) | Keystore envelope, DPAPI and Unix protection, installer requirements |
| [`docs/owner-authentication.md`](docs/owner-authentication.md) | Argon2id parameters, throttling, hash upgrades |
| [`docs/permission-model.md`](docs/permission-model.md) | Capabilities, roles, the privilege boundary |

Read [`docs/threat-model.md`](docs/threat-model.md) before exposing anything beyond
your LAN.

## Not supported, deliberately

Stealth or hidden installation, antivirus evasion, unattended access to devices you do
not administer, consent bypasses, or any form of covert operation. The agent announces
itself, logs its sessions, and shows a host-side indicator while a remote-control
session is active.

## Licence

MIT OR Apache-2.0.
