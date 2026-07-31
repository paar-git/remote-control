# Threat model

**Status: updated for Phase 2 (device identity, keystore, pairing, owner auth,
permissions). Completed and reviewed in Phase 9.**

Controls marked *(planned: Phase N)* are designed but not yet implemented. Do not rely
on them yet.

## What is being protected

1. **Confidentiality and integrity of sessions** — screen contents, keystrokes,
   terminal output, transferred files.
2. **Control of the server** — only the owner, from a paired client, may act on it.
3. **Device identity** — the client must be certain which machine it is talking to.
4. **Credentials at rest** — the owner password and session tokens.

## Assets

| Asset | Where it lives | Protection |
|---|---|---|
| Device private key | Versioned keystore file (DPAPI `CurrentUser` / `0600` in a `0700` dir), never the database | Implemented — see [`keystore-format.md`](keystore-format.md) |
| Pinned peer fingerprints | `trusted_device` table | Integrity of the local DB |
| Owner password | Argon2id (m=19 MiB, t=2, p=1) hash in `owner_account` | Implemented — see [`owner-authentication.md`](owner-authentication.md) |
| Session tokens | Hashed in `session_token`; plaintext in memory only | *(planned: Phase 3)* |
| Pairing code | Argon2id verifier with a per-code salt; 180 s TTL; single-use; 5-attempt cap | Implemented — see [`pairing-protocol.md`](pairing-protocol.md) |
| Session traffic | In flight only | mTLS 1.3 over QUIC *(planned: Phase 3)* |

## Trust boundaries

1. **Network → agent.** Everything crossing it is hostile until the peer certificate
   matches a pinned fingerprint.
2. **Client webview → client backend.** The webview is treated as untrusted; every IPC
   response is schema-validated and the capability grant is minimal.
3. **Client → agent.** An authenticated client is authorised for application-level
   actions, but the agent still enforces its own allowlist and deny-rules. The client
   is never the authority on what the agent may do.
4. **Agent (unprivileged) → privileged operations.** Only via the fixed allowlist.
5. **Coordinator → session.** No trust at all. It routes; it cannot read.

## Adversaries and controls

### A1. Attacker on the same Wi-Fi network

*Can:* see mDNS announcements, reach the agent's UDP port, attempt connections,
observe traffic volume and timing.

*Cannot:* connect — the TLS handshake requires a client certificate whose fingerprint
is already pinned in `trusted_device`. Cannot read traffic (TLS 1.3, forward secret).
Cannot pair — the pairing code is short-lived, single-use, attempt-capped, and never
transmitted; the proof is bound to both certificate fingerprints, so relaying the
exchange between different endpoints fails.

*Residual:* denial of service by flooding the port. Mitigated by connection rate
limiting and `auth_attempts_per_minute` *(planned: Phase 3)*, not eliminated. mDNS
announcements disclose that a host runs the agent; `discovery_enabled = false` turns
this off.

### A2. Stolen main PC

*Can:* obtain the client database with pinned fingerprints and the encrypted device
key; attempt to open the application.

*Cannot:* connect without unlocking — the app requires the owner password (Argon2id,
throttled), and auto-lock closes idle sessions. On Windows the device private key is
DPAPI-protected against the user account, so extracting the raw database is not enough
*(planned: Phase 2)*.

*Residual:* an attacker with the unlocked machine **and** the owner password has full
access. Mitigation is revocation: the agent's `trusted_device` list can revoke that
client, which takes effect on the next connection attempt. **Revocation is not
retroactive against an already-open session until Phase 7's session-kill lands.**

### A3. Stolen server

*Can:* obtain the agent's database and, on Linux, the key file if the disk is not
encrypted.

*Cannot:* use it to attack the client — the agent stores the client's *public*
fingerprint, not a credential that authenticates as the client.

*Residual:* the agent's identity key can be extracted from an unencrypted Linux disk,
letting an attacker impersonate the server to the client. **Full-disk encryption is a
documented prerequisite**, not something the application can substitute for. The client
would not detect this, because the fingerprint is genuine.

### A4. Compromised coordination server

*Can:* deny service, learn which device IDs communicate and when, lie about endpoints,
attempt to route both peers through an attacker-controlled relay.

*Cannot:* decrypt anything. The client and agent complete a mutually authenticated TLS
1.3 handshake *through* whatever path the coordinator suggests, and both verify pinned
fingerprints. A hostile relay sees ciphertext. It cannot authorise a new client — that
requires a pairing code the coordinator never sees.

*Residual:* metadata exposure and denial of service are unavoidable when using a
coordinator. `remote_access_enabled = false` (the default) avoids both entirely.

### A5. Replayed pairing code

*Controls:* the code is consumed atomically on first successful use
(`pairing_code.consumed_at_ms`); it expires after 180 seconds; failed attempts are
counted and the code is destroyed after 5; the proof is a MAC over a transcript
including both nonces and both certificate fingerprints, so a captured proof is
worthless against any other pair of endpoints.

*Residual:* someone who reads the code off the server console within its 180-second
window and pairs faster than the operator succeeds. This is inherent to out-of-band
codes; the mitigation is that pairing mode is only open when explicitly started.

### A6. Malicious file names

*Threat:* `../../../etc/shadow`, `C:\Windows\System32\...`, names containing NUL,
newlines, or bidirectional overrides that make `cod<U+202E>txt.exe` render as
`codexe.txt`.

*Controls:* the protocol transports names faithfully (tested) and the **receiver**
sanitises. `untrustedText` strips C0/C1 controls, DEL and `U+202A`–`U+202E` /
`U+2066`–`U+2069` before rendering, and the UI renders as inert text. Path
normalisation and root confinement are *(planned: Phase 5)*, along with symlink-escape
checks that resolve the final target rather than trusting the path string.

### A7. Command injection

*Controls:* no code path builds a shell command line. `resolve_power_action` and
`resolve_service_action` return a fixed program path and an explicit `argv`;
`validate_service_name` accepts only `[A-Za-z0-9._@-]`, rejects leading dashes, and
caps length; `systemctl` invocations insert `--` before the name. 18 injection payloads
are tested against both.

*Residual:* none identified for the allowlisted surface. The terminal feature
*(Phase 4)* deliberately **does** run a shell — that is its purpose — which is why it
is separately gated, privilege-labelled, and audit-logged.

### A8. Dependency compromise

*Controls:* `Cargo.lock` and `pnpm-lock.yaml` are committed; `onlyBuiltDependencies`
restricts which packages may run install scripts; the webview CSP forbids all external
origins, so a compromised frontend dependency cannot exfiltrate to the network.

*Planned (Phase 9):* `cargo audit` / `cargo deny` and `pnpm audit` in CI, and signed
update verification.

*Residual:* a malicious Rust crate runs with agent privileges. Reduced by keeping the
dependency set small and preferring widely-audited crates, not eliminated.

### A9. Session hijacking

*Controls:* sessions are bound to the QUIC connection, which is itself bound to the
mutually authenticated TLS session — there is no bearer token that works on a new
connection. Access tokens are short-lived (≤ 24 h, enforced by config validation) and
refresh tokens rotate, with reuse of a rotated token invalidating the chain
*(planned: Phase 2)*. Control requests carry a nonce and timestamp checked by
`ReplayGuard`.

### A10. Brute force

*Controls:* `auth_attempts_per_minute` is validated to be between 1 and 120;
`owner_account.failed_login_count` and `locked_until_ms` throttle password attempts and
survive a restart; the in-process `Throttle` refuses a locked-out account *before*
hashing, so lockout cannot be turned into a work-amplification vector, and its tracked-key
map is bounded so key-cycling cannot exhaust memory or evict an active lockout; pairing
codes are attempt-capped at 5; `SecurityError::ProofRejected` is deliberately
indistinguishable from a wrong code, so failures are not an oracle; a missing owner account
performs a full dummy Argon2id hash and returns the identical error, so login is not an
enumeration oracle either.

### A11. Substituted device identity

*Threat:* an attacker replaces a paired device's key, or presents one key under two
device ids, to inherit trust that was granted to something else.

*Controls:* the device id is *derived* from the Ed25519 identity public key, so a peer
cannot claim an id it does not hold the key for. `insert_paired_device` rejects an
identity fingerprint already registered under a different device id. The identity
fingerprint — not the certificate fingerprint — is what a client pins, so certificate
renewal is distinguishable from identity substitution, and rotations are recorded
explicitly.

*Residual:* an attacker who obtains the private key material itself is that device. This
is why the keystore protections and the full-disk-encryption prerequisite matter.

## Security assumptions Phase 3 networking must preserve

Phase 2 establishes trust. Phase 3 carries traffic, and it can invalidate every property
above if it takes shortcuts. Specifically:

1. **Certificate fingerprints in the pairing transcript must be the ones observed on the
   actual TLS connection**, never values copied from the peer's message body. Filling them
   in from what the peer *claims* destroys the anti-relay property entirely.
2. **Revocation is re-checked per connection**, at the repository layer. Cached frontend
   state, cached session state and long-lived connections are all non-authoritative.
3. **Every remote action passes a capability check** resolved from the trusted device's
   stored role at action time — not from a role asserted in the request.
4. **Authentication is throttled on the remote path too**, through the same abstraction,
   keyed to include the source. A remote attacker must not find an unthrottled channel.
5. **Application authorization never becomes OS privilege.** The privileged-agent
   allowlist stays the sole path to elevated work.
6. **Pairing is reachable only when the operator has opened a window.** There is no
   ambient pairing endpoint.
7. **Proofs, codes, verifiers, keys and DPAPI blobs stay out of logs, audit records and
   diagnostics**, on the network path as much as locally.

## Explicit non-goals

- Defending a server whose disk is unencrypted against physical theft.
- Defending against a compromised operating system on either endpoint.
- Anonymity. The coordinator learns metadata by design; do not use one if that matters.
- Multi-tenant use. The model assumes one owner who administers both machines.

## Deployment prerequisites

1. **Do not port-forward the agent to the internet.** Use the coordination service, or
   a VPN. If you must, restrict the source range at the firewall.
2. **Encrypt the server's disk.** See A3.
3. **Keep `remote_access_enabled = false`** unless you need it.
4. **Verify the fingerprint out-of-band at pairing time** — read it off the server
   console and compare it in the client. This is the one step that cannot be automated.
