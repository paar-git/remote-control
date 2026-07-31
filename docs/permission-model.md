# Permission model

Application authorization is expressed as **typed capabilities**. Implemented in
`crates/security/src/permissions.rs`.

## Why capabilities rather than role checks

Every check goes through `Role::grants` or `AuthorizationContext::require`. No call site
anywhere is permitted to write `if role == Role::Owner`. Two reasons:

1. Adding a role means updating one table, not auditing every branch in the codebase.
2. `Capability` is `#[non_exhaustive]` and the grant table is an exhaustive `match`, so
   **adding a capability without deciding which roles get it is a compile error** — not a
   silent grant, and not a silent denial that someone later "fixes" with a wildcard.

## Capabilities

| Capability | Grants |
|---|---|
| `RemoteDesktopView` | See the remote screen |
| `RemoteInput` | Inject mouse and keyboard input |
| `Terminal` | Open a terminal session |
| `FileRead` | List and download files |
| `FileWrite` | Upload, rename, move and delete files |
| `ProcessManagement` | List and terminate processes |
| `ServiceManagement` | Start, stop and configure services |
| `PowerControl` | Restart, shut down, sleep or lock the host |
| `SettingsManagement` | Read and change agent settings |
| `TrustedDeviceManagement` | Pair, rename and revoke trusted devices |

## Roles

| | Owner | Operator | ViewOnly |
|---|:---:|:---:|:---:|
| `RemoteDesktopView` | ✅ | ✅ | ✅ |
| `RemoteInput` | ✅ | ✅ | — |
| `Terminal` | ✅ | ✅ | — |
| `FileRead` | ✅ | ✅ | ✅ |
| `FileWrite` | ✅ | ✅ | — |
| `ProcessManagement` | ✅ | ✅ | — |
| `ServiceManagement` | ✅ | ✅ | — |
| `PowerControl` | ✅ | ✅ | — |
| `SettingsManagement` | ✅ | — | — |
| `TrustedDeviceManagement` | ✅ | — | — |

**Owner** holds every capability. This is written as an explicit `true` arm rather than a
wildcard, so a reviewer can see it is deliberate.

**Operator** covers day-to-day administration. Note what is absent: `SettingsManagement`
and `TrustedDeviceManagement` are reserved for the owner, so an operator **cannot grant
itself more** — neither by changing settings nor by pairing a new device at a higher role.

**ViewOnly** may watch the screen and read files, nothing else.

### Unknown roles fail closed

`Role::from_name` returns `None` for anything unrecognised. A stored role that this build
does not understand is rejected, never defaulted — a default would risk granting more than
intended.

## This is not OS privilege

Application authorization and operating-system privilege are **separate axes**, and the
system deliberately keeps them separate.

Holding `Capability::PowerControl` means the *application* will forward a power request to
the agent. The agent still:

* Resolves it through `rc_platform::privileged`, against a closed allowlist of fixed
  program paths and explicit argument vectors.
* Requires elevation where the OS requires it.
* Enforces its own deny-rules, including the protected-services list.

**An owner cannot use application permissions to bypass UAC, polkit, or the
protected-services list.** Being the application's owner is not being root, and the
privileged-agent boundary is not something the permission system can open.

## Phase 2 scope

A successfully authenticated owner receives full application-level permissions. That is
the intended Phase 2 behaviour — but the authorization still goes through the capability
system. `AuthorizationContext::require(capability)` is the only gate; there are no
scattered `is_owner` conditionals to audit later.

Requested permissions are bound into the pairing transcript, so a peer cannot request
`ViewOnly` and be recorded as `Owner`, nor have its request silently upgraded in transit.
See [`pairing-protocol.md`](pairing-protocol.md).

## What Phase 3 must preserve

1. **Every remote action must pass a capability check**, resolved from the trusted device's
   stored role at the time of the action — not from a role cached in the client, and not
   from a role asserted in the request.
2. **Revocation must be re-checked per connection**, at the repository layer. A revoked
   device holds no capabilities regardless of what any cached state says.
3. **Capability checks must not be moved to the frontend.** The desktop client hides
   controls the user cannot use, but that is presentation, not enforcement.
