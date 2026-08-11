# Owner authentication

The owner account is the single local administrative identity for the application.
Implemented in `crates/security/src/password.rs`, `crates/security/src/throttle.rs` and
`crates/storage/src/owner.rs`.

**There is no default password and no way to create an account without supplying one.**

## Password hashing

Production uses **Argon2id, m = 19456 KiB (19 MiB), t = 2, p = 1**, the first
configuration in the OWASP Password Storage Cheat Sheet's recommended set.

| Choice | Reasoning |
|---|---|
| **Argon2id** | The variant designed to resist both side-channel and GPU/ASIC attacks, and the one RFC 9106 recommends by default. Not Argon2i, not Argon2d. |
| **m = 19 MiB** | Makes GPU cracking uneconomic while completing in well under a second on a home server — and, importantly, while fitting on the low-memory Linux boxes people actually run agents on. |
| **t = 2, p = 1** | Pairs with that memory figure in the OWASP guidance. Raising `t` buys less than raising `m` for the same wall-clock cost. |
| **16-byte CSPRNG salt, unique per password** | Defeats precomputation and makes two identical passwords hash differently. |
| **No pepper** | A pepper the agent stores next to the database adds nothing against the attacker who has the database. |

Tests use `HashingPolicy::FAST_FOR_TESTS` (m = 64 KiB, t = 1) so the suite does not spend
a second per login. Production code always uses `HashingPolicy::PRODUCTION`.

## Input limits

| Limit | Value | Reasoning |
|---|---|---|
| Minimum length | 12 bytes | This is a personal-administration tool with a throttled local login, not a public web service. 12 characters *with lockout* is a materially stronger position than a longer minimum with none. |
| Maximum length | 1024 bytes | Bounds the work a single input can demand. Argon2's cost is dominated by `m` and `t`, but the bound removes the question. |

Also rejected: whitespace-only passwords (almost certainly a mistake, and leading or
trailing whitespace is invisible when re-entering) and passwords containing null bytes.

### No normalisation

The password is hashed as **the exact UTF-8 bytes supplied**. No Unicode normalisation, no
case folding, no trimming.

This is a deliberate choice with a real trade-off: a password typed with a composed
character on one platform and a decomposed one on another will not match. The alternative
is worse — normalisation silently changes what the user typed, and the set of strings that
normalise together is not something a user can reason about.

## Verification

* Comparison is constant-time inside Argon2's own verifier.
* The **code path** is uniform: a missing account still performs a full dummy hash
  (`verify_against_nothing`) before returning the *same* `InvalidCredentials` error, so
  neither timing nor the error message reveals whether an account exists.
* Password bytes live in `Zeroizing` buffers and are wiped as soon as hashing or
  verification completes.

### No account enumeration

Wrong password and unknown account are indistinguishable: identical error type, identical
error text, comparable work. This is asserted by a test comparing the rendered strings.

## Throttling and lockout

Authentication order is deliberate:

1. **Throttle check** — a locked-out account is refused *before* any hashing, so lockout
   cannot itself be turned into a way to make the server do expensive work.
2. **Account lookup** — dummy hash on miss, as above.
3. **Verification.**
4. **Bookkeeping** — success clears the failure counter and records the login; failure
   increments it and may set a lockout.
5. **Upgrade check** — see below.

### Properties

* Failures are counted per key within a rolling window.
* Lockout is **bounded**, not unbounded: an operator who fat-fingers a password is not
  locked out for a day.
* A successful login clears that account's counter — and only that account's, so one user's
  success cannot reset another's counter.
* The tracked-key map has a **memory ceiling**. An attacker cycling through usernames
  cannot grow it without bound. Currently-locked entries are retained in preference to idle
  ones, so flooding cannot be used to clear someone else's active lockout.
* Lockout state is persisted (`failed_login_count`, `locked_until_ms`), so restarting the
  agent does not clear an active lockout.

The throttle takes an injected `Clock`, so expiry and lockout recovery are tested
deterministically rather than with sleeps.

## Password-hash upgrades

Argon2 parameters are recorded **inside** the stored PHC string, so a stored hash always
carries the settings it was made with. The `owner_account` table additionally records them
in typed columns for queryability.

`PasswordCredential::needs_rehash` reports when a stored hash was made with weaker settings
than current policy. On the next **successful** login — the only moment the plaintext is
available — the hash is transparently recomputed at current policy and rewritten. The
result is reported as `password_hash_upgraded` and audited as
`auth.password_hash_upgraded`.

This means raising the policy in a future release costs users nothing and requires no
password reset.

## What never leaves the backend

* The password hash never appears on any frontend-facing type. `OwnerAccountRow` carries
  it; the DTOs returned by Tauri commands do not. A test asserts the hash is not returned
  to a caller.
* Raw passwords are never logged, never audited, never included in diagnostics.
* Access to the PHC string goes through `expose_phc_for_storage()`, named so every call
  site is visible in review.

## Audit events

| Event | Action |
|---|---|
| Owner account created | `auth.owner_created` |
| Login succeeded | `auth.login_succeeded` |
| Login failed | `auth.login_failed` |
| Login throttled | `auth.login_throttled` |
| Hash upgraded | `auth.password_hash_upgraded` |

No audit record contains the password, the hash, or the salt.

## What Phase 3 must preserve

1. **Owner authentication authorises the application, not the operating system.** A
   successful login does not grant OS privilege; the agent still resolves privileged work
   through `rc_platform::privileged`.
2. **Session state must not be the authority.** A session established by a successful login
   still has its capabilities checked per action through the permission system.
3. Remote authentication attempts must go through the same throttle abstraction, keyed to
   include the source, so a remote attacker cannot get an unthrottled channel.
