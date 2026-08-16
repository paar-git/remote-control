> Historical. Not current product documentation.

# Device Trust and Navigation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move persistent access off the address it was typed at and onto a TLS-verified device identity, add unattended access and a separate Administrator permission, and rebuild the window around four navigation categories.

**Architecture:** Every device already self-signs its TLS certificate with its Ed25519 identity key, so the certificate's subject public key *is* the identity. The receiving side extracts it from the certificate DER that `rc-transport` already retains, yielding a verified identity fingerprint that becomes the primary key of a new `trusted_devices` table. Admission gains an identity-lookup step ahead of the existing password and human-prompt branches; a fourth permission, `Administer`, gates a new control-channel surface for managing trust remotely. The interface gains a typed four-view router.

**Tech Stack:** Rust 2024 (sqlx/SQLite, quinn/QUIC, rustls, ed25519-dalek, rcgen, tokio, tracing), TypeScript + React 19 + Tailwind v4 + zod + Vitest + Testing Library, Tauri 2.

**Spec:** `docs/superpowers/specs/2026-08-14-device-trust-and-navigation-design.md`

## Global Constraints

- **Clippy is pedantic with `-D warnings` across all targets and all features.** A warning is a build failure. Every public item needs a doc comment; every `pub fn` that returns `Result` needs an `# Errors` section.
- **Migrations are additive only**, with exactly one sanctioned exception in this plan (dropping the two pin columns), justified in the migration header.
- **Fingerprints are stored as lowercase hex**, 64 characters. `Fingerprint::from_str` rejects uppercase deliberately.
- **Identity comparisons use `Fingerprint::ct_eq`, never `==` on the hex string.**
- **No secret is ever logged, returned to the webview, or placed in an error message.** There is no credential attached to a trust relationship; do not invent one.
- **`WireRefusal` must stay coarser than `RefusalReason`.** New local reasons collapse into `Rejected` unless the spec says otherwise.
- **The desktop client's IPC boundary is camelCase** (`#[serde(rename_all = "camelCase")]`), and every response is validated by a zod schema in `api.ts`. Nothing type-asserts.
- **Untrusted remote text goes through `untrustedText(n)`** in TypeScript before rendering.
- **Red (`--color-danger`) is reserved** for Disconnect, Revoke, Delete, security warnings and failures. Connect is `--color-accent`.
- **Test names are sentences describing the property**, matching the existing suites (`a_pinned_peer_presenting_a_different_fingerprint_is_refused_not_prompted`).
- Verification command for the whole tree: `pnpm verify`.

---

## File Structure

**Rust — new files**

| Path | Responsibility |
|---|---|
| `crates/security/src/certificate.rs` | Extract the Ed25519 identity key from a certificate DER. The only sanctioned source of a verified identity fingerprint. |
| `crates/storage/migrations/0004_device_trust.sql` | `trusted_devices`, `session_history`, `recent_connections` changes, widened permission bounds. |
| `crates/storage/src/trust.rs` | `TrustRepository` — the trusted-device table. |
| `crates/storage/src/history.rs` | `SessionHistoryRepository` — the session log. |
| `crates/host-agent/src/trust_service.rs` | The admin-gated control surface, including the no-self-modification rule. |
| `apps/desktop-client/src-tauri/src/trust_commands.rs` | Tauri commands over `TrustRepository` and the reachability probe. |
| `apps/desktop-client/src-tauri/src/inbound.rs` | Live inbound sessions on the desktop side, plus emergency disconnect. |

**Rust — modified**

| Path | Change |
|---|---|
| `crates/security/src/permissions.rs` | Add `Permission::Administer`, widen `KNOWN`. |
| `crates/security/src/lib.rs` | Export `certificate` module. |
| `crates/transport/src/tls.rs` | Add `peer_certificate_der`. |
| `crates/transport/src/handshake.rs` | `PeerIdentity` replaces the bare `Fingerprint` through accept. |
| `crates/host-agent/src/access.rs` | The new admission order. |
| `crates/protocol/src/control.rs` | Four admin requests, one response payload. |
| `crates/protocol/src/version.rs` | Minor bump. |
| `crates/storage/src/lib.rs` | `SUPPORTED_SCHEMA_VERSION` 3 → 4, module exports. |
| `crates/storage/src/recent.rs` | Drop pin API, add `known_identity`. |
| `crates/host-agent/src/server.rs` | Thread `PeerIdentity`, record history. |
| `apps/desktop-client/src-tauri/src/host.rs` | Trust-aware accept prompt. |
| `apps/desktop-client/src-tauri/src/connection.rs` | Outgoing identity pinning. |
| `apps/desktop-client/src-tauri/src/lib.rs` | Register new commands and state. |

**TypeScript — new files**

| Path | Responsibility |
|---|---|
| `apps/desktop-client/src/navigation.ts` | The `View` union and its labels. |
| `apps/desktop-client/src/AppShell.tsx` | Sidebar + animated view switch. |
| `apps/desktop-client/src/RemoteControlPage.tsx` | Connect, This Device, compact recent. |
| `apps/desktop-client/src/ThisDevice.tsx` | Identity, address, accepting toggle, advanced disclosure. |
| `apps/desktop-client/src/MyDevicesPage.tsx` | Trusted device cards + presence. |
| `apps/desktop-client/src/DeviceDetail.tsx` | Access / Permissions / Security, revoke. |
| `apps/desktop-client/src/GrantAdminDialog.tsx` | The strong administrator confirmation. |
| `apps/desktop-client/src/SessionsPage.tsx` | Active and recent sessions. |
| `apps/desktop-client/src/SettingsPage.tsx` | Sectioned settings. |
| `apps/desktop-client/src/InboundSessionBanner.tsx` | "Someone is controlling this machine". |
| `apps/desktop-client/src/DeviceCard.tsx` | The shared device card. |

**TypeScript — deleted**

`RemoteDeskCard.tsx`, `ThisDeskCard.tsx`, `RecentList.tsx`, `TrustedDevices.tsx`, `AppSidebar.tsx`, `MainWindow.tsx`, `SettingsDialog.tsx` and their tests, once their replacements pass. `DeviceAvatar.tsx`, `theme.ts` and `ui/Toggle.tsx` are kept.

---

## Task 1: Extract a verified identity from a certificate

**Files:**
- Create: `crates/security/src/certificate.rs`
- Modify: `crates/security/src/lib.rs`
- Test: in-module `#[cfg(test)]` in `certificate.rs`

**Interfaces:**
- Consumes: `Fingerprint::of_public_key`, `DeviceIdentity::generate`, `SecurityError`.
- Produces: `rc_security::certificate::identity_key_of_certificate(der: &[u8]) -> Result<[u8; 32]>` and `rc_security::identity_fingerprint_of_certificate(der: &[u8]) -> Result<Fingerprint>`.

- [ ] **Step 1: Write the failing test**

Add to `crates/security/src/certificate.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;
    use crate::identity::DeviceIdentity;

    #[test]
    fn a_generated_certificate_yields_the_identity_behind_it() {
        // The whole trust model rests on this: the fingerprint derived from the
        // certificate a peer presents must equal the fingerprint the peer itself
        // publishes as its identity. If these ever diverge, every trusted device
        // stops being recognised.
        let clock = TestClock::default();
        let identity = DeviceIdentity::generate("test-device", &clock).unwrap();
        let public = identity.public();

        let derived = identity_fingerprint_of_certificate(&public.certificate_der).unwrap();

        assert_eq!(derived, public.identity_fingerprint);
    }

    #[test]
    fn a_renewed_certificate_yields_the_same_identity() {
        // This is the bug the change exists to fix. Pinning the certificate makes an
        // ordinary renewal look like a substituted machine; pinning the identity does
        // not.
        let clock = TestClock::default();
        let mut identity = DeviceIdentity::generate("test-device", &clock).unwrap();
        let before = identity_fingerprint_of_certificate(&identity.public().certificate_der).unwrap();
        let certificate_before = identity.public().certificate_fingerprint;

        identity.renew_certificate(&clock).unwrap();

        let after = identity_fingerprint_of_certificate(&identity.public().certificate_der).unwrap();
        assert_eq!(before, after, "renewal must not change the identity");
        assert_ne!(
            certificate_before,
            identity.public().certificate_fingerprint,
            "the test is meaningless unless the certificate actually changed"
        );
    }

    #[test]
    fn two_devices_never_share_an_identity() {
        let clock = TestClock::default();
        let a = DeviceIdentity::generate("a", &clock).unwrap();
        let b = DeviceIdentity::generate("b", &clock).unwrap();

        assert_ne!(
            identity_fingerprint_of_certificate(&a.public().certificate_der).unwrap(),
            identity_fingerprint_of_certificate(&b.public().certificate_der).unwrap()
        );
    }

    #[test]
    fn garbage_is_refused_rather_than_hashed() {
        // Falling back to hashing whatever bytes arrived would mint a stable
        // "identity" for a peer that has no identity key at all, and that value
        // could then be trusted.
        for bad in [b"".as_slice(), b"not a certificate", &[0x30, 0x82, 0x01]] {
            assert!(identity_key_of_certificate(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn a_non_ed25519_certificate_is_refused() {
        // An RSA or ECDSA certificate has a subject public key that is not 32 bytes
        // of Ed25519. It must not be coerced into one.
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["other".to_owned()]).unwrap();
        let certificate = params.self_signed(&key).unwrap();

        assert!(identity_key_of_certificate(certificate.der()).is_err());
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p rc-security certificate`
Expected: FAIL — `certificate.rs` does not exist yet, so the module does not compile.

- [ ] **Step 3: Write the implementation**

Create `crates/security/src/certificate.rs`:

```rust
//! Reading a device's identity out of the certificate it presented.
//!
//! # Why this is sound
//!
//! Every device in this system generates an Ed25519 identity key and a certificate
//! **self-signed by that key** — see [`crate::identity::DeviceIdentity`]. The
//! certificate's subject public key therefore *is* the identity public key, and a peer
//! that completed a TLS handshake with it has proved possession of the private half.
//!
//! That makes the identity fingerprint of a presented certificate a value the peer
//! cannot lie about, unlike anything it reports in a message body. It is the only
//! sanctioned trust key: `DeviceDescriptor::device_id` is a claim and is display text.
//!
//! # Why renewal is safe
//!
//! Renewal issues a new certificate from the same key. The certificate fingerprint
//! changes; the value computed here does not. Trust anchored on it survives an ordinary
//! maintenance event that would otherwise fail every pinned peer.

use x509_parser::prelude::*;

use crate::error::{Result, SecurityError};
use crate::fingerprint::Fingerprint;

/// Length of a raw Ed25519 public key.
const ED25519_KEY_LEN: usize = 32;

/// The Ed25519 subject public key of a DER-encoded certificate.
///
/// # Errors
/// [`SecurityError::MalformedIdentity`] if the bytes are not a parseable certificate, or
/// if its subject public key is not a 32-byte Ed25519 key. Both are refusals rather than
/// approximations: coercing some other key type into 32 bytes would mint a stable
/// identity for a device that has none, and that value could then be trusted.
pub fn identity_key_of_certificate(der: &[u8]) -> Result<[u8; ED25519_KEY_LEN]> {
    let (_, certificate) =
        X509Certificate::from_der(der).map_err(|_| SecurityError::MalformedIdentity)?;

    let spki = certificate.public_key();
    if spki.algorithm.algorithm != oid_registry::OID_SIG_ED25519 {
        return Err(SecurityError::MalformedIdentity);
    }

    spki.subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| SecurityError::MalformedIdentity)
}

/// The identity fingerprint of a DER-encoded certificate. **The trust key.**
///
/// # Errors
/// As [`identity_key_of_certificate`].
pub fn identity_fingerprint_of_certificate(der: &[u8]) -> Result<Fingerprint> {
    identity_key_of_certificate(der).map(|key| Fingerprint::of_public_key(&key))
}
```

Add the dependency to `crates/security/Cargo.toml` under `[dependencies]`:

```toml
x509-parser = "0.16"
oid-registry = "0.7"
```

and to `crates/security/Cargo.toml` under `[dev-dependencies]` (the non-Ed25519 test needs it; check whether `rcgen` is already a normal dependency there — it is, so no change is needed).

Wire it up in `crates/security/src/lib.rs`, adding to the module list and the re-exports:

```rust
pub mod certificate;
```

```rust
pub use certificate::{identity_fingerprint_of_certificate, identity_key_of_certificate};
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p rc-security certificate`
Expected: PASS, 5 tests.

Run: `cargo clippy -p rc-security --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/security/src/certificate.rs crates/security/src/lib.rs crates/security/Cargo.toml Cargo.lock
git commit -m "feat(security): derive a device's identity from the certificate it presented

The trust key becomes the Ed25519 subject public key of the presented
certificate rather than the certificate's own digest. A peer proved possession
of that key by completing TLS, so it cannot lie about it, and renewal does not
change it -- which is the bug the old certificate pin would have hit on the far
side's first renewal.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 2: Carry a verified identity through the handshake

**Files:**
- Modify: `crates/transport/src/tls.rs` (add `peer_certificate_der`)
- Modify: `crates/transport/src/handshake.rs:80-100` (`AuthenticatedPeer`), `:154-166` (`accept_handshake`), `:209-300` (`finish_accept`)
- Modify: `crates/transport/src/lib.rs` (export `PeerIdentity`)
- Test: `crates/transport/src/handshake.rs` in-module tests, `crates/transport/tests/connection_e2e.rs`

**Interfaces:**
- Consumes: `rc_security::identity_fingerprint_of_certificate` (Task 1).
- Produces:
  - `rc_transport::PeerIdentity { certificate_fingerprint: Fingerprint, identity_fingerprint: Fingerprint, device_id: DeviceId }`
  - `PeerIdentity::from_certificate_der(der: &[u8]) -> rc_security::Result<PeerIdentity>`
  - `rc_transport::tls::peer_certificate_der(connection: &quinn::Connection) -> Result<Vec<u8>>`
  - `accept_handshake` / `finish_accept` now take `observed: PeerIdentity`, and the `authorize` callback signature becomes `FnOnce(PeerIdentity, PeerAddress, String, Option<String>) -> Fut`.
  - `AuthenticatedPeer` gains `identity_fingerprint: Fingerprint`; its `device_id` is now derived from the identity key rather than the certificate fingerprint.

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` in `crates/transport/src/handshake.rs`:

```rust
#[test]
fn a_peer_identity_is_derived_from_the_certificate_not_claimed_by_the_peer() {
    let clock = rc_security::clock::TestClock::default();
    let identity = rc_security::DeviceIdentity::generate("peer", &clock).unwrap();
    let public = identity.public();

    let derived = PeerIdentity::from_certificate_der(&public.certificate_der).unwrap();

    assert_eq!(derived.identity_fingerprint, public.identity_fingerprint);
    assert_eq!(derived.certificate_fingerprint, public.certificate_fingerprint);
    assert_eq!(
        derived.device_id, public.device_id,
        "the device id must come from the identity key, so the same device always \
         reports the same id -- deriving it from the certificate made it change on \
         every renewal"
    );
}

#[test]
fn a_peer_identity_cannot_be_built_from_a_certificate_with_no_identity() {
    assert!(PeerIdentity::from_certificate_der(b"not a certificate").is_err());
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p rc-transport peer_identity`
Expected: FAIL — `PeerIdentity` is not defined.

- [ ] **Step 3: Write the implementation**

In `crates/transport/src/handshake.rs`, above `AuthenticatedPeer`, add:

```rust
/// Who a peer is, established from the certificate it actually presented.
///
/// Built only by [`PeerIdentity::from_certificate_der`] from the DER the TLS verifier
/// recorded — never from a message body. A peer that could name its own identity could
/// name someone else's, which is the whole property that makes trust decisions sound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Fingerprint of the certificate presented on this connection. Changes on renewal.
    pub certificate_fingerprint: Fingerprint,
    /// Fingerprint of the identity key behind it. **The trust key.** Stable.
    pub identity_fingerprint: Fingerprint,
    /// Stable id derived from the same identity key.
    pub device_id: DeviceId,
}

impl PeerIdentity {
    /// Establish a peer's identity from the certificate it presented.
    ///
    /// # Errors
    /// Propagates [`rc_security::SecurityError::MalformedIdentity`] when the certificate
    /// carries no Ed25519 identity key. Such a connection is refused rather than
    /// admitted under an invented identity.
    pub fn from_certificate_der(der: &[u8]) -> rc_security::Result<Self> {
        let key = rc_security::identity_key_of_certificate(der)?;
        Ok(Self {
            certificate_fingerprint: Fingerprint::of_certificate_der(der),
            identity_fingerprint: Fingerprint::of_public_key(&key),
            device_id: rc_security::derive_device_id(&key),
        })
    }
}
```

Add `identity_fingerprint: Fingerprint` to `AuthenticatedPeer` and replace the doc comment on `device_id` (which currently explains deriving it from the certificate fingerprint):

```rust
    /// Stable identifier derived from the peer's **identity** key, so the same device
    /// keeps the same id across certificate renewal.
    pub device_id: DeviceId,
    /// The identity the peer proved by completing TLS. The key trust is stored under.
    pub identity_fingerprint: Fingerprint,
```

Change the `observed` parameter of `accept_handshake` and `finish_accept` from `Fingerprint` to `PeerIdentity`, and both `where` clauses from

```rust
    F: FnOnce(Fingerprint, PeerAddress, String, Option<String>) -> Fut + Send,
```

to

```rust
    F: FnOnce(PeerIdentity, PeerAddress, String, Option<String>) -> Fut + Send,
```

At `handshake.rs:289`, replace the derivation and populate the new field:

```rust
                device_id: observed.device_id,
                identity_fingerprint: observed.identity_fingerprint,
                certificate_fingerprint: observed.certificate_fingerprint,
```

At the `tracing::warn!` on refusal (around `:300`), log the identity rather than the certificate, since that is the value that names the device:

```rust
                    identity = %observed.identity_fingerprint,
```

In `crates/transport/src/tls.rs`, beside `peer_certificate_fingerprint`, add:

```rust
/// The DER of the certificate the peer presented **on this connection**.
///
/// The sanctioned source for establishing a [`crate::handshake::PeerIdentity`]. As with
/// the fingerprint, this must come from the connection rather than from anything the
/// peer sent in a message body.
///
/// # Errors
/// [`TransportError::NoPeerCertificate`] if the connection carries no peer certificate,
/// or if it presented anything other than exactly one end-entity certificate.
pub fn peer_certificate_der(connection: &quinn::Connection) -> Result<Vec<u8>> {
    let identity = connection
        .peer_identity()
        .ok_or(TransportError::NoPeerCertificate)?;
    let chain = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .map_err(|_| TransportError::NoPeerCertificate)?;

    match chain.as_slice() {
        [end_entity] => Ok(end_entity.as_ref().to_vec()),
        _ => Err(TransportError::NoPeerCertificate),
    }
}
```

Export from `crates/transport/src/lib.rs`:

```rust
pub use handshake::PeerIdentity;
```

Then fix every caller the compiler flags — `crates/host-agent/src/server.rs` and `apps/desktop-client/src-tauri/src/host.rs` build the `authorize` closure, and their call sites now pass `PeerIdentity::from_certificate_der(&tls::peer_certificate_der(&connection)?)`. A connection whose certificate yields no identity is refused with `WireRefusal::Rejected` before the closure runs.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p rc-transport`
Expected: PASS, including the existing `connection_e2e.rs` suite unchanged.

Run: `cargo test -p rc-host-agent && cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: PASS and clean.

- [ ] **Step 5: Commit**

```bash
git add crates/transport crates/host-agent apps/desktop-client/src-tauri/src/host.rs
git commit -m "feat(transport): carry a verified peer identity through the handshake

PeerIdentity replaces the bare certificate fingerprint through accept, so the
admission decision receives an identity the peer proved rather than one it
claimed. AuthenticatedPeer::device_id now comes from the identity key, which is
what makes it stable across renewal -- it was derived from the certificate
fingerprint and therefore changed whenever the certificate did.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 3: A fourth permission

**Files:**
- Modify: `crates/security/src/permissions.rs`
- Modify: `crates/protocol/src/version.rs`
- Test: in-module tests in `permissions.rs`

**Interfaces:**
- Produces: `Permission::Administer`, `Permission::ALL: [Self; 4]`, `PermissionSet::KNOWN = 0b0000_1111`, name `"administer"`.

- [ ] **Step 1: Write the failing test**

Add to `crates/security/src/permissions.rs` tests:

```rust
#[test]
fn administer_is_a_permission_of_its_own() {
    let set = PermissionSet::NONE.with(Permission::Administer);
    assert!(set.contains(Permission::Administer));
    assert!(!set.contains(Permission::ControlInput));
    assert!(!set.contains(Permission::TransferFiles));
    assert!(!set.contains(Permission::ViewMetrics));
}

#[test]
fn no_other_permission_implies_administer() {
    // The separation the design rests on: nothing a session was given for ordinary
    // control may be read as authority to manage trust.
    for permission in [
        Permission::ControlInput,
        Permission::TransferFiles,
        Permission::ViewMetrics,
    ] {
        assert!(!PermissionSet::NONE.with(permission).contains(Permission::Administer));
    }
}

#[test]
fn all_still_means_every_known_permission() {
    assert_eq!(Permission::ALL.len(), 4);
    for permission in Permission::ALL {
        assert!(PermissionSet::ALL.contains(permission));
    }
}

#[test]
fn administers_name_is_stable() {
    assert_eq!(Permission::Administer.name(), "administer");
}

#[test]
fn the_administer_bit_is_known() {
    assert_eq!(PermissionSet::from_bits(0b0000_1000), Some(PermissionSet::NONE.with(Permission::Administer)));
    assert_eq!(PermissionSet::from_bits(0b0001_0000), None, "bit 5 is still unknown");
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p rc-security permissions`
Expected: FAIL — no variant `Administer`.

- [ ] **Step 3: Write the implementation**

In `crates/security/src/permissions.rs`:

```rust
    /// Read and change this machine's trusted devices and their permissions.
    ///
    /// Deliberately separate from the other three, and from unattended access. A device
    /// permitted to reconnect without approval has said nothing about whether it may
    /// rewrite the list of who else may. This is never granted from the Accept dialog.
    Administer,
```

```rust
    pub const ALL: [Self; 4] = [
        Self::ControlInput,
        Self::TransferFiles,
        Self::ViewMetrics,
        Self::Administer,
    ];
```

```rust
            Self::Administer => "administer",
```

```rust
            Self::Administer => 0b0000_1000,
```

```rust
    const KNOWN: u8 = 0b0000_1111;
```

Update the module doc comment: "Three permissions" becomes "Four permissions", and note that `Administer` is granted only from the device detail screen.

In `crates/protocol/src/version.rs`, bump the minor of `CURRENT_VERSION` by one, and extend the comment to record why: a set carrying the `Administer` bit is refused rather than masked by a build that predates it.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p rc-security -p rc-protocol`
Expected: PASS. Existing `permissions` tests that assert three permissions will need their counts updated — update them, do not delete them.

- [ ] **Step 5: Commit**

```bash
git add crates/security/src/permissions.rs crates/protocol/src/version.rs
git commit -m "feat(security): add Administer as a fourth, separate permission

Nothing granted for ordinary remote control implies authority over the trust
database, so it is its own bit rather than an escalation of an existing one.
The protocol minor is bumped: from_bits refuses the new bit rather than masking
it, which is the behaviour that keeps a set meaning the same thing on both sides.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 4: The trusted-devices table

**Files:**
- Create: `crates/storage/migrations/0004_device_trust.sql`
- Create: `crates/storage/src/trust.rs`
- Modify: `crates/storage/src/lib.rs`, `crates/storage/src/recent.rs`
- Test: in-module tests in `trust.rs`

**Interfaces:**
- Produces:
```rust
pub struct TrustedDevice {
    pub identity_fingerprint: Fingerprint,
    pub device_id: String,
    pub display_name: String,
    pub os_family: String,
    pub last_address: Option<String>,
    pub added_ms: i64,
    pub last_connected_ms: Option<i64>,
    pub unattended: bool,
    pub suspended: bool,
    pub permissions: PermissionSet,
}

pub struct TrustRepository { /* … */ }
impl TrustRepository {
    pub fn new(database: &Database) -> Self;
    pub async fn list(&self) -> Result<Vec<TrustedDevice>>;
    pub async fn find(&self, identity: Fingerprint) -> Result<Option<TrustedDevice>>;
    pub async fn find_by_address(&self, address: &str) -> Result<Option<TrustedDevice>>;
    pub async fn trust(&self, device: &NewTrustedDevice) -> Result<()>;
    pub async fn set_permissions(&self, identity: Fingerprint, permissions: PermissionSet) -> Result<()>;
    pub async fn set_unattended(&self, identity: Fingerprint, enabled: bool) -> Result<()>;
    pub async fn set_suspended(&self, identity: Fingerprint, suspended: bool) -> Result<()>;
    pub async fn record_connection(&self, identity: Fingerprint, address: &str, now_ms: i64) -> Result<()>;
    pub async fn revoke(&self, identity: Fingerprint) -> Result<()>;
}

pub struct NewTrustedDevice {
    pub identity_fingerprint: Fingerprint,
    pub device_id: String,
    pub display_name: String,
    pub os_family: String,
    pub address: String,
    pub permissions: PermissionSet,
    pub unattended: bool,
    pub now_ms: i64,
}
```
- Also produces on `RecentRepository`: `set_known_identity(address, Fingerprint)`, and `RecentConnection::known_identity: Option<Fingerprint>`. `set_always_allow` and the two pin fields are **removed**.

- [ ] **Step 1: Write the failing test**

Create the test module at the bottom of `crates/storage/src/trust.rs`:

```rust
#[cfg(test)]
mod tests {
    use rc_security::{Fingerprint, Permission, PermissionSet};

    use super::*;
    use crate::test_support::temp_database;

    fn identity(byte: u8) -> Fingerprint {
        Fingerprint::from_bytes([byte; 32])
    }

    fn candidate(byte: u8) -> NewTrustedDevice {
        NewTrustedDevice {
            identity_fingerprint: identity(byte),
            device_id: "dev-1".to_owned(),
            display_name: "Gaming PC".to_owned(),
            os_family: "windows".to_owned(),
            address: "192.168.1.77:7443".to_owned(),
            permissions: PermissionSet::NONE.with(Permission::ViewMetrics),
            unattended: false,
            now_ms: 1_700_000_000_000,
        }
    }

    #[tokio::test]
    async fn an_empty_database_trusts_nothing() {
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        assert!(repository.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn trusting_a_device_stores_it_under_its_identity() {
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();

        let found = repository.find(identity(7)).await.unwrap().unwrap();
        assert_eq!(found.display_name, "Gaming PC");
        assert_eq!(found.permissions, PermissionSet::NONE.with(Permission::ViewMetrics));
        assert!(!found.unattended, "trust must not imply unattended access");
        assert!(!found.suspended);
        assert!(
            !found.permissions.contains(Permission::Administer),
            "trust must never imply administrator"
        );
    }

    #[tokio::test]
    async fn a_different_identity_is_a_different_device() {
        // The property the whole design rests on. Same name, same address, different
        // key: not the same device, and not covered by the other's grant.
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();

        assert!(repository.find(identity(8)).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn unattended_and_permissions_move_independently() {
        // Section 6 of the design, asserted rather than described: granting one must
        // leave the other exactly where it was.
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();
        let before = repository.find(identity(7)).await.unwrap().unwrap().permissions;

        repository.set_unattended(identity(7), true).await.unwrap();

        let after = repository.find(identity(7)).await.unwrap().unwrap();
        assert!(after.unattended);
        assert_eq!(after.permissions, before, "permissions must not move with access");

        repository
            .set_permissions(identity(7), PermissionSet::ALL)
            .await
            .unwrap();
        let after = repository.find(identity(7)).await.unwrap().unwrap();
        assert!(after.unattended, "access must not move with permissions");
    }

    #[tokio::test]
    async fn revoking_removes_the_row_entirely() {
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();
        repository.set_unattended(identity(7), true).await.unwrap();

        repository.revoke(identity(7)).await.unwrap();

        assert!(repository.find(identity(7)).await.unwrap().is_none());
        assert!(
            repository.find_by_address("192.168.1.77:7443").await.unwrap().is_none(),
            "nothing about the relationship may survive a revocation"
        );
    }

    #[tokio::test]
    async fn suspending_keeps_the_row_and_its_settings() {
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();
        repository.set_unattended(identity(7), true).await.unwrap();

        repository.set_suspended(identity(7), true).await.unwrap();

        let found = repository.find(identity(7)).await.unwrap().unwrap();
        assert!(found.suspended);
        assert!(found.unattended, "suspension is temporary; settings are retained");
    }

    #[tokio::test]
    async fn trusting_the_same_identity_twice_updates_rather_than_duplicates() {
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();

        let mut again = candidate(7);
        again.display_name = "Renamed".to_owned();
        again.permissions = PermissionSet::ALL;
        repository.trust(&again).await.unwrap();

        let all = repository.list().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].display_name, "Renamed");
        assert_eq!(all[0].permissions, PermissionSet::ALL);
    }

    #[tokio::test]
    async fn find_by_address_answers_the_identity_change_check() {
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();

        let found = repository
            .find_by_address("192.168.1.77:7443")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.identity_fingerprint, identity(7));
        assert!(repository.find_by_address("10.0.0.1:7443").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn recording_a_connection_updates_the_address_and_time_only() {
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();

        repository
            .record_connection(identity(7), "10.0.0.5:7443", 1_700_000_999_000)
            .await
            .unwrap();

        let found = repository.find(identity(7)).await.unwrap().unwrap();
        assert_eq!(found.last_address.as_deref(), Some("10.0.0.5:7443"));
        assert_eq!(found.last_connected_ms, Some(1_700_000_999_000));
        assert_eq!(
            found.permissions,
            PermissionSet::NONE.with(Permission::ViewMetrics),
            "recording a connection must never widen a grant"
        );
        assert!(!found.unattended, "nor may it grant unattended access");
    }

    #[tokio::test]
    async fn administrator_is_stored_as_an_ordinary_permission_bit() {
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();

        repository
            .set_permissions(identity(7), PermissionSet::NONE.with(Permission::Administer))
            .await
            .unwrap();

        assert!(
            repository
                .find(identity(7))
                .await
                .unwrap()
                .unwrap()
                .permissions
                .contains(Permission::Administer)
        );
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p rc-storage trust`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Write the migration and the repository**

Create `crates/storage/migrations/0004_device_trust.sql`:

```sql
-- Device-identity trust.
--
-- Persistent access moves off the address it was typed at and onto the device identity
-- it was granted to. The trust key is the SHA-256 of a peer's Ed25519 identity public
-- key, read from the certificate it presents (rc-security::certificate) and therefore
-- proved by the TLS handshake rather than claimed in a message.
--
-- This migration drops two columns, which breaks the additive-only policy that 0003
-- reinstated. It is done once, for one reason: recent_connections.pinned_fingerprint
-- holds a *certificate* digest, and the identity behind it was never recorded, so the
-- new key cannot be derived from the old row. Carrying the columns forward would leave
-- a second, address-keyed answer to "may this device in?", which is exactly the defect
-- being removed. Anything currently pinned must be trusted once more.

-- Devices a human has decided to remember.
--
-- Keyed on the identity, not the address: a device reached at a new address is the same
-- device and keeps its grant, and a different device answering at a familiar address is
-- a stranger.
CREATE TABLE trusted_devices (
    identity_fingerprint TEXT    NOT NULL PRIMARY KEY,
    -- The peer's self-reported device id. Display only; never used to decide anything.
    device_id            TEXT    NOT NULL,
    display_name         TEXT    NOT NULL,
    os_family            TEXT    NOT NULL,
    -- Where it last connected from. Shown to the operator, and used to detect a
    -- different device answering at a trusted device's address. NEVER authenticates.
    last_address         TEXT,
    added_ms             INTEGER NOT NULL,
    last_connected_ms    INTEGER,
    -- How the device gets in: may it reconnect without anyone approving?
    unattended           INTEGER NOT NULL DEFAULT 0,
    -- Temporarily refused, with the row and every setting on it retained.
    suspended            INTEGER NOT NULL DEFAULT 0,
    -- What an admitted session may do, including bit 4, Administer. Separate from
    -- `unattended` on purpose: how a device gets in says nothing about what it may do.
    permissions          INTEGER NOT NULL DEFAULT 0,

    CHECK (length(identity_fingerprint) = 64),
    CHECK (length(device_id) BETWEEN 1 AND 128),
    CHECK (length(display_name) BETWEEN 1 AND 255),
    CHECK (length(os_family) BETWEEN 1 AND 32),
    CHECK (last_address IS NULL OR length(last_address) BETWEEN 1 AND 255),
    CHECK (added_ms > 0),
    CHECK (last_connected_ms IS NULL OR last_connected_ms > 0),
    CHECK (unattended IN (0, 1)),
    CHECK (suspended IN (0, 1)),
    CHECK (permissions BETWEEN 0 AND 15)
) STRICT;

CREATE INDEX idx_trusted_devices_last_address ON trusted_devices (last_address);

-- What happened, so Sessions can show it. Capped by the writer, not by the schema.
CREATE TABLE session_history (
    id                   INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    session_id           TEXT,
    identity_fingerprint TEXT,
    device_name          TEXT    NOT NULL,
    direction            TEXT    NOT NULL,
    address              TEXT    NOT NULL,
    started_ms           INTEGER NOT NULL,
    ended_ms             INTEGER,
    permissions          INTEGER NOT NULL DEFAULT 0,
    outcome              TEXT    NOT NULL,
    end_reason           TEXT,

    CHECK (identity_fingerprint IS NULL OR length(identity_fingerprint) = 64),
    CHECK (length(device_name) BETWEEN 1 AND 255),
    CHECK (direction IN ('incoming', 'outgoing')),
    CHECK (length(address) BETWEEN 1 AND 255),
    CHECK (started_ms > 0),
    CHECK (ended_ms IS NULL OR ended_ms >= started_ms),
    CHECK (permissions BETWEEN 0 AND 15),
    CHECK (outcome IN ('completed', 'refused', 'failed'))
) STRICT;

CREATE INDEX idx_session_history_started ON session_history (started_ms DESC);

-- Unattended permissions may now carry the Administer bit.
--
-- SQLite cannot alter a CHECK in place, so the single-row table is rebuilt. The row is
-- carried across verbatim; nothing is re-decided.
CREATE TABLE host_settings_new (
    id                     INTEGER NOT NULL PRIMARY KEY,
    accepting              INTEGER NOT NULL DEFAULT 1,
    listen_port            INTEGER NOT NULL DEFAULT 7443,
    machine_name           TEXT    NOT NULL,
    unattended_phc         TEXT,
    unattended_permissions INTEGER NOT NULL DEFAULT 0,

    CHECK (id = 1),
    CHECK (accepting IN (0, 1)),
    CHECK (listen_port BETWEEN 1 AND 65535),
    CHECK (length(machine_name) BETWEEN 1 AND 255),
    CHECK (unattended_permissions BETWEEN 0 AND 15),
    CHECK (unattended_phc IS NOT NULL OR unattended_permissions = 0)
) STRICT;

INSERT INTO host_settings_new
    (id, accepting, listen_port, machine_name, unattended_phc, unattended_permissions)
SELECT id, accepting, listen_port, machine_name, unattended_phc, unattended_permissions
FROM host_settings;

DROP TABLE host_settings;
ALTER TABLE host_settings_new RENAME TO host_settings;

-- recent_connections keeps its address key -- it is the outgoing dial history, and the
-- address is what the user types. The pin columns go; an identity the client verifies on
-- every subsequent connection replaces them.
CREATE TABLE recent_connections_new (
    address           TEXT    NOT NULL PRIMARY KEY,
    machine_name      TEXT    NOT NULL,
    last_connected_ms INTEGER NOT NULL,
    -- Recorded on the first successful outgoing connection and verified thereafter, so
    -- the client pins an identity rather than a certificate that will be renewed.
    known_identity    TEXT,

    CHECK (length(address) BETWEEN 1 AND 255),
    CHECK (length(machine_name) BETWEEN 1 AND 255),
    CHECK (last_connected_ms > 0),
    CHECK (known_identity IS NULL OR length(known_identity) = 64)
) STRICT;

INSERT INTO recent_connections_new (address, machine_name, last_connected_ms)
SELECT address, machine_name, last_connected_ms FROM recent_connections;

DROP TABLE recent_connections;
ALTER TABLE recent_connections_new RENAME TO recent_connections;

CREATE INDEX idx_recent_connections_last_connected
    ON recent_connections (last_connected_ms DESC);
```

Create `crates/storage/src/trust.rs` with the module doc, the two structs and the repository. The doc comment must record the two rules the tests pin:

```rust
//! Devices a human has decided to remember.
//!
//! Keyed on the **identity fingerprint** — the SHA-256 of the peer's Ed25519 identity
//! public key, read from the certificate it presented. Not on an address, and not on a
//! certificate digest: an address is not an identity, and a certificate is a credential
//! the identity rotates for itself.
//!
//! # Two columns that must never move together
//!
//! `unattended` answers *how a device gets in*. `permissions` answers *what it may do*.
//! [`TrustRepository::set_unattended`] and [`TrustRepository::set_permissions`] each
//! write exactly one of them. Granting a laptop unattended access to a desktop must not
//! widen a single permission bit, and granting Administrator must not let anything in
//! that was not already allowed in.
//!
//! # `record_connection` never grants
//!
//! It runs on every admitted connection to keep the address and time current, and it
//! writes neither `unattended` nor `permissions`. If it did, a device whose grant a
//! human had narrowed would silently regain it by reconnecting — the same trap
//! `RecentRepository::record` documents.
```

Implement each method as a single statement, converting `Fingerprint` with `.to_hex()` on the way in and `parse::<Fingerprint>()` on the way out via a `TrustedDeviceRaw` `TryFrom`, following `recent.rs:164-205` exactly. `trust` is an upsert:

```sql
INSERT INTO trusted_devices
    (identity_fingerprint, device_id, display_name, os_family, last_address,
     added_ms, last_connected_ms, unattended, suspended, permissions)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
ON CONFLICT(identity_fingerprint) DO UPDATE SET
    device_id = excluded.device_id,
    display_name = excluded.display_name,
    os_family = excluded.os_family,
    last_address = excluded.last_address,
    last_connected_ms = excluded.last_connected_ms,
    unattended = excluded.unattended,
    permissions = excluded.permissions
```

`record_connection` writes only `last_address` and `last_connected_ms`. `set_permissions`, `set_unattended` and `set_suspended` each `UPDATE` one column and return `StorageError::NotFound` when `rows_affected() == 0`. `find_by_address` selects `WHERE last_address = ?`.

In `crates/storage/src/recent.rs`, delete `set_always_allow`, delete the `pinned_fingerprint` and `pinned_permissions` fields and their raw-row mapping, add `known_identity: Option<Fingerprint>` with the same `TryFrom` treatment, and add:

```rust
    /// Record the identity this address is now known to have.
    ///
    /// Written on the first successful connection and compared on every later one, so a
    /// substituted machine at a familiar address is visible rather than silent.
    ///
    /// # Errors
    /// [`crate::StorageError::NotFound`] if the address has no recorded connection.
    pub async fn set_known_identity(&self, address: &str, identity: Fingerprint) -> Result<()> {
```

Delete the two `recent.rs` tests covering `set_always_allow` and replace them with one asserting `set_known_identity` round-trips, and one asserting `record` leaves `known_identity` untouched.

In `crates/storage/src/lib.rs`: `pub mod trust;`, `pub use trust::{NewTrustedDevice, TrustRepository, TrustedDevice};`, and `SUPPORTED_SCHEMA_VERSION` from `3` to `4`. Fix `repo_tests.rs` and the `lib.rs` tests that reference the dropped columns.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p rc-storage`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/storage
git commit -m "feat(storage): key trust on device identity rather than on an address

trusted_devices is keyed on the identity fingerprint, so a device reached at a
new address keeps its grant and a stranger answering at a familiar address does
not inherit one. unattended and permissions are separate columns written by
separate methods, and record_connection writes neither.

Drops recent_connections' two pin columns. They hold a certificate digest whose
identity was never recorded, so they cannot be migrated; keeping them would
leave a second, address-keyed answer to the admission question.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 5: The session log

**Files:**
- Create: `crates/storage/src/history.rs`
- Modify: `crates/storage/src/lib.rs`
- Test: in-module tests in `history.rs`

**Interfaces:**
- Produces:
```rust
pub enum SessionDirection { Incoming, Outgoing }   // as_str -> "incoming" | "outgoing"
pub enum SessionOutcome { Completed, Refused, Failed }  // as_str -> "completed" | ...
pub struct SessionRecord {
    pub id: i64,
    pub session_id: Option<String>,
    pub identity_fingerprint: Option<Fingerprint>,
    pub device_name: String,
    pub direction: SessionDirection,
    pub address: String,
    pub started_ms: i64,
    pub ended_ms: Option<i64>,
    pub permissions: PermissionSet,
    pub outcome: SessionOutcome,
    pub end_reason: Option<String>,
}
pub struct NewSessionRecord { /* same, without id */ }
impl SessionHistoryRepository {
    pub fn new(database: &Database) -> Self;
    pub async fn record(&self, entry: &NewSessionRecord) -> Result<i64>;
    pub async fn finish(&self, id: i64, ended_ms: i64, outcome: SessionOutcome, end_reason: Option<&str>) -> Result<()>;
    pub async fn list(&self, limit: u32) -> Result<Vec<SessionRecord>>;
}
pub const HISTORY_LIMIT: u32 = 500;
```

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use rc_security::{Fingerprint, Permission, PermissionSet};

    use super::*;
    use crate::test_support::temp_database;

    fn entry(started_ms: i64) -> NewSessionRecord {
        NewSessionRecord {
            session_id: Some("ses-1".to_owned()),
            identity_fingerprint: Some(Fingerprint::from_bytes([7u8; 32])),
            device_name: "Gaming PC".to_owned(),
            direction: SessionDirection::Incoming,
            address: "192.168.1.77:7443".to_owned(),
            started_ms,
            permissions: PermissionSet::NONE.with(Permission::ViewMetrics),
            outcome: SessionOutcome::Completed,
            end_reason: None,
        }
    }

    #[tokio::test]
    async fn a_recorded_session_comes_back_with_what_it_held() {
        let database = temp_database().await;
        let repository = SessionHistoryRepository::new(&database);
        repository.record(&entry(1_700_000_000_000)).await.unwrap();

        let all = repository.list(50).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].device_name, "Gaming PC");
        assert_eq!(all[0].direction, SessionDirection::Incoming);
        assert_eq!(all[0].permissions, PermissionSet::NONE.with(Permission::ViewMetrics));
        assert!(all[0].ended_ms.is_none(), "a live session has not ended");
    }

    #[tokio::test]
    async fn finishing_a_session_records_when_and_why() {
        let database = temp_database().await;
        let repository = SessionHistoryRepository::new(&database);
        let id = repository.record(&entry(1_700_000_000_000)).await.unwrap();

        repository
            .finish(id, 1_700_000_060_000, SessionOutcome::Completed, Some("user_requested"))
            .await
            .unwrap();

        let record = &repository.list(50).await.unwrap()[0];
        assert_eq!(record.ended_ms, Some(1_700_000_060_000));
        assert_eq!(record.end_reason.as_deref(), Some("user_requested"));
    }

    #[tokio::test]
    async fn a_refused_connection_is_recorded_without_a_session_or_an_identity() {
        // A stranger that was turned away has no session id and no trust row, and the
        // Sessions page still has to be able to show that it happened.
        let database = temp_database().await;
        let repository = SessionHistoryRepository::new(&database);
        let mut refused = entry(1_700_000_000_000);
        refused.session_id = None;
        refused.identity_fingerprint = None;
        refused.outcome = SessionOutcome::Refused;
        refused.permissions = PermissionSet::NONE;

        repository.record(&refused).await.unwrap();

        let record = &repository.list(50).await.unwrap()[0];
        assert_eq!(record.outcome, SessionOutcome::Refused);
        assert!(record.identity_fingerprint.is_none());
    }

    #[tokio::test]
    async fn the_list_is_most_recent_first() {
        let database = temp_database().await;
        let repository = SessionHistoryRepository::new(&database);
        for (started, name) in [(1_000_i64, "OLDEST"), (3_000, "NEWEST"), (2_000, "MIDDLE")] {
            let mut record = entry(started);
            record.device_name = name.to_owned();
            repository.record(&record).await.unwrap();
        }

        let names: Vec<String> = repository
            .list(50)
            .await
            .unwrap()
            .into_iter()
            .map(|record| record.device_name)
            .collect();
        assert_eq!(names, vec!["NEWEST", "MIDDLE", "OLDEST"]);
    }

    #[tokio::test]
    async fn history_is_capped_so_an_unattended_machine_does_not_grow_forever() {
        let database = temp_database().await;
        let repository = SessionHistoryRepository::new(&database);
        for index in 0..(HISTORY_LIMIT + 20) {
            repository.record(&entry(1_000 + i64::from(index))).await.unwrap();
        }

        let all = repository.list(HISTORY_LIMIT + 100).await.unwrap();
        assert_eq!(all.len() as u32, HISTORY_LIMIT);
        assert_eq!(
            all.last().unwrap().started_ms,
            1_000 + i64::from(20),
            "the oldest rows are the ones dropped"
        );
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p rc-storage history`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Write the implementation**

Create `crates/storage/src/history.rs`. `record` inserts, then trims in the same call:

```rust
        sqlx::query(
            "DELETE FROM session_history
             WHERE id NOT IN (
                 SELECT id FROM session_history ORDER BY started_ms DESC, id DESC LIMIT ?
             )",
        )
        .bind(i64::from(HISTORY_LIMIT))
        .execute(&self.pool)
        .await?;
```

`list` is `ORDER BY started_ms DESC, id DESC LIMIT ?`. The two enums get `as_str` and a `FromStr`-style `parse` returning `StorageError::MalformedColumn`, following the `TryFrom` pattern in `recent.rs`. Export from `lib.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p rc-storage`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/storage
git commit -m "feat(storage): record session history, capped at 500 rows

A refused connection has no session id and no trust row and must still be
recordable, so both are nullable. The cap is applied by the writer on every
insert rather than by a job, so an unattended machine cannot grow the table
without bound.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 6: Admission by device identity

**Files:**
- Modify: `crates/host-agent/src/access.rs`
- Test: `crates/host-agent/src/access.rs` in-module tests

**Interfaces:**
- Consumes: `PeerIdentity` (Task 2), `TrustRepository` (Task 4), `Permission::Administer` (Task 3).
- Produces:
  - `ConnectionRequest.identity: PeerIdentity` replaces `fingerprint: Fingerprint`.
  - `AcceptRequest` gains `device_id: String`, `os_family: String`, `identity_fingerprint: Fingerprint`, `trusted: bool`.
  - `AcceptDecision::Accept { permissions: PermissionSet, trust: TrustChoice }`.
  - `pub enum TrustChoice { Once, Remember, RememberUnattended }`.
  - `RefusalReason::Suspended`, collapsing to `WireRefusal::Rejected`.
  - `AccessDeps.trust: &'a TrustRepository` replaces `recent`.

- [ ] **Step 1: Write the failing test**

Replace the pin-related tests in `access.rs` and add these. Keep every existing password, throttle, timing, dialog-concurrency and stale-answer test unchanged.

```rust
    #[tokio::test]
    async fn an_unattended_device_is_admitted_with_exactly_what_it_was_granted() {
        let granted = PermissionSet::NONE.with(Permission::TransferFiles);
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness.trust_device(identity_a(), granted, true).await;

        let outcome = harness.authorize(request_from(identity_a(), None)).await.unwrap();

        assert_eq!(outcome, Authorization::Granted(granted));
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn a_trusted_device_without_unattended_access_still_reaches_the_prompt() {
        // Trust Device and Allow Unattended Access are different decisions. Remembering
        // a machine must not stop it asking.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept {
            permissions: PermissionSet::ALL,
            trust: TrustChoice::Once,
        }))
        .await;
        harness
            .trust_device(identity_a(), PermissionSet::ALL, false)
            .await;

        let outcome = harness.authorize(request_from(identity_a(), None)).await.unwrap();

        assert_eq!(outcome, Authorization::Granted(PermissionSet::ALL));
        assert_eq!(harness.prompt().asked(), 1, "it must still have been asked");
    }

    #[tokio::test]
    async fn the_prompt_is_told_the_device_is_already_trusted() {
        let harness = Harness::new(RecordingPrompt::new(AcceptDecision::Dismiss)).await;
        harness
            .trust_device(identity_a(), PermissionSet::ALL, false)
            .await;

        let _ = harness.authorize(request_from(identity_a(), None)).await.unwrap();

        let seen = harness.prompt().last_request().unwrap();
        assert!(seen.trusted, "a returning device must not look like a stranger");
        assert_eq!(seen.identity_fingerprint, identity_a().identity_fingerprint);
    }

    #[tokio::test]
    async fn a_different_device_cannot_use_another_devices_authorization() {
        // The property the whole change exists for. Device A has unattended access.
        // Device B, presenting its own key from the same address, is a stranger.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness
            .trust_device(identity_a(), PermissionSet::ALL, true)
            .await;

        let outcome = harness.authorize(request_from(identity_b(), None)).await.unwrap();

        assert_ne!(
            outcome,
            Authorization::Granted(PermissionSet::ALL),
            "device B must never be admitted under device A's grant"
        );
    }

    #[tokio::test]
    async fn a_stranger_at_a_trusted_devices_address_is_refused_not_prompted() {
        // The loudest failure the system has, re-anchored. The machine that answers at
        // a trusted address is not the machine that was trusted, and that question must
        // not arrive as a routine click.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept {
            permissions: PermissionSet::ALL,
            trust: TrustChoice::Once,
        }))
        .await;
        harness
            .trust_device(identity_a(), PermissionSet::ALL, true)
            .await;

        let outcome = harness.authorize(request_from(identity_b(), None)).await.unwrap();

        assert_eq!(outcome, Authorization::Refused(RefusalReason::IdentityChanged));
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn a_renewed_certificate_does_not_break_trust() {
        // An ordinary maintenance event on the far side. The certificate fingerprint
        // differs; the identity does not; the device is still the device.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness
            .trust_device(identity_a(), PermissionSet::ALL, true)
            .await;

        let renewed = PeerIdentity {
            certificate_fingerprint: Fingerprint::from_bytes([99u8; 32]),
            ..identity_a()
        };
        let outcome = harness.authorize(request_from(renewed, None)).await.unwrap();

        assert_eq!(outcome, Authorization::Granted(PermissionSet::ALL));
    }

    #[tokio::test]
    async fn a_suspended_device_is_refused_and_never_prompted() {
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept {
            permissions: PermissionSet::ALL,
            trust: TrustChoice::Once,
        }))
        .await;
        harness
            .trust_device(identity_a(), PermissionSet::ALL, true)
            .await;
        harness
            .trust()
            .set_suspended(identity_a().identity_fingerprint, true)
            .await
            .unwrap();

        let outcome = harness.authorize(request_from(identity_a(), None)).await.unwrap();

        assert_eq!(outcome, Authorization::Refused(RefusalReason::Suspended));
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn a_revoked_device_cannot_reconnect_unattended() {
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness
            .trust_device(identity_a(), PermissionSet::ALL, true)
            .await;
        harness
            .trust()
            .revoke(identity_a().identity_fingerprint)
            .await
            .unwrap();

        let outcome = harness.authorize(request_from(identity_a(), None)).await.unwrap();

        assert_eq!(
            outcome,
            Authorization::Refused(RefusalReason::Dismissed),
            "with the grant gone it is a stranger, and the scripted human said no"
        );
    }

    #[tokio::test]
    async fn an_unattended_device_granted_nothing_is_refused_not_given_an_empty_session() {
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness
            .trust_device(identity_a(), PermissionSet::NONE, true)
            .await;

        let outcome = harness.authorize(request_from(identity_a(), None)).await.unwrap();

        assert_eq!(outcome, Authorization::Refused(RefusalReason::Dismissed));
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn administrator_is_never_reachable_from_the_accept_dialog() {
        // Whatever the dialog returns, the Administer bit must not survive it. The
        // dialog is clicked many times a day; authority over the trust database is not
        // something it may confer.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept {
            permissions: PermissionSet::ALL,
            trust: TrustChoice::RememberUnattended,
        }))
        .await;

        let outcome = harness.authorize(request_from(identity_a(), None)).await.unwrap();

        let Authorization::Granted(granted) = outcome else {
            panic!("expected a grant, got {outcome:?}")
        };
        assert!(!granted.contains(Permission::Administer));
        let stored = harness
            .trust()
            .find(identity_a().identity_fingerprint)
            .await
            .unwrap()
            .unwrap();
        assert!(!stored.permissions.contains(Permission::Administer));
    }

    #[tokio::test]
    async fn allow_once_persists_nothing() {
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept {
            permissions: PermissionSet::ALL,
            trust: TrustChoice::Once,
        }))
        .await;

        let outcome = harness.authorize(request_from(identity_a(), None)).await.unwrap();

        assert_eq!(outcome, Authorization::Granted(PermissionSet::ALL));
        assert!(
            harness.trust().list().await.unwrap().is_empty(),
            "Accept Once must leave no trace to reconnect against"
        );
    }

    #[tokio::test]
    async fn trust_device_persists_without_granting_unattended_access() {
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept {
            permissions: PermissionSet::NONE.with(Permission::ViewMetrics),
            trust: TrustChoice::Remember,
        }))
        .await;

        let _ = harness.authorize(request_from(identity_a(), None)).await.unwrap();

        let stored = harness
            .trust()
            .find(identity_a().identity_fingerprint)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.permissions, PermissionSet::NONE.with(Permission::ViewMetrics));
        assert!(!stored.unattended, "remembering is not the same as letting in unasked");
    }

    #[tokio::test]
    async fn allow_unattended_access_persists_the_access_too() {
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept {
            permissions: PermissionSet::ALL,
            trust: TrustChoice::RememberUnattended,
        }))
        .await;

        let _ = harness.authorize(request_from(identity_a(), None)).await.unwrap();

        let stored = harness
            .trust()
            .find(identity_a().identity_fingerprint)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.unattended);
    }
```

Add to the test harness:

```rust
    fn identity_a() -> PeerIdentity {
        PeerIdentity {
            certificate_fingerprint: Fingerprint::from_bytes([1u8; 32]),
            identity_fingerprint: Fingerprint::from_bytes([7u8; 32]),
            device_id: rc_protocol::DeviceId::from_uuid(uuid::Uuid::from_u128(1)),
        }
    }

    fn identity_b() -> PeerIdentity {
        PeerIdentity {
            certificate_fingerprint: Fingerprint::from_bytes([2u8; 32]),
            identity_fingerprint: Fingerprint::from_bytes([8u8; 32]),
            device_id: rc_protocol::DeviceId::from_uuid(uuid::Uuid::from_u128(2)),
        }
    }

    fn request_from(identity: PeerIdentity, password: Option<&str>) -> ConnectionRequest {
        ConnectionRequest {
            address: "192.168.1.77:7443".parse::<PeerAddress>().unwrap(),
            identity,
            machine_name: "WORK-LAPTOP".to_owned(),
            os_family: "windows".to_owned(),
            unattended_password: password.map(str::to_owned),
        }
    }
```

and on `Harness`:

```rust
        async fn trust_device(
            &self,
            identity: PeerIdentity,
            permissions: PermissionSet,
            unattended: bool,
        ) {
            self.trust
                .trust(&rc_storage::NewTrustedDevice {
                    identity_fingerprint: identity.identity_fingerprint,
                    device_id: identity.device_id.to_canonical_string(),
                    display_name: "WORK-LAPTOP".to_owned(),
                    os_family: "windows".to_owned(),
                    address: "192.168.1.77:7443".to_owned(),
                    permissions,
                    unattended,
                    now_ms: 1_000,
                })
                .await
                .expect("seeding a trusted device must succeed");
        }

        fn trust(&self) -> &rc_storage::TrustRepository {
            &self.trust
        }
```

`RecordingPrompt` is `ScriptedPrompt` plus `last: Mutex<Option<AcceptRequest>>`, storing the request it was shown and exposing `last_request()`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p rc-host-agent access`
Expected: FAIL — `TrustChoice` and `ConnectionRequest::identity` do not exist.

- [ ] **Step 3: Write the implementation**

Rewrite the identity branch of `authorize_connection`, leaving steps 0, 3 and 4 exactly as they are:

```rust
    // Read once. Two reads could straddle a settings change and decide against two
    // different configurations within one connection.
    let settings = deps.settings.load().await?;
    if !settings.accepting {
        return Ok(Authorization::Refused(RefusalReason::NotAccepting));
    }

    let key = request.address.to_string();
    let identity = request.identity.identity_fingerprint;

    // 1. A decision a human already took about *this device*, found by the identity it
    //    proved rather than by the address it arrived from.
    if let Some(device) = deps.trust.find(identity).await? {
        if device.suspended {
            return Ok(Authorization::Refused(RefusalReason::Suspended));
        }
        if device.unattended {
            deps.trust.record_connection(identity, &key, deps.clock.now_ms()).await?;
            return Ok(grant_or_refuse(device.permissions));
        }
        // Trusted, but not for unattended access. That is a decision to remember the
        // machine, not a decision to let it in unasked, so it falls through to the
        // human below — carrying the fact that it is known.
    } else if let Some(known) = deps.trust.find_by_address(&key).await?
        && !known.identity_fingerprint.ct_eq(&identity)
    {
        // Something else is answering where a trusted device used to. That is either a
        // reinstall or a substitution, and both need a deliberate decision — never a
        // routine click on a dialog people answer many times a day.
        return Ok(Authorization::Refused(RefusalReason::IdentityChanged));
    }
```

The human branch gains the trust write. Note that `Administer` is stripped in exactly one place, so no future branch can reintroduce it:

```rust
    let trusted = deps.trust.find(identity).await?.is_some();
    let answer = deps
        .prompt
        .ask(AcceptRequest {
            request_id: request_id.clone(),
            address: key.clone(),
            identity_fingerprint: identity,
            device_id: request.identity.device_id.to_canonical_string(),
            machine_name: request.machine_name.clone(),
            os_family: request.os_family.clone(),
            trusted,
        })
        .await;

    if answer.request_id != request_id {
        return Ok(Authorization::Refused(RefusalReason::Dismissed));
    }

    let AcceptDecision::Accept { permissions, trust } = answer.decision else {
        return Ok(Authorization::Refused(RefusalReason::Dismissed));
    };

    // The dialog can never confer authority over the trust database. Stripped here,
    // once, rather than trusted not to be set by whatever implements the prompt.
    let permissions = permissions.without(Permission::Administer);

    let outcome = grant_or_refuse(permissions);
    if let Authorization::Granted(granted) = outcome
        && matches!(trust, TrustChoice::Remember | TrustChoice::RememberUnattended)
    {
        deps.trust
            .trust(&rc_storage::NewTrustedDevice {
                identity_fingerprint: identity,
                device_id: request.identity.device_id.to_canonical_string(),
                display_name: request.machine_name.clone(),
                os_family: request.os_family.clone(),
                address: key,
                permissions: granted,
                unattended: matches!(trust, TrustChoice::RememberUnattended),
                now_ms: deps.clock.now_ms(),
            })
            .await?;
    }

    Ok(outcome)
```

Add `Suspended` to `RefusalReason` and to the `From` impl's `Rejected` arm, with a comment: a peer that could tell "suspended" from "rejected" would learn it is known to this machine, which is exactly what a revoked device must not learn. Extend `a_wire_refusal_does_not_distinguish_a_wrong_password_from_a_dismissal` to cover it.

Update the module doc comment to describe four ways in, and `docs/access-model.md` accordingly — that documentation edit belongs in this commit, not a later one.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p rc-host-agent`
Expected: PASS, including every retained password, throttle and dialog-concurrency test.

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/host-agent/src/access.rs docs/access-model.md
git commit -m "feat(host-agent): admit connections by device identity

Trust is looked up by the identity a peer proved through TLS. A device reached
at a new address keeps its grant; a different device at a trusted device's
address is refused as IdentityChanged rather than prompted; a renewed
certificate is no longer an identity change at all.

Trust Device and Allow Unattended Access become different outcomes, and the
Administer bit is stripped from whatever the dialog returns -- in one place, so
a future branch cannot reintroduce it.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 7: Wire the new admission into both hosts

**Files:**
- Modify: `crates/host-agent/src/server.rs`, `crates/host-agent/src/main.rs`
- Modify: `apps/desktop-client/src-tauri/src/host.rs`, `apps/desktop-client/src-tauri/src/host_commands.rs`, `apps/desktop-client/src-tauri/src/lib.rs`
- Test: `crates/host-agent/tests/access_e2e.rs`

**Interfaces:**
- Consumes: everything from Tasks 2, 4, 6.
- Produces: `AcceptRequestDto` gains `deviceId`, `osFamily`, `identityFingerprint`, `trusted`; `answer_accept_request` takes `trust: TrustChoice` as a camelCase string `"once" | "remember" | "remember_unattended"`.

- [ ] **Step 1: Write the failing test**

Add to `crates/host-agent/tests/access_e2e.rs`, alongside the existing nine cases and using the same helpers:

```rust
#[tokio::test]
async fn a_device_with_unattended_access_is_admitted_without_a_prompt_after_a_restart() {
    // Persistence asserted against the real binary rather than against the table: the
    // agent is stopped and started, and the device connects again.
    let fixture = AgentFixture::start().await;
    let client = TestClient::generate();
    fixture
        .seed_trusted_device(&client, PermissionSet::ALL, true)
        .await;

    let first = client.connect(&fixture).await.expect("must be admitted");
    assert_eq!(first.permissions, PermissionSet::ALL);
    drop(first);

    let fixture = fixture.restart().await;

    let second = client.connect(&fixture).await.expect("trust must survive a restart");
    assert_eq!(second.permissions, PermissionSet::ALL);
    assert_eq!(fixture.prompts_raised(), 0, "no human was ever asked");
}

#[tokio::test]
async fn a_revoked_device_is_refused_after_a_restart() {
    // Revocation must invalidate the authorization, not merely hide a row.
    let fixture = AgentFixture::start().await;
    let client = TestClient::generate();
    fixture
        .seed_trusted_device(&client, PermissionSet::ALL, true)
        .await;
    fixture.revoke(&client).await;

    let fixture = fixture.restart().await;

    let outcome = client.connect(&fixture).await;
    assert!(outcome.is_err(), "a revoked device must not get back in");
}

#[tokio::test]
async fn a_second_device_cannot_reuse_the_first_devices_grant() {
    let fixture = AgentFixture::start().await;
    let trusted = TestClient::generate();
    let stranger = TestClient::generate();
    fixture
        .seed_trusted_device(&trusted, PermissionSet::ALL, true)
        .await;

    let outcome = stranger.connect(&fixture).await;

    assert!(
        outcome.is_err(),
        "holding a different key must mean holding no grant"
    );
}
```

`AgentFixture` gains `seed_trusted_device`, `revoke`, `restart` (stop the process, reuse the same database path, start again) and `prompts_raised`. `TestClient::generate` builds a real `DeviceIdentity` so each test client presents a genuinely different key.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p rc-host-agent --test access_e2e`
Expected: FAIL — the fixture helpers do not exist.

- [ ] **Step 3: Write the implementation**

In `crates/host-agent/src/server.rs`, at the point the connection is accepted, build the identity before anything else and refuse a connection that has none:

```rust
    let der = rc_transport::tls::peer_certificate_der(&connection)?;
    let Ok(identity) = rc_transport::PeerIdentity::from_certificate_der(&der) else {
        tracing::warn!("refusing a peer whose certificate carries no identity key");
        return Err(/* the crate's refusal path */);
    };
```

Pass `identity` to `accept_handshake`, and inside the `authorize` closure build the new `ConnectionRequest` with `identity`, `machine_name` and `os_family` from the `Hello` descriptor. Construct `AccessDeps` with `trust: &trust_repository`. Record `session_history` on admission and on refusal, and call `SessionHistoryRepository::finish` when the session ends.

In `apps/desktop-client/src-tauri/src/host.rs`, mirror the same construction, extend `AcceptRequestDto` with the four new fields, and change `answer_accept_request` to carry a `TrustChoice`. `AcceptDecision::Accept { permissions, trust }` replaces the tuple variant throughout.

Register `TrustRepository` and `SessionHistoryRepository` in the Tauri managed state in `lib.rs`, beside the existing repositories.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --workspace -- --test-threads=1`
Expected: PASS, including all twelve `access_e2e` cases.

- [ ] **Step 5: Commit**

```bash
git add crates/host-agent apps/desktop-client/src-tauri/src
git commit -m "feat: admit by identity in both the agent and the desktop host

Both doors build a PeerIdentity from the certificate the peer presented and
refuse a connection whose certificate carries no identity key. Trust and
revocation are asserted against the real rc-agent binary across a restart.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 8: The administrator surface

**Files:**
- Modify: `crates/protocol/src/control.rs`
- Create: `crates/host-agent/src/trust_service.rs`
- Modify: `crates/host-agent/src/lib.rs`, `crates/host-agent/src/server.rs`
- Test: in-module tests in `trust_service.rs`

**Interfaces:**
- Produces on `ControlRequestPayload`: `ListTrustedDevices`, `SetDevicePermissions { identity: String, permissions: WirePermissions }`, `SetUnattendedAccess { identity: String, enabled: bool }`, `RevokeDevice { identity: String }`.
- Produces on `ControlResponsePayload`: `TrustedDevices(Box<Vec<TrustedDeviceSummary>>)`.
- Produces `rc_host_agent::trust_service::TrustService::new(TrustRepository, Fingerprint) -> Self` where the second argument is **the identity of the session being served**, and `handle(&self, session: &Session, payload: &ControlRequestPayload) -> Result<ControlResponsePayload>`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use rc_security::{Fingerprint, Permission, PermissionSet};

    use super::*;

    fn caller() -> Fingerprint { Fingerprint::from_bytes([1u8; 32]) }
    fn other() -> Fingerprint { Fingerprint::from_bytes([2u8; 32]) }

    #[tokio::test]
    async fn a_session_without_administer_is_refused_every_request() {
        // Re-checked per request like every other permission, so a grant withdrawn
        // mid-session stops being answered immediately.
        let harness = Harness::new().await;
        let session = Session::new(PermissionSet::ALL.without(Permission::Administer));

        for payload in harness.every_admin_request(other()) {
            let error = harness.service().handle(&session, &payload).await.unwrap_err();
            assert!(
                matches!(error, AccessError::PermissionDenied { .. }),
                "got {error:?} for {payload:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_admin_session_can_read_and_change_another_device() {
        let harness = Harness::new().await;
        harness.seed(other(), PermissionSet::NONE, false).await;
        let session = Session::new(PermissionSet::NONE.with(Permission::Administer));

        harness
            .service()
            .handle(
                &session,
                &ControlRequestPayload::SetUnattendedAccess {
                    identity: other().to_hex(),
                    enabled: true,
                },
            )
            .await
            .unwrap();

        assert!(harness.stored(other()).await.unattended);
    }

    #[tokio::test]
    async fn an_admin_session_cannot_modify_its_own_trust_row() {
        // Without this an administrator could grant itself unattended access it was
        // never given, or make itself un-revokable. The three mutating requests must
        // all refuse, not just the obvious one.
        let harness = Harness::new().await;
        harness.seed(caller(), PermissionSet::NONE.with(Permission::Administer), false).await;
        let session = Session::new(PermissionSet::NONE.with(Permission::Administer));

        for payload in harness.every_mutating_request(caller()) {
            let error = harness.service().handle(&session, &payload).await.unwrap_err();
            assert!(
                matches!(error, AccessError::PermissionDenied { .. }),
                "self-modification must be refused, got {error:?} for {payload:?}"
            );
        }

        let unchanged = harness.stored(caller()).await;
        assert!(!unchanged.unattended);
        assert!(unchanged.permissions.contains(Permission::Administer));
    }

    #[tokio::test]
    async fn revoking_another_device_removes_it() {
        let harness = Harness::new().await;
        harness.seed(other(), PermissionSet::ALL, true).await;
        let session = Session::new(PermissionSet::NONE.with(Permission::Administer));

        harness
            .service()
            .handle(&session, &ControlRequestPayload::RevokeDevice { identity: other().to_hex() })
            .await
            .unwrap();

        assert!(harness.find(other()).await.is_none());
    }

    #[tokio::test]
    async fn a_listing_carries_no_credential() {
        // There is no credential attached to a trust relationship, and the summary must
        // not invent one. This guards against a field being added later that does.
        let harness = Harness::new().await;
        harness.seed(other(), PermissionSet::ALL, true).await;
        let session = Session::new(PermissionSet::NONE.with(Permission::Administer));

        let response = harness
            .service()
            .handle(&session, &ControlRequestPayload::ListTrustedDevices)
            .await
            .unwrap();

        let ControlResponsePayload::TrustedDevices(devices) = response else {
            panic!("expected a listing")
        };
        let encoded = format!("{devices:?}").to_lowercase();
        for forbidden in ["password", "secret", "token", "phc", "argon"] {
            assert!(!encoded.contains(forbidden), "a listing must not carry {forbidden}");
        }
    }

    #[tokio::test]
    async fn a_malformed_identity_is_refused_rather_than_matched_loosely() {
        let harness = Harness::new().await;
        let session = Session::new(PermissionSet::NONE.with(Permission::Administer));

        for bad in ["", "not-hex", &"A".repeat(64)] {
            let error = harness
                .service()
                .handle(&session, &ControlRequestPayload::RevokeDevice { identity: bad.to_owned() })
                .await
                .unwrap_err();
            assert!(matches!(error, AccessError::InvalidArgument { .. }), "got {error:?}");
        }
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p rc-host-agent trust_service`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Write the implementation**

Add the four request variants and the response payload to `crates/protocol/src/control.rs`, with `TrustedDeviceSummary` carrying `identity_fingerprint`, `device_id`, `display_name`, `os_family`, `last_address`, `added_ms`, `last_connected_ms`, `unattended`, `suspended`, `permissions: WirePermissions` — and a doc comment stating that no credential exists to carry.

Create `crates/host-agent/src/trust_service.rs`:

```rust
//! Managing trust from a remote session.
//!
//! Every request here is gated on [`Permission::Administer`], re-checked per request
//! like every other permission, so authority withdrawn mid-session stops being answered
//! immediately rather than at the next reconnection.
//!
//! # A session may not modify its own trust row
//!
//! Enforced once, in [`TrustService::guard_target`], for all three mutating requests.
//! Without it an administrator could grant itself unattended access it was never given,
//! or make itself un-revokable — turning one grant into a permanent one. The identity
//! compared against is the one the session was *admitted under*, taken from the
//! connection, never from the request body.
```

`guard_target` parses the hex into a `Fingerprint` (rejecting anything malformed as `InvalidArgument`, which also rejects the uppercase form) and refuses with `PermissionDenied` when it `ct_eq`s the session's own identity. `handle` calls `session.require(Permission::Administer)?` first, then `guard_target` on the three mutating variants, then delegates to the repository.

Dispatch it from `server.rs` beside the metrics and file services.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p rc-host-agent -p rc-protocol`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/protocol/src/control.rs crates/host-agent
git commit -m "feat(host-agent): let an administrator manage trust remotely

Four control requests behind Permission::Administer, re-checked per request. A
session may not target its own trust row: without that, an administrator could
grant itself unattended access it was never given or make itself un-revokable,
so the check is in one place and covers all three mutating requests.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 9: The client pins an identity too

**Files:**
- Modify: `apps/desktop-client/src-tauri/src/connection.rs`
- Test: in-module tests in `connection.rs`

**Interfaces:**
- Consumes: `RecentRepository::set_known_identity`, `PeerIdentity`.
- Produces: `ConnectionState::Refused { reason: RefusalReason::IdentityChanged }` when a dialled address answers with a different identity than the one recorded.

- [ ] **Step 1: Write the failing test**

```rust
    #[tokio::test]
    async fn the_first_connection_to_an_address_records_the_identity_it_answered_with() {
        let harness = ConnectionHarness::new().await;
        harness.complete_connection("10.0.0.1:7443", identity(7)).await.unwrap();

        let recorded = harness.recent().find("10.0.0.1:7443").await.unwrap().unwrap();
        assert_eq!(recorded.known_identity, Some(identity(7)));
    }

    #[tokio::test]
    async fn a_familiar_address_answering_with_a_different_identity_is_refused() {
        // The client side of the property the host enforces. A substituted machine must
        // be visible rather than silently connected to.
        let harness = ConnectionHarness::new().await;
        harness.complete_connection("10.0.0.1:7443", identity(7)).await.unwrap();

        let outcome = harness.complete_connection("10.0.0.1:7443", identity(8)).await;

        assert!(matches!(
            outcome,
            Err(ConnectionError::IdentityChanged { .. })
        ));
    }

    #[tokio::test]
    async fn a_renewed_certificate_at_a_familiar_address_is_accepted() {
        let harness = ConnectionHarness::new().await;
        harness.complete_connection("10.0.0.1:7443", identity(7)).await.unwrap();

        let renewed = PeerIdentity {
            certificate_fingerprint: Fingerprint::from_bytes([42u8; 32]),
            ..identity(7)
        };

        assert!(harness.complete_connection("10.0.0.1:7443", renewed).await.is_ok());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p rc-desktop-client connection`
Expected: FAIL.

- [ ] **Step 3: Write the implementation**

After the outgoing handshake succeeds, derive the server's `PeerIdentity` from its certificate DER, compare against `RecentConnection::known_identity` with `ct_eq`, refuse on mismatch before opening any channel, and record it when absent. The comparison happens before the session is usable, so a substituted machine never receives a request.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p rc-desktop-client`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/desktop-client/src-tauri/src/connection.rs
git commit -m "feat(client): pin the identity behind a dialled address

Recorded on the first successful connection and compared on every later one,
before any channel opens. Certificate renewal on the far side is accepted; a
different machine at a familiar address is refused.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 10: Live inbound sessions and emergency disconnect

**Files:**
- Create: `apps/desktop-client/src-tauri/src/inbound.rs`
- Modify: `apps/desktop-client/src-tauri/src/host.rs`, `lib.rs`
- Test: in-module tests in `inbound.rs`

**Interfaces:**
- Produces:
```rust
pub struct InboundSession {
    pub session_id: String,
    pub identity_fingerprint: String,
    pub device_name: String,
    pub address: String,
    pub permissions: PermissionSet,
    pub started_ms: i64,
}
pub struct InboundRegistry { /* … */ }
impl InboundRegistry {
    pub fn new() -> Self;
    pub fn admit(&self, session: InboundSession) -> InboundGuard;  // released on Drop
    pub fn list(&self) -> Vec<InboundSession>;
    pub fn disconnect(&self, session_id: &str) -> bool;
    pub fn disconnect_all(&self) -> usize;
}
```
- Tauri commands: `inbound_sessions() -> Vec<InboundSessionDto>`, `disconnect_inbound(sessionId) -> bool`, `emergency_disconnect() -> u32` (drops every inbound session **and** sets `accepting = false`).

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn an_admitted_session_is_visible_to_the_person_at_the_keyboard() {
        let registry = InboundRegistry::new();
        let _guard = registry.admit(sample_session("ses-1"));

        let live = registry.list();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].session_id, "ses-1");
    }

    #[test]
    fn a_session_that_ends_stops_being_listed_however_it_ended() {
        // Released on Drop, so a panicking or cancelled handler cannot leave a session
        // on screen that no longer exists.
        let registry = InboundRegistry::new();
        {
            let _guard = registry.admit(sample_session("ses-1"));
            assert_eq!(registry.list().len(), 1);
        }
        assert!(registry.list().is_empty());
    }

    #[test]
    fn emergency_disconnect_drops_every_session() {
        let registry = InboundRegistry::new();
        let _a = registry.admit(sample_session("ses-1"));
        let _b = registry.admit(sample_session("ses-2"));

        assert_eq!(registry.disconnect_all(), 2);
        assert!(registry.list().is_empty());
    }

    #[test]
    fn disconnecting_an_unknown_session_reports_that_rather_than_pretending() {
        let registry = InboundRegistry::new();
        assert!(!registry.disconnect("never-existed"));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p rc-desktop-client inbound`
Expected: FAIL.

- [ ] **Step 3: Write the implementation**

`InboundGuard` holds an `Arc` to the registry and its session id, removing itself in `Drop` — the same reservation pattern `rc_host_agent::sessions` documents, and for the same reason: no path out may leak an entry. `disconnect` and `disconnect_all` fire a `tokio::sync::Notify` per session that the connection task selects on, so a disconnect actually closes the QUIC connection rather than only removing a row. The `emergency_disconnect` command calls `disconnect_all` and then `SettingsRepository::set_accepting(false)` — closing the door as well as the session.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p rc-desktop-client`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/desktop-client/src-tauri/src/inbound.rs apps/desktop-client/src-tauri/src/host.rs apps/desktop-client/src-tauri/src/lib.rs
git commit -m "feat(client): track inbound sessions and add emergency disconnect

Remote control of this machine must never be invisible to the person sitting at
it. Entries are released on Drop, so a cancelled handler cannot leave a session
listed that no longer exists, and emergency disconnect closes the door as well
as the sessions.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 11: Commands and schemas

**Files:**
- Create: `apps/desktop-client/src-tauri/src/trust_commands.rs`
- Modify: `apps/desktop-client/src-tauri/src/lib.rs`, `apps/desktop-client/src/api.ts`
- Test: `apps/desktop-client/src/api.test.ts` (create)

**Interfaces:**
- Produces these commands and their `api.ts` wrappers:

| Command | TypeScript |
|---|---|
| `list_trusted_devices` | `listTrustedDevices(): Promise<TrustedDevice[]>` |
| `set_device_permissions` | `setDevicePermissions(identity, permissions): Promise<null>` |
| `set_device_unattended` | `setDeviceUnattended(identity, enabled): Promise<null>` |
| `set_device_suspended` | `setDeviceSuspended(identity, suspended): Promise<null>` |
| `revoke_device` | `revokeDevice(identity): Promise<null>` |
| `probe_device` | `probeDevice(address): Promise<Presence>` |
| `list_session_history` | `listSessionHistory(): Promise<SessionRecord[]>` |
| `inbound_sessions` | `listInboundSessions(): Promise<InboundSession[]>` |
| `disconnect_inbound` | `disconnectInbound(sessionId): Promise<boolean>` |
| `emergency_disconnect` | `emergencyDisconnect(): Promise<number>` |

- Produces `trustedDeviceSchema`, `sessionRecordSchema`, `inboundSessionSchema`, `presenceSchema = z.enum(['online','offline','checking'])`, and `permissionSchema` extended with `'administer'`.

- [ ] **Step 1: Write the failing test**

Create `apps/desktop-client/src/api.test.ts`:

```ts
import { describe, expect, it } from 'vitest';

import { permissionSchema, trustedDeviceSchema, sessionRecordSchema } from './api.js';

describe('permissionSchema', () => {
  it('knows the administrator permission', () => {
    expect(permissionSchema.safeParse('administer').success).toBe(true);
  });

  it('refuses a permission this build has no control for', () => {
    // The enum is closed on purpose: a backend that learns a permission the
    // interface has not learned must fail validation rather than render a name
    // nobody has written a control for.
    expect(permissionSchema.safeParse('launch_missiles').success).toBe(false);
  });
});

describe('trustedDeviceSchema', () => {
  const valid = {
    identityFingerprint: 'a'.repeat(64),
    deviceId: 'dev-00000000-0000-0000-0000-000000000001',
    displayName: 'Gaming PC',
    osFamily: 'windows',
    lastAddress: '192.168.1.77:7443',
    addedMs: 1_700_000_000_000,
    lastConnectedMs: 1_700_000_060_000,
    unattended: true,
    suspended: false,
    permissions: ['view_metrics'],
  };

  it('accepts a well-formed device', () => {
    expect(trustedDeviceSchema.safeParse(valid).success).toBe(true);
  });

  it('strips a field the backend should never be sending', () => {
    // The schema must not pass through anything resembling a credential, in the
    // same way settingsSchema refuses to carry the unattended password.
    const parsed = trustedDeviceSchema.parse({ ...valid, unattendedPassword: 'hunter2' });
    expect(parsed).not.toHaveProperty('unattendedPassword');
  });

  it('refuses a malformed identity rather than rendering it', () => {
    expect(trustedDeviceSchema.safeParse({ ...valid, identityFingerprint: 'nope' }).success).toBe(
      false,
    );
  });

  it('sanitises a display name chosen by the other machine', () => {
    // A name is chosen by whoever owns that machine. A bidi override in it would
    // render as a different name than it is.
    const parsed = trustedDeviceSchema.parse({ ...valid, displayName: 'co‮gnp.exe' });
    expect(parsed.displayName).not.toContain('‮');
  });
});

describe('sessionRecordSchema', () => {
  it('accepts a refused connection with no identity and no session', () => {
    const parsed = sessionRecordSchema.safeParse({
      id: 1,
      sessionId: null,
      identityFingerprint: null,
      deviceName: 'Unknown',
      direction: 'incoming',
      address: '10.0.0.9:7443',
      startedMs: 1_700_000_000_000,
      endedMs: null,
      permissions: [],
      outcome: 'refused',
      endReason: null,
    });
    expect(parsed.success).toBe(true);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pnpm --filter @rc/desktop-client test:run api`
Expected: FAIL — `trustedDeviceSchema` is not exported.

- [ ] **Step 3: Write the implementation**

Extend `permissionSchema` to `z.enum(['control_input', 'transfer_files', 'view_metrics', 'administer'])`. Add the schemas, using `untrustedText(64)` for `displayName` and `untrustedText(32)` for `osFamily`, `fingerprintSchema` for identities, and `z.array(permissionSchema)` for permissions. Add the ten wrappers following the existing `call(name, schema, args)` shape exactly.

Create `trust_commands.rs` with the Tauri commands over `TrustRepository`, `SessionHistoryRepository` and `InboundRegistry`, all `#[serde(rename_all = "camelCase")]` DTOs. `probe_device` opens a QUIC connection to the address and **drops it before sending `Authenticate`**, with a 3-second timeout, returning `online` / `offline`; the far side therefore never raises a prompt and never records a session. Register everything in `lib.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pnpm --filter @rc/desktop-client test:run && cargo test -p rc-desktop-client`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/desktop-client
git commit -m "feat(client): expose trust, history, presence and inbound sessions over IPC

The presence probe drops the connection before Authenticate, so checking whether
a device is reachable never raises a prompt on it and never records a session.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 12: Navigation

**Files:**
- Create: `apps/desktop-client/src/navigation.ts`, `apps/desktop-client/src/AppShell.tsx`
- Modify: `apps/desktop-client/src/App.tsx`, `apps/desktop-client/src/index.css`
- Delete: `apps/desktop-client/src/AppSidebar.tsx`
- Test: `apps/desktop-client/src/appShell.test.tsx` (create)

**Interfaces:**
- Produces:
```ts
export type View = 'remote-control' | 'my-devices' | 'sessions' | 'settings';
export const VIEWS: readonly { id: View; label: string; icon: LucideIcon }[];
export function AppShell(props: {
  view: View;
  onNavigate: (view: View) => void;
  banner: React.ReactNode;
  children: React.ReactNode;
}): React.JSX.Element;
```

- [ ] **Step 1: Write the failing test**

```tsx
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { AppShell } from './AppShell';

describe('AppShell', () => {
  it('offers exactly the four categories', () => {
    render(
      <AppShell view="remote-control" onNavigate={vi.fn()} banner={null}>
        <p>content</p>
      </AppShell>,
    );

    const nav = screen.getByRole('navigation', { name: 'Main' });
    const items = within(nav).getAllByRole('button');
    expect(items.map((item) => item.textContent)).toEqual([
      'Remote Control',
      'My Devices',
      'Sessions',
      'Settings',
    ]);
  });

  it('marks the current category so it is obvious which one you are on', () => {
    render(
      <AppShell view="sessions" onNavigate={vi.fn()} banner={null}>
        <p>content</p>
      </AppShell>,
    );

    expect(screen.getByRole('button', { name: 'Sessions' })).toHaveAttribute(
      'aria-current',
      'page',
    );
    expect(screen.getByRole('button', { name: 'My Devices' })).not.toHaveAttribute('aria-current');
  });

  it('navigates when a category is chosen', async () => {
    const onNavigate = vi.fn();
    render(
      <AppShell view="remote-control" onNavigate={onNavigate} banner={null}>
        <p>content</p>
      </AppShell>,
    );

    await userEvent.click(screen.getByRole('button', { name: 'My Devices' }));

    expect(onNavigate).toHaveBeenCalledWith('my-devices');
  });

  it('has no disabled navigation item', () => {
    // Every category must lead somewhere. A permanently disabled item is a
    // placeholder, which is the thing this rework removes.
    render(
      <AppShell view="remote-control" onNavigate={vi.fn()} banner={null}>
        <p>content</p>
      </AppShell>,
    );

    const nav = screen.getByRole('navigation', { name: 'Main' });
    for (const item of within(nav).getAllByRole('button')) {
      expect(item).toBeEnabled();
    }
  });

  it('renders a banner above the content when one is given', () => {
    render(
      <AppShell view="remote-control" onNavigate={vi.fn()} banner={<p>someone is connected</p>}>
        <p>content</p>
      </AppShell>,
    );

    expect(screen.getByText('someone is connected')).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pnpm --filter @rc/desktop-client test:run appShell`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

`navigation.ts` holds the `View` union and `VIEWS` (icons: `MonitorSmartphone`, `HardDrive`, `Activity`, `Settings` from lucide-react). `AppShell` renders a 216px labelled sidebar with the product mark at the top, the four items, the current one filled with `bg-(--color-accent-soft) text-(--color-accent)` and `aria-current="page"`, a `<main>` region keyed on `view` so React remounts it, and the `animate-view-in` class for the transition.

Add to `index.css` under `@layer utilities`:

```css
  /* A page change should settle rather than swap. Reduced motion is honoured by
     the global rule above, which clamps every animation duration. */
  @keyframes rc-view-in {
    from {
      opacity: 0;
      transform: translateY(6px);
    }
    to {
      opacity: 1;
      transform: none;
    }
  }

  .animate-view-in {
    animation: rc-view-in 180ms var(--ease-ui) both;
  }
```

In `App.tsx`, replace `MainWindow` and the `settingsOpen` boolean with `const [view, setView] = useState<View>('remote-control')` and an `AppShell` wrapping a switch over the four pages. Delete `AppSidebar.tsx`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pnpm --filter @rc/desktop-client test:run`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/desktop-client/src
git rm apps/desktop-client/src/AppSidebar.tsx
git commit -m "feat(ui): four navigation categories, each of which leads somewhere

Replaces the icon rail whose Devices item scrolled the page and whose Sessions
and File transfer items were permanently disabled. A test asserts no navigation
item is disabled, so a placeholder cannot come back quietly.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 13: The Remote Control page

**Files:**
- Create: `apps/desktop-client/src/RemoteControlPage.tsx`, `apps/desktop-client/src/ThisDevice.tsx`, `apps/desktop-client/src/DeviceCard.tsx`
- Delete: `RemoteDeskCard.tsx`, `ThisDeskCard.tsx`, `RecentList.tsx`, `TrustedDevices.tsx`, `MainWindow.tsx`, `mainWindow.test.tsx`
- Test: `apps/desktop-client/src/remoteControl.test.tsx`, `apps/desktop-client/src/thisDevice.test.tsx`

**Interfaces:**
- Consumes: `connectToAddress`, `getHostStatus`, `setAccepting`, `getLocalIdentity`, `listRecent`, `listTrustedDevices`, `describeConnectionState`, `isBusy`.
- Produces: `RemoteControlPage({ connection, onConnected, onToast, onViewAllDevices })`, `ThisDevice({ status, identity, os, onToggleAccepting, toggling })`, `DeviceCard({ device, presence, onConnect, onOpen, busy })`.

- [ ] **Step 1: Write the failing test**

```tsx
describe('RemoteControlPage', () => {
  it('makes connecting the primary action and does not colour it as a warning', () => {
    renderPage();
    const connect = screen.getByRole('button', { name: 'Connect' });
    expect(connect.className).toContain('--color-accent');
    expect(connect.className).not.toContain('--color-danger');
  });

  it('connects to the address that was typed', async () => {
    const connectToAddress = vi.mocked(api.connectToAddress);
    renderPage();

    await userEvent.type(
      screen.getByLabelText('Device ID, hostname, or IP address'),
      '192.168.1.77',
    );
    await userEvent.click(screen.getByRole('button', { name: 'Connect' }));

    expect(connectToAddress).toHaveBeenCalledWith('192.168.1.77:7443', null);
  });

  it('shows progress while the connection is being made rather than appearing inert', () => {
    renderPage({ connection: { state: 'connecting', address: '192.168.1.77:7443' } });

    expect(screen.getByRole('status')).toHaveTextContent('Connecting to 192.168.1.77:7443…');
    expect(screen.getByRole('button', { name: 'Connect' })).toBeDisabled();
  });

  it('reports a refusal in a way that says what to do about it', () => {
    renderPage({
      connection: {
        state: 'refused',
        reason: 'identity_changed',
        message: 'That machine is not the one you trusted.',
      },
    });

    expect(screen.getByRole('alert')).toHaveTextContent('That machine is not the one you trusted.');
  });

  it('shows at most five recent devices and a way to see the rest', async () => {
    vi.mocked(api.listRecent).mockResolvedValue(
      Array.from({ length: 9 }, (_, index) => ({
        address: `10.0.0.${String(index)}:7443`,
        machineName: `Device ${String(index)}`,
        lastConnectedMs: 1_700_000_000_000 - index,
        knownIdentity: null,
      })),
    );
    renderPage();

    expect(await screen.findAllByTestId('recent-device')).toHaveLength(5);
    expect(screen.getByRole('button', { name: 'View all devices' })).toBeInTheDocument();
  });

  it('offers a compact empty state rather than a large empty container', async () => {
    vi.mocked(api.listRecent).mockResolvedValue([]);
    renderPage();

    expect(await screen.findByText(/no recent devices/i)).toBeInTheDocument();
    expect(screen.queryByTestId('recent-device')).not.toBeInTheDocument();
  });
});

describe('ThisDevice', () => {
  it('leads with the address, because that is what the other machine dials', () => {
    renderThisDevice();
    expect(screen.getByLabelText('Connect using')).toHaveTextContent('192.168.1.77:7443');
  });

  it('shows the device id as an identity to verify, not as something to dial', () => {
    renderThisDevice();
    const id = screen.getByLabelText('Device ID');
    expect(id).toBeInTheDocument();
    expect(screen.getByText(/verify this on the other machine/i)).toBeInTheDocument();
  });

  it('keeps IPv6 and hostname out of the way until they are asked for', async () => {
    renderThisDevice();
    expect(screen.queryByText('fe80::1')).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /advanced network information/i }));

    expect(screen.getByText('fe80::1')).toBeInTheDocument();
  });

  it('turns incoming connections on and off for real', async () => {
    const onToggleAccepting = vi.fn();
    renderThisDevice({ onToggleAccepting });

    await userEvent.click(screen.getByRole('switch', { name: 'Allow incoming connections' }));

    expect(onToggleAccepting).toHaveBeenCalledWith(false);
  });

  it('says it is not reachable when incoming connections are off', () => {
    renderThisDevice({ status: { accepting: false } });
    expect(screen.getByRole('status')).toHaveTextContent('Not accepting connections');
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pnpm --filter @rc/desktop-client test:run remoteControl thisDevice`
Expected: FAIL.

- [ ] **Step 3: Write the implementation**

`RemoteControlPage` renders, in order: a `Card` holding the heading "Connect to a device", the `TextField` labelled `Device ID, hostname, or IP address`, the accent `Connect` button, a `role="status"` line driven by `describeConnectionState`, and a `role="alert"` for `refused`/`failed`; then `ThisDevice`; then a compact recent list capped at five with a `View all devices` button calling `onViewAllDevices`.

`ThisDevice` renders the machine name, a `StatusBadge` reading `Ready for connections` or `Not accepting connections`, a labelled `Connect using` row with the address and a `CopyButton`, a labelled `Device ID` row with `identity.deviceId` formatted in display groups plus the caption `identity — verify this on the other machine`, the `Toggle` for accepting, and a `<details>`-style disclosure containing local IPv4, IPv6, hostname, listen port and connection method from `HostStatus`.

Delete the five superseded components and `mainWindow.test.tsx`, moving any assertion in it that still describes live behaviour into the new suites rather than dropping it.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pnpm --filter @rc/desktop-client test:run`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/desktop-client/src
git rm apps/desktop-client/src/RemoteDeskCard.tsx apps/desktop-client/src/ThisDeskCard.tsx apps/desktop-client/src/RecentList.tsx apps/desktop-client/src/TrustedDevices.tsx apps/desktop-client/src/MainWindow.tsx apps/desktop-client/src/mainWindow.test.tsx
git commit -m "feat(ui): rebuild the home page around connecting

Connect is the visual centre and is accent-coloured, not red. This Device leads
with the address, because that is what the other machine dials, and carries the
device id beneath it as the identity to verify. IPv4, IPv6 and hostname move
into a disclosure -- nobody should need to understand IPv6 to use this.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 14: My Devices

**Files:**
- Create: `MyDevicesPage.tsx`, `DeviceDetail.tsx`, `GrantAdminDialog.tsx`
- Test: `myDevices.test.tsx`, `deviceDetail.test.tsx`

**Interfaces:**
- Consumes: `listTrustedDevices`, `setDevicePermissions`, `setDeviceUnattended`, `setDeviceSuspended`, `revokeDevice`, `probeDevice`.
- Produces: `MyDevicesPage({ onConnect, onToast })`, `DeviceDetail({ device, presence, onChanged, onClose, onToast })`, `GrantAdminDialog({ device, onConfirm, onCancel })`.

- [ ] **Step 1: Write the failing test**

```tsx
describe('MyDevicesPage', () => {
  it('shows a trusted device with what it may do and when it was last used', async () => {
    mockDevices([device({ displayName: 'Gaming PC', osFamily: 'windows', unattended: true })]);
    render(<MyDevicesPage onConnect={vi.fn()} onToast={vi.fn()} />);

    expect(await screen.findByText('Gaming PC')).toBeInTheDocument();
    expect(screen.getByText('Windows')).toBeInTheDocument();
    expect(screen.getByText('Unattended access')).toBeInTheDocument();
    expect(screen.getByText(/last connected/i)).toBeInTheDocument();
  });

  it('shows a device as online only once the probe has said so', async () => {
    mockDevices([device({ lastAddress: '10.0.0.1:7443' })]);
    let resolve: (value: 'online') => void = () => undefined;
    vi.mocked(api.probeDevice).mockReturnValue(new Promise((r) => { resolve = r; }));
    render(<MyDevicesPage onConnect={vi.fn()} onToast={vi.fn()} />);

    expect(await screen.findByText('Checking…')).toBeInTheDocument();
    act(() => { resolve('online'); });
    expect(await screen.findByText('Online')).toBeInTheDocument();
  });

  it('says offline rather than nothing when a device cannot be reached', async () => {
    mockDevices([device({ lastAddress: '10.0.0.1:7443' })]);
    vi.mocked(api.probeDevice).mockResolvedValue('offline');
    render(<MyDevicesPage onConnect={vi.fn()} onToast={vi.fn()} />);

    expect(await screen.findByText('Offline')).toBeInTheDocument();
  });

  it('marks an administrator without shouting about it', async () => {
    mockDevices([device({ permissions: ['view_metrics', 'administer'] })]);
    render(<MyDevicesPage onConnect={vi.fn()} onToast={vi.fn()} />);

    const badge = await screen.findByText('Admin access');
    expect(badge.className).not.toContain('--color-danger');
  });

  it('has a compact empty state when nothing has been trusted yet', async () => {
    mockDevices([]);
    render(<MyDevicesPage onConnect={vi.fn()} onToast={vi.fn()} />);

    expect(await screen.findByText(/no trusted devices yet/i)).toBeInTheDocument();
  });
});

describe('DeviceDetail', () => {
  it('shows access and permissions as separate sections', () => {
    renderDetail();
    expect(screen.getByRole('heading', { name: 'Access' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Permissions' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Security' })).toBeInTheDocument();
  });

  it('offers only the permissions this build actually enforces', () => {
    renderDetail();
    const permissions = within(screen.getByTestId('permissions-section')).getAllByRole('switch');
    expect(permissions.map((s) => s.getAttribute('aria-label'))).toEqual([
      'Keyboard & Mouse',
      'File Transfer',
      'System Metrics',
    ]);
  });

  it('turns unattended access on without touching a permission', async () => {
    const setDeviceUnattended = vi.mocked(api.setDeviceUnattended);
    const setDevicePermissions = vi.mocked(api.setDevicePermissions);
    renderDetail();

    await userEvent.click(screen.getByRole('switch', { name: 'Connect without approval' }));

    expect(setDeviceUnattended).toHaveBeenCalledWith(IDENTITY, true);
    expect(setDevicePermissions).not.toHaveBeenCalled();
  });

  it('never grants administrator without an explicit confirmation', async () => {
    const setDevicePermissions = vi.mocked(api.setDevicePermissions);
    renderDetail();

    await userEvent.click(screen.getByRole('switch', { name: 'Administrator Access' }));

    expect(setDevicePermissions).not.toHaveBeenCalled();
    expect(screen.getByRole('dialog', { name: 'Grant Administrator Access?' })).toBeInTheDocument();
  });

  it('grants administrator only after the confirmation is accepted', async () => {
    const setDevicePermissions = vi.mocked(api.setDevicePermissions);
    renderDetail();
    await userEvent.click(screen.getByRole('switch', { name: 'Administrator Access' }));

    await userEvent.click(screen.getByRole('button', { name: 'Grant Administrator Access' }));

    expect(setDevicePermissions).toHaveBeenCalledWith(
      IDENTITY,
      expect.arrayContaining(['administer']),
    );
  });

  it('leaves administrator alone when the confirmation is cancelled', async () => {
    const setDevicePermissions = vi.mocked(api.setDevicePermissions);
    renderDetail();
    await userEvent.click(screen.getByRole('switch', { name: 'Administrator Access' }));

    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(setDevicePermissions).not.toHaveBeenCalled();
    expect(screen.getByRole('switch', { name: 'Administrator Access' })).not.toBeChecked();
  });

  it('removes administrator without a confirmation, because narrowing is always safe', async () => {
    const setDevicePermissions = vi.mocked(api.setDevicePermissions);
    renderDetail({ permissions: ['view_metrics', 'administer'] });

    await userEvent.click(screen.getByRole('switch', { name: 'Administrator Access' }));

    expect(setDevicePermissions).toHaveBeenCalledWith(IDENTITY, ['view_metrics']);
  });

  it('explains what administrator granted when the indicator is used', async () => {
    renderDetail({ permissions: ['administer'] });

    await userEvent.click(screen.getByRole('button', { name: 'Admin access' }));

    expect(screen.getByRole('dialog')).toHaveTextContent('Manage this machine’s trusted devices');
  });

  it('revokes with a confirmation and colours it as destructive', async () => {
    const revokeDevice = vi.mocked(api.revokeDevice);
    renderDetail();

    const revoke = screen.getByRole('button', { name: 'Revoke Access' });
    expect(revoke.className).toContain('--color-danger');
    await userEvent.click(revoke);
    await userEvent.click(screen.getByRole('button', { name: 'Revoke' }));

    expect(revokeDevice).toHaveBeenCalledWith(IDENTITY);
  });

  it('can suspend a device without revoking it', async () => {
    const setDeviceSuspended = vi.mocked(api.setDeviceSuspended);
    renderDetail();

    await userEvent.click(screen.getByRole('switch', { name: 'Temporarily disable' }));

    expect(setDeviceSuspended).toHaveBeenCalledWith(IDENTITY, true);
    expect(vi.mocked(api.revokeDevice)).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pnpm --filter @rc/desktop-client test:run myDevices deviceDetail`
Expected: FAIL.

- [ ] **Step 3: Write the implementation**

`MyDevicesPage` loads devices, fires `probeDevice` for each with `lastAddress` concurrently, and renders `DeviceCard`s. `DeviceCard` shows an icon, name, presence dot, OS, trust level (`Unattended access` / `Trusted access`), an unobtrusive `Admin access` badge using `--color-text-secondary` on `--color-hover`, the last-connected line, `Connect`, and a `⋯` button opening `DeviceDetail`.

`DeviceDetail` renders the three sections. The `Administrator Access` switch, when turning **on**, opens `GrantAdminDialog` and applies nothing until confirmed; turning **off** applies immediately. `GrantAdminDialog` names the device and lists the privileges being granted, exactly as the design states, with `Cancel` taking initial focus and `Grant Administrator Access` in the danger colour.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pnpm --filter @rc/desktop-client test:run`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/desktop-client/src
git commit -m "feat(ui): My Devices, with access and permissions kept apart

Turning on unattended access touches no permission, and turning on
Administrator applies nothing until a confirmation naming the device and the
privileges is accepted. Removing it needs no confirmation, because narrowing is
always safe. Presence is a real probe with three states, never a fabricated dot.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 15: Sessions

**Files:**
- Create: `SessionsPage.tsx`, `InboundSessionBanner.tsx`
- Modify: `App.tsx`
- Test: `sessions.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
describe('SessionsPage', () => {
  it('separates what is happening now from what already happened', async () => {
    mockInbound([inboundSession({ deviceName: 'Gaming PC' })]);
    mockHistory([record({ deviceName: 'Laptop', outcome: 'completed' })]);
    render(<SessionsPage onToast={vi.fn()} />);

    expect(await screen.findByRole('heading', { name: 'Active Sessions' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Recent Sessions' })).toBeInTheDocument();
    expect(within(screen.getByTestId('active-sessions')).getByText('Gaming PC')).toBeInTheDocument();
    expect(within(screen.getByTestId('recent-sessions')).getByText('Laptop')).toBeInTheDocument();
  });

  it('shows what an active session is permitted to do', async () => {
    mockInbound([inboundSession({ permissions: ['view_metrics', 'transfer_files'] })]);
    render(<SessionsPage onToast={vi.fn()} />);

    expect(await screen.findByText('System Metrics')).toBeInTheDocument();
    expect(screen.getByText('File Transfer')).toBeInTheDocument();
  });

  it('disconnects an active session', async () => {
    const disconnectInbound = vi.mocked(api.disconnectInbound);
    mockInbound([inboundSession({ sessionId: 'ses-1' })]);
    render(<SessionsPage onToast={vi.fn()} />);

    await userEvent.click(await screen.findByRole('button', { name: 'Disconnect' }));

    expect(disconnectInbound).toHaveBeenCalledWith('ses-1');
  });

  it('shows a failed connection as failed rather than omitting it', async () => {
    mockInbound([]);
    mockHistory([record({ deviceName: 'Office PC', outcome: 'refused', endReason: null })]);
    render(<SessionsPage onToast={vi.fn()} />);

    expect(await screen.findByText('Refused')).toBeInTheDocument();
  });

  it('uses a compact empty state rather than a large empty container', async () => {
    mockInbound([]);
    mockHistory([]);
    render(<SessionsPage onToast={vi.fn()} />);

    expect(await screen.findByText(/no sessions yet/i)).toBeInTheDocument();
    expect(screen.queryByTestId('recent-sessions')).not.toBeInTheDocument();
  });
});

describe('InboundSessionBanner', () => {
  it('is absent when nobody is connected', () => {
    render(<InboundSessionBanner sessions={[]} onDisconnect={vi.fn()} onEmergency={vi.fn()} />);
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });

  it('says who is controlling this machine and for how long', () => {
    render(
      <InboundSessionBanner
        sessions={[inboundSession({ deviceName: 'Gaming PC', startedMs: Date.now() - 65_000 })]}
        onDisconnect={vi.fn()}
        onEmergency={vi.fn()}
      />,
    );

    const banner = screen.getByRole('status');
    expect(banner).toHaveTextContent('Gaming PC');
    expect(banner).toHaveTextContent('1m');
  });

  it('offers an emergency disconnect that is coloured as destructive', async () => {
    const onEmergency = vi.fn();
    render(
      <InboundSessionBanner
        sessions={[inboundSession({})]}
        onDisconnect={vi.fn()}
        onEmergency={onEmergency}
      />,
    );

    const button = screen.getByRole('button', { name: 'Emergency Disconnect' });
    expect(button.className).toContain('--color-danger');
    await userEvent.click(button);
    expect(onEmergency).toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pnpm --filter @rc/desktop-client test:run sessions`
Expected: FAIL.

- [ ] **Step 3: Write the implementation**

`SessionsPage` polls `listInboundSessions` every two seconds and loads `listSessionHistory` once, rendering two sections with `data-testid`s, omitting a section entirely when it is empty and showing one shared compact `EmptyState` when both are. Duration comes from a shared `formatDuration` added to `format.ts` with its own tests.

`InboundSessionBanner` renders `null` for an empty list, otherwise a `role="status"` strip above the content in `AppShell`'s banner slot, with per-session `Disconnect` and one `Emergency Disconnect`. Wire it in `App.tsx` from a poll of `listInboundSessions`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pnpm --filter @rc/desktop-client test:run`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/desktop-client/src
git commit -m "feat(ui): Sessions, and a banner while someone is controlling this machine

Remote control of a machine must never be invisible to the person sitting at it,
so the banner sits above every page and carries an emergency disconnect that
closes the door as well as the session.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 16: Settings

**Files:**
- Create: `SettingsPage.tsx`
- Delete: `SettingsDialog.tsx`, `settings.test.tsx` (replaced by `settingsPage.test.tsx`)
- Test: `settingsPage.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
describe('SettingsPage', () => {
  it('organises settings into sections rather than more navigation', async () => {
    render(<SettingsPage onToast={vi.fn()} onViewDevices={vi.fn()} />);

    for (const section of ['Remote Access', 'Security', 'Network', 'Appearance']) {
      expect(await screen.findByRole('heading', { name: section })).toBeInTheDocument();
    }
  });

  it('offers no setting this build cannot honour', async () => {
    // Start with system, start minimized and minimize to tray have no
    // implementation. A switch that changes nothing is the placeholder this
    // rework removes.
    render(<SettingsPage onToast={vi.fn()} onViewDevices={vi.fn()} />);
    await screen.findByRole('heading', { name: 'Remote Access' });

    for (const absent of [/start with system/i, /start minimi[sz]ed/i, /minimi[sz]e to tray/i]) {
      expect(screen.queryByText(absent)).not.toBeInTheDocument();
    }
  });

  it('changes the theme for real', async () => {
    render(<SettingsPage onToast={vi.fn()} onViewDevices={vi.fn()} />);

    await userEvent.click(await screen.findByRole('radio', { name: 'Dark' }));

    expect(document.documentElement.dataset['theme']).toBe('dark');
  });

  it('sets the unattended password through the backend and never renders it back', async () => {
    const setUnattendedPassword = vi.mocked(api.setUnattendedPassword);
    render(<SettingsPage onToast={vi.fn()} onViewDevices={vi.fn()} />);

    await userEvent.type(await screen.findByLabelText('Unattended password'), 'correct horse');
    await userEvent.click(screen.getByRole('button', { name: 'Save password' }));

    expect(setUnattendedPassword).toHaveBeenCalledWith('correct horse', expect.any(Array));
    expect(screen.queryByDisplayValue('correct horse')).not.toBeInTheDocument();
  });

  it('sends you to My Devices rather than duplicating the list', async () => {
    const onViewDevices = vi.fn();
    render(<SettingsPage onToast={vi.fn()} onViewDevices={onViewDevices} />);

    await userEvent.click(await screen.findByRole('button', { name: 'Manage trusted devices' }));

    expect(onViewDevices).toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pnpm --filter @rc/desktop-client test:run settingsPage`
Expected: FAIL.

- [ ] **Step 3: Write the implementation**

`SettingsPage` reuses the existing dialog's data flow (`getHostSettings`, `setAccepting`, `setUnattendedPassword`, the update pane) laid out as four `Card` sections. Security links to My Devices and states the administrator rule in a sentence; Network holds the listen port, the addresses and a diagnostics button running `probeDevice` against this machine's own address; Appearance holds the light/dark/system radio group over the existing `theme.ts`. Move `UpdatesPane` into Network. Delete the dialog.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pnpm --filter @rc/desktop-client test:run`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/desktop-client/src
git rm apps/desktop-client/src/SettingsDialog.tsx apps/desktop-client/src/settings.test.tsx
git commit -m "feat(ui): Settings as a page of sections

General is absent: start with system, start minimized and minimize to tray have
no implementation behind them, and a test asserts they stay absent rather than
returning as switches that change nothing.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 17: The Accept dialog

**Files:**
- Modify: `apps/desktop-client/src/AcceptDialog.tsx`, `acceptDialog.test.tsx`

- [ ] **Step 1: Write the failing test**

Keep every existing test (dismiss-has-focus, Escape refuses, withdrawal removes the dialog) and add:

```tsx
  it('identifies the device that is knocking', async () => {
    await raise({ machineName: 'Koren Laptop', deviceId: 'dev-1', osFamily: 'windows' });

    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveTextContent('Koren Laptop');
    expect(dialog).toHaveTextContent('Windows');
    expect(dialog).toHaveTextContent('dev-1');
  });

  it('says whether this device is already trusted', async () => {
    await raise({ trusted: true });
    expect(screen.getByText('Trusted device')).toBeInTheDocument();
  });

  it('accepts once without remembering anything', async () => {
    const answer = vi.mocked(api.answerAcceptRequest);
    await raise({});

    await userEvent.click(screen.getByRole('button', { name: 'Accept Once' }));

    expect(answer).toHaveBeenCalledWith('req-1', expect.any(Array), 'once');
  });

  it('remembers a device without letting it in unasked', async () => {
    const answer = vi.mocked(api.answerAcceptRequest);
    await raise({});

    await userEvent.click(screen.getByRole('button', { name: 'Accept & Trust' }));

    expect(answer).toHaveBeenCalledWith('req-1', expect.any(Array), 'remember');
  });

  it('does not offer unattended access from the primary buttons', async () => {
    // Permanent access must take a deliberate second act, not fall out of the
    // control people click several times a day.
    await raise({});

    expect(
      screen.queryByRole('button', { name: /allow unattended/i }),
    ).not.toBeInTheDocument();
  });

  it('grants unattended access only after the extra step is taken', async () => {
    const answer = vi.mocked(api.answerAcceptRequest);
    await raise({});

    await userEvent.click(screen.getByRole('button', { name: 'Accept & Trust' }));
    await userEvent.click(screen.getByRole('checkbox', { name: /connect without approval/i }));
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));

    expect(answer).toHaveBeenCalledWith('req-1', expect.any(Array), 'remember_unattended');
  });

  it('never offers administrator', async () => {
    await raise({});
    expect(screen.queryByText(/administrator/i)).not.toBeInTheDocument();
  });

  it('refuses when nothing is ticked rather than opening an empty session', async () => {
    const answer = vi.mocked(api.answerAcceptRequest);
    const dismiss = vi.mocked(api.dismissAcceptRequest);
    await raise({});
    for (const box of screen.getAllByRole('checkbox')) await userEvent.click(box);

    await userEvent.click(screen.getByRole('button', { name: 'Accept Once' }));

    expect(answer).not.toHaveBeenCalled();
    expect(dismiss).toHaveBeenCalledWith('req-1');
  });
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pnpm --filter @rc/desktop-client test:run acceptDialog`
Expected: FAIL.

- [ ] **Step 3: Write the implementation**

Render the device block (name, id, OS, address, identity in display groups, `Trusted device` badge when `trusted`), the three permission checkboxes, then `Reject` (initial focus), `Accept Once` and `Accept & Trust`. Choosing `Accept & Trust` reveals a second panel with the `Connect without approval` checkbox, a sentence explaining that the device will be able to connect with nobody at the keyboard, and a `Confirm` button. `answerAcceptRequest` gains the `trust` argument.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pnpm --filter @rc/desktop-client test:run`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/desktop-client/src
git commit -m "feat(ui): three answers on the Accept dialog, and unattended behind a second step

Accept Once persists nothing. Accept & Trust remembers without letting the
device in unasked. Unattended access is reachable only through an extra
deliberate act, and administrator is not reachable here at all.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 18: Documentation and full verification

**Files:**
- Modify: `docs/access-model.md`, `docs/threat-model.md`, `docs/network-protocol.md`, `README.md`, `PROGRESS.md`

- [ ] **Step 1: Update the documentation**

`access-model.md`: four ways in, the identity anchor, why `IdentityChanged` is now an address-versus-identity mismatch, the `Suspended` collapse into `Rejected`, the four permissions, and the three dialog answers. `threat-model.md`: the trust key is proved by TLS and cannot be claimed; revocation invalidates because there is no bearer credential; the no-self-modification rule. `network-protocol.md`: the four admin requests and the minor bump. `README.md` and `PROGRESS.md`: the four categories, what works, and the un-migratable pins.

- [ ] **Step 2: Run the full verification**

Run: `pnpm verify`
Expected: every step clean. Record the actual test counts.

- [ ] **Step 3: Fix whatever it reports**

Do not adjust a test to make it pass. If a test fails, use superpowers:systematic-debugging.

- [ ] **Step 4: Re-run to confirm**

Run: `pnpm verify`
Expected: clean, and the recorded counts go into `PROGRESS.md`.

- [ ] **Step 5: Commit**

```bash
git add docs README.md PROGRESS.md
git commit -m "docs: describe the identity-anchored access model

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage.** §1 navigation → Task 12. §2 Remote Control → 13. §3 This Device → 13. §4 My Devices → 14. §5 trust options → 6, 17. §6 separation → 3, 4, 14. §7 administrator → 3, 8, 14. §8 permission profiles → 3, 14. §9 detail screen → 14. §10 revoking → 4, 8, 14. §11 Sessions → 5, 15. §12 connection states → 13. §13 Settings → 16. §14 security architecture → 1, 2, 4, 6, 9. §15 incoming UI → 17. §16 visual hierarchy → 12–17. §17 device cards → 13, 14. §18 recent on home → 13. §19 admin indicator → 14. §20 active-session security → 10, 15. §23 tests → distributed, all thirteen present. Restart persistence → 7.

**Type consistency.** `PeerIdentity` is defined in Task 2 and consumed in 6, 7, 9 with the same three fields. `TrustChoice` is defined in 6 and consumed in 7, 17 with the same three variants and the same wire strings. `NewTrustedDevice` field names match between 4, 6 and 7. `permissionSchema` gains `'administer'` in 11 and is used in 14. `Presence` is `'online' | 'offline' | 'checking'` in 11 and 14.

**One gap found and closed:** the spec's §12 "Finding device / Establishing secure connection" sub-states are not separately observable — the client cannot distinguish them without a wire signal the design forbids. Task 13 renders the states the union actually carries, and the design's "Waiting for the remote device…" timer covers the rest. No task promises a state the backend cannot report.
