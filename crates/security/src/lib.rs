//! Security services: device identity, keystore, owner authentication, permissions.
//!
//! This crate owns every secret in the system. The rules it is written to:
//!
//! * **No secret is ever logged.** Types holding key material redact themselves in
//!   [`std::fmt::Debug`] and do not implement [`serde::Serialize`].
//! * **No custom cryptography.** Ed25519 (`ed25519-dalek`), SHA-256 (`sha2`), BLAKE3
//!   for keyed MACs and key derivation, Argon2id for passwords. This crate composes
//!   those primitives; it does not invent any.
//! * **Every comparison of a secret is constant time**, via `subtle`.
//! * **Time and randomness are injected** ([`clock`]), so expiry, throttling and
//!   lockout are tested deterministically while production uses the real clock and the
//!   OS CSPRNG.
//! * **Fail closed.** An unreadable keystore, an unsafe file mode, an unknown format
//!   version or an ambiguous state is an error, never a fallback.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod clock;
pub mod error;
pub mod fingerprint;
pub mod identity;
pub mod keystore;
pub mod password;
pub mod permissions;
pub mod throttle;

pub use clock::{Clock, OsRandom, RandomSource, RandomSourceExt, SystemClock};
pub use error::{Result, SecurityError};
pub use fingerprint::Fingerprint;
pub use identity::{DeviceIdentity, DeviceIdentityPublic, derive_device_id};
pub use keystore::Keystore;
pub use password::{HashingPolicy, OwnerCredential};
pub use permissions::{Permission, PermissionSet};
pub use throttle::{Throttle, ThrottlePolicy};
