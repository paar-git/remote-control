//! Protocol version negotiation.
//!
//! The wire protocol uses a `major.minor` scheme:
//!
//! * **major** — breaking change. Peers with differing majors refuse to talk.
//! * **minor** — additive change. A peer may receive messages it does not know about
//!   and must ignore unknown variants gracefully; the effective feature set is the
//!   minimum of the two minors.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{ProtocolError, Result};

/// Protocol version implemented by this build.
///
/// `1.1` added the `Administer` permission bit and the trust-management requests it
/// gates. The bump is minor rather than major because the additions are ignorable: an
/// older peer never sends them, and a permission set carrying the new bit is *refused*
/// by `PermissionSet::from_bits` rather than silently masked, so the two builds cannot
/// end up reading the same bits as different grants.
pub const CURRENT_VERSION: ProtocolVersion = ProtocolVersion { major: 1, minor: 1 };

/// A `major.minor` protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProtocolVersion {
    /// Breaking-change component.
    pub major: u16,
    /// Additive-change component.
    pub minor: u16,
}

impl ProtocolVersion {
    /// Construct a version.
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Returns `true` when this version can interoperate with `other`.
    ///
    /// Compatibility requires an identical major version. Minor differences are tolerated.
    #[must_use]
    pub const fn is_compatible_with(self, other: Self) -> bool {
        self.major == other.major
    }

    /// The feature level both peers can rely on: same major, lower of the two minors.
    ///
    /// # Errors
    /// Returns [`ProtocolError::IncompatibleVersion`] when the majors differ.
    pub fn negotiate(self, peer: Self) -> Result<Self> {
        if !self.is_compatible_with(peer) {
            return Err(ProtocolError::IncompatibleVersion { peer, ours: self });
        }
        Ok(Self {
            major: self.major,
            minor: self.minor.min(peer.minor),
        })
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_major_is_compatible() {
        assert!(ProtocolVersion::new(1, 0).is_compatible_with(ProtocolVersion::new(1, 7)));
    }

    #[test]
    fn different_major_is_incompatible() {
        assert!(!ProtocolVersion::new(1, 0).is_compatible_with(ProtocolVersion::new(2, 0)));
    }

    #[test]
    fn negotiate_picks_lower_minor() {
        let agreed = ProtocolVersion::new(1, 5)
            .negotiate(ProtocolVersion::new(1, 2))
            .unwrap();
        assert_eq!(agreed, ProtocolVersion::new(1, 2));

        let agreed = ProtocolVersion::new(1, 2)
            .negotiate(ProtocolVersion::new(1, 5))
            .unwrap();
        assert_eq!(agreed, ProtocolVersion::new(1, 2));
    }

    #[test]
    fn negotiate_rejects_major_mismatch() {
        let err = ProtocolVersion::new(1, 0)
            .negotiate(ProtocolVersion::new(2, 0))
            .unwrap_err();
        assert!(matches!(err, ProtocolError::IncompatibleVersion { .. }));
    }

    #[test]
    fn display_is_dotted() {
        assert_eq!(ProtocolVersion::new(3, 14).to_string(), "3.14");
    }
}
