//! Strongly-typed identifiers.
//!
//! Using distinct newtypes rather than bare strings/UUIDs prevents a whole class of
//! insecure-direct-object-reference bugs where, say, a session id is accepted where a
//! device id was meant.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ProtocolError, Result};

macro_rules! uuid_newtype {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Generate a fresh random identifier.
            #[must_use]
            pub fn generate() -> Self {
                Self(Uuid::new_v4())
            }

            /// Wrap an existing UUID.
            #[must_use]
            pub const fn from_uuid(id: Uuid) -> Self {
                Self(id)
            }

            /// Borrow the inner UUID.
            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            /// Textual form used in databases, logs and on the wire.
            #[must_use]
            pub fn to_canonical_string(&self) -> String {
                format!("{}{}", $prefix, self.0.as_hyphenated())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", $prefix, self.0.as_hyphenated())
            }
        }

        impl FromStr for $name {
            type Err = ProtocolError;

            fn from_str(s: &str) -> Result<Self> {
                let raw = s.strip_prefix($prefix).unwrap_or(s);
                Uuid::parse_str(raw).map(Self).map_err(|_| ProtocolError::MalformedId)
            }
        }
    };
}

uuid_newtype!(
    /// Stable identity of a paired device. Survives reinstalls of the client UI but is
    /// regenerated if the device's identity key is regenerated.
    DeviceId,
    "dev_"
);

uuid_newtype!(
    /// Identity of a user account inside the application.
    UserId,
    "usr_"
);

uuid_newtype!(
    /// A single authenticated connection between a client and an agent.
    SessionId,
    "ses_"
);

uuid_newtype!(
    /// Correlates a request with its response on the control channel.
    RequestId,
    "req_"
);

uuid_newtype!(
    /// One first-time pairing exchange. Distinct from [`SessionId`] because a pairing
    /// session exists *before* trust does, and confusing the two would let an
    /// unauthenticated peer act where an authenticated one is expected.
    PairingSessionId,
    "pair_"
);

uuid_newtype!(
    /// A single terminal (PTY) session inside a connection.
    TerminalId,
    "trm_"
);

uuid_newtype!(
    /// A single file transfer job, resumable across reconnects.
    TransferId,
    "trf_"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_through_canonical_string() {
        let id = DeviceId::generate();
        let parsed: DeviceId = id.to_canonical_string().parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn accepts_bare_uuid_without_prefix() {
        let id = SessionId::generate();
        let bare = id.as_uuid().as_hyphenated().to_string();
        assert_eq!(bare.parse::<SessionId>().unwrap(), id);
    }

    #[test]
    fn rejects_garbage() {
        assert!("dev_not-a-uuid".parse::<DeviceId>().is_err());
        assert!("".parse::<DeviceId>().is_err());
        assert!("../../etc/passwd".parse::<DeviceId>().is_err());
    }

    #[test]
    fn display_carries_type_prefix() {
        let id = Uuid::nil();
        assert!(DeviceId::from_uuid(id).to_string().starts_with("dev_"));
        assert!(TerminalId::from_uuid(id).to_string().starts_with("trm_"));
    }

    #[test]
    fn generated_ids_are_unique() {
        let a = DeviceId::generate();
        let b = DeviceId::generate();
        assert_ne!(a, b);
    }
}
