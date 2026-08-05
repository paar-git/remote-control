//! Wire protocol for the remote-control platform.
//!
//! This crate is the single source of truth for everything that crosses the network
//! between the desktop client and the host agent. It is deliberately dependency-light
//! and contains no I/O, so both sides — and the test suite — can depend on it freely.
//!
//! # Design rules
//!
//! * **Nothing here trusts its input.** Types carry untrusted strings (file names,
//!   hostnames, process names); validating and sanitising them is the receiver's job,
//!   and doc comments call out every such field.
//! * **Everything is bounded.** See [`limits`]. The framing layer rejects oversized
//!   frames from the header alone, before allocating.
//! * **Enums are externally tagged.** The wire format ([`postcard`]) is not
//!   self-describing, so serde's internally-tagged representation cannot round-trip.
//! * **Enums are `#[non_exhaustive]`.** Adding a variant is a minor-version change;
//!   peers must handle decode failures of unknown variants as a soft error.
//!
//! # Layout
//!
//! | Module | Purpose |
//! |---|---|
//! | [`frame`] | Length-prefixed framing and channel multiplexing |
//! | [`version`] | Version negotiation |
//! | [`limits`] | Hard size and count ceilings |
//! | [`ids`] | Typed identifiers |
//! | [`replay`] | Sliding-window replay detection |
//! | [`control`] | Handshake, session lifecycle, errors |
//! | [`pairing`] | First-time trust establishment |
//! | [`terminal`] | PTY sessions |
//! | [`files`] | Browsing and resumable transfer |
//! | [`system`] | Metrics, processes, services, power |
//! | [`desktop`] | Video streaming and input injection |

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod control;
pub mod desktop;
pub mod error;
pub mod files;
pub mod frame;
pub mod ids;
pub mod limits;
pub mod pairing;
pub mod replay;
pub mod system;
pub mod terminal;
pub mod version;

pub use error::{ProtocolError, Result};
pub use frame::{Channel, Frame, FrameDecoder};
pub use ids::{DeviceId, PairingSessionId, RequestId, SessionId, TerminalId, TransferId, UserId};
pub use version::{CURRENT_VERSION, ProtocolVersion};

/// Application-Layer Protocol Negotiation identifier offered on every QUIC/TLS
/// connection. Peers that do not offer it are rejected at the TLS layer, which cheaply
/// turns away internet background scanning.
pub const ALPN_PROTOCOL: &[u8] = b"rc/1";

/// Default UDP port the host agent listens on for QUIC.
pub const DEFAULT_AGENT_PORT: u16 = 47_811;

/// Default TCP port for the agent's loopback-only health endpoint.
pub const DEFAULT_AGENT_HEALTH_PORT: u16 = 47_813;

/// Default TCP port the optional coordination service listens on.
pub const DEFAULT_COORDINATION_PORT: u16 = 47_812;

/// mDNS service type used for local discovery.
pub const MDNS_SERVICE_TYPE: &str = "_remotectl._udp.local.";

/// Current wall-clock time in milliseconds since the Unix epoch.
///
/// Returns `0` if the system clock is set before the epoch, which the replay guard
/// then rejects as excessively skewed rather than panicking.
#[must_use]
pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::control::{DeviceDescriptor, OsFamily};
    use crate::ids::DeviceId;

    pub fn sample_descriptor() -> DeviceDescriptor {
        DeviceDescriptor {
            device_id: DeviceId::generate(),
            display_name: "test-device".into(),
            hostname: "test-host".into(),
            os_family: OsFamily::Linux,
            os_version: "Ubuntu 24.04".into(),
            app_version: env!("CARGO_PKG_VERSION").into(),
            certificate_fingerprint: "00".repeat(32),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_is_versioned() {
        assert!(ALPN_PROTOCOL.starts_with(b"rc/"));
    }

    #[test]
    fn default_ports_are_in_the_registered_range() {
        const { assert!(DEFAULT_AGENT_PORT > 1024) }
        const { assert!(DEFAULT_COORDINATION_PORT > 1024) }
        const { assert!(DEFAULT_AGENT_PORT != DEFAULT_COORDINATION_PORT) }
        const { assert!(DEFAULT_AGENT_HEALTH_PORT > 1024) }
        const { assert!(DEFAULT_AGENT_HEALTH_PORT != DEFAULT_AGENT_PORT) }
        const { assert!(DEFAULT_AGENT_HEALTH_PORT != DEFAULT_COORDINATION_PORT) }
    }

    #[test]
    fn now_ms_is_plausible() {
        // Later than 2020-01-01 and earlier than 2100-01-01.
        let now = now_ms();
        assert!(now > 1_577_836_800_000);
        assert!(now < 4_102_444_800_000);
    }

    #[test]
    fn mdns_service_type_is_well_formed() {
        assert!(MDNS_SERVICE_TYPE.starts_with('_'));
        assert!(MDNS_SERVICE_TYPE.ends_with(".local."));
    }
}
