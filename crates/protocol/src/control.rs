//! Control-channel messages: handshake, authorization and session lifecycle.

use serde::{Deserialize, Serialize};

use crate::ids::{DeviceId, RequestId, SessionId};
use crate::version::ProtocolVersion;

/// Coarse operating-system family of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OsFamily {
    /// Microsoft Windows.
    Windows,
    /// Any Linux distribution.
    Linux,
    /// Apple macOS. Not yet supported by an agent build, reserved for forward compat.
    MacOs,
    /// Reported by a peer we do not recognise.
    Unknown,
}

/// Non-secret facts a device publishes about itself during the handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceDescriptor {
    /// Stable identity of the device.
    pub device_id: DeviceId,
    /// User-visible name. Untrusted: sanitise before rendering.
    pub display_name: String,
    /// Machine hostname as reported by the OS. Untrusted.
    pub hostname: String,
    /// OS family.
    pub os_family: OsFamily,
    /// Human-readable OS version, e.g. `"Windows 11 Pro 26200"`. Untrusted.
    pub os_version: String,
    /// Version of the agent or client software.
    pub app_version: String,
    /// Lowercase hex SHA-256 of the device's TLS certificate.
    pub certificate_fingerprint: String,
}

/// Which side of the connection a peer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerRole {
    /// The controlling desktop client.
    Client,
    /// The controlled host agent.
    Agent,
}

/// Capabilities a peer offers. Absent capabilities must be treated as unsupported
/// rather than assumed, so older and newer builds interoperate.
// This is a feature-flag set, not state: each flag is independent and named, and
// collapsing them into enums or a bitfield would lose the `#[serde(default)]`
// forward-compatibility that lets old peers parse messages from new ones.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Capabilities {
    /// Screen capture and input injection are available.
    pub remote_desktop: bool,
    /// File browsing and transfer are available.
    pub file_transfer: bool,
    /// System metrics are available.
    pub monitoring: bool,
    /// Process enumeration and termination are available.
    pub process_management: bool,
    /// Service control is available.
    pub service_management: bool,
    /// Power actions are available.
    pub power_control: bool,
    /// Clipboard can be synchronised.
    pub clipboard: bool,
    /// Wake-on-LAN is configured.
    pub wake_on_lan: bool,
    /// Number of displays that can be captured.
    pub display_count: u8,
}

/// First message on the control channel, sent by the initiator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Protocol version the sender implements.
    pub version: ProtocolVersion,
    /// Whether the sender is a client or an agent.
    pub role: PeerRole,
    /// Who the sender claims to be. Claims here are only trusted after the TLS
    /// certificate has been verified against a pinned fingerprint.
    pub descriptor: DeviceDescriptor,
    /// What the sender can do.
    pub capabilities: Capabilities,
    /// Sender's wall-clock time, milliseconds since the Unix epoch. Used to detect
    /// clock skew before evaluating timestamped anti-replay data.
    pub sent_at_ms: i64,
}

/// The very first message on a control stream.
///
/// A connection is opened for exactly one of two purposes: running a session as an
/// already-trusted device, or running a first-time pairing exchange. Which one it is
/// has to be **stated**, not inferred.
///
/// Inferring it would mean attempting to decode the same bytes as two different types
/// and taking whichever succeeded. The wire format ([`postcard`]) is not
/// self-describing, so that is not merely fragile — a byte string that decodes cleanly
/// as one type frequently decodes cleanly as the other, and the peer would choose which
/// by construction. An explicit tag makes the agent's first branch — *is this connection
/// even allowed to pair?* — one it decides rather than one the peer decides for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Opening {
    /// The peer claims to be trusted already and wants a session.
    Hello(Box<Hello>),
    /// The peer is not trusted and wants to run the pairing exchange. Permitted only
    /// while the operator has a pairing window open.
    Pairing(Box<crate::pairing::PairingMessage>),
}

/// Response to [`Hello`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloAck {
    /// Version both peers agreed on.
    pub negotiated_version: ProtocolVersion,
    /// Responder's identity.
    pub descriptor: DeviceDescriptor,
    /// Responder's capabilities.
    pub capabilities: Capabilities,
    /// Responder's wall-clock time in milliseconds since the Unix epoch.
    pub sent_at_ms: i64,
    /// Whether the initiator is already a trusted, non-revoked device. When `false`
    /// the connection may only be used to run the pairing exchange.
    pub already_paired: bool,
    /// Identifier the agent assigned to this session.
    ///
    /// Not a credential. Authentication is the mutually-authenticated TLS connection
    /// itself, which cannot be transplanted onto another connection; this value exists
    /// so both sides, the audit trail and the operator's "active sessions" list all
    /// name the same session. Nothing is authorized by presenting it.
    pub session_id: SessionId,
    /// Seconds of inactivity after which the agent will end the session, or `0` when
    /// no idle timeout applies.
    pub idle_timeout_secs: u32,
}

/// Why a connection was refused. Kept deliberately vague to avoid acting as an oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RejectReason {
    /// Protocol majors differ.
    IncompatibleVersion,
    /// Presented identity is not paired, or was revoked.
    NotAuthorized,
    /// Too many attempts from this peer; back off.
    RateLimited,
    /// The agent is shutting down or otherwise not accepting sessions.
    Unavailable,
    /// Input failed validation.
    BadRequest,
}

/// Terminal reply when a connection cannot proceed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reject {
    /// Machine-readable reason.
    pub reason: RejectReason,
    /// Seconds to wait before retrying, when the reason is [`RejectReason::RateLimited`].
    pub retry_after_secs: Option<u32>,
}

/// Why a session ended. Distinguishing intentional from accidental closure is what
/// lets the client suppress automatic reconnection after a deliberate disconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DisconnectReason {
    /// The local user pressed Disconnect. Never auto-reconnect after this.
    UserRequested,
    /// The host operator ended the session (e.g. the emergency shortcut).
    HostTerminated,
    /// The session token expired or was revoked.
    SessionExpired,
    /// Idle longer than the configured timeout.
    IdleTimeout,
    /// The agent is restarting or shutting down; reconnecting later is expected.
    AgentShutdown,
    /// A protocol violation was detected.
    ProtocolError,
    /// The transport failed. Eligible for automatic reconnection.
    TransportFailure,
}

impl DisconnectReason {
    /// Whether a client should attempt to reconnect automatically after this reason.
    ///
    /// Intentional disconnects and authorization failures must never trigger an
    /// automatic retry loop.
    #[must_use]
    pub const fn permits_auto_reconnect(self) -> bool {
        match self {
            Self::AgentShutdown | Self::TransportFailure | Self::IdleTimeout => true,
            Self::UserRequested
            | Self::HostTerminated
            | Self::SessionExpired
            | Self::ProtocolError => false,
        }
    }
}

/// Sent by either peer to close a session cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disconnect {
    /// Why the session is ending.
    pub reason: DisconnectReason,
    /// Optional operator-facing detail. Never contains secrets.
    pub detail: Option<String>,
}

/// Control-channel request envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlRequest {
    /// Correlates with [`ControlResponse::request_id`].
    pub request_id: RequestId,
    /// Session the request belongs to.
    pub session_id: SessionId,
    /// Milliseconds since the Unix epoch, for replay checks.
    pub sent_at_ms: i64,
    /// Random per-request value, for replay checks.
    pub nonce: [u8; 16],
    /// The request itself.
    pub payload: ControlRequestPayload,
}

/// Every request that can be issued over the control channel.
///
/// Externally tagged: postcard is not self-describing and cannot decode serde's
/// internally-tagged representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ControlRequestPayload {
    /// Liveness probe. Carries a client timestamp for round-trip measurement.
    Ping {
        /// Echoed back verbatim.
        token: u64,
    },
    /// Ask the agent for a full dashboard snapshot.
    SystemSnapshot,
    /// Ask the agent for facts that do not change between snapshots.
    HostInfo,
    /// Subscribe to periodic metrics on the metrics channel.
    SubscribeMetrics {
        /// Requested update interval. Clamped by the agent to a sane floor.
        interval_ms: u32,
    },
    /// Stop periodic metrics.
    UnsubscribeMetrics,
    /// End the session.
    Disconnect(Disconnect),
}

/// Control-channel response envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlResponse {
    /// The request this answers.
    pub request_id: RequestId,
    /// Outcome.
    pub result: ControlResult,
}

/// Success or failure of a control request.
///
/// Not `Eq`, because a successful payload may carry a snapshot of floating-point
/// utilisation figures and equality on those is not a meaningful operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlResult {
    /// The request succeeded.
    Ok(ControlResponsePayload),
    /// The request failed.
    Err {
        /// Machine-readable code.
        code: ErrorCode,
        /// Operator-facing message. Never contains secrets or raw OS error strings
        /// that might leak paths the caller is not authorized to see.
        message: String,
    },
}

/// Successful control-channel payloads.
///
/// Not `Eq`: a snapshot carries floating-point utilisation figures, and equality on
/// those is not a meaningful operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ControlResponsePayload {
    /// Nothing to return.
    Empty,
    /// Reply to [`ControlRequestPayload::Ping`].
    Pong {
        /// Echo of the request token.
        token: u64,
        /// Agent wall-clock time, milliseconds since the Unix epoch.
        agent_time_ms: i64,
    },
    /// Accepted metrics interval after clamping.
    MetricsSubscribed {
        /// Effective interval in milliseconds.
        interval_ms: u32,
    },
    /// A full dashboard snapshot.
    ///
    /// Boxed because it is far larger than every other variant, and an un-boxed variant
    /// sets the size of the whole enum — including the `Pong` sent several times a
    /// minute.
    Snapshot(Box<crate::system::SystemSnapshot>),
    /// Static facts about the host that do not change between snapshots.
    HostInfo(Box<HostSummary>),
}

/// Facts about a host that change rarely enough to fetch once per session.
///
/// Kept out of [`ControlResponsePayload::Snapshot`] deliberately: sending the CPU model
/// and kernel version several times a minute would be repetition, and a dashboard that
/// re-renders them on every tick makes them look like live readings when they are not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostSummary {
    /// Machine hostname. Untrusted text.
    pub hostname: String,
    /// OS family.
    pub os_family: OsFamily,
    /// Human-readable OS name and version. Untrusted text.
    pub os_version: String,
    /// Kernel version. Untrusted text.
    pub kernel_version: String,
    /// CPU architecture.
    pub architecture: String,
    /// Number of logical processors.
    pub logical_cores: u32,
    /// Agent version.
    pub agent_version: String,
    /// The account the agent runs as. Untrusted text.
    pub agent_user: String,
    /// Whether the agent process holds Administrator or root.
    pub agent_elevated: bool,
    /// When the host last booted, milliseconds since the Unix epoch.
    pub booted_at_ms: i64,
}

/// Machine-readable error codes shared by every channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    /// Caller lacks permission for this operation.
    PermissionDenied,
    /// The requested object does not exist.
    NotFound,
    /// Input failed validation.
    InvalidArgument,
    /// The operation is not supported on this platform or build.
    Unsupported,
    /// A resource limit was hit.
    ResourceExhausted,
    /// Too many requests.
    RateLimited,
    /// The session is no longer valid.
    SessionInvalid,
    /// The request needs explicit user confirmation that has not been given.
    ConfirmationRequired,
    /// The operation is blocked by a safety deny-rule.
    Forbidden,
    /// An unexpected internal failure. Details go to the log, not the wire.
    Internal,
    /// The operation was cancelled by the caller.
    Cancelled,
    /// The operation timed out.
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intentional_disconnect_never_auto_reconnects() {
        assert!(!DisconnectReason::UserRequested.permits_auto_reconnect());
        assert!(!DisconnectReason::HostTerminated.permits_auto_reconnect());
    }

    #[test]
    fn auth_failures_never_auto_reconnect() {
        assert!(!DisconnectReason::SessionExpired.permits_auto_reconnect());
        assert!(!DisconnectReason::ProtocolError.permits_auto_reconnect());
    }

    #[test]
    fn transport_failure_permits_auto_reconnect() {
        assert!(DisconnectReason::TransportFailure.permits_auto_reconnect());
        assert!(DisconnectReason::AgentShutdown.permits_auto_reconnect());
    }

    #[test]
    fn capabilities_default_to_everything_off() {
        let caps = Capabilities::default();
        assert!(!caps.remote_desktop);
        assert!(!caps.power_control);
        assert_eq!(caps.display_count, 0);
    }

    #[test]
    fn an_opening_states_its_purpose_rather_than_being_guessed_at() {
        // Both variants must round-trip through the real wire format, and the tag must
        // be what distinguishes them — not a decode attempt.
        let hello = Opening::Hello(Box::new(Hello {
            version: crate::CURRENT_VERSION,
            role: PeerRole::Client,
            descriptor: crate::test_support::sample_descriptor(),
            capabilities: Capabilities::default(),
            sent_at_ms: 0,
        }));
        let pairing = Opening::Pairing(Box::new(crate::pairing::PairingMessage::Failed(
            crate::pairing::PairFailure::CodeExpired,
        )));

        for message in [hello, pairing] {
            let bytes = postcard::to_stdvec(&message).unwrap();
            let back: Opening = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(message, back);
        }
    }

    #[test]
    fn the_two_opening_variants_do_not_share_a_leading_byte() {
        // The discriminator has to actually discriminate on the wire.
        let hello = postcard::to_stdvec(&Opening::Hello(Box::new(Hello {
            version: crate::CURRENT_VERSION,
            role: PeerRole::Client,
            descriptor: crate::test_support::sample_descriptor(),
            capabilities: Capabilities::default(),
            sent_at_ms: 0,
        })))
        .unwrap();
        let pairing = postcard::to_stdvec(&Opening::Pairing(Box::new(
            crate::pairing::PairingMessage::Failed(crate::pairing::PairFailure::CodeExpired),
        )))
        .unwrap();

        assert_ne!(hello.first(), pairing.first());
    }

    #[test]
    fn capabilities_deserialize_with_missing_fields() {
        // A newer peer omitting fields an older peer expects must not fail to parse.
        let caps: Capabilities = serde_json::from_str(r#"{"remote_desktop":true}"#).unwrap();
        assert!(caps.remote_desktop);
        assert!(!caps.power_control);
    }
}
