//! Control-channel messages: handshake, authorization and session lifecycle.

use std::fmt;

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

/// The first message on a new connection.
///
/// This is a single-variant enum on purpose. Postcard is not self-describing, so a
/// bare struct here would leave a future second kind of opening indistinguishable
/// except by attempting two decodes — which would let the peer choose the branch.
/// Keeping the discriminant costs one byte and keeps that door shut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Opening {
    /// The peer wants a session.
    Hello(Box<Hello>),
}

/// Response to [`Hello`]: the versions are compatible, keep going.
///
/// # It carries nothing but the version, deliberately
///
/// This is sent *before* the responder has decided whether to admit the peer, and the
/// listener is trust-on-first-use, so anything here is disclosed to whoever can reach
/// the port and complete TLS — including a peer the user then dismisses. The
/// responder's identity, capabilities, clock and session id therefore travel on
/// [`SessionAuthorization::Granted`] instead, which is sent only to a peer that has
/// actually been admitted. A refused peer learns that it was refused and nothing about
/// the machine it reached.
///
/// Adding a field here is not a small change: it moves that field from
/// "disclosed to admitted peers" to "disclosed to anyone who can reach the port".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloAck {
    /// Version both peers agreed on.
    pub negotiated_version: ProtocolVersion,
}

impl HelloAck {
    /// Acknowledge a peer on `negotiated_version`.
    #[must_use]
    pub const fn for_version(negotiated_version: ProtocolVersion) -> Self {
        Self { negotiated_version }
    }
}

/// Sent by the initiator immediately after [`HelloAck`].
///
/// The password travels inside the already-established mutually-authenticated TLS
/// connection, so it is never on the wire in the clear, and it is never part of
/// [`Hello`] — a peer that has not yet seen who it is talking to should not have sent
/// a secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authenticate {
    /// The canonical address the user dialled.
    ///
    /// The responder uses this as the key for pinned identities. It is carried here so
    /// the responder never has to guess from the QUIC remote socket address, whose port
    /// is ephemeral and therefore not the address the user saved.
    pub dialed_address: String,
    /// The unattended-access password, when the user supplied one.
    pub unattended_password: Option<String>,
}

impl fmt::Debug for Authenticate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Authenticate")
            .field("dialed_address", &self.dialed_address)
            .field(
                "unattended_password",
                &self.unattended_password.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// The permissions granted to a session, as carried on the wire.
///
/// A bitset mirroring `rc_security::PermissionSet`, kept as a separate type here rather
/// than reused directly: `rc-security` already depends on `rc-protocol` (for
/// [`DeviceId`] and the shared clock), so this crate depending back on `rc-security`
/// would be a cycle. Whichever crate depends on both — `rc-transport`, in practice —
/// converts between the two at the boundary; this type carries only what postcard needs
/// to (de)serialise the bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WirePermissions(pub u8);

/// What a peer is told about its own connection.
///
/// This is the first message that says anything about the responder itself, and it is
/// sent only after the admission decision — see [`HelloAck`] for why everything
/// identifying now rides here rather than on the acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionAuthorization {
    /// Proceed. These permissions hold for the whole session and cannot be widened.
    Granted {
        /// The granted permissions, as wire bits. See [`WirePermissions`].
        permissions: WirePermissions,
        /// The responder's identity, including the machine name the initiator shows in
        /// its Recent list.
        descriptor: Box<DeviceDescriptor>,
        /// What the responder can do.
        capabilities: Capabilities,
        /// The responder's wall-clock time in milliseconds since the Unix epoch.
        sent_at_ms: i64,
        /// Identifier the responder assigned to this session.
        ///
        /// Not a credential. Authentication is the mutually-authenticated TLS
        /// connection itself, which cannot be transplanted onto another connection;
        /// this value exists so both sides, the local log and the operator's "active
        /// sessions" list all name the same session. Nothing is authorized by
        /// presenting it.
        session_id: SessionId,
        /// Seconds of inactivity after which the responder will end the session, or `0`
        /// when no idle timeout applies.
        idle_timeout_secs: u32,
    },
    /// Do not proceed.
    Refused {
        /// Why, in terms safe to disclose to the peer.
        reason: WireRefusal,
    },
}

/// Why a peer was refused, as the peer is told it.
///
/// Deliberately coarser than the receiving machine's own reason. A dismissal, a wrong
/// password and a lockout are one value here (`Rejected`): distinguishing them would
/// tell a caller whether unattended access is configured and whether its guesses are
/// landing. The finer-grained local reason lives in `rc-host-agent`'s `RefusalReason`
/// and is never sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum WireRefusal {
    /// The machine is not accepting connections at all.
    NotAccepting,
    /// A pinned peer presented a different certificate.
    IdentityChanged,
    /// Refused. Says nothing about which of the several ways it was refused.
    Rejected,
}

/// Why a connection was refused. Kept deliberately vague to avoid acting as an oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RejectReason {
    /// Protocol majors differ.
    IncompatibleVersion,
    /// The presented identity is not authorised for a session.
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
    /// Read the responder's trusted devices.
    ///
    /// This and the three below require `Administer`, which is granted only from a
    /// device's own settings on the machine being controlled — never from the Accept
    /// dialog. See `rc_host_agent::trust_service`.
    ListTrustedDevices,
    /// Change what a trusted device may do.
    SetDevicePermissions {
        /// Lowercase hex identity fingerprint of the device to change.
        identity: String,
        /// The permissions it should hold from now on.
        permissions: WirePermissions,
    },
    /// Turn a trusted device's unattended reconnection on or off.
    SetUnattendedAccess {
        /// Lowercase hex identity fingerprint of the device to change.
        identity: String,
        /// Whether it may reconnect without anyone approving.
        enabled: bool,
    },
    /// Remove a trust relationship entirely.
    RevokeDevice {
        /// Lowercase hex identity fingerprint of the device to forget.
        identity: String,
    },
    /// End the session.
    Disconnect(Disconnect),
}

/// A trusted device, as an administrator session is told about it.
///
/// # It carries no credential, because there is none
///
/// A device is authenticated by holding its identity private key, not by presenting a
/// stored token, so there is nothing secret attached to a trust relationship that could
/// be disclosed here. A field added to this type that *did* carry one would be sending a
/// secret to a remote peer, which is why the absence is stated rather than left implied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedDeviceSummary {
    /// Lowercase hex fingerprint of the device's identity key. Public, not secret.
    pub identity_fingerprint: String,
    /// The device id it reported. Display only.
    pub device_id: String,
    /// The name it reported. Untrusted text.
    pub display_name: String,
    /// The operating-system family it reported. Untrusted text.
    pub os_family: OsFamily,
    /// Where it last connected from, if it has. Untrusted text.
    pub last_address: Option<String>,
    /// When a human first trusted it.
    pub added_ms: i64,
    /// When it was last admitted.
    pub last_connected_ms: Option<i64>,
    /// Whether it may reconnect without anyone approving.
    pub unattended: bool,
    /// Whether it is temporarily refused.
    pub suspended: bool,
    /// What an admitted session from it receives.
    pub permissions: WirePermissions,
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
    /// The responder's trusted devices.
    ///
    /// Boxed for the same reason [`ControlResponsePayload::Snapshot`] is: an un-boxed
    /// variant would set the size of every control response, including the `Pong` sent
    /// several times a minute.
    TrustedDevices(Box<Vec<TrustedDeviceSummary>>),
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
        assert!(!caps.clipboard);
        assert_eq!(caps.display_count, 0);
    }

    #[test]
    fn an_opening_states_its_purpose_rather_than_being_guessed_at() {
        // The opening must round-trip through the real wire format, and it must still
        // carry a leading discriminant so a second kind of opening can be added later
        // without the peer choosing which decode succeeds.
        let hello = Opening::Hello(Box::new(Hello {
            version: crate::CURRENT_VERSION,
            role: PeerRole::Client,
            descriptor: crate::test_support::sample_descriptor(),
            capabilities: Capabilities::default(),
            sent_at_ms: 0,
        }));

        let bytes = postcard::to_stdvec(&hello).unwrap();
        assert_eq!(
            bytes.first(),
            Some(&0),
            "the variant tag must precede the body"
        );

        let back: Opening = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(hello, back);
    }

    #[test]
    fn session_authorization_round_trips_through_postcard() {
        let granted = SessionAuthorization::Granted {
            permissions: WirePermissions(0b0000_0111),
            descriptor: Box::new(crate::test_support::sample_descriptor()),
            capabilities: Capabilities::default(),
            sent_at_ms: 1_700_000_000_000,
            session_id: SessionId::generate(),
            idle_timeout_secs: 1800,
        };
        let bytes = postcard::to_stdvec(&granted).unwrap();
        assert_eq!(
            postcard::from_bytes::<SessionAuthorization>(&bytes).unwrap(),
            granted
        );
    }

    #[test]
    fn a_refusal_round_trips_through_postcard() {
        for reason in [
            WireRefusal::NotAccepting,
            WireRefusal::IdentityChanged,
            WireRefusal::Rejected,
        ] {
            let refused = SessionAuthorization::Refused { reason };
            let bytes = postcard::to_stdvec(&refused).unwrap();
            assert_eq!(
                postcard::from_bytes::<SessionAuthorization>(&bytes).unwrap(),
                refused
            );
        }
    }

    #[test]
    fn an_authenticate_message_carrying_no_password_is_the_common_case() {
        let message = Authenticate {
            dialed_address: "192.168.1.77:7443".to_owned(),
            unattended_password: None,
        };
        let bytes = postcard::to_stdvec(&message).unwrap();
        assert_eq!(
            postcard::from_bytes::<Authenticate>(&bytes).unwrap(),
            message
        );
    }

    #[test]
    fn capabilities_deserialize_with_missing_fields() {
        // A newer peer omitting fields an older peer expects must not fail to parse.
        let caps: Capabilities = serde_json::from_str(r#"{"remote_desktop":true}"#).unwrap();
        assert!(caps.remote_desktop);
        assert!(!caps.clipboard);
    }
}
