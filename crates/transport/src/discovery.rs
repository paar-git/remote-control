//! Local-network discovery over mDNS.
//!
//! # What discovery is, and what it is emphatically not
//!
//! Discovery answers one question: *what address is my server on today?* It is a
//! convenience for a home network where the router hands out a different lease after a
//! power cut. It is **not** authentication, and nothing in this module is trusted.
//!
//! Everything an announcement contains — the device id, the name, the fingerprint — is
//! attacker-controllable. Anyone on the LAN can broadcast a record claiming any device
//! id they like. What stops that from mattering is that a discovered address is only
//! ever used as a *hint about where to dial*: the connection that follows still performs
//! mutual TLS against the pinned certificate, and an impostor fails there.
//!
//! Concretely, the rules this module holds itself to:
//!
//! * A discovered device is never added to the trusted list.
//! * A discovered fingerprint is never pinned, and never compared as proof of anything.
//!   It is carried so the UI can show *which* of several servers a record probably is,
//!   and it is labelled untrusted everywhere it appears.
//! * Discovery being disabled must not prevent connecting: the last known address, the
//!   configured hostname and a manually typed address all still work.
//!
//! # What the agent publishes
//!
//! A TXT record with the device id, display name and identity fingerprint. None of
//! these is secret — a client is expected to see all three during pairing — but the
//! agent can still be run with discovery off, which is the right default for a machine
//! on a network the operator does not control.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use rc_protocol::{DeviceId, MDNS_SERVICE_TYPE};
use rc_security::Fingerprint;

use crate::error::{Result, TransportError};

/// TXT key holding the device id.
const TXT_DEVICE_ID: &str = "did";

/// TXT key holding the display name.
const TXT_DISPLAY_NAME: &str = "name";

/// TXT key holding the identity fingerprint.
const TXT_FINGERPRINT: &str = "fp";

/// TXT key holding the agent's protocol version.
const TXT_PROTOCOL: &str = "proto";

/// Longest display name accepted from an announcement.
///
/// An unbounded name from the network would flow straight into the UI. This is well
/// above any real device name and well below anything that could be used to flood a
/// list view.
const MAX_ANNOUNCED_NAME_BYTES: usize = 64;

/// A server seen on the local network.
///
/// **Every field is untrusted.** See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredAgent {
    /// The device id the announcement claims. Not proof of anything.
    pub device_id: DeviceId,
    /// The name the announcement claims, already sanitised for display.
    pub display_name: String,
    /// The identity fingerprint the announcement claims. Never pinned from here.
    pub identity_fingerprint: Option<Fingerprint>,
    /// Addresses the record resolved to, in the order they were reported.
    pub addresses: Vec<SocketAddr>,
    /// Protocol major version the announcement claims, when it is parseable.
    pub protocol_major: Option<u16>,
}

impl DiscoveredAgent {
    /// The address to try first.
    ///
    /// IPv4 is preferred: a home LAN nearly always has working IPv4, whereas IPv6 on
    /// the same segment is frequently link-local-only and fails after a long timeout.
    #[must_use]
    pub fn preferred_address(&self) -> Option<SocketAddr> {
        self.addresses
            .iter()
            .find(|address| address.is_ipv4())
            .or_else(|| self.addresses.first())
            .copied()
    }

    /// Whether this record plausibly describes `device_id`.
    ///
    /// A *hint*, used to pick which discovered record to dial for a saved server. The
    /// connection still authenticates; a false match costs one failed dial.
    #[must_use]
    pub fn matches(&self, device_id: DeviceId) -> bool {
        self.device_id == device_id
    }
}

/// Publishes this agent on the local network.
///
/// Dropping the handle withdraws the announcement.
// `ServiceDaemon` is not `Debug`, so the derive is written by hand rather than dropped:
// callers hold this inside larger structures that are.
pub struct Advertiser {
    daemon: mdns_sd::ServiceDaemon,
    full_name: String,
}

impl Advertiser {
    /// Start announcing an agent.
    ///
    /// `instance` is used to build the service instance name and must be unique on the
    /// segment; the device id is the natural choice.
    ///
    /// # Errors
    /// [`TransportError::Io`] if the mDNS responder cannot start or the record is
    /// rejected. Discovery is optional, so callers should log and continue rather than
    /// treating this as fatal.
    pub fn start(
        device_id: DeviceId,
        display_name: &str,
        identity_fingerprint: Fingerprint,
        port: u16,
    ) -> Result<Self> {
        let daemon = mdns_sd::ServiceDaemon::new().map_err(|err| TransportError::Io {
            reason: format!("could not start the mDNS responder: {err}"),
        })?;

        // The instance name must be a valid DNS label. A device id is hex and hyphens
        // after its prefix, so it already is one; the display name is not, and is
        // carried in TXT instead of in the name.
        let instance = instance_label(device_id);

        let mut properties = HashMap::new();
        properties.insert(TXT_DEVICE_ID.to_owned(), device_id.to_canonical_string());
        properties.insert(TXT_DISPLAY_NAME.to_owned(), sanitise_name(display_name));
        properties.insert(TXT_FINGERPRINT.to_owned(), identity_fingerprint.to_hex());
        properties.insert(
            TXT_PROTOCOL.to_owned(),
            rc_protocol::CURRENT_VERSION.major.to_string(),
        );

        let service = mdns_sd::ServiceInfo::new(
            MDNS_SERVICE_TYPE,
            &instance,
            &format!("{instance}.local."),
            (),
            port,
            properties,
        )
        .map_err(|err| TransportError::Io {
            reason: format!("could not build the mDNS record: {err}"),
        })?
        // Resolving the host's own addresses is what makes the record answerable on a
        // machine with several interfaces.
        .enable_addr_auto();

        let full_name = service.get_fullname().to_owned();

        daemon.register(service).map_err(|err| TransportError::Io {
            reason: format!("could not publish the mDNS record: {err}"),
        })?;

        tracing::info!(%device_id, port, "announcing on the local network");
        Ok(Self { daemon, full_name })
    }
}

impl std::fmt::Debug for Advertiser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Advertiser")
            .field("full_name", &self.full_name)
            .finish_non_exhaustive()
    }
}

impl Drop for Advertiser {
    /// Withdraw the announcement.
    ///
    /// Best-effort: the daemon is shutting down anyway, and a failure here has no
    /// remedy beyond letting the record time out.
    fn drop(&mut self) {
        if let Err(err) = self.daemon.unregister(&self.full_name) {
            tracing::debug!(%err, "could not withdraw the mDNS record");
        }
        if let Err(err) = self.daemon.shutdown() {
            tracing::debug!(%err, "could not stop the mDNS responder");
        }
    }
}

/// Browse the local network for agents.
///
/// Collects for `timeout` and returns what was seen. Returning a snapshot rather than a
/// live stream keeps the caller simple: discovery is used at the moment a user opens a
/// screen or a reconnect needs an address, not continuously.
///
/// # Errors
/// [`TransportError::Io`] if the responder cannot start. An empty result is **not** an
/// error: no agents may be running, or mDNS may be filtered by the network.
pub async fn browse(timeout: Duration) -> Result<Vec<DiscoveredAgent>> {
    let daemon = mdns_sd::ServiceDaemon::new().map_err(|err| TransportError::Io {
        reason: format!("could not start the mDNS responder: {err}"),
    })?;

    let receiver = daemon
        .browse(MDNS_SERVICE_TYPE)
        .map_err(|err| TransportError::Io {
            reason: format!("could not browse for agents: {err}"),
        })?;

    let mut found: HashMap<DeviceId, DiscoveredAgent> = HashMap::new();
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        // `recv_async` is the daemon's own future; the timeout bounds the whole browse
        // so a silent network cannot hang the caller.
        // A closed channel or an elapsed deadline both mean the same thing here:
        // report what has been seen so far.
        let Ok(Ok(event)) = tokio::time::timeout(remaining, receiver.recv_async()).await else {
            break;
        };

        if let mdns_sd::ServiceEvent::ServiceResolved(info) = event
            && let Some(agent) = parse_service(&info)
        {
            // Later records for the same device replace earlier ones: an agent that
            // changed address republishes, and the newer answer is the right one.
            found.insert(agent.device_id, agent);
        }
    }

    if let Err(err) = daemon.shutdown() {
        tracing::debug!(%err, "could not stop the mDNS responder after browsing");
    }

    let mut agents: Vec<DiscoveredAgent> = found.into_values().collect();
    // A stable order, so a list in the UI does not reshuffle between refreshes.
    agents.sort_by(|a, b| {
        a.display_name
            .cmp(&b.display_name)
            .then(a.device_id.cmp(&b.device_id))
    });

    tracing::debug!(count = agents.len(), "local discovery finished");
    Ok(agents)
}

/// Turn a resolved mDNS record into a [`DiscoveredAgent`], or discard it.
///
/// A record without a parseable device id is dropped rather than given a placeholder:
/// an entry the client cannot match to a saved server has no use, and inventing an id
/// for it would risk colliding with a real one.
fn parse_service(info: &mdns_sd::ResolvedService) -> Option<DiscoveredAgent> {
    let properties = &info.txt_properties;

    let device_id = properties
        .get_property_val_str(TXT_DEVICE_ID)?
        .parse::<DeviceId>()
        .ok()?;

    let display_name = properties
        .get_property_val_str(TXT_DISPLAY_NAME)
        .map_or_else(|| device_id.to_canonical_string(), sanitise_name);

    // A malformed fingerprint is dropped rather than kept as a string: it is only ever
    // used for display, and a value that failed to parse should not reach the UI
    // looking like a fingerprint.
    let identity_fingerprint = properties
        .get_property_val_str(TXT_FINGERPRINT)
        .and_then(|raw| raw.parse::<Fingerprint>().ok());

    let protocol_major = properties
        .get_property_val_str(TXT_PROTOCOL)
        .and_then(|raw| raw.parse::<u16>().ok());

    let port = info.port;
    let mut addresses: Vec<SocketAddr> = info
        .addresses
        .iter()
        .map(|ip| SocketAddr::new(ip.to_ip_addr(), port))
        .collect();
    // `addresses` is a `HashSet`, so its iteration order varies run to run. Sorting
    // keeps `preferred_address` deterministic.
    addresses.sort();

    if addresses.is_empty() {
        return None;
    }

    Some(DiscoveredAgent {
        device_id,
        display_name,
        identity_fingerprint,
        addresses,
        protocol_major,
    })
}

/// A DNS-safe instance label for a device.
fn instance_label(device_id: DeviceId) -> String {
    // Hyphens and hex only, so the result is always a valid label.
    format!("rc-{}", device_id.as_uuid().as_simple())
}

/// Make an announced name safe to store and render.
///
/// Announcements come from the network, so the name is attacker-controlled. Control
/// characters and bidirectional overrides are removed — the latter because a name
/// containing U+202E can render as a completely different string — and the result is
/// truncated on a character boundary.
fn sanitise_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() && !is_bidi_override(*c))
        .collect();
    let trimmed = cleaned.trim();

    if trimmed.is_empty() {
        return "unnamed device".to_owned();
    }

    truncate_on_char_boundary(trimmed, MAX_ANNOUNCED_NAME_BYTES).to_owned()
}

/// Whether a character can reorder the text around it when rendered.
const fn is_bidi_override(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'
    )
}

/// Truncate to at most `max_bytes`, never splitting a character.
fn truncate_on_char_boundary(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    fn agent_with(addresses: Vec<SocketAddr>) -> DiscoveredAgent {
        DiscoveredAgent {
            device_id: DeviceId::generate(),
            display_name: "server".to_owned(),
            identity_fingerprint: None,
            addresses,
            protocol_major: Some(1),
        }
    }

    #[test]
    fn ipv4_is_preferred_over_ipv6() {
        // A home LAN nearly always routes IPv4; link-local IPv6 fails slowly.
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1);
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2);

        let agent = agent_with(vec![v6, v4]);
        assert_eq!(agent.preferred_address(), Some(v4));
    }

    #[test]
    fn ipv6_is_used_when_it_is_all_there_is() {
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1);
        assert_eq!(agent_with(vec![v6]).preferred_address(), Some(v6));
    }

    #[test]
    fn an_agent_with_no_address_has_nothing_to_dial() {
        assert_eq!(agent_with(vec![]).preferred_address(), None);
    }

    #[test]
    fn a_record_only_matches_its_own_device_id() {
        let agent = agent_with(vec![]);
        assert!(agent.matches(agent.device_id));
        assert!(!agent.matches(DeviceId::generate()));
    }

    #[test]
    fn control_characters_are_stripped_from_announced_names() {
        // The name goes straight into a list view; an announcement can put anything
        // in it.
        assert_eq!(sanitise_name("home\u{0}server\n"), "homeserver");
    }

    #[test]
    fn bidirectional_overrides_are_stripped_from_announced_names() {
        // Without this, a device could announce a name that renders as another's.
        let deceptive = "serv\u{202E}rekcatta";
        assert!(!sanitise_name(deceptive).contains('\u{202E}'));
    }

    #[test]
    fn an_empty_or_blank_name_becomes_a_placeholder() {
        assert_eq!(sanitise_name("   "), "unnamed device");
        assert_eq!(sanitise_name(""), "unnamed device");
        assert_eq!(sanitise_name("\u{0}\u{1}"), "unnamed device");
    }

    #[test]
    fn an_overlong_name_is_truncated_without_splitting_a_character() {
        let long = "é".repeat(200);
        let sanitised = sanitise_name(&long);
        assert!(sanitised.len() <= MAX_ANNOUNCED_NAME_BYTES);
        // Would panic on a split character; the assertion is that it does not.
        assert!(sanitised.chars().all(|c| c == 'é'));
    }

    #[test]
    fn an_instance_label_is_a_valid_dns_label() {
        let label = instance_label(DeviceId::generate());
        assert!(
            label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "got {label}"
        );
        assert!(label.len() <= 63, "a DNS label is at most 63 bytes");
    }

    #[test]
    fn instance_labels_are_distinct_per_device() {
        assert_ne!(
            instance_label(DeviceId::generate()),
            instance_label(DeviceId::generate())
        );
    }

    #[tokio::test]
    async fn browsing_an_empty_network_returns_empty_rather_than_failing() {
        // No agent is running in the test process. Discovery finding nothing is a
        // normal outcome — mDNS is frequently filtered — and must not be an error, or
        // the client would report a failure where the right answer is "type an
        // address".
        let found = browse(Duration::from_millis(150)).await;
        match found {
            Ok(agents) => assert!(agents.iter().all(|a| !a.addresses.is_empty())),
            // Some CI sandboxes forbid multicast sockets outright. That is a genuine
            // I/O failure and is allowed to surface as one.
            Err(TransportError::Io { .. }) => {}
            Err(other) => panic!("unexpected discovery error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_browse_returns_within_its_timeout() {
        let started = std::time::Instant::now();
        let _ = browse(Duration::from_millis(100)).await;
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "browsing must be bounded by its timeout"
        );
    }
}
