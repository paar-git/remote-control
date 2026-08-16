//! The address a user types to reach another machine.
//!
//! An IPv4 address, an IPv6 address or a hostname, each with an optional `:port`. No
//! scheme, no path, no query. Accepting a URL would imply the transport honours the
//! scheme, and it does not — this is always QUIC.
//!
//! An unbracketed IPv6 address with a trailing `:9000` is genuinely ambiguous: it is
//! indistinguishable from an address whose final group is `9000`. Rather than guess,
//! the whole string is taken as the host and the default port applies. Brackets are
//! how the user says otherwise, and [`Display`](std::fmt::Display) always emits them.
//!
//! Parsing is deliberately stricter than a resolver would be. An obviously malformed
//! entry is reported under the address field while the user is still looking at it,
//! rather than surfacing seconds later as a connection failure indistinguishable from
//! an unreachable machine.

use std::fmt;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;

use crate::error::{Result, TransportError};

/// A machine to dial.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerAddress {
    /// An IP address or a hostname. IPv6 addresses are stored unbracketed.
    pub host: String,
    /// The QUIC port.
    pub port: u16,
}

impl PeerAddress {
    /// The port used when the address does not name one.
    pub const DEFAULT_PORT: u16 = 7443;

    /// The longest address accepted, matching the database column's `CHECK`.
    const MAX_LEN: usize = 255;

    /// Resolve to socket addresses.
    ///
    /// A hostname may resolve to several; all are returned in the order the resolver
    /// gave them, and the caller tries each. Resolution failure is an error, never an
    /// empty list, so "no such host" cannot be mistaken for "nothing to try".
    ///
    /// # Errors
    /// If the name cannot be resolved, or resolves to no addresses at all.
    pub fn to_socket_addrs(&self) -> Result<Vec<SocketAddr>> {
        let resolved: Vec<SocketAddr> = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|source| TransportError::UnresolvableAddress {
                address: self.to_string(),
                reason: source.to_string(),
            })?
            .collect();

        if resolved.is_empty() {
            return Err(TransportError::UnresolvableAddress {
                address: self.to_string(),
                reason: "the name resolved to no addresses".to_owned(),
            });
        }
        Ok(resolved)
    }
}

impl FromStr for PeerAddress {
    type Err = TransportError;

    fn from_str(text: &str) -> Result<Self> {
        let trimmed = text.trim();
        let invalid = || TransportError::InvalidAddress(text.to_owned());

        if trimmed.is_empty() || trimmed.len() > Self::MAX_LEN {
            return Err(invalid());
        }
        // A scheme, a path or a query means the user typed a URL. Half-understanding it
        // would imply the transport honours the scheme.
        if trimmed.contains("://") || trimmed.contains('/') || trimmed.contains('?') {
            return Err(invalid());
        }

        let (host, port) = if let Some(rest) = trimmed.strip_prefix('[') {
            // Bracketed: an IPv6 literal, with or without a port.
            let (inside, after) = rest.split_once(']').ok_or_else(invalid)?;
            let port = match after {
                "" => Self::DEFAULT_PORT,
                _ => parse_port(after.strip_prefix(':').ok_or_else(invalid)?, text)?,
            };
            // Brackets mean IPv6 specifically. A bracketed IPv4 address or hostname is
            // a malformed address, not a generous synonym.
            if !matches!(inside.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
                return Err(invalid());
            }
            (inside.to_owned(), port)
        } else if trimmed.matches(':').count() > 1 {
            // More than one colon and no brackets: an unbracketed IPv6 address. The
            // whole string is the host — a trailing group cannot be told from a port.
            if trimmed.parse::<IpAddr>().is_err() {
                return Err(invalid());
            }
            (trimmed.to_owned(), Self::DEFAULT_PORT)
        } else if let Some((host, port)) = trimmed.split_once(':') {
            (host.to_owned(), parse_port(port, text)?)
        } else {
            (trimmed.to_owned(), Self::DEFAULT_PORT)
        };

        if !is_plausible_host(&host) {
            return Err(invalid());
        }
        Ok(Self { host, port })
    }
}

impl fmt::Display for PeerAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(formatter, "[{}]:{}", self.host, self.port)
        } else {
            write!(formatter, "{}:{}", self.host, self.port)
        }
    }
}

/// A port that a peer could actually be listening on.
///
/// Zero means "any free port" to the operating system, so it is never something to
/// dial.
fn parse_port(text: &str, whole: &str) -> Result<u16> {
    match text.parse::<u16>() {
        Ok(0) | Err(_) => Err(TransportError::InvalidAddress(whole.to_owned())),
        Ok(port) => Ok(port),
    }
}

/// Whether a host could be a hostname or an IP literal.
///
/// Permissive about what a resolver will accept and strict about what cannot possibly
/// be a host, so an obviously wrong entry is reported in the interface rather than as a
/// resolution failure seconds later.
fn is_plausible_host(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && !host.starts_with('-')
        && !host.ends_with('-')
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '-' || character == '.'
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_ipv4_address_takes_the_default_port() {
        let address: PeerAddress = "192.168.1.77".parse().unwrap();
        assert_eq!(address.host, "192.168.1.77");
        assert_eq!(address.port, PeerAddress::DEFAULT_PORT);
    }

    #[test]
    fn an_explicit_port_is_honoured() {
        let address: PeerAddress = "192.168.1.77:9000".parse().unwrap();
        assert_eq!(address.host, "192.168.1.77");
        assert_eq!(address.port, 9000);
    }

    #[test]
    fn a_bare_ipv6_address_takes_the_default_port() {
        let address: PeerAddress = "fe80::1".parse().unwrap();
        assert_eq!(address.host, "fe80::1");
        assert_eq!(address.port, PeerAddress::DEFAULT_PORT);
    }

    #[test]
    fn a_bracketed_ipv6_address_with_a_port_is_parsed() {
        let address: PeerAddress = "[fe80::1]:9000".parse().unwrap();
        assert_eq!(address.host, "fe80::1");
        assert_eq!(address.port, 9000);
    }

    #[test]
    fn a_hostname_is_accepted() {
        let address: PeerAddress = "work-laptop.local".parse().unwrap();
        assert_eq!(address.host, "work-laptop.local");
        assert_eq!(address.port, PeerAddress::DEFAULT_PORT);
    }

    #[test]
    fn a_hostname_with_a_port_is_accepted() {
        let address: PeerAddress = "work-laptop.local:9000".parse().unwrap();
        assert_eq!(address.host, "work-laptop.local");
        assert_eq!(address.port, 9000);
    }

    #[test]
    fn surrounding_whitespace_is_ignored() {
        // People paste addresses. A trailing space is not a different machine.
        let address: PeerAddress = "  192.168.1.77  ".parse().unwrap();
        assert_eq!(address.host, "192.168.1.77");
    }

    #[test]
    fn an_empty_address_is_refused() {
        assert!("".parse::<PeerAddress>().is_err());
        assert!("   ".parse::<PeerAddress>().is_err());
    }

    #[test]
    fn port_zero_is_refused() {
        // Port 0 means "any free port" to the operating system, which is not something
        // a peer can be listening on.
        assert!("192.168.1.77:0".parse::<PeerAddress>().is_err());
    }

    #[test]
    fn a_port_above_the_range_is_refused() {
        assert!("192.168.1.77:70000".parse::<PeerAddress>().is_err());
    }

    #[test]
    fn a_url_is_refused_rather_than_half_understood() {
        // Accepting a scheme would imply the transport honours it. It does not; this
        // is always QUIC.
        assert!("https://192.168.1.77".parse::<PeerAddress>().is_err());
    }

    #[test]
    fn a_path_is_refused() {
        assert!("192.168.1.77/admin".parse::<PeerAddress>().is_err());
    }

    #[test]
    fn an_unbracketed_ipv6_address_keeps_the_default_port_rather_than_guessing() {
        // "fe80::1:9000" cannot be told from an address whose last group is 9000, so
        // the whole string is the host. Brackets are how the user says otherwise.
        let address: PeerAddress = "fe80::1:9000".parse().unwrap();
        assert_eq!(address.port, PeerAddress::DEFAULT_PORT);
        assert_eq!(address.host, "fe80::1:9000");
    }

    #[test]
    fn an_unbracketed_string_with_two_colons_that_is_not_an_address_is_refused() {
        // Refusing beats treating "not:an:address" as a hostname the resolver will
        // reject seconds later.
        assert!("not:an:address".parse::<PeerAddress>().is_err());
    }

    #[test]
    fn a_bracketed_host_that_is_not_an_ipv6_address_is_refused() {
        assert!("[notanaddress]:9000".parse::<PeerAddress>().is_err());
        assert!("[192.168.1.77]:9000".parse::<PeerAddress>().is_err());
    }

    #[test]
    fn an_unclosed_bracket_is_refused() {
        assert!("[fe80::1:9000".parse::<PeerAddress>().is_err());
    }

    #[test]
    fn a_hostname_with_a_leading_or_trailing_dash_or_dot_is_refused() {
        for text in ["-host", "host-", ".host", "host."] {
            assert!(
                text.parse::<PeerAddress>().is_err(),
                "`{text}` should not parse"
            );
        }
    }

    #[test]
    fn an_address_longer_than_the_column_allows_is_refused() {
        // The database column caps an address at 255 characters. Refusing here means a
        // storage error can never be the first time anyone hears about it.
        let too_long = "a".repeat(256);
        assert!(too_long.parse::<PeerAddress>().is_err());
    }

    #[test]
    fn display_round_trips_through_parse() {
        for text in [
            "192.168.1.77:9000",
            "work-laptop.local:7443",
            "[fe80::1]:9000",
        ] {
            let address: PeerAddress = text.parse().unwrap();
            assert_eq!(address.to_string(), text);
            assert_eq!(address.to_string().parse::<PeerAddress>().unwrap(), address);
        }
    }

    #[test]
    fn loopback_resolves_to_at_least_one_socket_address() {
        let address: PeerAddress = "127.0.0.1:9000".parse().unwrap();
        let resolved = address.to_socket_addrs().unwrap();
        assert!(!resolved.is_empty());
        assert_eq!(resolved[0].port(), 9000);
    }

    #[test]
    fn a_name_that_does_not_resolve_is_an_error_not_an_empty_list() {
        // An empty list would let "no such host" be mistaken for "nothing to try",
        // which reads to the caller as a successful lookup of a machine with no
        // addresses.
        let address: PeerAddress = "invalid.invalid:9000".parse().unwrap();
        assert!(address.to_socket_addrs().is_err());
    }
}
