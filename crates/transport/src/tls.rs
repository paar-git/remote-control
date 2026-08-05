//! Mutually-authenticated TLS 1.3 with pinned, self-signed device certificates.
//!
//! # Why there is no certificate authority
//!
//! Both peers are machines the same person administers. There is no third party whose
//! opinion about their names is worth anything, and introducing one would mean trusting
//! it. Instead each device generates a self-signed certificate over its long-term
//! Ed25519 identity key, and peers pin **fingerprints** established during pairing.
//!
//! This inverts the usual model in a way worth stating plainly: a certificate here
//! proves nothing on its own. It is a container for a public key. All the trust comes
//! from the fingerprint comparison, which is why the verifiers below ignore names,
//! expiry-based revocation and chain building entirely — those checks answer questions
//! that do not apply.
//!
//! # What the verifiers actually check
//!
//! | Check | Why |
//! |---|---|
//! | Certificate parses as X.509 | Anything else cannot carry a key |
//! | Exactly one certificate, no chain | A chain would imply a CA we do not have |
//! | SHA-256 of the DER matches a pin, when pinning | The trust decision |
//! | The signature over the TLS transcript verifies | Proves possession of the private key |
//!
//! Hostname verification is **deliberately absent**: the peer is identified by key, not
//! by name, and an agent reached over a coordinator has no stable name to verify.
//!
//! # The observed-certificate rule
//!
//! [`ObservedPeer`] records the certificate the peer actually presented on *this*
//! connection. Every downstream decision — the trust lookup, and above all the pairing
//! transcript — must use this value and never a fingerprint copied out of a message
//! body. A peer that could name its own fingerprint could name someone else's, and the
//! transcript's anti-relay property would be worth nothing.

use std::sync::{Arc, Mutex};

use rc_security::{DeviceIdentity, Fingerprint};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use crate::error::{Result, TransportError};

/// ALPN protocol identifier. Version-tagged so a future incompatible transport can be
/// introduced without a peer silently negotiating the wrong one.
pub const ALPN: &[u8] = b"rc/1";

/// The certificate a peer presented on a live connection.
///
/// Populated by the verifier during the handshake and read afterwards. This is the only
/// sanctioned source of a peer's certificate fingerprint.
#[derive(Debug, Clone, Default)]
pub struct ObservedPeer {
    inner: Arc<Mutex<Option<ObservedCertificate>>>,
}

/// What was observed about a peer's certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedCertificate {
    /// SHA-256 over the DER encoding.
    pub fingerprint: Fingerprint,
    /// The DER bytes themselves.
    pub der: Vec<u8>,
}

impl ObservedPeer {
    /// An empty slot, to be filled during the handshake.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record what the peer presented. Called by the verifier.
    fn record(&self, der: &[u8]) {
        let observed = ObservedCertificate {
            fingerprint: Fingerprint::of_certificate_der(der),
            der: der.to_vec(),
        };
        if let Ok(mut slot) = self.inner.lock() {
            *slot = Some(observed);
        }
    }

    /// What the peer presented, if the handshake got far enough.
    #[must_use]
    pub fn get(&self) -> Option<ObservedCertificate> {
        self.inner.lock().ok().and_then(|slot| slot.clone())
    }

    /// The observed fingerprint, if any.
    #[must_use]
    pub fn fingerprint(&self) -> Option<Fingerprint> {
        self.get().map(|observed| observed.fingerprint)
    }
}

/// Which peers a verifier will accept.
#[derive(Debug, Clone)]
pub enum PinPolicy {
    /// Accept only a certificate whose fingerprint matches exactly.
    ///
    /// Used for every connection to an already-paired device.
    Pinned(Fingerprint),

    /// Accept any well-formed self-signed certificate, recording what was seen.
    ///
    /// Used **only** during pairing, where no pin exists yet — that is the entire
    /// problem pairing solves. Safety comes from the pairing transcript, which binds
    /// the observed fingerprints of both peers, so an interposed attacker cannot make
    /// both sides agree. Using this policy anywhere else would remove the transport's
    /// authentication entirely.
    TrustOnFirstUse,
}

/// Verifies the agent's certificate from the client's side.
#[derive(Debug)]
struct PinningServerVerifier {
    policy: PinPolicy,
    observed: ObservedPeer,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinningServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        verify_pinned(
            end_entity,
            intermediates,
            &self.policy,
            &self.observed,
            "server",
        )?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Verifies the client's certificate from the agent's side.
#[derive(Debug)]
struct PinningClientVerifier {
    policy: PinPolicy,
    observed: ObservedPeer,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ClientCertVerifier for PinningClientVerifier {
    /// Client certificates are mandatory. An anonymous client is refused at the TLS
    /// layer rather than being allowed to connect and rejected later.
    fn client_auth_mandatory(&self) -> bool {
        true
    }

    /// Empty: there are no CAs to advertise, and naming any would be misleading.
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        verify_pinned(
            end_entity,
            intermediates,
            &self.policy,
            &self.observed,
            "client",
        )?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The shared pinning check used by both directions.
fn verify_pinned(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    policy: &PinPolicy,
    observed: &ObservedPeer,
    side: &'static str,
) -> std::result::Result<(), rustls::Error> {
    // A chain implies a CA. We have none, so a chain can only mean the peer is not
    // speaking our protocol — or is trying to smuggle a certificate past the pin.
    if !intermediates.is_empty() {
        tracing::warn!(side, "peer presented a certificate chain; refusing");
        return Err(rustls::Error::General(
            "a certificate chain is not accepted; devices are self-signed".to_owned(),
        ));
    }

    // Recorded before the pin decision, so a mismatch can be reported with the
    // fingerprint that was actually seen.
    observed.record(end_entity);

    match policy {
        PinPolicy::Pinned(expected) => {
            let presented = Fingerprint::of_certificate_der(end_entity);
            // Constant-time: the comparison is against a value an attacker chooses.
            if presented.ct_eq(expected) {
                Ok(())
            } else {
                // The fingerprints are not secret, but they are long; logging the
                // presented one is what lets an operator tell a renewal apart from an
                // attack.
                tracing::warn!(
                    side,
                    expected = %expected,
                    presented = %presented,
                    "peer certificate does not match the pinned fingerprint"
                );
                Err(rustls::Error::General(
                    "peer certificate does not match the pinned identity".to_owned(),
                ))
            }
        }
        PinPolicy::TrustOnFirstUse => Ok(()),
    }
}

/// The certificate fingerprint the peer presented **on this connection**.
///
/// This is the sanctioned source of a peer's fingerprint for every authorization and
/// pairing decision.
///
/// [`ObservedPeer`] cannot serve that purpose on a listener: one `ObservedPeer` belongs
/// to the endpoint, so with two clients connecting at once the second handshake
/// overwrites the first's record, and a lookup could be performed against the wrong
/// peer's certificate. That is exactly the confusion the whole pinning design exists to
/// prevent, so the value is read back from the connection instead, where QUIC keeps it
/// per-connection and it cannot be raced.
///
/// # Errors
/// [`TransportError::IdentityProofRejected`] if the peer presented no certificate, or
/// presented something other than a single end-entity certificate. Neither is reachable
/// through the verifiers above — client authentication is mandatory and chains are
/// refused — so reaching it means the connection did not come through them.
pub fn peer_certificate_fingerprint(connection: &quinn::Connection) -> Result<Fingerprint> {
    let identity = connection
        .peer_identity()
        .ok_or(TransportError::IdentityProofRejected)?;

    let certificates = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| TransportError::IdentityProofRejected)?;

    // Exactly one, for the same reason `verify_pinned` refuses a chain.
    match certificates.as_slice() {
        [end_entity] => Ok(Fingerprint::of_certificate_der(end_entity)),
        _ => Err(TransportError::IdentityProofRejected),
    }
}

/// The crypto provider used everywhere. `ring`, matching the `quinn` feature set.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// This device's certificate and private key, in the form rustls wants.
fn own_credentials(
    identity: &DeviceIdentity,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certificate = CertificateDer::from(identity.public().certificate_der.clone());

    // The PKCS#8 encoding is produced on demand and dropped as soon as rustls has taken
    // a copy; `export_pkcs8` returns a zeroizing buffer.
    let pkcs8 = identity.export_pkcs8()?;
    let key =
        PrivateKeyDer::try_from(pkcs8.to_vec()).map_err(|err| TransportError::Configuration {
            reason: format!("the device private key is not usable for TLS: {err}"),
        })?;

    Ok((vec![certificate], key))
}

/// Build the agent's TLS configuration.
///
/// Returns the config together with the [`ObservedPeer`] that will hold whatever
/// certificate the connecting client presents.
///
/// # Errors
/// [`TransportError::Configuration`] if the identity's key cannot be used for TLS.
pub fn server_config(
    identity: &DeviceIdentity,
    policy: PinPolicy,
) -> Result<(rustls::ServerConfig, ObservedPeer)> {
    let observed = ObservedPeer::new();
    let (certificates, key) = own_credentials(identity)?;

    let verifier = Arc::new(PinningClientVerifier {
        policy,
        observed: observed.clone(),
        provider: provider(),
    });

    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        // TLS 1.3 only. 1.2 is enabled in the crate's feature set for dependency
        // reasons but is not offered here: there is no legacy peer to accommodate,
        // and 1.3 removes whole categories of downgrade and cipher negotiation.
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| TransportError::Configuration {
            reason: err.to_string(),
        })?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, key)
        .map_err(|err| TransportError::Configuration {
            reason: err.to_string(),
        })?;

    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok((config, observed))
}

/// Build the client's TLS configuration.
///
/// # Errors
/// [`TransportError::Configuration`] if the identity's key cannot be used for TLS.
pub fn client_config(
    identity: &DeviceIdentity,
    policy: PinPolicy,
) -> Result<(rustls::ClientConfig, ObservedPeer)> {
    let observed = ObservedPeer::new();
    let (certificates, key) = own_credentials(identity)?;

    let verifier = Arc::new(PinningServerVerifier {
        policy,
        observed: observed.clone(),
        provider: provider(),
    });

    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| TransportError::Configuration {
            reason: err.to_string(),
        })?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certificates, key)
        .map_err(|err| TransportError::Configuration {
            reason: err.to_string(),
        })?;

    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok((config, observed))
}

#[cfg(test)]
mod tests {
    use rc_security::SystemClock;

    use super::*;

    fn identity(name: &str) -> DeviceIdentity {
        DeviceIdentity::generate(name, &SystemClock).unwrap()
    }

    #[test]
    fn both_configurations_build_from_a_device_identity() {
        let id = identity("agent");
        let pin = PinPolicy::Pinned(id.public().certificate_fingerprint);

        let (server, _) = server_config(&id, pin.clone()).unwrap();
        let (client, _) = client_config(&id, pin).unwrap();

        assert_eq!(server.alpn_protocols, vec![ALPN.to_vec()]);
        assert_eq!(client.alpn_protocols, vec![ALPN.to_vec()]);
    }

    #[test]
    fn an_observed_peer_starts_empty_and_records_what_it_sees() {
        let id = identity("peer");
        let observed = ObservedPeer::new();
        assert!(observed.get().is_none(), "nothing seen before a handshake");

        observed.record(&id.public().certificate_der);

        let seen = observed.get().expect("a certificate was recorded");
        assert_eq!(seen.fingerprint, id.public().certificate_fingerprint);
        assert_eq!(seen.der, id.public().certificate_der);
    }

    #[test]
    fn the_observed_fingerprint_is_derived_from_bytes_not_claims() {
        // The value must come from the certificate itself. If this ever reads from a
        // message field instead, the pairing transcript's anti-relay property breaks.
        let a = identity("a");
        let b = identity("b");

        let observed = ObservedPeer::new();
        observed.record(&a.public().certificate_der);
        assert_eq!(
            observed.fingerprint(),
            Some(a.public().certificate_fingerprint)
        );

        observed.record(&b.public().certificate_der);
        assert_eq!(
            observed.fingerprint(),
            Some(b.public().certificate_fingerprint),
            "the latest observation wins"
        );
        assert_ne!(
            a.public().certificate_fingerprint,
            b.public().certificate_fingerprint
        );
    }

    #[test]
    fn a_matching_pin_is_accepted_and_a_different_one_is_refused() {
        let real = identity("real-agent");
        let impostor = identity("impostor");

        let pin = PinPolicy::Pinned(real.public().certificate_fingerprint);
        let observed = ObservedPeer::new();

        let good = CertificateDer::from(real.public().certificate_der.clone());
        assert!(verify_pinned(&good, &[], &pin, &observed, "server").is_ok());

        let bad = CertificateDer::from(impostor.public().certificate_der.clone());
        assert!(
            verify_pinned(&bad, &[], &pin, &observed, "server").is_err(),
            "a certificate that does not match the pin must be refused"
        );
    }

    #[test]
    fn a_refused_certificate_is_still_observed() {
        // The operator needs to see which fingerprint was presented, otherwise a
        // legitimate renewal is indistinguishable from an attack.
        let real = identity("real");
        let impostor = identity("impostor");
        let pin = PinPolicy::Pinned(real.public().certificate_fingerprint);
        let observed = ObservedPeer::new();

        let bad = CertificateDer::from(impostor.public().certificate_der.clone());
        let _ = verify_pinned(&bad, &[], &pin, &observed, "server");

        assert_eq!(
            observed.fingerprint(),
            Some(impostor.public().certificate_fingerprint),
            "the presented certificate must be recorded even when refused"
        );
    }

    #[test]
    fn trust_on_first_use_accepts_an_unknown_certificate_but_records_it() {
        let unknown = identity("never-seen");
        let observed = ObservedPeer::new();
        let cert = CertificateDer::from(unknown.public().certificate_der.clone());

        assert!(
            verify_pinned(&cert, &[], &PinPolicy::TrustOnFirstUse, &observed, "client").is_ok()
        );
        assert_eq!(
            observed.fingerprint(),
            Some(unknown.public().certificate_fingerprint),
            "pairing depends on this value being the observed one"
        );
    }

    #[tokio::test]
    async fn the_per_connection_fingerprint_matches_the_peer_that_actually_connected() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use crate::endpoint::{AgentListener, ClientConnector};

        let agent = identity("agent");
        let client = identity("client");

        let (listener, _) = AgentListener::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &agent,
            PinPolicy::Pinned(client.public().certificate_fingerprint),
        )
        .unwrap();
        let address = listener.local_address().unwrap();

        let (connector, _) = ClientConnector::new(
            &client,
            PinPolicy::Pinned(agent.public().certificate_fingerprint),
        )
        .unwrap();

        let (accepted, connected) = tokio::join!(listener.accept(), connector.connect(address));
        let agent_side = accepted.unwrap().unwrap();
        let client_side = connected.unwrap();

        // Each side reads the *other* device's certificate off its own connection.
        assert_eq!(
            peer_certificate_fingerprint(&agent_side).unwrap(),
            client.public().certificate_fingerprint
        );
        assert_eq!(
            peer_certificate_fingerprint(&client_side).unwrap(),
            agent.public().certificate_fingerprint
        );
    }

    #[tokio::test]
    async fn concurrent_connections_do_not_share_a_fingerprint() {
        // The bug this function exists to make impossible: with a single per-endpoint
        // `ObservedPeer`, two clients handshaking at once leave one record, and the
        // agent could authorize one client against the other's certificate.
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use crate::endpoint::{AgentListener, ClientConnector};

        let agent = identity("agent");
        let first = identity("first-client");
        let second = identity("second-client");

        let (listener, endpoint_observed) = AgentListener::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &agent,
            PinPolicy::TrustOnFirstUse,
        )
        .unwrap();
        let address = listener.local_address().unwrap();

        let (first_connector, _) =
            ClientConnector::new(&first, PinPolicy::TrustOnFirstUse).unwrap();
        let (second_connector, _) =
            ClientConnector::new(&second, PinPolicy::TrustOnFirstUse).unwrap();

        // Accepting has to run concurrently with dialling: a QUIC handshake does not
        // complete until the listener has taken the incoming connection, so connecting
        // both before accepting either would simply deadlock.
        let accept_both = async {
            let first = listener.accept().await.unwrap().unwrap();
            let second = listener.accept().await.unwrap().unwrap();
            [first, second]
        };
        let dial_both = async {
            tokio::join!(
                first_connector.connect(address),
                second_connector.connect(address)
            )
        };

        let (accepted, dialled) = tokio::join!(accept_both, dial_both);
        dialled.0.unwrap();
        dialled.1.unwrap();

        let observed: std::collections::HashSet<Fingerprint> = accepted
            .iter()
            .map(|connection| peer_certificate_fingerprint(connection).unwrap())
            .collect();

        assert_eq!(
            observed,
            [
                first.public().certificate_fingerprint,
                second.public().certificate_fingerprint
            ]
            .into_iter()
            .collect::<std::collections::HashSet<_>>(),
            "each connection must report the certificate of its own peer"
        );

        // The endpoint-wide record holds only whichever handshake finished last, which
        // is precisely why authorization must not read from it.
        assert!(endpoint_observed.fingerprint().is_some());
    }

    #[test]
    fn a_certificate_chain_is_refused_under_every_policy() {
        // A chain implies a CA. Accepting one would mean accepting a certificate we did
        // not pin because something else vouched for it.
        let a = identity("a");
        let b = identity("b");
        let observed = ObservedPeer::new();

        let end = CertificateDer::from(a.public().certificate_der.clone());
        let intermediate = [CertificateDer::from(b.public().certificate_der.clone())];

        for policy in [
            PinPolicy::Pinned(a.public().certificate_fingerprint),
            PinPolicy::TrustOnFirstUse,
        ] {
            assert!(
                verify_pinned(&end, &intermediate, &policy, &observed, "server").is_err(),
                "a chain must be refused"
            );
        }
    }
}
