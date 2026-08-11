//! QUIC transport, mutually-authenticated TLS, and the connection lifecycle.
//!
//! # Shape of a connection
//!
//! ```text
//!   client                                            agent
//!     │                                                 │
//!     │──── QUIC + mTLS 1.3, ALPN "rc/1" ──────────────►│
//!     │     both certificates pinned by fingerprint     │
//!     │                                                 │
//!     │──── Hello (device id, version, capabilities) ──►│
//!     │                                                 │  trust lookup
//!     │                                                 │  revocation re-check
//!     │◄─── HelloAck (session, granted capabilities) ───│
//!     │                                                 │
//!     │◄════ six independent channel streams ══════════►│
//! ```
//!
//! # Why the layers are separate
//!
//! TLS proves *which key* is on the other end. It does not know whether that key is
//! still trusted — revocation happens in the database, minutes or months after a
//! certificate was pinned. So authentication is two steps:
//!
//! 1. [`tls`] pins the certificate fingerprint and records what was actually observed.
//! 2. [`handshake`] looks the device up, **re-checks revocation**, and only then admits
//!    it.
//!
//! Collapsing these — trusting the TLS result alone — would make revocation take effect
//! only when a certificate happened to change, which is to say never.
//!
//! # Channels
//!
//! Each [`rc_protocol::Channel`] gets its own QUIC stream, so a file transfer cannot
//! head-of-line block input events. Frame limits are enforced per channel from the
//! header, before allocation, by [`rc_protocol`].

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod channel;
pub mod endpoint;
pub mod error;
pub mod handshake;
pub mod pairing;
pub mod tls;

pub use channel::{ChannelReader, ChannelWriter, accept_channel, open_channel};
pub use endpoint::{AgentListener, ClientConnector};
pub use error::{RejectionCause, Result, TransportError};
pub use handshake::{AuthenticatedPeer, TrustDirectory, TrustRecord};
pub use pairing::{PairingRecorder, PairingService, pair_as_client};
pub use tls::{ALPN, ObservedCertificate, ObservedPeer, PinPolicy, peer_certificate_fingerprint};
