//! QUIC transport, mutually-authenticated TLS, and the connection lifecycle.
//!
//! # Shape of a connection
//!
//! ```text
//!   client                                            agent
//!     │                                                 │
//!     │──── QUIC + mTLS 1.3, ALPN "rc/1" ──────────────►│
//!     │                                                 │
//!     │──── Hello (device id, version, capabilities) ──►│
//!     │                                                 │  version and role checks
//!     │◄─── HelloAck (negotiated version, only) ────────│
//!     │──── Authenticate (dialled address, password) ──►│
//!     │                                                 │  admission decision
//!     │◄─── SessionAuthorization ───────────────────────│
//!     │       Granted (permissions, who this is)        │
//!     │       or Refused (one coarse reason)            │
//!     │                                                 │
//!     │◄════ independent channel streams ══════════════►│
//! ```
//!
//! # Why the layers are separate
//!
//! TLS proves *which key* is on the other end. It cannot answer whether that key may
//! have a session, because in this design that is a decision the machine being
//! controlled makes — usually by asking its user. So admission is two steps:
//!
//! 1. [`tls`] records the certificate fingerprint that was actually observed.
//! 2. [`handshake`] carries that fingerprint to a decision the *caller* makes, and
//!    carries the answer back.
//!
//! Collapsing these — admitting whoever completes TLS — would leave a remote-control
//! agent with no authorisation step at all.
//!
//! Note where the split falls. `HelloAck` is sent before anything has been decided, so
//! it says only that the versions are compatible; everything identifying the machine
//! waits for `SessionAuthorization::Granted`. A peer that is refused learns that it was
//! refused, and nothing about what it reached.
//!
//! # Channels
//!
//! Each [`rc_protocol::Channel`] gets its own QUIC stream, so a file transfer cannot
//! head-of-line block input events. Frame limits are enforced per channel from the
//! header, before allocation, by [`rc_protocol`].

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod address;
pub mod channel;
pub mod endpoint;
pub mod error;
pub mod handshake;
pub mod tls;

pub use address::PeerAddress;
pub use channel::{ChannelReader, ChannelWriter, accept_channel, open_channel};
pub use endpoint::{AgentListener, ClientConnector};
pub use error::{Result, TransportError};
pub use handshake::{AuthenticatedPeer, PeerIdentity};
pub use tls::{
    ALPN, ObservedCertificate, ObservedPeer, PinPolicy, peer_certificate_der,
    peer_certificate_fingerprint,
};
