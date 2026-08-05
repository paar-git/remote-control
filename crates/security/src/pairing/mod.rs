//! Secure first-time pairing.
//!
//! Pairing is how two devices that have never met establish mutual, long-lived trust,
//! using a short code the operator carries out-of-band.
//!
//! # The exchange
//!
//! ```text
//!  Operator                Agent                                   Client
//!     │                      │                                        │
//!     │  starts pairing ────►│  begin_pairing()                       │
//!     │◄── code shown ───────│  generates code, stores only verifier  │
//!     │                      │                                        │
//!     │──────────────── types the code ───────────────────────────────►
//!     │                      │                                        │
//!     │                      │◄── 1. ClientIdentityClaim ─────────────│
//!     │                      │                                        │
//!     │                      │─── 2. PairingChallenge ───────────────►│
//!     │                      │    (agent identity, nonce, salt)       │
//!     │                      │                                        │
//!     │                      │            both sides build the same transcript
//!     │                      │                                        │
//!     │                      │◄── 3. ClientProof ─────────────────────│
//!     │                      │    (MAC + Ed25519 signature)           │
//!     │                      │                                        │
//!     │                      │─── 4. AgentConfirmation ──────────────►│
//!     │                      │    (MAC + Ed25519 signature)           │
//!     │                      │                                        │
//!     │                  records trust                          pins agent identity
//! ```
//!
//! # Why each step exists
//!
//! * The **claim** binds the client's device id to its public key: the id is derived
//!   from the key, so a client cannot claim an identity it does not hold.
//! * The **challenge** gives the client the agent's fingerprints and the verifier
//!   salt. Nothing secret is disclosed — without the code the salt is useless.
//! * The **proof** carries two independent assertions: a MAC keyed by the code
//!   verifier (proving the operator's code was entered correctly) and a signature by
//!   the client's identity key (proving the client holds the key behind its claimed
//!   fingerprint). Either alone would be insufficient.
//! * The **confirmation** proves the *agent* also knew the code and holds the key
//!   behind the fingerprint the client is about to pin, which is what stops an
//!   attacker who guessed the code from impersonating the server.
//!
//! Both proofs cover a transcript committing to both identities, both fingerprints,
//! both nonces, the expiry and the requested permissions — see [`transcript`].
//!
//! # Security properties, and what enforces each
//!
//! | Property | Enforced by |
//! |---|---|
//! | Expiry | [`session::PairingSession::refresh`] against an injected clock |
//! | Single use | atomic `Challenged → Consumed` under one mutex |
//! | Attempt cap | failure counter, terminal `AttemptsExhausted` |
//! | No replay across sessions | session id and both nonces in the transcript |
//! | No relay to another endpoint | both certificate fingerprints in the transcript |
//! | No permission tampering | requested role and capabilities in the transcript |
//! | No downgrade | protocol version in the transcript, floor in `Transcript::build` |
//! | Raw code never stored | only `Argon2id(code, salt)` is retained |
//! | Not an oracle | wrong code and wrong transcript both yield `ProofRejected` |

pub mod client;
pub mod code;
pub mod session;
pub mod transcript;

pub use client::{PairedAgent, PairingClient};
pub use code::{CODE_ALPHABET, CODE_LENGTH, CodeVerifier, PairingCode};
pub use session::{
    AgentConfirmation, ClientIdentityClaim, ClientProof, OpenedPairing, PairingChallenge,
    PairingManager, PairingOutcome, PairingPolicy, PairingState,
};
pub use transcript::{
    RequestedPermissions, Transcript, TranscriptInputs, role_from_wire, role_to_wire,
};

#[cfg(test)]
mod tests;
