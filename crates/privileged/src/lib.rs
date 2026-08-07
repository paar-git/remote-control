//! The privileged helper: a separate process that performs allowlisted operations.
//!
//! # Why there are two processes at all
//!
//! The agent needs to restart services and shut the machine down. It does **not** need
//! to be able to do anything else with those privileges, and it is the process exposed
//! to the network — the one an attacker reaches first.
//!
//! So privilege is split. The agent runs unelevated and asks; a small helper runs
//! elevated and decides. Compromising the agent yields the ability to *request*
//! operations from a closed list, not the ability to run arbitrary code as root.
//!
//! That is only true if the helper is genuinely the decision-maker, which is the rule
//! this crate is built around:
//!
//! > **The helper re-validates every request against the allowlist itself.**
//! > It never trusts that its caller already did.
//!
//! The agent validates too, so a mistake is caught early and reported well. But the
//! agent's check is a convenience; the helper's is the control.
//!
//! # What crosses the wire
//!
//! An *operation*, never a command. The request names a [`rc_protocol::system::PowerAction`]
//! or a service name plus a [`rc_protocol::system::ServiceAction`]. There is no field
//! that could carry a program path, an argument vector or a shell string, so there is
//! nothing for an injection to inject into — the resolution from operation to
//! `(program, argv)` happens inside the helper, from constants.
//!
//! # How the helper knows who is asking
//!
//! A token file, written by the helper at startup into a directory only the agent's
//! account and administrators can read. Being able to read that file *is* the
//! authorization, exactly as for the agent's own local control endpoint.
//!
//! The socket is loopback-only and its address is not configurable, so no configuration
//! mistake can put it on the network.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod client;
pub mod protocol;
pub mod server;

pub use client::PrivilegedClient;
pub use protocol::{
    HelperError, HelperRequest, HelperResponse, PrivilegedOperation, TOKEN_FILE_NAME, Token,
};
pub use server::HelperServer;
