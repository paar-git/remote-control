//! The host side of the product, as a library.
//!
//! Both the desktop application and the optional service run this code. There is one
//! implementation of accepting a connection, deciding what it may do and serving it —
//! a second would be a second set of authorisation bugs.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod access;
pub mod config;
pub mod error;
pub mod file_service;
pub mod health;
pub mod identity;
pub mod logging;
pub mod metrics_service;
pub mod server;
pub mod sessions;

pub use access::{
    AcceptAnswer, AcceptDecision, AcceptPrompt, AcceptRequest, AccessDeps, Authorization,
    ConnectionRequest, RefusalReason, authorize_connection,
};
// `WireRefusal` travels on the wire, so it is defined in `rc-protocol` rather than
// here; re-exported for convenience since callers of this crate reach for it alongside
// `RefusalReason`.
pub use rc_protocol::control::WireRefusal;
