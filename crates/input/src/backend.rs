//! Injection backends.
//!
//! [`mock`] records calls and is always available; it is what lets the pipeline be
//! tested without a desktop. The real backend is behind the `inject` feature so that
//! the translation logic — and its tests — build on a machine with no display server.

pub mod mock;

#[cfg(feature = "inject")]
pub mod displays;
#[cfg(feature = "inject")]
pub mod enigo;
#[cfg(feature = "inject")]
pub mod keymap;

pub mod position;
