//! Taking the chords the operator's own desktop reserves.
//!
//! # Why this is its own crate
//!
//! Every platform hands over `Alt+Tab` through a different privileged mechanism, and
//! all of them are FFI. `rc-input` is `#![forbid(unsafe_code)]` on purpose — that is
//! what lets a Windows machine verify macOS and Linux chord translation — so the unsafe
//! lives here instead, and `rc-input` keeps the guarantee.
//!
//! The split is also where the testing sits. Everything decision-shaped —
//! *which* chords the local desktop claims, *when* a grab should be held, and what to do
//! with one that was caught — is in [`rc_input::grab`], is pure, and is tested on every
//! platform. What is left here installs and removes a hook and nothing else.
//!
//! # The promise
//!
//! A grab takes keystrokes away from the operator's own machine. While one is held their
//! `Alt+Tab` stops switching their own windows, which is the point while they are driving
//! a remote desktop and a serious bug at any other moment. Every backend releases in
//! `Drop`, and [`rc_input::grab::GrabGuard`] is the type that makes an early return or a
//! panic release too.
//!
//! # What is implemented
//!
//! Windows, macOS and X11. Each reports [`GrabError::Refused`] rather than returning
//! something that silently takes nothing — an operator told the grab is on, whose
//! `Alt+Tab` still switches their local windows, would reasonably conclude the remote
//! session was broken. Wayland has no portable equivalent, so a Wayland session gets
//! whatever `XWayland` can offer or a refusal.

// The workspace warns on `unsafe_code`, and `rc-input` forbids it outright. This crate
// is the exception that lets both of those stay true: every unsafe block in the project
// is here, in the thin shims that install and remove a platform hook, where it can be
// reviewed as a unit rather than scattered through the input layer.
#![allow(unsafe_code)]

use std::sync::mpsc::Sender;

use rc_input::grab::{GrabError, KeyGrab};
use rc_input::intent::Chord;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::WindowsKeyGrab;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacosKeyGrab;

#[cfg(all(unix, not(target_os = "macos")))]
mod linux;
#[cfg(all(unix, not(target_os = "macos")))]
pub use linux::LinuxKeyGrab;

/// A grab for this platform, forwarding the chords it takes to `sink`.
///
/// # Errors
/// [`GrabError::Unsupported`] where this build has no backend, and
/// [`GrabError::Refused`] where the platform has one but would not provide it.
#[cfg(target_os = "windows")]
pub fn new_grab(sink: Sender<Chord>) -> Result<Box<dyn KeyGrab + Send>, GrabError> {
    Ok(Box::new(WindowsKeyGrab::new(sink)?))
}

/// A grab for this platform, forwarding the chords it takes to `sink`.
///
/// # Errors
/// Always [`GrabError::Unsupported`] on this platform: no backend is written yet.
///
/// Wayland has no portable equivalent at all and would need the compositor's
/// cooperation.
#[cfg(target_os = "macos")]
pub fn new_grab(sink: Sender<Chord>) -> Result<Box<dyn KeyGrab + Send>, GrabError> {
    Ok(Box::new(MacosKeyGrab::new(sink)))
}

/// A grab for this platform, forwarding the chords it takes to `sink`.
///
/// # Errors
/// [`GrabError::Refused`] where no X server can be reached, which includes a Wayland
/// session with no `XWayland`.
#[cfg(all(unix, not(target_os = "macos")))]
pub fn new_grab(sink: Sender<Chord>) -> Result<Box<dyn KeyGrab + Send>, GrabError> {
    Ok(Box::new(LinuxKeyGrab::new(sink)))
}

/// A grab for this platform, forwarding the chords it takes to `sink`.
///
/// # Errors
/// Always [`GrabError::Unsupported`] on this platform: no backend is written yet.
#[cfg(not(any(target_os = "windows", target_os = "macos", unix)))]
pub fn new_grab(_sink: Sender<Chord>) -> Result<Box<dyn KeyGrab + Send>, GrabError> {
    Err(GrabError::Unsupported)
}
