//! The real backend: the one place in the tree that injects into an operating system.
//!
//! # Why a crate rather than direct FFI
//!
//! Injection is `SendInput` on Windows, `CGEventPost` on macOS and `XTestFakeKeyEvent`
//! on X11 — three unsafe FFI surfaces with three different failure modes.
//! [`enigo`] encapsulates them, which keeps `unsafe` out of this workspace entirely
//! and leaves the interesting logic — translation, held-key tracking, acknowledgement —
//! pure and testable. If a platform later needs behaviour enigo cannot express, this
//! file is the only one that changes: [`crate::InputSink`] is the seam.
//!
//! # Failures are diagnosed, not swallowed
//!
//! Each platform refuses input for its own reason, and the operator can only act on
//! the *specific* one:
//!
//! * **macOS** silently no-ops without Accessibility permission — `CGEventPost`
//!   reports success either way. [`probe`] therefore tests construction explicitly
//!   rather than inferring from a call that cannot fail, and reports
//!   [`InputFailure::NotPermitted`].
//! * **Windows** blocks injection into a higher-integrity window (UIPI) unless the
//!   agent is elevated: [`InputFailure::Blocked`].
//! * **Linux/Wayland** refuses synthetic input altogether without a portal, so it is
//!   detected up front and reported as [`InputFailure::Unavailable`] rather than
//!   accepting events and dropping them.

use enigo::{
    Axis, Button, Coordinate, Direction, Enigo, Keyboard as _, Mouse as _, Settings,
};
use rc_protocol::{Intent, InputCapability, InputFailure, KeyState, MouseButton, PhysicalKey};

use crate::{HostOs, InputError, InputSink, Result, intent};

/// Injects through the host's native input API.
pub struct EnigoSink {
    enigo: Enigo,
    capability: InputCapability,
}

impl std::fmt::Debug for EnigoSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnigoSink")
            .field("capability", &self.capability)
            .finish_non_exhaustive()
    }
}

/// Whether this machine can inject input, and if not, precisely why.
///
/// Called once at session start so a host that cannot inject says so before the
/// operator starts typing into a void.
#[must_use]
pub fn probe() -> InputCapability {
    if let Some(reason) = wayland_refusal() {
        return InputCapability::Unavailable { reason };
    }

    match Enigo::new(&Settings::default()) {
        Ok(_) => InputCapability::Full,
        Err(err) => {
            tracing::warn!(%err, "this host cannot inject input");
            InputCapability::Unavailable {
                reason: construction_failure(),
            }
        }
    }
}

/// Wayland blocks synthetic input without a portal, so it is refused up front.
///
/// Returns `None` on every other platform, and on Linux under X11.
fn wayland_refusal() -> Option<InputFailure> {
    #[cfg(target_os = "linux")]
    {
        let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some()
            || std::env::var("XDG_SESSION_TYPE")
                .is_ok_and(|kind| kind.eq_ignore_ascii_case("wayland"));
        // XWayland gives a usable X11 connection even in a Wayland session, so an
        // available DISPLAY means XTest will work and the session is not refused.
        if wayland && std::env::var_os("DISPLAY").is_none() {
            return Some(InputFailure::Unavailable);
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// What a failure to construct the backend means on this platform.
const fn construction_failure() -> InputFailure {
    #[cfg(target_os = "macos")]
    {
        // The overwhelmingly common cause: Accessibility permission not granted.
        InputFailure::NotPermitted
    }
    #[cfg(not(target_os = "macos"))]
    {
        InputFailure::Unavailable
    }
}

impl EnigoSink {
    /// Build a sink for this machine.
    ///
    /// # Errors
    /// [`InputError::Refused`] when the platform will not permit injection, carrying
    /// the specific reason so the operator learns what to fix.
    pub fn new() -> Result<Self> {
        if let Some(reason) = wayland_refusal() {
            return Err(InputError::Refused(reason));
        }
        let enigo = Enigo::new(&Settings::default())
            .map_err(|err| InputError::Backend(err.to_string()))?;
        Ok(Self {
            enigo,
            capability: InputCapability::Full,
        })
    }
}

/// Translate a portable button to enigo's.
#[expect(
    clippy::match_same_arms,
    reason = "the catch-all shares a body with Left by coincidence, not by meaning"
)]
const fn button_of(button: MouseButton) -> Button {
    match button {
        MouseButton::Left => Button::Left,
        MouseButton::Right => Button::Right,
        MouseButton::Middle => Button::Middle,
        MouseButton::Back => Button::Back,
        MouseButton::Forward => Button::Forward,
        // The protocol enum is non-exhaustive; an unknown button is treated as the
        // primary one rather than dropped, since a click was certainly intended.
        _ => Button::Left,
    }
}

const fn direction_of(state: KeyState) -> Direction {
    match state {
        KeyState::Down => Direction::Press,
        KeyState::Up => Direction::Release,
    }
}

impl InputSink for EnigoSink {
    fn pointer_move(&mut self, x: f32, y: f32, _display: u8) -> Result<()> {
        // Normalised coordinates are widened to pixels here, and only here: this is
        // the first point at which the extra range is actually used.
        let (width, height) = self
            .enigo
            .main_display()
            .map_err(|err| InputError::Backend(err.to_string()))?;

        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_precision_loss,
            reason = "a pixel coordinate is an integer by definition, and the product \
                      of a clamped 0..=1 fraction with a display dimension cannot \
                      exceed i32"
        )]
        let (px, py) = (
            (x * width as f32).round() as i32,
            (y * height as f32).round() as i32,
        );

        self.enigo
            .move_mouse(px, py, Coordinate::Abs)
            .map_err(map_err)
    }

    fn button(&mut self, button: MouseButton, state: KeyState) -> Result<()> {
        self.enigo
            .button(button_of(button), direction_of(state))
            .map_err(map_err)
    }

    fn scroll(&mut self, dx: f32, dy: f32) -> Result<()> {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "wheel deltas are whole notches at the OS level"
        )]
        let (ix, iy) = (dx.round() as i32, dy.round() as i32);

        // A delta that rounds to nothing is not an error and must not be reported as
        // one; sub-notch trackpad samples are legitimately common.
        if ix != 0 {
            self.enigo.scroll(ix, Axis::Horizontal).map_err(map_err)?;
        }
        if iy != 0 {
            self.enigo.scroll(iy, Axis::Vertical).map_err(map_err)?;
        }
        Ok(())
    }

    fn key(&mut self, key: PhysicalKey, state: KeyState) -> Result<()> {
        let native = super::keymap::to_enigo(key)
            .ok_or(InputError::Refused(InputFailure::NotSupported))?;
        self.enigo
            .key(native, direction_of(state))
            .map_err(map_err)
    }

    fn capability(&self) -> InputCapability {
        self.capability
    }

    fn host_os(&self) -> Option<HostOs> {
        HostOs::current()
    }

    fn supported_intents(&self) -> Vec<Intent> {
        self.host_os().map(intent::supported).unwrap_or_default()
    }
}

/// Map an enigo failure to the reason the operator can act on.
fn map_err(err: enigo::InputError) -> InputError {
    match err {
        // enigo reports a refused simulation when the OS rejected the event, which on
        // Windows is UIPI and on macOS is a missing Accessibility grant.
        enigo::InputError::Simulate(_) => InputError::Refused(refusal_reason()),
        other => InputError::Backend(other.to_string()),
    }
}

const fn refusal_reason() -> InputFailure {
    #[cfg(target_os = "macos")]
    {
        InputFailure::NotPermitted
    }
    #[cfg(target_os = "windows")]
    {
        InputFailure::Blocked
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        InputFailure::Unavailable
    }
}
