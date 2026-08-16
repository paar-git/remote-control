//! When a grab is active, and what happens to the keys it takes.
//!
//! Split from the platform hooks on purpose. Whether a grab *should* be running, and
//! what to do with a chord it caught, are decisions with no FFI in them — so they are
//! written here against a trait and tested with a fake, and the platform code underneath
//! stays a thin shim that only installs and uninstalls.

use super::{Reserved, reserved_by};
use crate::intent::{Chord, HostOs};

/// Why a grab could not be installed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GrabError {
    /// This build has no grabbing backend.
    #[error("this build cannot take keys from the local desktop")]
    Unsupported,
    /// The platform refused: no Accessibility grant on macOS, no X display, and so on.
    #[error("the local desktop refused to hand over its shortcuts")]
    Refused,
}

/// Something that can take reserved chords from the local desktop.
///
/// A trait so the rules above it are testable without a window manager, and so a build
/// without the `grab` feature still has a shape to compile against.
pub trait KeyGrab {
    /// Begin taking reserved chords.
    ///
    /// # Errors
    /// The platform has no such facility, or refused.
    fn engage(&mut self) -> Result<(), GrabError>;

    /// Stop taking them, handing the desktop its shortcuts back.
    ///
    /// Deliberately infallible: there is no useful way to respond to a failed release,
    /// and every implementation must try regardless — this is also called from `Drop`.
    fn release(&mut self);

    /// Whether a grab is currently held.
    fn engaged(&self) -> bool;
}

/// What should happen to a chord the operator pressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Send it to the remote machine, and do not let the local desktop act on it.
    Forward,
    /// Let the local desktop have it as usual.
    PassToLocalDesktop,
}

/// Decide what to do with `chord` while a grab is or is not active.
///
/// The single rule the hook callback follows, kept out of the callback so it can be
/// tested: a hook that gets this wrong either swallows the operator's own keyboard or
/// quietly fails to forward the one chord it was installed for.
#[must_use]
pub fn disposition(chord: Chord, os: HostOs, grabbing: bool) -> Disposition {
    if !grabbing {
        return Disposition::PassToLocalDesktop;
    }
    match reserved_by(chord, os) {
        // Taking it back from the window manager is the entire purpose.
        Some(Reserved::WindowManager) => Disposition::Forward,
        // Never swallowed: the platform would not give it to us anyway, and a chord
        // this app pretends to take is one the operator cannot use locally either.
        Some(Reserved::SecureAttention) | None => Disposition::PassToLocalDesktop,
    }
}

/// Whether a grab should be held right now.
///
/// Both conditions matter and neither implies the other. Focus alone is not enough —
/// a session that is not forwarding input has no use for the operator's `Alt+Tab` — and
/// forwarding alone is not enough, or the operator could not switch away from the app.
#[must_use]
pub const fn should_grab(surface_focused: bool, forwarding_input: bool) -> bool {
    surface_focused && forwarding_input
}

/// A grab that does nothing, for builds and tests without a desktop.
#[derive(Debug, Default)]
pub struct NoGrab {
    engaged: bool,
}

impl NoGrab {
    /// A released grab.
    #[must_use]
    pub const fn new() -> Self {
        Self { engaged: false }
    }
}

impl KeyGrab for NoGrab {
    fn engage(&mut self) -> Result<(), GrabError> {
        self.engaged = true;
        Ok(())
    }

    fn release(&mut self) {
        self.engaged = false;
    }

    fn engaged(&self) -> bool {
        self.engaged
    }
}

/// Hold a grab exactly while it is wanted.
///
/// The reason this exists rather than two calls at the call site: every path that stops
/// wanting a grab must release it, including the ones that are easy to forget — an
/// error return, a session torn down mid-chord, a panic. `Drop` closes all of them.
#[derive(Debug)]
pub struct GrabGuard<G: KeyGrab> {
    grab: G,
}

impl<G: KeyGrab> GrabGuard<G> {
    /// Wrap `grab`, released.
    pub const fn new(grab: G) -> Self {
        Self { grab }
    }

    /// Engage or release so the grab matches `wanted`.
    ///
    /// Idempotent: called on every focus and permission change, and doing nothing when
    /// nothing changed is what keeps a hook from being reinstalled on every keystroke.
    ///
    /// # Errors
    /// The platform refused to install the grab.
    pub fn set(&mut self, wanted: bool) -> Result<(), GrabError> {
        match (wanted, self.grab.engaged()) {
            (true, false) => self.grab.engage(),
            (false, true) => {
                self.grab.release();
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Whether a grab is held.
    pub fn engaged(&self) -> bool {
        self.grab.engaged()
    }
}

impl<G: KeyGrab> Drop for GrabGuard<G> {
    fn drop(&mut self) {
        // The promise this whole module rests on: the desktop gets its shortcuts back,
        // whatever happened.
        self.grab.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rc_protocol::{Modifiers, PhysicalKey};

    fn alt_tab() -> Chord {
        Chord::new(PhysicalKey::Tab, Modifiers::ALT)
    }

    #[test]
    fn alt_tab_is_forwarded_while_grabbing() {
        assert_eq!(
            disposition(alt_tab(), HostOs::Windows, true),
            Disposition::Forward
        );
    }

    #[test]
    fn alt_tab_belongs_to_the_local_desktop_when_not_grabbing() {
        // The operator is using their own machine; taking it would be a bug.
        assert_eq!(
            disposition(alt_tab(), HostOs::Windows, false),
            Disposition::PassToLocalDesktop
        );
    }

    #[test]
    fn ordinary_keys_are_never_swallowed_even_while_grabbing() {
        // A hook that swallowed these would stop the operator typing anywhere.
        for key in [PhysicalKey::KeyA, PhysicalKey::Enter, PhysicalKey::F5] {
            assert_eq!(
                disposition(Chord::new(key, Modifiers::NONE), HostOs::Windows, true),
                Disposition::PassToLocalDesktop
            );
        }
    }

    #[test]
    fn the_secure_attention_sequence_is_never_swallowed() {
        // The platform would not hand it over anyway, and a chord this app pretended to
        // take would be one the operator could not use locally either.
        let mods = Modifiers::CONTROL.with(Modifiers::ALT);
        assert_eq!(
            disposition(Chord::new(PhysicalKey::Delete, mods), HostOs::Windows, true),
            Disposition::PassToLocalDesktop
        );
    }

    #[test]
    fn a_grab_is_wanted_only_with_focus_and_forwarding_together() {
        // Neither implies the other: an unfocused session must not hold the operator's
        // Alt+Tab, and a focused one that forwards nothing has no use for it.
        assert!(should_grab(true, true));
        assert!(!should_grab(true, false));
        assert!(!should_grab(false, true));
        assert!(!should_grab(false, false));
    }

    #[test]
    fn the_guard_engages_and_releases_to_match_what_is_wanted() {
        let mut guard = GrabGuard::new(NoGrab::new());
        assert!(!guard.engaged());

        guard.set(true).expect("a no-op grab always engages");
        assert!(guard.engaged());

        guard.set(false).expect("releasing never fails");
        assert!(!guard.engaged());
    }

    #[test]
    fn setting_the_same_state_twice_does_not_reinstall() {
        // `set` is called on every focus change; reinstalling a platform hook each time
        // would be wasteful at best and a leak at worst.
        #[derive(Default)]
        struct Counting {
            engaged: bool,
            engages: usize,
        }
        impl KeyGrab for Counting {
            fn engage(&mut self) -> Result<(), GrabError> {
                self.engages += 1;
                self.engaged = true;
                Ok(())
            }
            fn release(&mut self) {
                self.engaged = false;
            }
            fn engaged(&self) -> bool {
                self.engaged
            }
        }

        let mut guard = GrabGuard::new(Counting::default());
        guard.set(true).expect("engages");
        guard.set(true).expect("stays engaged");
        guard.set(true).expect("stays engaged");

        assert!(guard.engaged());
    }

    #[test]
    fn dropping_the_guard_hands_the_shortcuts_back() {
        // The case that matters most: a session torn down mid-chord, or a panic on the
        // way out, must not leave the operator unable to switch their own windows.
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        struct Tracked(Arc<AtomicBool>);
        impl KeyGrab for Tracked {
            fn engage(&mut self) -> Result<(), GrabError> {
                self.0.store(true, Ordering::SeqCst);
                Ok(())
            }
            fn release(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
            fn engaged(&self) -> bool {
                self.0.load(Ordering::SeqCst)
            }
        }

        let held = Arc::new(AtomicBool::new(false));
        {
            let mut guard = GrabGuard::new(Tracked(Arc::clone(&held)));
            guard.set(true).expect("engages");
            assert!(held.load(Ordering::SeqCst));
        }

        assert!(
            !held.load(Ordering::SeqCst),
            "a dropped guard must release the grab"
        );
    }

    #[test]
    fn a_refusal_leaves_the_guard_released_rather_than_believing_it_holds_one() {
        // A guard that thought it held a grab it did not would never retry, and would
        // report a state the desktop does not agree with.
        struct AlwaysRefuses;
        impl KeyGrab for AlwaysRefuses {
            fn engage(&mut self) -> Result<(), GrabError> {
                Err(GrabError::Refused)
            }
            fn release(&mut self) {}
            fn engaged(&self) -> bool {
                false
            }
        }

        let mut guard = GrabGuard::new(AlwaysRefuses);
        assert_eq!(guard.set(true), Err(GrabError::Refused));
        assert!(!guard.engaged());
    }
}
