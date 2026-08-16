//! Catching the chords the *operator's own* machine would otherwise swallow.
//!
//! # The gap this closes
//!
//! Every other key an operator presses reaches the app, which forwards it. `Alt+Tab`
//! does not: the operator's own window manager acts on it first, switching their local
//! windows, and the remote machine never hears about it. The same is true of `Alt+Esc`,
//! the Windows key, `Cmd+Tab` on macOS and whatever the local desktop has claimed.
//!
//! Closing it means asking the OS for the keystroke *before* the window manager gets
//! it, which every platform spells differently and all of them treat as a privileged
//! thing to want.
//!
//! # What must never happen
//!
//! A grab is a promise to hand keystrokes back. While one is active the operator's own
//! `Alt+Tab` stops switching their own windows — which is the entire point while they
//! are driving a remote machine, and a serious bug at any other moment. So:
//!
//! - A grab is active only while the session surface holds focus *and* input is being
//!   forwarded. Losing either releases it.
//! - Every backend releases in `Drop`, so an early return or a panic cannot leak one.
//! - Nothing here grabs a chord the platform reserves absolutely.
//!   [`Reserved::SecureAttention`] is the honest name for `Ctrl+Alt+Del`: it is handled
//!   on a separate desktop that no ordinary process can hook, and pretending otherwise
//!   would leave an operator believing they had sent it.
//!
//! # The policy is separate from the mechanism
//!
//! Which chords are worth taking is a per-OS fact that needs no privileges to decide,
//! so it lives here as plain data and is tested everywhere. The taking itself is behind
//! the `grab` feature, for the same reason injection is behind `inject`.

use rc_protocol::{Intent, Modifiers, PhysicalKey};

use crate::intent::{Chord, HostOs};

mod session;

pub use session::{Disposition, GrabError, GrabGuard, KeyGrab, NoGrab, disposition, should_grab};

/// Why a chord cannot simply be forwarded like any other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reserved {
    /// The local window manager acts on it first, but a hook can take it back.
    WindowManager,
    /// The platform handles it below any process: `Ctrl+Alt+Del` and its kin.
    ///
    /// Cannot be grabbed by anything this program is allowed to do. Named so the
    /// interface can say so, rather than offering a switch that quietly does nothing.
    SecureAttention,
}

/// Whether `chord` is one the operator's own OS would act on before this app sees it.
///
/// Judged against the **controller's** OS, not the host's — this is about what the
/// machine under the operator's hands does with the keystroke, which is a different
/// question from what the remote machine would do with it.
#[must_use]
pub fn reserved_by(chord: Chord, os: HostOs) -> Option<Reserved> {
    if is_secure_attention(chord, os) {
        return Some(Reserved::SecureAttention);
    }
    window_manager_intent(chord, os).map(|_| Reserved::WindowManager)
}

/// The secure attention sequence, which no hook may take.
fn is_secure_attention(chord: Chord, os: HostOs) -> bool {
    match os {
        // Ctrl+Alt+Del is dispatched on the Secure Desktop, above every hook.
        HostOs::Windows => {
            chord.key == PhysicalKey::Delete
                && chord.mods.contains(Modifiers::CONTROL)
                && chord.mods.contains(Modifiers::ALT)
        }
        // Neither platform has an equivalent an ordinary process is barred from seeing.
        HostOs::MacOs | HostOs::Linux => false,
    }
}

/// Chords the local desktop claims *and* this build can forward, with the intent each
/// one means.
///
/// The two halves are deliberately one function. A chord that is grabbed but has no
/// intent to send would be strictly worse than not grabbing it: the operator's own
/// desktop would not act on it and neither would the remote one, so the keystroke would
/// simply vanish. That is why the bare Windows key and `Ctrl+Esc` are absent — they open
/// a local menu, and this build has no intent meaning "open the host's menu" to send in
/// exchange.
fn window_manager_intent(chord: Chord, os: HostOs) -> Option<Intent> {
    let meta = chord.mods.contains(Modifiers::META);
    let alt = chord.mods.contains(Modifiers::ALT);

    match os {
        HostOs::Windows | HostOs::Linux => match chord.key {
            // Alt+Tab switches windows and Alt+Esc cycles them. Shift is not tested:
            // it only reverses the direction, and the reversed form is claimed just as
            // firmly by the desktop.
            PhysicalKey::Tab | PhysicalKey::Escape if alt => Some(Intent::SwitchApp),
            PhysicalKey::KeyD if meta => Some(Intent::ShowDesktop),
            PhysicalKey::KeyL if meta => Some(Intent::LockScreen),
            _ => None,
        },
        HostOs::MacOs => match chord.key {
            // macOS switches applications with Command, not Alt.
            PhysicalKey::Tab if meta => Some(Intent::SwitchApp),
            _ => None,
        },
    }
}

/// The intent a grabbed chord should be forwarded as.
///
/// `None` for anything not worth grabbing, which is the same set: see
/// [`window_manager_intent`].
#[must_use]
pub fn grabbed_intent(chord: Chord, os: HostOs) -> Option<Intent> {
    // A chord the platform will not surrender is not grabbed, so it has no intent here
    // either, however much it looks like one.
    if is_secure_attention(chord, os) {
        return None;
    }
    window_manager_intent(chord, os)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chord(key: PhysicalKey, mods: Modifiers) -> Chord {
        Chord::new(key, mods)
    }

    #[test]
    fn alt_tab_is_claimed_by_the_local_window_manager() {
        // The chord this module exists for: without a grab it switches the operator's
        // own windows and never reaches the remote machine.
        assert_eq!(
            reserved_by(chord(PhysicalKey::Tab, Modifiers::ALT), HostOs::Windows),
            Some(Reserved::WindowManager)
        );
        assert_eq!(
            reserved_by(chord(PhysicalKey::Tab, Modifiers::ALT), HostOs::Linux),
            Some(Reserved::WindowManager)
        );
    }

    #[test]
    fn reversing_alt_tab_with_shift_is_claimed_just_as_firmly() {
        let mods = Modifiers::ALT.with(Modifiers::SHIFT);
        assert_eq!(
            reserved_by(chord(PhysicalKey::Tab, mods), HostOs::Windows),
            Some(Reserved::WindowManager)
        );
    }

    #[test]
    fn ctrl_alt_del_is_named_unreachable_rather_than_promised() {
        // It is dispatched on the Secure Desktop, above every hook. Offering it as
        // something this app can forward would leave an operator believing they had
        // sent it to a machine they cannot see.
        let mods = Modifiers::CONTROL.with(Modifiers::ALT);
        assert_eq!(
            reserved_by(chord(PhysicalKey::Delete, mods), HostOs::Windows),
            Some(Reserved::SecureAttention)
        );
    }

    #[test]
    fn a_chord_with_nothing_to_send_in_exchange_is_left_alone() {
        // A bare Windows key opens the local menu, and this build has no intent meaning
        // "open the host's menu". Grabbing it would be strictly worse than not: the
        // operator's own desktop would not act on it and neither would the remote one,
        // so the keystroke would simply vanish.
        assert_eq!(
            reserved_by(
                chord(PhysicalKey::MetaLeft, Modifiers::NONE),
                HostOs::Windows
            ),
            None
        );
        assert_eq!(
            reserved_by(
                chord(PhysicalKey::Escape, Modifiers::CONTROL),
                HostOs::Windows
            ),
            None
        );
    }

    #[test]
    fn everything_grabbed_has_an_intent_to_forward() {
        // The invariant the whole policy rests on. A grabbed chord with no intent is a
        // swallowed keystroke that reaches neither machine.
        let candidates = [
            (PhysicalKey::Tab, Modifiers::ALT),
            (PhysicalKey::Tab, Modifiers::ALT.with(Modifiers::SHIFT)),
            (PhysicalKey::Escape, Modifiers::ALT),
            (PhysicalKey::KeyD, Modifiers::META),
            (PhysicalKey::KeyL, Modifiers::META),
            (PhysicalKey::Tab, Modifiers::META),
            (PhysicalKey::MetaLeft, Modifiers::NONE),
            (PhysicalKey::KeyA, Modifiers::NONE),
            (PhysicalKey::Delete, Modifiers::CONTROL.with(Modifiers::ALT)),
        ];

        for os in [HostOs::Windows, HostOs::MacOs, HostOs::Linux] {
            for (key, mods) in candidates {
                let c = chord(key, mods);
                if reserved_by(c, os) == Some(Reserved::WindowManager) {
                    assert!(
                        grabbed_intent(c, os).is_some(),
                        "{key:?}+{mods:?} is grabbed on {os:?} with nothing to send"
                    );
                }
            }
        }
    }

    #[test]
    fn alt_tab_is_forwarded_as_switch_app_so_the_host_spells_it_itself() {
        // The point of the intent layer: a Windows operator's Alt+Tab arrives on a
        // macOS host as Cmd+Tab, because the host renders the meaning in its own chord.
        assert_eq!(
            grabbed_intent(chord(PhysicalKey::Tab, Modifiers::ALT), HostOs::Windows),
            Some(Intent::SwitchApp)
        );
        assert_eq!(
            grabbed_intent(chord(PhysicalKey::Tab, Modifiers::META), HostOs::MacOs),
            Some(Intent::SwitchApp)
        );
    }

    #[test]
    fn the_secure_attention_sequence_has_no_intent_to_forward() {
        // It is never grabbed, so it must never look forwardable either.
        let mods = Modifiers::CONTROL.with(Modifiers::ALT);
        assert_eq!(
            grabbed_intent(chord(PhysicalKey::Delete, mods), HostOs::Windows),
            None
        );
    }

    #[test]
    fn cmd_tab_is_claimed_on_macos_and_alt_tab_is_not() {
        // macOS switches applications with Cmd, not Alt. Grabbing Alt+Tab there would
        // take a chord the operator's machine was going to deliver anyway.
        assert_eq!(
            reserved_by(chord(PhysicalKey::Tab, Modifiers::META), HostOs::MacOs),
            Some(Reserved::WindowManager)
        );
        assert_eq!(
            reserved_by(chord(PhysicalKey::Tab, Modifiers::ALT), HostOs::MacOs),
            None
        );
    }

    #[test]
    fn show_desktop_and_lock_are_claimed_where_they_map_to_an_intent() {
        assert_eq!(
            grabbed_intent(chord(PhysicalKey::KeyD, Modifiers::META), HostOs::Windows),
            Some(Intent::ShowDesktop)
        );
        assert_eq!(
            grabbed_intent(chord(PhysicalKey::KeyL, Modifiers::META), HostOs::Windows),
            Some(Intent::LockScreen)
        );
    }

    #[test]
    fn ordinary_typing_is_never_grabbed() {
        // A grab that took ordinary keys would be a keylogger with extra steps, and it
        // would stop the operator using their own machine entirely.
        for os in [HostOs::Windows, HostOs::MacOs, HostOs::Linux] {
            for key in [
                PhysicalKey::KeyA,
                PhysicalKey::Digit1,
                PhysicalKey::Enter,
                PhysicalKey::Space,
                PhysicalKey::ArrowUp,
                PhysicalKey::F5,
            ] {
                assert_eq!(
                    reserved_by(chord(key, Modifiers::NONE), os),
                    None,
                    "{key:?} must reach the app the ordinary way on {os:?}"
                );
            }
        }
    }

    #[test]
    fn a_plain_shortcut_is_left_alone() {
        // Ctrl+C already reaches the app; taking it would add a hook for nothing.
        assert_eq!(
            reserved_by(
                chord(PhysicalKey::KeyC, Modifiers::CONTROL),
                HostOs::Windows
            ),
            None
        );
    }

    #[test]
    fn delete_without_both_modifiers_is_an_ordinary_key() {
        // Ctrl+Delete and Alt+Delete are ordinary editing chords; only the pair is the
        // secure attention sequence.
        assert_eq!(
            reserved_by(
                chord(PhysicalKey::Delete, Modifiers::CONTROL),
                HostOs::Windows
            ),
            None
        );
        assert_eq!(
            reserved_by(chord(PhysicalKey::Delete, Modifiers::ALT), HostOs::Windows),
            None
        );
    }
}
