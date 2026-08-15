//! [`PhysicalKey`] to the backend's key type.
//!
//! # A known and deliberate compromise
//!
//! [`PhysicalKey`] identifies a key by *position*, the way W3C `KeyboardEvent.code`
//! does. Reproducing that exactly on the host would mean injecting raw scancodes,
//! which every OS spells differently and which enigo exposes only through
//! platform-specific escape hatches.
//!
//! So character keys are injected by the character they bear on a US layout, and the
//! non-character keys — modifiers, function keys, navigation, editing — are injected
//! by name, which *is* position-independent. The consequence is precise and worth
//! stating: if the **host** is set to a non-US layout, a letter key may produce that
//! layout's character rather than the one in the same position. Modifiers, shortcuts,
//! arrows and function keys are unaffected, because none of them go through the
//! character path.
//!
//! Fixing this properly means per-OS scancode tables. That is a contained change: this
//! file is the only thing that would need to know.

use enigo::Key;
use rc_protocol::PhysicalKey;

/// The backend key for `key`, or `None` if this build cannot express it.
///
/// Returning `None` rather than a near-miss is deliberate: pressing some *other* key
/// on a machine the operator cannot see is worse than pressing none and saying so.
#[must_use]
#[expect(clippy::too_many_lines, reason = "a flat lookup table reads best whole")]
// `allow` rather than `expect`: which arms exist here is platform-dependent, so whether
// two of them coincide is too. An `expect` that is fulfilled on Linux and unfulfilled on
// macOS would fail the build on one platform whichever way it was written.
#[allow(
    clippy::match_same_arms,
    reason = "distinct physical keys that happen to share a character today; merging them would erase the distinction the scancode work will need"
)]
pub fn to_enigo(key: PhysicalKey) -> Option<Key> {
    Some(match key {
        // Character keys. Lowercase: shifting is the caller's business, expressed by
        // holding Shift, exactly as a physical keyboard does.
        PhysicalKey::KeyA => Key::Unicode('a'),
        PhysicalKey::KeyB => Key::Unicode('b'),
        PhysicalKey::KeyC => Key::Unicode('c'),
        PhysicalKey::KeyD => Key::Unicode('d'),
        PhysicalKey::KeyE => Key::Unicode('e'),
        PhysicalKey::KeyF => Key::Unicode('f'),
        PhysicalKey::KeyG => Key::Unicode('g'),
        PhysicalKey::KeyH => Key::Unicode('h'),
        PhysicalKey::KeyI => Key::Unicode('i'),
        PhysicalKey::KeyJ => Key::Unicode('j'),
        PhysicalKey::KeyK => Key::Unicode('k'),
        PhysicalKey::KeyL => Key::Unicode('l'),
        PhysicalKey::KeyM => Key::Unicode('m'),
        PhysicalKey::KeyN => Key::Unicode('n'),
        PhysicalKey::KeyO => Key::Unicode('o'),
        PhysicalKey::KeyP => Key::Unicode('p'),
        PhysicalKey::KeyQ => Key::Unicode('q'),
        PhysicalKey::KeyR => Key::Unicode('r'),
        PhysicalKey::KeyS => Key::Unicode('s'),
        PhysicalKey::KeyT => Key::Unicode('t'),
        PhysicalKey::KeyU => Key::Unicode('u'),
        PhysicalKey::KeyV => Key::Unicode('v'),
        PhysicalKey::KeyW => Key::Unicode('w'),
        PhysicalKey::KeyX => Key::Unicode('x'),
        PhysicalKey::KeyY => Key::Unicode('y'),
        PhysicalKey::KeyZ => Key::Unicode('z'),

        PhysicalKey::Digit0 => Key::Unicode('0'),
        PhysicalKey::Digit1 => Key::Unicode('1'),
        PhysicalKey::Digit2 => Key::Unicode('2'),
        PhysicalKey::Digit3 => Key::Unicode('3'),
        PhysicalKey::Digit4 => Key::Unicode('4'),
        PhysicalKey::Digit5 => Key::Unicode('5'),
        PhysicalKey::Digit6 => Key::Unicode('6'),
        PhysicalKey::Digit7 => Key::Unicode('7'),
        PhysicalKey::Digit8 => Key::Unicode('8'),
        PhysicalKey::Digit9 => Key::Unicode('9'),

        PhysicalKey::Minus => Key::Unicode('-'),
        PhysicalKey::Equal => Key::Unicode('='),
        PhysicalKey::BracketLeft => Key::Unicode('['),
        PhysicalKey::BracketRight => Key::Unicode(']'),
        PhysicalKey::Backslash => Key::Unicode('\\'),
        PhysicalKey::Semicolon => Key::Unicode(';'),
        PhysicalKey::Quote => Key::Unicode('\''),
        PhysicalKey::Backquote => Key::Unicode('`'),
        PhysicalKey::Comma => Key::Unicode(','),
        PhysicalKey::Period => Key::Unicode('.'),
        PhysicalKey::Slash => Key::Unicode('/'),

        // Named keys: position-independent on every platform.
        PhysicalKey::F1 => Key::F1,
        PhysicalKey::F2 => Key::F2,
        PhysicalKey::F3 => Key::F3,
        PhysicalKey::F4 => Key::F4,
        PhysicalKey::F5 => Key::F5,
        PhysicalKey::F6 => Key::F6,
        PhysicalKey::F7 => Key::F7,
        PhysicalKey::F8 => Key::F8,
        PhysicalKey::F9 => Key::F9,
        PhysicalKey::F10 => Key::F10,
        PhysicalKey::F11 => Key::F11,
        PhysicalKey::F12 => Key::F12,

        PhysicalKey::Escape => Key::Escape,
        PhysicalKey::Tab => Key::Tab,
        PhysicalKey::CapsLock => Key::CapsLock,
        PhysicalKey::Space => Key::Space,
        PhysicalKey::Backspace => Key::Backspace,
        PhysicalKey::Enter | PhysicalKey::NumpadEnter => Key::Return,

        PhysicalKey::ArrowUp => Key::UpArrow,
        PhysicalKey::ArrowDown => Key::DownArrow,
        PhysicalKey::ArrowLeft => Key::LeftArrow,
        PhysicalKey::ArrowRight => Key::RightArrow,
        PhysicalKey::Home => Key::Home,
        PhysicalKey::End => Key::End,
        PhysicalKey::PageUp => Key::PageUp,
        PhysicalKey::PageDown => Key::PageDown,
        PhysicalKey::Delete => Key::Delete,

        // Modifiers. The generic name is used rather than a left/right variant: the
        // side-specific ones are not available on every platform, and no shortcut in
        // the intent tables depends on which side was used.
        PhysicalKey::ShiftLeft | PhysicalKey::ShiftRight => Key::Shift,
        PhysicalKey::ControlLeft | PhysicalKey::ControlRight => Key::Control,
        PhysicalKey::AltLeft | PhysicalKey::AltRight => Key::Alt,
        PhysicalKey::MetaLeft | PhysicalKey::MetaRight => Key::Meta,

        // Numpad digits are injected as their characters. Distinguishing them from the
        // number row needs scancodes; see the module docs.
        PhysicalKey::Numpad0 => Key::Unicode('0'),
        PhysicalKey::Numpad1 => Key::Unicode('1'),
        PhysicalKey::Numpad2 => Key::Unicode('2'),
        PhysicalKey::Numpad3 => Key::Unicode('3'),
        PhysicalKey::Numpad4 => Key::Unicode('4'),
        PhysicalKey::Numpad5 => Key::Unicode('5'),
        PhysicalKey::Numpad6 => Key::Unicode('6'),
        PhysicalKey::Numpad7 => Key::Unicode('7'),
        PhysicalKey::Numpad8 => Key::Unicode('8'),
        PhysicalKey::Numpad9 => Key::Unicode('9'),
        PhysicalKey::NumpadAdd => Key::Unicode('+'),
        PhysicalKey::NumpadSubtract => Key::Unicode('-'),
        PhysicalKey::NumpadMultiply => Key::Unicode('*'),
        PhysicalKey::NumpadDivide => Key::Unicode('/'),
        PhysicalKey::NumpadDecimal => Key::Unicode('.'),

        // Keys the backend expresses on some platforms but not all. Gating them per
        // platform rather than refusing them everywhere is the difference between "this
        // host cannot do that" and "no host can": Shift+Insert paste and the PrintScreen
        // key work on a Windows or Linux host, and only macOS genuinely lacks them.
        // An absent arm falls through to `_` below and is refused there.
        #[cfg(any(target_os = "windows", all(unix, not(target_os = "macos"))))]
        PhysicalKey::Insert => Key::Insert,
        #[cfg(any(target_os = "windows", all(unix, not(target_os = "macos"))))]
        PhysicalKey::PrintScreen => Key::PrintScr,
        #[cfg(any(target_os = "windows", all(unix, not(target_os = "macos"))))]
        PhysicalKey::Pause => Key::Pause,
        #[cfg(all(unix, not(target_os = "macos")))]
        PhysicalKey::ScrollLock => Key::ScrollLock,

        // No portable equivalent on any supported platform; refused, not approximated.
        PhysicalKey::ContextMenu => return None,

        // PhysicalKey is non-exhaustive: a newer peer's key is refused, not guessed.
        // This also refuses the keys whose arms above are compiled out on this platform.
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{HostOs, render, supported};

    /// Everything this build advertises, this build can inject.
    ///
    /// The intent table and this keymap are two lists that have to agree, and nothing
    /// but a test makes them. When they drift, `supported()` promises an intent that is
    /// then refused at the moment of injection — the host reports `NotSupported` for
    /// something it had already claimed it could do, which is precisely the dishonesty
    /// the table design exists to prevent.
    ///
    /// Scoped to [`HostOs::current`] on purpose. A host only ever renders its own
    /// table, and the keymap is compiled for one platform, so "the Linux table is
    /// injectable" is a claim only a Linux build can make — asserting it from a macOS
    /// build would be modelling another platform's capabilities, which is the thing
    /// this design refuses to do. CI runs on all three, so all three tables are covered.
    /// The keys that were refused on every platform because one platform lacks them.
    ///
    /// Blanket-refusing these cost Windows and Linux hosts real function — Shift+Insert
    /// paste, and the `PrintScreen` key that the Linux screenshot intent is spelled with.
    #[cfg(any(target_os = "windows", all(unix, not(target_os = "macos"))))]
    #[test]
    fn keys_absent_only_on_macos_are_injectable_here() {
        for key in [
            PhysicalKey::Insert,
            PhysicalKey::PrintScreen,
            PhysicalKey::Pause,
        ] {
            assert!(to_enigo(key).is_some(), "{key:?} should be injectable here");
        }
    }

    #[test]
    fn context_menu_is_refused_on_every_platform() {
        // No portable equivalent anywhere, so this one stays refused rather than
        // becoming a near-miss keypress on a machine the operator cannot see.
        assert!(to_enigo(PhysicalKey::ContextMenu).is_none());
    }

    #[test]
    fn every_advertised_intent_can_actually_be_injected() {
        let Some(os) = HostOs::current() else {
            return; // no table for this platform; nothing is advertised
        };
        for intent in supported(os) {
            let chord = render(intent, os).expect("supported() came from the table");
            assert!(
                to_enigo(chord.key).is_some(),
                "{os:?} spells {intent:?} with {:?}, which this backend cannot inject",
                chord.key
            );
        }
    }
}
