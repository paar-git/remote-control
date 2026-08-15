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
#[expect(
    clippy::match_same_arms,
    reason = "distinct physical keys that happen to share a character today; merging               them would erase the distinction the scancode work will need"
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

        // Not expressible portably; refused rather than approximated.
        PhysicalKey::Insert
        | PhysicalKey::PrintScreen
        | PhysicalKey::ScrollLock
        | PhysicalKey::Pause
        | PhysicalKey::ContextMenu => return None,

        // PhysicalKey is non-exhaustive: a newer peer's key is refused, not guessed.
        _ => return None,
    })
}
