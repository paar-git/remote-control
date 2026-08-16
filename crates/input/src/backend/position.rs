//! Injecting a key by *position* rather than by the character it bears.
//!
//! # What this fixes, and what it cannot
//!
//! [`PhysicalKey`] identifies a key by position, the way W3C `KeyboardEvent.code` does.
//! Injecting it as a character — which is what `keymap::to_enigo` does on its own —
//! assumes the host reads that character off a US layout. On a host set to anything
//! else, a letter key could produce a different character, and `WASD` in a game could
//! land on four keys that are nowhere near each other.
//!
//! This module carries the per-OS code for each character key, so the position travels
//! instead of the character. It is exactly the "per-OS scancode tables" the keymap's own
//! documentation named as the fix, and it stays contained to these two files.
//!
//! # The platforms do not offer the same thing
//!
//! `enigo::Key::Other` means something different on each OS, so this module can only be
//! as good as what is underneath it:
//!
//! - **Windows** — a virtual-key code. Positional for the ANSI block.
//! - **macOS** — a `CGKeyCode`, which is genuinely positional: `kVK_ANSI_A` is the
//!   physical key left of `S` whatever the layout says it types.
//! - **Linux** — a *keysym*, which names a character rather than a position. There is
//!   nothing positional to send, so this module reports nothing there and the caller
//!   keeps the character path. Saying so is better than pretending three platforms are
//!   fixed when two are.
//!
//! # Only character keys go through here
//!
//! Modifiers, function keys, navigation and editing keys are already position
//! independent as named keys, and are already correct. Routing them through a numeric
//! table would add a way to be wrong in exchange for nothing.

use rc_protocol::PhysicalKey;

/// The platform's own code for `key`'s position, if this platform has a positional one.
///
/// `None` means the caller should fall back to the character path — either because this
/// is not a character key, or because this platform has no positional code to give.
#[must_use]
pub fn position_code(key: PhysicalKey) -> Option<u32> {
    platform_code(key)
}

/// Windows virtual-key codes.
///
/// Letters and digits are the documented ASCII-aligned ranges; the punctuation keys are
/// the `VK_OEM_*` constants, which are defined by *position* on the ANSI layout and are
/// exactly why the character path was wrong for them.
#[cfg(target_os = "windows")]
const fn platform_code(key: PhysicalKey) -> Option<u32> {
    Some(match key {
        PhysicalKey::KeyA => 0x41,
        PhysicalKey::KeyB => 0x42,
        PhysicalKey::KeyC => 0x43,
        PhysicalKey::KeyD => 0x44,
        PhysicalKey::KeyE => 0x45,
        PhysicalKey::KeyF => 0x46,
        PhysicalKey::KeyG => 0x47,
        PhysicalKey::KeyH => 0x48,
        PhysicalKey::KeyI => 0x49,
        PhysicalKey::KeyJ => 0x4A,
        PhysicalKey::KeyK => 0x4B,
        PhysicalKey::KeyL => 0x4C,
        PhysicalKey::KeyM => 0x4D,
        PhysicalKey::KeyN => 0x4E,
        PhysicalKey::KeyO => 0x4F,
        PhysicalKey::KeyP => 0x50,
        PhysicalKey::KeyQ => 0x51,
        PhysicalKey::KeyR => 0x52,
        PhysicalKey::KeyS => 0x53,
        PhysicalKey::KeyT => 0x54,
        PhysicalKey::KeyU => 0x55,
        PhysicalKey::KeyV => 0x56,
        PhysicalKey::KeyW => 0x57,
        PhysicalKey::KeyX => 0x58,
        PhysicalKey::KeyY => 0x59,
        PhysicalKey::KeyZ => 0x5A,

        PhysicalKey::Digit0 => 0x30,
        PhysicalKey::Digit1 => 0x31,
        PhysicalKey::Digit2 => 0x32,
        PhysicalKey::Digit3 => 0x33,
        PhysicalKey::Digit4 => 0x34,
        PhysicalKey::Digit5 => 0x35,
        PhysicalKey::Digit6 => 0x36,
        PhysicalKey::Digit7 => 0x37,
        PhysicalKey::Digit8 => 0x38,
        PhysicalKey::Digit9 => 0x39,

        // VK_OEM_*, named for the character they bear on a US layout but defined by
        // position.
        PhysicalKey::Semicolon => 0xBA,    // VK_OEM_1
        PhysicalKey::Equal => 0xBB,        // VK_OEM_PLUS
        PhysicalKey::Comma => 0xBC,        // VK_OEM_COMMA
        PhysicalKey::Minus => 0xBD,        // VK_OEM_MINUS
        PhysicalKey::Period => 0xBE,       // VK_OEM_PERIOD
        PhysicalKey::Slash => 0xBF,        // VK_OEM_2
        PhysicalKey::Backquote => 0xC0,    // VK_OEM_3
        PhysicalKey::BracketLeft => 0xDB,  // VK_OEM_4
        PhysicalKey::Backslash => 0xDC,    // VK_OEM_5
        PhysicalKey::BracketRight => 0xDD, // VK_OEM_6
        PhysicalKey::Quote => 0xDE,        // VK_OEM_7

        // Everything else is a named key, already position independent.
        _ => return None,
    })
}

/// macOS `CGKeyCode`s, the `kVK_ANSI_*` constants from Carbon's `HIToolbox`.
///
/// Genuinely positional, and deliberately not in alphabetical order: the numbering
/// follows the original Apple keyboard's wiring, which is why `A` is 0 and `B` is 11.
#[cfg(target_os = "macos")]
const fn platform_code(key: PhysicalKey) -> Option<u32> {
    Some(match key {
        PhysicalKey::KeyA => 0x00,
        PhysicalKey::KeyS => 0x01,
        PhysicalKey::KeyD => 0x02,
        PhysicalKey::KeyF => 0x03,
        PhysicalKey::KeyH => 0x04,
        PhysicalKey::KeyG => 0x05,
        PhysicalKey::KeyZ => 0x06,
        PhysicalKey::KeyX => 0x07,
        PhysicalKey::KeyC => 0x08,
        PhysicalKey::KeyV => 0x09,
        PhysicalKey::KeyB => 0x0B,
        PhysicalKey::KeyQ => 0x0C,
        PhysicalKey::KeyW => 0x0D,
        PhysicalKey::KeyE => 0x0E,
        PhysicalKey::KeyR => 0x0F,
        PhysicalKey::KeyY => 0x10,
        PhysicalKey::KeyT => 0x11,
        PhysicalKey::KeyO => 0x1F,
        PhysicalKey::KeyU => 0x20,
        PhysicalKey::KeyI => 0x22,
        PhysicalKey::KeyP => 0x23,
        PhysicalKey::KeyL => 0x25,
        PhysicalKey::KeyJ => 0x26,
        PhysicalKey::KeyK => 0x28,
        PhysicalKey::KeyN => 0x2D,
        PhysicalKey::KeyM => 0x2E,

        PhysicalKey::Digit1 => 0x12,
        PhysicalKey::Digit2 => 0x13,
        PhysicalKey::Digit3 => 0x14,
        PhysicalKey::Digit4 => 0x15,
        PhysicalKey::Digit6 => 0x16,
        PhysicalKey::Digit5 => 0x17,
        PhysicalKey::Digit9 => 0x19,
        PhysicalKey::Digit7 => 0x1A,
        PhysicalKey::Digit8 => 0x1C,
        PhysicalKey::Digit0 => 0x1D,

        PhysicalKey::Equal => 0x18,
        PhysicalKey::Minus => 0x1B,
        PhysicalKey::BracketRight => 0x1E,
        PhysicalKey::BracketLeft => 0x21,
        PhysicalKey::Quote => 0x27,
        PhysicalKey::Semicolon => 0x29,
        PhysicalKey::Backslash => 0x2A,
        PhysicalKey::Comma => 0x2B,
        PhysicalKey::Slash => 0x2C,
        PhysicalKey::Period => 0x2F,
        PhysicalKey::Backquote => 0x32,

        _ => return None,
    })
}

/// Linux has no positional code to offer through this interface.
///
/// `enigo::Key::Other` is a *keysym* on Linux, which names a character rather than a
/// position — the very thing the character path already does. Returning `None` keeps
/// the caller on that path rather than dressing the same behaviour up as a fix.
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
const fn platform_code(_key: PhysicalKey) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every character key, which is exactly the set this module claims to cover.
    const CHARACTER_KEYS: [PhysicalKey; 48] = [
        PhysicalKey::KeyA,
        PhysicalKey::KeyB,
        PhysicalKey::KeyC,
        PhysicalKey::KeyD,
        PhysicalKey::KeyE,
        PhysicalKey::KeyF,
        PhysicalKey::KeyG,
        PhysicalKey::KeyH,
        PhysicalKey::KeyI,
        PhysicalKey::KeyJ,
        PhysicalKey::KeyK,
        PhysicalKey::KeyL,
        PhysicalKey::KeyM,
        PhysicalKey::KeyN,
        PhysicalKey::KeyO,
        PhysicalKey::KeyP,
        PhysicalKey::KeyQ,
        PhysicalKey::KeyR,
        PhysicalKey::KeyS,
        PhysicalKey::KeyT,
        PhysicalKey::KeyU,
        PhysicalKey::KeyV,
        PhysicalKey::KeyW,
        PhysicalKey::KeyX,
        PhysicalKey::KeyY,
        PhysicalKey::KeyZ,
        PhysicalKey::Digit0,
        PhysicalKey::Digit1,
        PhysicalKey::Digit2,
        PhysicalKey::Digit3,
        PhysicalKey::Digit4,
        PhysicalKey::Digit5,
        PhysicalKey::Digit6,
        PhysicalKey::Digit7,
        PhysicalKey::Digit8,
        PhysicalKey::Digit9,
        PhysicalKey::Minus,
        PhysicalKey::Equal,
        PhysicalKey::BracketLeft,
        PhysicalKey::BracketRight,
        PhysicalKey::Backslash,
        PhysicalKey::Semicolon,
        PhysicalKey::Quote,
        PhysicalKey::Backquote,
        PhysicalKey::Comma,
        PhysicalKey::Period,
        PhysicalKey::Slash,
        PhysicalKey::Space,
    ];

    #[test]
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    fn no_two_positions_share_a_code() {
        // The failure this guards against is silent and bad: a duplicated code means
        // one key injects another, on a machine the operator cannot see. A typo in a
        // hand-written table of fifty numbers is exactly how that happens.
        let mut seen: Vec<(PhysicalKey, u32)> = Vec::new();
        for key in CHARACTER_KEYS {
            let Some(code) = position_code(key) else {
                continue;
            };
            assert!(
                !seen.iter().any(|(_, existing)| *existing == code),
                "{key:?} reuses code {code:#04x}, already taken by {:?}",
                seen.iter().find(|(_, e)| *e == code).map(|(k, _)| *k)
            );
            seen.push((key, code));
        }
    }

    #[test]
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    fn every_letter_and_digit_has_a_position() {
        // A gap here is not a compile error, it is a key that silently falls back to
        // the character path — which is the bug this module exists to remove.
        for key in CHARACTER_KEYS {
            if key == PhysicalKey::Space {
                continue;
            }
            assert!(
                position_code(key).is_some(),
                "{key:?} has no positional code on this platform"
            );
        }
    }

    #[test]
    fn a_named_key_is_left_to_the_character_path() {
        // Modifiers, function keys and navigation are already position independent.
        // Routing them through a numeric table would add a way to be wrong for nothing.
        for key in [
            PhysicalKey::F1,
            PhysicalKey::ControlLeft,
            PhysicalKey::ShiftLeft,
            PhysicalKey::Enter,
            PhysicalKey::ArrowUp,
            PhysicalKey::Space,
        ] {
            assert_eq!(position_code(key), None, "{key:?} must stay a named key");
        }
    }

    #[test]
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    fn linux_reports_nothing_rather_than_dressing_up_the_character_path() {
        // `Key::Other` is a keysym here, which names a character rather than a
        // position. Claiming a fix that is not one would be worse than the gap.
        for key in CHARACTER_KEYS {
            assert_eq!(position_code(key), None);
        }
    }
}
