//! Remote input wire types.
//!
//! # Physical keys and logical intents are different things
//!
//! Typing, terminals and games need the *physical* key that was pressed, reproduced
//! exactly. Shortcuts need the opposite: `Ctrl+C` on a Windows controller must become
//! `Cmd+C` on a macOS host, because the host is what decides how copying is spelled.
//!
//! Collapsing the two breaks one of them. So they travel as separate messages:
//! [`PhysicalKey`] is never remapped, and [`Intent`] carries meaning rather than keys.
//! The controller recognises its own OS's chord and sends the intent; the host renders
//! that intent in its own native chord. Neither side needs to model the other's
//! conventions, which is why three detection tables and three rendering tables cover
//! all nine platform pairs.
//!
//! # Modifiers are named by role
//!
//! [`Modifiers::META`] is the Windows key on Windows, Command on macOS and Super on
//! Linux. Naming modifiers by the job they do rather than by the vendor that shipped
//! them is what stops a "Windows key" identity ever being emitted onto macOS.

use serde::{Deserialize, Serialize};

/// Whether a key or button is going down or coming up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    /// Pressed.
    Down,
    /// Released.
    Up,
}

/// Mouse buttons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MouseButton {
    /// Primary button.
    Left,
    /// Secondary button.
    Right,
    /// Wheel click.
    Middle,
    /// Back.
    Back,
    /// Forward.
    Forward,
}

/// Logical modifier keys, as a bitset.
///
/// Named by role rather than by vendor: [`Self::META`] is Win / Command / Super
/// depending on the machine the chord is finally delivered to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct Modifiers(u8);

impl Modifiers {
    /// No modifiers held.
    pub const NONE: Self = Self(0);
    /// Shift.
    pub const SHIFT: Self = Self(0b0000_0001);
    /// Control.
    pub const CONTROL: Self = Self(0b0000_0010);
    /// Alt / Option.
    pub const ALT: Self = Self(0b0000_0100);
    /// Windows key / Command / Super.
    pub const META: Self = Self(0b0000_1000);

    /// A set containing both `self` and `other`.
    #[must_use]
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether every modifier in `other` is present in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether no modifier is held.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The raw bits, for tests and diagnostics.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Build from raw bits, ignoring unknown ones.
    #[must_use]
    pub const fn from_bits_truncate(bits: u8) -> Self {
        Self(bits & 0b0000_1111)
    }

    /// Each modifier present, as the physical key conventionally used to hold it.
    ///
    /// The left-hand key is chosen because it is the one present on every keyboard.
    #[must_use]
    pub fn keys(self) -> Vec<PhysicalKey> {
        let mut keys = Vec::new();
        if self.contains(Self::CONTROL) {
            keys.push(PhysicalKey::ControlLeft);
        }
        if self.contains(Self::ALT) {
            keys.push(PhysicalKey::AltLeft);
        }
        if self.contains(Self::SHIFT) {
            keys.push(PhysicalKey::ShiftLeft);
        }
        if self.contains(Self::META) {
            keys.push(PhysicalKey::MetaLeft);
        }
        keys
    }
}

/// A layout-independent physical key.
///
/// These follow W3C `KeyboardEvent.code` semantics, which identify a key by its
/// position rather than by the character it produces. A French AZERTY controller and a
/// US QWERTY host therefore agree on which key was struck without either needing to
/// know the other's layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
#[expect(missing_docs, reason = "each variant is one self-describing key")]
pub enum PhysicalKey {
    KeyA, KeyB, KeyC, KeyD, KeyE, KeyF, KeyG, KeyH, KeyI, KeyJ, KeyK, KeyL, KeyM,
    KeyN, KeyO, KeyP, KeyQ, KeyR, KeyS, KeyT, KeyU, KeyV, KeyW, KeyX, KeyY, KeyZ,

    Digit0, Digit1, Digit2, Digit3, Digit4,
    Digit5, Digit6, Digit7, Digit8, Digit9,

    F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12,

    Escape, Tab, CapsLock, Space, Backspace, Enter,
    Minus, Equal, BracketLeft, BracketRight, Backslash,
    Semicolon, Quote, Backquote, Comma, Period, Slash,

    ArrowUp, ArrowDown, ArrowLeft, ArrowRight,
    Home, End, PageUp, PageDown, Insert, Delete,

    ShiftLeft, ShiftRight, ControlLeft, ControlRight,
    AltLeft, AltRight, MetaLeft, MetaRight,

    Numpad0, Numpad1, Numpad2, Numpad3, Numpad4,
    Numpad5, Numpad6, Numpad7, Numpad8, Numpad9,
    NumpadAdd, NumpadSubtract, NumpadMultiply, NumpadDivide,
    NumpadDecimal, NumpadEnter,

    PrintScreen, ScrollLock, Pause, ContextMenu,
}

impl PhysicalKey {
    /// Map a W3C `KeyboardEvent.code` string to a key.
    ///
    /// Returns `None` for codes this build does not carry, so an unrecognised key is
    /// dropped at the edge rather than delivered as some *other* key.
    #[must_use]
    pub fn from_w3c_code(code: &str) -> Option<Self> {
        Some(match code {
            "KeyA" => Self::KeyA, "KeyB" => Self::KeyB, "KeyC" => Self::KeyC,
            "KeyD" => Self::KeyD, "KeyE" => Self::KeyE, "KeyF" => Self::KeyF,
            "KeyG" => Self::KeyG, "KeyH" => Self::KeyH, "KeyI" => Self::KeyI,
            "KeyJ" => Self::KeyJ, "KeyK" => Self::KeyK, "KeyL" => Self::KeyL,
            "KeyM" => Self::KeyM, "KeyN" => Self::KeyN, "KeyO" => Self::KeyO,
            "KeyP" => Self::KeyP, "KeyQ" => Self::KeyQ, "KeyR" => Self::KeyR,
            "KeyS" => Self::KeyS, "KeyT" => Self::KeyT, "KeyU" => Self::KeyU,
            "KeyV" => Self::KeyV, "KeyW" => Self::KeyW, "KeyX" => Self::KeyX,
            "KeyY" => Self::KeyY, "KeyZ" => Self::KeyZ,

            "Digit0" => Self::Digit0, "Digit1" => Self::Digit1, "Digit2" => Self::Digit2,
            "Digit3" => Self::Digit3, "Digit4" => Self::Digit4, "Digit5" => Self::Digit5,
            "Digit6" => Self::Digit6, "Digit7" => Self::Digit7, "Digit8" => Self::Digit8,
            "Digit9" => Self::Digit9,

            "F1" => Self::F1, "F2" => Self::F2, "F3" => Self::F3, "F4" => Self::F4,
            "F5" => Self::F5, "F6" => Self::F6, "F7" => Self::F7, "F8" => Self::F8,
            "F9" => Self::F9, "F10" => Self::F10, "F11" => Self::F11, "F12" => Self::F12,

            "Escape" => Self::Escape, "Tab" => Self::Tab, "CapsLock" => Self::CapsLock,
            "Space" => Self::Space, "Backspace" => Self::Backspace,
            "Enter" => Self::Enter,
            "Minus" => Self::Minus, "Equal" => Self::Equal,
            "BracketLeft" => Self::BracketLeft, "BracketRight" => Self::BracketRight,
            "Backslash" => Self::Backslash, "Semicolon" => Self::Semicolon,
            "Quote" => Self::Quote, "Backquote" => Self::Backquote,
            "Comma" => Self::Comma, "Period" => Self::Period, "Slash" => Self::Slash,

            "ArrowUp" => Self::ArrowUp, "ArrowDown" => Self::ArrowDown,
            "ArrowLeft" => Self::ArrowLeft, "ArrowRight" => Self::ArrowRight,
            "Home" => Self::Home, "End" => Self::End,
            "PageUp" => Self::PageUp, "PageDown" => Self::PageDown,
            "Insert" => Self::Insert, "Delete" => Self::Delete,

            "ShiftLeft" => Self::ShiftLeft, "ShiftRight" => Self::ShiftRight,
            "ControlLeft" => Self::ControlLeft, "ControlRight" => Self::ControlRight,
            "AltLeft" => Self::AltLeft, "AltRight" => Self::AltRight,
            // Chromium reports the Command and Super keys under the Meta codes on
            // macOS and Linux respectively, so one mapping serves all three.
            "MetaLeft" | "OSLeft" => Self::MetaLeft,
            "MetaRight" | "OSRight" => Self::MetaRight,

            "Numpad0" => Self::Numpad0, "Numpad1" => Self::Numpad1,
            "Numpad2" => Self::Numpad2, "Numpad3" => Self::Numpad3,
            "Numpad4" => Self::Numpad4, "Numpad5" => Self::Numpad5,
            "Numpad6" => Self::Numpad6, "Numpad7" => Self::Numpad7,
            "Numpad8" => Self::Numpad8, "Numpad9" => Self::Numpad9,
            "NumpadAdd" => Self::NumpadAdd, "NumpadSubtract" => Self::NumpadSubtract,
            "NumpadMultiply" => Self::NumpadMultiply,
            "NumpadDivide" => Self::NumpadDivide,
            "NumpadDecimal" => Self::NumpadDecimal, "NumpadEnter" => Self::NumpadEnter,

            "PrintScreen" => Self::PrintScreen, "ScrollLock" => Self::ScrollLock,
            "Pause" => Self::Pause, "ContextMenu" => Self::ContextMenu,

            _ => return None,
        })
    }

    /// Whether this key is itself a modifier.
    ///
    /// Modifier keys are excluded from intent detection: a chord is recognised by its
    /// non-modifier key plus the modifier set, so `Ctrl` alone is never an intent.
    #[must_use]
    pub const fn is_modifier(self) -> bool {
        matches!(
            self,
            Self::ShiftLeft
                | Self::ShiftRight
                | Self::ControlLeft
                | Self::ControlRight
                | Self::AltLeft
                | Self::AltRight
                | Self::MetaLeft
                | Self::MetaRight
        )
    }
}

/// A semantic action, independent of how any OS spells it.
///
/// This set is deliberately **closed**. A chord that does not map to one of these
/// travels as physical keys and is never remapped, which is what keeps typing, games
/// and terminals exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Intent {
    /// Copy the selection.
    Copy,
    /// Paste the clipboard.
    Paste,
    /// Cut the selection.
    Cut,
    /// Select everything.
    SelectAll,
    /// Undo.
    Undo,
    /// Redo.
    Redo,
    /// Save.
    Save,
    /// Open find / search.
    Find,
    /// Close the focused window.
    CloseWindow,
    /// Switch between applications.
    SwitchApp,
    /// Show the desktop / minimise everything.
    ShowDesktop,
    /// Lock the session.
    LockScreen,
    /// Take a screenshot on the host.
    Screenshot,
    /// The platform's secure attention sequence, where permitted.
    SecureAttention,
}

/// Why an input event could not be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InputFailure {
    /// The OS refused: macOS Accessibility permission has not been granted.
    NotPermitted,
    /// The OS blocked it: Windows UIPI refused injection into a higher-privilege window.
    Blocked,
    /// No injection backend is usable, e.g. a Wayland session with no portal.
    Unavailable,
    /// The host has no equivalent for this intent.
    NotSupported,
    /// The session does not hold `control_input`.
    ViewOnly,
}

impl InputFailure {
    /// A short operator-facing explanation.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::NotPermitted => {
                "the host has not granted accessibility permission to inject input"
            }
            Self::Blocked => "the host's window manager refused the injection",
            Self::Unavailable => "the host has no usable input backend",
            Self::NotSupported => "the host has no equivalent for that action",
            Self::ViewOnly => "this session may not control the host",
        }
    }
}

/// Input events sent from controller to host.
///
/// The host must drop every one of these unless the session is authenticated,
/// authorized for control, and currently in control mode.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InputEvent {
    /// Absolute pointer move, normalised to 0.0–1.0 of the captured display so that
    /// DPI and resolution differences between the two machines do not matter.
    ///
    /// Unacknowledged: motion is continuous, and an ack per sample would add a round
    /// trip to pointer lag. Progress is reported by [`InputAck::Applied`] instead.
    MouseMove {
        /// Horizontal position, 0.0–1.0.
        x: f32,
        /// Vertical position, 0.0–1.0.
        y: f32,
        /// Ordering counter, echoed in the applied watermark.
        seq: u32,
    },
    /// Wheel or trackpad scroll, in wheel deltas. Unacknowledged, as for motion.
    Scroll {
        /// Horizontal delta.
        delta_x: f32,
        /// Vertical delta.
        delta_y: f32,
        /// Ordering counter.
        seq: u32,
    },
    /// Button pressed. Acknowledged.
    MouseDown {
        /// Which button.
        button: MouseButton,
        /// Correlates the acknowledgement.
        seq: u32,
    },
    /// Button released. Acknowledged.
    MouseUp {
        /// Which button.
        button: MouseButton,
        /// Correlates the acknowledgement.
        seq: u32,
    },
    /// Physical key pressed. Never remapped. Acknowledged.
    KeyDown {
        /// Which key, by position.
        key: PhysicalKey,
        /// Whether this is an autorepeat.
        repeat: bool,
        /// Correlates the acknowledgement.
        seq: u32,
    },
    /// Physical key released. Acknowledged.
    KeyUp {
        /// Which key, by position.
        key: PhysicalKey,
        /// Correlates the acknowledgement.
        seq: u32,
    },
    /// A semantic action, to be rendered in the host's own native chord.
    Intent {
        /// What the operator meant.
        intent: Intent,
        /// Correlates the acknowledgement.
        seq: u32,
    },
}

impl InputEvent {
    /// Whether this event is individually acknowledged.
    ///
    /// Only acknowledged events may ever be logged as having succeeded.
    #[must_use]
    pub const fn is_acknowledged(&self) -> bool {
        !matches!(self, Self::MouseMove { .. } | Self::Scroll { .. })
    }

    /// The event's ordering counter.
    #[must_use]
    pub const fn seq(&self) -> u32 {
        match *self {
            Self::MouseMove { seq, .. }
            | Self::Scroll { seq, .. }
            | Self::MouseDown { seq, .. }
            | Self::MouseUp { seq, .. }
            | Self::KeyDown { seq, .. }
            | Self::KeyUp { seq, .. }
            | Self::Intent { seq, .. } => seq,
        }
    }
}

/// Host → controller acknowledgements on the input channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InputAck {
    /// The event was applied to the host's OS.
    Ok {
        /// Which event.
        seq: u32,
    },
    /// The event could not be applied, and why.
    Failed {
        /// Which event.
        seq: u32,
        /// The real cause.
        reason: InputFailure,
    },
    /// Every unacknowledged event up to and including this sequence has been applied.
    Applied {
        /// Highest applied sequence.
        watermark: u32,
    },
}

/// Whether a host can inject input at all, decided once at session start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InputCapability {
    /// Input can be injected.
    Full,
    /// Input cannot be injected, for this reason.
    Unavailable {
        /// Why.
        reason: InputFailure,
    },
}

impl InputCapability {
    /// Whether input may be attempted.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Full)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modifiers_combine_and_test() {
        let combo = Modifiers::CONTROL.with(Modifiers::SHIFT);
        assert!(combo.contains(Modifiers::CONTROL));
        assert!(combo.contains(Modifiers::SHIFT));
        assert!(!combo.contains(Modifiers::META));
        assert!(!combo.is_empty());
        assert!(Modifiers::NONE.is_empty());
    }

    #[test]
    fn modifier_keys_are_left_hand_and_ordered() {
        let keys = Modifiers::CONTROL.with(Modifiers::META).keys();
        assert_eq!(keys, vec![PhysicalKey::ControlLeft, PhysicalKey::MetaLeft]);
    }

    #[test]
    fn w3c_codes_map_to_keys() {
        assert_eq!(PhysicalKey::from_w3c_code("KeyC"), Some(PhysicalKey::KeyC));
        assert_eq!(PhysicalKey::from_w3c_code("ArrowUp"), Some(PhysicalKey::ArrowUp));
        assert_eq!(PhysicalKey::from_w3c_code("F11"), Some(PhysicalKey::F11));
    }

    #[test]
    fn command_and_super_arrive_as_meta() {
        // Chromium reports Command on macOS and Super on Linux under these codes.
        // Both must land on Meta so neither is mistaken for a Windows-specific key.
        assert_eq!(PhysicalKey::from_w3c_code("MetaLeft"), Some(PhysicalKey::MetaLeft));
        assert_eq!(PhysicalKey::from_w3c_code("OSLeft"), Some(PhysicalKey::MetaLeft));
        assert_eq!(PhysicalKey::from_w3c_code("OSRight"), Some(PhysicalKey::MetaRight));
    }

    #[test]
    fn unknown_codes_are_dropped_rather_than_guessed() {
        // Delivering some *other* key would be worse than delivering none.
        assert_eq!(PhysicalKey::from_w3c_code("Fn"), None);
        assert_eq!(PhysicalKey::from_w3c_code(""), None);
        assert_eq!(PhysicalKey::from_w3c_code("LaunchMail"), None);
    }

    #[test]
    fn modifier_keys_are_recognised() {
        assert!(PhysicalKey::ControlLeft.is_modifier());
        assert!(PhysicalKey::MetaRight.is_modifier());
        assert!(!PhysicalKey::KeyC.is_modifier());
    }

    #[test]
    fn motion_is_unacknowledged_and_discrete_actions_are_not() {
        assert!(!InputEvent::MouseMove { x: 0.5, y: 0.5, seq: 1 }.is_acknowledged());
        assert!(!InputEvent::Scroll { delta_x: 0.0, delta_y: 1.0, seq: 2 }.is_acknowledged());
        assert!(InputEvent::MouseDown { button: MouseButton::Left, seq: 3 }.is_acknowledged());
        assert!(InputEvent::Intent { intent: Intent::Copy, seq: 4 }.is_acknowledged());
        assert!(
            InputEvent::KeyDown { key: PhysicalKey::KeyA, repeat: false, seq: 5 }
                .is_acknowledged()
        );
    }

    #[test]
    fn every_event_reports_its_sequence() {
        assert_eq!(InputEvent::MouseMove { x: 0.0, y: 0.0, seq: 7 }.seq(), 7);
        assert_eq!(InputEvent::Intent { intent: Intent::Paste, seq: 9 }.seq(), 9);
    }

    #[test]
    fn input_events_stay_small_on_the_wire() {
        // The input channel ceiling is 4 KiB; flooding must be bounded by the rate
        // limiter rather than by frame size.
        let ev = InputEvent::MouseMove { x: 0.5, y: 0.25, seq: 1 };
        assert!(postcard::to_stdvec(&ev).unwrap().len() < 32);
    }

    #[test]
    fn input_events_roundtrip() {
        let events = [
            InputEvent::MouseMove { x: 0.0, y: 1.0, seq: 1 },
            InputEvent::MouseDown { button: MouseButton::Right, seq: 2 },
            InputEvent::Scroll { delta_x: -1.5, delta_y: 3.0, seq: 3 },
            InputEvent::KeyDown { key: PhysicalKey::KeyA, repeat: true, seq: 4 },
            InputEvent::KeyUp { key: PhysicalKey::KeyA, seq: 5 },
            InputEvent::Intent { intent: Intent::SecureAttention, seq: 6 },
        ];
        for ev in events {
            let bytes = postcard::to_stdvec(&ev).unwrap();
            assert_eq!(postcard::from_bytes::<InputEvent>(&bytes).unwrap(), ev);
        }
    }

    #[test]
    fn acks_roundtrip() {
        let acks = [
            InputAck::Ok { seq: 1 },
            InputAck::Failed { seq: 2, reason: InputFailure::NotPermitted },
            InputAck::Applied { watermark: 99 },
        ];
        for ack in acks {
            let bytes = postcard::to_stdvec(&ack).unwrap();
            assert_eq!(postcard::from_bytes::<InputAck>(&bytes).unwrap(), ack);
        }
    }

    #[test]
    fn capability_gates_usage() {
        assert!(InputCapability::Full.is_usable());
        assert!(
            !InputCapability::Unavailable { reason: InputFailure::Unavailable }.is_usable()
        );
    }
}
