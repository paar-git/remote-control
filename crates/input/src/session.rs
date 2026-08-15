//! What the session is currently holding down.
//!
//! # Why this exists
//!
//! A remote session can end at any moment: the network drops, the operator clicks
//! Disconnect, Emergency Stop fires. If it ends between a key going down and coming
//! up, that key stays down on the host — the host's OS has no idea a connection was
//! involved. A session dropped during `Ctrl+C` leaves Ctrl jammed, and every
//! subsequent keystroke on that machine is a shortcut. The person sitting at it has
//! to work out what happened and press Ctrl themselves.
//!
//! So the host tracks what it has pressed and releases all of it on teardown. Release
//! order is the reverse of press order: modifiers go down first and must come up last,
//! or releasing them early re-interprets the keys still held.

use rc_protocol::{KeyState, MouseButton, PhysicalKey};

/// Keys and buttons the host currently holds down for one session.
#[derive(Debug, Default, Clone)]
pub struct HeldKeys {
    keys: Vec<PhysicalKey>,
    buttons: Vec<MouseButton>,
}

impl HeldKeys {
    /// Nothing held.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            keys: Vec::new(),
            buttons: Vec::new(),
        }
    }

    /// Record a key transition.
    ///
    /// Repeated presses of an already-held key do not stack: autorepeat sends many
    /// downs and exactly one up, so counting them would leave a phantom hold.
    pub fn key(&mut self, key: PhysicalKey, state: KeyState) {
        match state {
            KeyState::Down => {
                if !self.keys.contains(&key) {
                    self.keys.push(key);
                }
            }
            KeyState::Up => self.keys.retain(|held| *held != key),
        }
    }

    /// Record a button transition.
    pub fn button(&mut self, button: MouseButton, state: KeyState) {
        match state {
            KeyState::Down => {
                if !self.buttons.contains(&button) {
                    self.buttons.push(button);
                }
            }
            KeyState::Up => self.buttons.retain(|held| *held != button),
        }
    }

    /// Whether `key` is currently held.
    #[must_use]
    pub fn holds_key(&self, key: PhysicalKey) -> bool {
        self.keys.contains(&key)
    }

    /// Whether `button` is currently held.
    #[must_use]
    pub fn holds_button(&self, button: MouseButton) -> bool {
        self.buttons.contains(&button)
    }

    /// Whether anything at all is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.buttons.is_empty()
    }

    /// The releases needed to leave the host in a neutral state, in the order they
    /// must be performed, and clear the record.
    ///
    /// Buttons are released before keys so a drag ends before its modifiers lift, and
    /// keys are released newest-first so modifiers pressed early come up last.
    pub fn drain_releases(&mut self) -> (Vec<MouseButton>, Vec<PhysicalKey>) {
        let mut buttons = std::mem::take(&mut self.buttons);
        buttons.reverse();
        let mut keys = std::mem::take(&mut self.keys);
        keys.reverse();
        (buttons, keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_is_held_to_begin_with() {
        assert!(HeldKeys::new().is_empty());
    }

    #[test]
    fn a_press_is_held_until_released() {
        let mut held = HeldKeys::new();
        held.key(PhysicalKey::ControlLeft, KeyState::Down);
        assert!(held.holds_key(PhysicalKey::ControlLeft));
        held.key(PhysicalKey::ControlLeft, KeyState::Up);
        assert!(!held.holds_key(PhysicalKey::ControlLeft));
        assert!(held.is_empty());
    }

    #[test]
    fn autorepeat_does_not_stack() {
        // Many downs, one up. Counting presses would leave a phantom hold forever.
        let mut held = HeldKeys::new();
        for _ in 0..10 {
            held.key(PhysicalKey::KeyA, KeyState::Down);
        }
        held.key(PhysicalKey::KeyA, KeyState::Up);
        assert!(held.is_empty());
    }

    #[test]
    fn releasing_something_never_pressed_is_harmless() {
        let mut held = HeldKeys::new();
        held.key(PhysicalKey::KeyA, KeyState::Up);
        held.button(MouseButton::Left, KeyState::Up);
        assert!(held.is_empty());
    }

    #[test]
    fn modifiers_are_released_last() {
        // Ctrl down, C down. Releasing Ctrl first would turn the pending C release
        // into a bare C, typing a character into whatever has focus.
        let mut held = HeldKeys::new();
        held.key(PhysicalKey::ControlLeft, KeyState::Down);
        held.key(PhysicalKey::KeyC, KeyState::Down);

        let (_, keys) = held.drain_releases();
        assert_eq!(keys, vec![PhysicalKey::KeyC, PhysicalKey::ControlLeft]);
    }

    #[test]
    fn buttons_are_released_before_keys() {
        // A drag with a modifier must finish the drag before the modifier lifts.
        let mut held = HeldKeys::new();
        held.key(PhysicalKey::ShiftLeft, KeyState::Down);
        held.button(MouseButton::Left, KeyState::Down);

        let (buttons, keys) = held.drain_releases();
        assert_eq!(buttons, vec![MouseButton::Left]);
        assert_eq!(keys, vec![PhysicalKey::ShiftLeft]);
    }

    #[test]
    fn draining_clears_the_record() {
        let mut held = HeldKeys::new();
        held.key(PhysicalKey::AltLeft, KeyState::Down);
        held.button(MouseButton::Right, KeyState::Down);

        let _ = held.drain_releases();
        assert!(held.is_empty());
        // A second teardown must not re-release anything.
        let (buttons, keys) = held.drain_releases();
        assert!(buttons.is_empty() && keys.is_empty());
    }

    #[test]
    fn a_completed_chord_leaves_nothing_to_release() {
        let mut held = HeldKeys::new();
        for (key, state) in [
            (PhysicalKey::ControlLeft, KeyState::Down),
            (PhysicalKey::KeyC, KeyState::Down),
            (PhysicalKey::KeyC, KeyState::Up),
            (PhysicalKey::ControlLeft, KeyState::Up),
        ] {
            held.key(key, state);
        }
        assert!(held.is_empty());
    }
}
