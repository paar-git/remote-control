//! Platform-independent remote input.
//!
//! # The layering
//!
//! ```text
//!   InputEvent (wire)
//!        │
//!   InputSession ── semantics: intents, held-key tracking, coordinate handling
//!        │
//!   InputSink ───── physical injection only: keys, buttons, motion, scroll
//!        │
//!   backend::enigo ─ the one place that talks to the operating system
//! ```
//!
//! A backend implements *physical* injection and nothing else. Everything semantic —
//! translating an [`Intent`] into this host's native chord, remembering what is held
//! down, refusing input the session may not perform — lives in [`InputSession`], which
//! is pure and therefore testable against [`backend::mock`] with no desktop present.
//!
//! # Why the OS is a parameter rather than a `cfg`
//!
//! [`InputSession::new`] takes the [`HostOs`] to translate for instead of reading
//! `cfg!(target_os)`. That is what allows a Windows CI machine to verify macOS and
//! Linux chord rendering, and it is why all nine controller→host pairs can be tested
//! anywhere. Production code passes [`HostOs::current`].

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod backend;
pub mod display;
pub mod grab;
pub mod intent;
pub mod session;

pub use display::{Crossing, DisplayTopology, Edge};
pub use intent::{Chord, HostOs, detect, render};
pub use session::HeldKeys;

use rc_protocol::{
    InputAck, InputCapability, InputEvent, InputFailure, Intent, KeyState, MouseButton, PhysicalKey,
};

/// Why an injection did not happen.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum InputError {
    /// The operating system, or this session's permissions, refused it.
    #[error("input refused: {}", .0.describe())]
    Refused(InputFailure),
    /// The backend itself failed.
    #[error("input backend failed: {0}")]
    Backend(String),
}

impl InputError {
    /// The wire-reportable cause.
    #[must_use]
    pub const fn failure(&self) -> InputFailure {
        match self {
            Self::Refused(reason) => *reason,
            // A backend that errored is, from the operator's point of view, blocked.
            Self::Backend(_) => InputFailure::Blocked,
        }
    }
}

/// Result of an injection.
pub type Result<T> = std::result::Result<T, InputError>;

/// Physical input injection. Implemented once per platform.
///
/// Deliberately narrow: no intents, no state, no policy. Everything above this is
/// shared across platforms, so a new OS means implementing these five methods.
pub trait InputSink: Send {
    /// Move the pointer to a virtual-desktop pixel.
    ///
    /// Resolution from a normalised position on some display to this absolute point
    /// happens in [`InputSession`], using the host's real topology — so a backend never
    /// needs to know which monitor an event came from, and multi-monitor correctness is
    /// decided once rather than once per platform.
    ///
    /// # Errors
    /// [`InputError`] if the OS refuses.
    fn pointer_move_to(&mut self, gx: i64, gy: i64) -> Result<()>;

    /// Press or release a mouse button.
    ///
    /// # Errors
    /// [`InputError`] if the OS refuses.
    fn button(&mut self, button: MouseButton, state: KeyState) -> Result<()>;

    /// Scroll by wheel deltas.
    ///
    /// # Errors
    /// [`InputError`] if the OS refuses.
    fn scroll(&mut self, dx: f32, dy: f32) -> Result<()>;

    /// Press or release a physical key. Never remapped.
    ///
    /// # Errors
    /// [`InputError`] if the OS refuses.
    fn key(&mut self, key: PhysicalKey, state: KeyState) -> Result<()>;

    /// Whether this host can inject at all.
    fn capability(&self) -> InputCapability;

    /// Which OS this backend drives, if it is one with a chord table.
    fn host_os(&self) -> Option<HostOs>;

    /// Which intents this host can spell.
    fn supported_intents(&self) -> Vec<Intent>;
}

/// One session's input state: what is held, and how to spell intents here.
///
/// Owns the [`InputSink`] for the life of the session so that teardown can release
/// whatever is still down.
#[derive(Debug)]
pub struct InputSession<S: InputSink> {
    sink: S,
    os: Option<HostOs>,
    held: HeldKeys,
    may_control: bool,
    watermark: u32,
    /// The host's monitors, as last enumerated.
    ///
    /// Held here rather than in the backend because every platform needs the same
    /// answer to "where is this normalised point?", and computing it once means a
    /// mixed-DPI, mixed-resolution arrangement behaves identically on all three.
    topology: DisplayTopology,
}

impl<S: InputSink> InputSession<S> {
    /// A session injecting through `sink`, spelling intents for `os`.
    ///
    /// `may_control` is the session's `control_input` grant. When false every event is
    /// refused with [`InputFailure::ViewOnly`] — the check lives here, above the
    /// backend, so no platform can forget it.
    pub fn new(sink: S, os: Option<HostOs>, may_control: bool) -> Self {
        Self {
            sink,
            os,
            held: HeldKeys::new(),
            may_control,
            watermark: 0,
            topology: DisplayTopology::default(),
        }
    }

    /// Replace the known display arrangement.
    ///
    /// Called whenever the host re-enumerates, including mid-session when a monitor is
    /// plugged in, removed or rearranged.
    pub fn set_topology(&mut self, topology: DisplayTopology) {
        self.topology = topology;
    }

    /// The display arrangement this session is resolving coordinates against.
    pub const fn topology(&self) -> &DisplayTopology {
        &self.topology
    }

    /// A session for the OS this binary runs on.
    pub fn for_current_os(sink: S, may_control: bool) -> Self {
        Self::new(sink, HostOs::current(), may_control)
    }

    /// Whether this host can inject at all.
    pub fn capability(&self) -> InputCapability {
        if !self.may_control {
            return InputCapability::Unavailable {
                reason: InputFailure::ViewOnly,
            };
        }
        self.sink.capability()
    }

    /// The highest applied sequence for unacknowledged events.
    pub const fn watermark(&self) -> u32 {
        self.watermark
    }

    /// What is currently held down.
    pub const fn held(&self) -> &HeldKeys {
        &self.held
    }

    /// The sink, for assertions in tests.
    pub const fn sink(&self) -> &S {
        &self.sink
    }

    /// Apply one wire event, returning the acknowledgement to send back.
    ///
    /// Returns `None` for unacknowledged events; their progress is reported through
    /// [`Self::watermark`] instead. The distinction is what keeps logging honest: only
    /// an event that produces an [`InputAck`] may ever be logged as having succeeded.
    pub fn apply(&mut self, event: InputEvent) -> Option<InputAck> {
        let seq = event.seq();
        let acknowledged = event.is_acknowledged();

        let outcome = self.dispatch(event);

        match (acknowledged, outcome) {
            (true, Ok(())) => Some(InputAck::Ok { seq }),
            (true, Err(err)) => Some(InputAck::Failed {
                seq,
                reason: err.failure(),
            }),
            (false, Ok(())) => {
                self.watermark = self.watermark.max(seq);
                None
            }
            (false, Err(_)) => {
                // Motion that failed is not acknowledged and not logged; the watermark
                // simply does not advance, which is what tells the controller.
                None
            }
        }
    }

    fn dispatch(&mut self, event: InputEvent) -> Result<()> {
        if !self.may_control {
            return Err(InputError::Refused(InputFailure::ViewOnly));
        }

        match event {
            InputEvent::MouseMove { x, y, display, .. } => {
                // Clamped rather than rejected: a controller rounding 1.0000001 should
                // move the pointer to the edge, not drop the sample.
                let x = x.clamp(0.0, 1.0);
                let y = y.clamp(0.0, 1.0);

                // Resolved against the display the viewer was actually looking at. If
                // that monitor has since gone away, the event is refused rather than
                // applied to whichever display happens to be at that fraction — a
                // click landing on the wrong screen is worse than one that did not land.
                let target = self
                    .topology
                    .resolve(display)
                    .ok_or(InputError::Refused(InputFailure::Unavailable))?;
                let (gx, gy) = self
                    .topology
                    .to_global(target, x, y)
                    .ok_or(InputError::Refused(InputFailure::Unavailable))?;
                self.sink.pointer_move_to(gx, gy)
            }
            InputEvent::Scroll {
                delta_x, delta_y, ..
            } => self.sink.scroll(delta_x, delta_y),
            InputEvent::MouseDown { button, .. } => {
                self.sink.button(button, KeyState::Down)?;
                self.held.button(button, KeyState::Down);
                Ok(())
            }
            InputEvent::MouseUp { button, .. } => {
                self.sink.button(button, KeyState::Up)?;
                self.held.button(button, KeyState::Up);
                Ok(())
            }
            InputEvent::KeyDown { key, .. } => {
                self.sink.key(key, KeyState::Down)?;
                self.held.key(key, KeyState::Down);
                Ok(())
            }
            InputEvent::KeyUp { key, .. } => {
                self.sink.key(key, KeyState::Up)?;
                self.held.key(key, KeyState::Up);
                Ok(())
            }
            InputEvent::Intent { intent, .. } => self.apply_intent(intent),
            // The protocol enum is non-exhaustive: a newer peer's variant is refused
            // rather than guessed at.
            _ => Err(InputError::Refused(InputFailure::NotSupported)),
        }
    }

    /// Spell `intent` the way this host spells it, and press it.
    fn apply_intent(&mut self, intent: Intent) -> Result<()> {
        let os = self
            .os
            .ok_or(InputError::Refused(InputFailure::NotSupported))?;
        let chord = render(intent, os).ok_or(InputError::Refused(InputFailure::NotSupported))?;

        self.press_chord(chord)
    }

    /// Press and fully release a chord: modifiers down, key down, key up, modifiers up.
    ///
    /// Released in reverse for the same reason teardown is: lifting a modifier while
    /// its key is still down turns the pending release into a bare keystroke.
    fn press_chord(&mut self, chord: Chord) -> Result<()> {
        let modifiers = chord.mods.keys();

        for modifier in &modifiers {
            self.sink.key(*modifier, KeyState::Down)?;
            self.held.key(*modifier, KeyState::Down);
        }

        let struck = self.sink.key(chord.key, KeyState::Down).and_then(|()| {
            self.held.key(chord.key, KeyState::Down);
            self.sink.key(chord.key, KeyState::Up)
        });
        self.held.key(chord.key, KeyState::Up);

        // Modifiers come up whether or not the key itself landed, so a failure midway
        // cannot leave them stuck.
        for modifier in modifiers.iter().rev() {
            let _ = self.sink.key(*modifier, KeyState::Up);
            self.held.key(*modifier, KeyState::Up);
        }

        struck
    }

    /// Release everything still held. Call on every session teardown.
    ///
    /// Errors are swallowed deliberately: this runs while the session is already
    /// ending, and a backend that cannot release is not something the operator can act
    /// on. Leaving the *rest* held because one release failed would be worse.
    pub fn release_all(&mut self) {
        let (buttons, keys) = self.held.drain_releases();
        for button in buttons {
            let _ = self.sink.button(button, KeyState::Up);
        }
        for key in keys {
            let _ = self.sink.key(key, KeyState::Up);
        }
    }
}

impl<S: InputSink> Drop for InputSession<S> {
    fn drop(&mut self) {
        // The guarantee has to survive a panic or an early return somewhere above, not
        // only the paths that remember to call release_all.
        if !self.held.is_empty() {
            tracing::warn!("session ended with keys held; releasing them");
            self.release_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend::mock::{Call, MockSink};
    use display::DisplayTopology;
    use rc_protocol::Modifiers;

    fn session(os: HostOs) -> InputSession<MockSink> {
        let mut session = InputSession::new(MockSink::new(), Some(os), true);
        session.set_topology(two_displays());
        session
    }

    /// A 1080p primary with a 1440p monitor to its right, hanging 200px lower —
    /// mixed resolution and mixed alignment, which is the interesting case.
    fn two_displays() -> DisplayTopology {
        DisplayTopology::new(vec![
            rc_protocol::desktop::DisplayInfo {
                index: 0,
                name: "Primary".to_owned(),
                width: 1920,
                height: 1080,
                scale_factor: 1.0,
                origin_x: 0,
                origin_y: 0,
                primary: true,
                refresh_hz: Some(60),
            },
            rc_protocol::desktop::DisplayInfo {
                index: 1,
                name: "Secondary".to_owned(),
                width: 2560,
                height: 1440,
                scale_factor: 2.0,
                origin_x: 1920,
                origin_y: 200,
                primary: false,
                refresh_hz: Some(144),
            },
        ])
    }

    #[test]
    fn a_key_press_reaches_the_backend_unchanged() {
        let mut s = session(HostOs::Windows);
        let ack = s.apply(InputEvent::KeyDown {
            key: PhysicalKey::KeyA,
            repeat: false,
            seq: 1,
        });
        assert_eq!(ack, Some(InputAck::Ok { seq: 1 }));
        assert_eq!(
            s.sink().key_calls(),
            vec![(PhysicalKey::KeyA, KeyState::Down)]
        );
    }

    #[test]
    fn typing_is_never_translated_on_any_host() {
        // The same physical key must arrive as itself regardless of host OS.
        for os in HostOs::all() {
            let mut s = session(os);
            s.apply(InputEvent::KeyDown {
                key: PhysicalKey::KeyC,
                repeat: false,
                seq: 1,
            });
            s.apply(InputEvent::KeyUp {
                key: PhysicalKey::KeyC,
                seq: 2,
            });
            assert_eq!(
                s.sink().key_calls(),
                vec![
                    (PhysicalKey::KeyC, KeyState::Down),
                    (PhysicalKey::KeyC, KeyState::Up)
                ],
                "physical key was altered for {os:?}"
            );
        }
    }

    #[test]
    fn copy_intent_is_spelled_per_host() {
        let expected = [
            (HostOs::Windows, PhysicalKey::ControlLeft),
            (HostOs::MacOs, PhysicalKey::MetaLeft),
            (HostOs::Linux, PhysicalKey::ControlLeft),
        ];
        for (os, modifier) in expected {
            let mut s = session(os);
            let ack = s.apply(InputEvent::Intent {
                intent: Intent::Copy,
                seq: 1,
            });
            assert_eq!(ack, Some(InputAck::Ok { seq: 1 }));
            assert_eq!(
                s.sink().key_calls(),
                vec![
                    (modifier, KeyState::Down),
                    (PhysicalKey::KeyC, KeyState::Down),
                    (PhysicalKey::KeyC, KeyState::Up),
                    (modifier, KeyState::Up),
                ],
                "copy was spelled wrong on {os:?}"
            );
        }
    }

    #[test]
    fn a_chord_leaves_nothing_held() {
        for os in HostOs::all() {
            let mut s = session(os);
            s.apply(InputEvent::Intent {
                intent: Intent::Paste,
                seq: 1,
            });
            assert!(s.held().is_empty(), "{os:?} left keys held after a chord");
        }
    }

    #[test]
    fn an_unsupported_intent_is_refused_with_the_true_reason() {
        let mut s = session(HostOs::MacOs);
        let ack = s.apply(InputEvent::Intent {
            intent: Intent::SecureAttention,
            seq: 7,
        });
        assert_eq!(
            ack,
            Some(InputAck::Failed {
                seq: 7,
                reason: InputFailure::NotSupported
            })
        );
        // Nothing was pressed: a refusal must not half-perform the action.
        assert!(s.sink().calls().is_empty());
    }

    #[test]
    fn motion_is_not_acknowledged_but_advances_the_watermark() {
        let mut s = session(HostOs::Windows);
        assert_eq!(
            s.apply(InputEvent::MouseMove {
                x: 0.5,
                y: 0.5,
                display: 0,
                seq: 4
            }),
            None
        );
        assert_eq!(s.watermark(), 4);
        // Centre of a 1920x1080 display at the origin.
        assert_eq!(s.sink().calls(), &[Call::PointerMove { gx: 960, gy: 540 }]);
    }

    #[test]
    fn motion_on_a_secondary_display_lands_on_that_display() {
        // The whole point of multi-monitor support: the same fraction must resolve to
        // a completely different part of the virtual desktop.
        let mut s = session(HostOs::Windows);
        s.apply(InputEvent::MouseMove {
            x: 0.5,
            y: 0.5,
            display: 1,
            seq: 1,
        });
        assert_eq!(
            s.sink().calls(),
            &[Call::PointerMove {
                gx: 1920 + 1280,
                gy: 200 + 720
            }]
        );
    }

    #[test]
    fn the_same_fraction_differs_between_displays() {
        let mut s = session(HostOs::Windows);
        s.apply(InputEvent::MouseMove {
            x: 0.25,
            y: 0.25,
            display: 0,
            seq: 1,
        });
        s.apply(InputEvent::MouseMove {
            x: 0.25,
            y: 0.25,
            display: 1,
            seq: 2,
        });
        let calls = s.sink().calls();
        assert_ne!(
            calls[0], calls[1],
            "both displays resolved to the same point"
        );
    }

    #[test]
    fn motion_aimed_at_a_vanished_display_is_refused_not_misplaced() {
        // A monitor unplugged mid-drag must not silently redirect the pointer onto a
        // different screen at the same fraction.
        let mut s = InputSession::new(MockSink::new(), Some(HostOs::Windows), true);
        s.set_topology(DisplayTopology::default());
        assert_eq!(
            s.apply(InputEvent::MouseMove {
                x: 0.5,
                y: 0.5,
                display: 3,
                seq: 1
            }),
            None
        );
        assert!(s.sink().calls().is_empty());
        assert_eq!(
            s.watermark(),
            0,
            "a refused move must not advance the watermark"
        );
    }

    #[test]
    fn motion_falls_back_to_the_primary_when_its_display_disappears() {
        // The display is gone but others remain: the session continues on the primary
        // rather than dying.
        let mut s = session(HostOs::Windows);
        s.apply(InputEvent::MouseMove {
            x: 0.0,
            y: 0.0,
            display: 9,
            seq: 1,
        });
        assert_eq!(s.sink().calls(), &[Call::PointerMove { gx: 0, gy: 0 }]);
    }

    #[test]
    fn the_watermark_never_goes_backwards() {
        // Reordering cannot make the controller think earlier motion was undone.
        let mut s = session(HostOs::Windows);
        s.apply(InputEvent::MouseMove {
            x: 0.1,
            y: 0.1,
            display: 0,
            seq: 9,
        });
        s.apply(InputEvent::MouseMove {
            x: 0.2,
            y: 0.2,
            display: 0,
            seq: 3,
        });
        assert_eq!(s.watermark(), 9);
    }

    #[test]
    fn out_of_range_coordinates_are_clamped_not_dropped() {
        let mut s = session(HostOs::Windows);
        s.apply(InputEvent::MouseMove {
            x: 1.5,
            y: -0.2,
            display: 0,
            seq: 1,
        });
        // Clamped to the far right edge and the top of display 0.
        assert_eq!(s.sink().calls(), &[Call::PointerMove { gx: 1919, gy: 0 }]);
    }

    #[test]
    fn a_view_only_session_refuses_everything() {
        let mut s = InputSession::new(MockSink::new(), Some(HostOs::Windows), false);
        let ack = s.apply(InputEvent::MouseDown {
            button: MouseButton::Left,
            seq: 1,
        });
        assert_eq!(
            ack,
            Some(InputAck::Failed {
                seq: 1,
                reason: InputFailure::ViewOnly
            })
        );
        assert!(s.sink().calls().is_empty());
        assert!(!s.capability().is_usable());
    }

    #[test]
    fn a_refusing_backend_reports_its_real_reason() {
        let mut s = InputSession::new(
            MockSink::failing(InputFailure::NotPermitted),
            Some(HostOs::MacOs),
            true,
        );
        let ack = s.apply(InputEvent::KeyDown {
            key: PhysicalKey::KeyA,
            repeat: false,
            seq: 2,
        });
        assert_eq!(
            ack,
            Some(InputAck::Failed {
                seq: 2,
                reason: InputFailure::NotPermitted
            })
        );
    }

    #[test]
    fn a_failed_press_is_not_recorded_as_held() {
        // Otherwise teardown would "release" a key that was never pressed.
        let mut s = InputSession::new(
            MockSink::failing(InputFailure::Blocked),
            Some(HostOs::Windows),
            true,
        );
        s.apply(InputEvent::KeyDown {
            key: PhysicalKey::KeyA,
            repeat: false,
            seq: 1,
        });
        assert!(s.held().is_empty());
    }

    #[test]
    fn a_drag_is_just_down_move_up() {
        let mut s = session(HostOs::Windows);
        s.apply(InputEvent::MouseDown {
            button: MouseButton::Left,
            seq: 1,
        });
        s.apply(InputEvent::MouseMove {
            x: 0.2,
            y: 0.3,
            display: 0,
            seq: 2,
        });
        // Continuing the drag onto the second display, which is what makes a drag
        // across a monitor boundary work.
        s.apply(InputEvent::MouseMove {
            x: 0.6,
            y: 0.7,
            display: 1,
            seq: 3,
        });
        s.apply(InputEvent::MouseUp {
            button: MouseButton::Left,
            seq: 4,
        });

        assert_eq!(
            s.sink().calls(),
            &[
                Call::Button {
                    button: MouseButton::Left,
                    state: KeyState::Down
                },
                Call::PointerMove { gx: 384, gy: 324 },
                Call::PointerMove {
                    gx: 1920 + 1536,
                    gy: 200 + 1008
                },
                Call::Button {
                    button: MouseButton::Left,
                    state: KeyState::Up
                },
            ]
        );
        assert!(s.held().is_empty());
    }

    #[test]
    fn a_double_click_is_two_click_pairs_in_order() {
        let mut s = session(HostOs::Windows);
        for seq in 1..=4 {
            let event = if seq % 2 == 1 {
                InputEvent::MouseDown {
                    button: MouseButton::Left,
                    seq,
                }
            } else {
                InputEvent::MouseUp {
                    button: MouseButton::Left,
                    seq,
                }
            };
            s.apply(event);
        }
        assert_eq!(s.sink().calls().len(), 4);
        assert!(s.held().is_empty());
    }

    #[test]
    fn every_mouse_button_reaches_the_backend() {
        for button in [
            MouseButton::Left,
            MouseButton::Right,
            MouseButton::Middle,
            MouseButton::Back,
            MouseButton::Forward,
        ] {
            let mut s = session(HostOs::Windows);
            s.apply(InputEvent::MouseDown { button, seq: 1 });
            assert_eq!(
                s.sink().calls(),
                &[Call::Button {
                    button,
                    state: KeyState::Down
                }]
            );
        }
    }

    #[test]
    fn scrolling_passes_both_axes_through() {
        let mut s = session(HostOs::Windows);
        s.apply(InputEvent::Scroll {
            delta_x: -2.0,
            delta_y: 3.5,
            seq: 1,
        });
        assert_eq!(s.sink().calls(), &[Call::Scroll { dx: -2.0, dy: 3.5 }]);
    }

    #[test]
    fn teardown_releases_a_stuck_modifier_in_the_right_order() {
        // The bug this exists to prevent: a session dropped mid-chord leaving Ctrl
        // jammed down on the remote machine.
        let mut s = session(HostOs::Windows);
        s.apply(InputEvent::KeyDown {
            key: PhysicalKey::ControlLeft,
            repeat: false,
            seq: 1,
        });
        s.apply(InputEvent::KeyDown {
            key: PhysicalKey::KeyC,
            repeat: false,
            seq: 2,
        });

        s.release_all();

        let keys = s.sink().key_calls();
        assert_eq!(
            &keys[2..],
            &[
                (PhysicalKey::KeyC, KeyState::Up),
                (PhysicalKey::ControlLeft, KeyState::Up),
            ]
        );
        assert!(s.held().is_empty());
    }

    #[test]
    fn teardown_releases_a_held_mouse_button() {
        let mut s = session(HostOs::Windows);
        s.apply(InputEvent::MouseDown {
            button: MouseButton::Left,
            seq: 1,
        });
        s.release_all();
        assert_eq!(
            s.sink().calls().last(),
            Some(&Call::Button {
                button: MouseButton::Left,
                state: KeyState::Up
            })
        );
    }

    #[test]
    fn teardown_on_a_clean_session_does_nothing() {
        let mut s = session(HostOs::Windows);
        s.apply(InputEvent::KeyDown {
            key: PhysicalKey::KeyA,
            repeat: false,
            seq: 1,
        });
        s.apply(InputEvent::KeyUp {
            key: PhysicalKey::KeyA,
            seq: 2,
        });
        let before = s.sink().calls().len();
        s.release_all();
        assert_eq!(s.sink().calls().len(), before);
    }

    #[test]
    fn autorepeat_presses_do_not_leave_a_phantom_hold() {
        let mut s = session(HostOs::Windows);
        for seq in 1..=5 {
            s.apply(InputEvent::KeyDown {
                key: PhysicalKey::KeyA,
                repeat: seq > 1,
                seq,
            });
        }
        s.apply(InputEvent::KeyUp {
            key: PhysicalKey::KeyA,
            seq: 6,
        });
        assert!(s.held().is_empty());
    }

    // --- the nine pairs, end to end through the session ---------------------------

    #[test]
    fn all_nine_pairs_deliver_copy_as_the_host_spells_it() {
        for from in HostOs::all() {
            // What the operator physically types on the controller.
            let typed = render(Intent::Copy, from).unwrap();
            let recognised = detect(typed, from).expect("controller recognises copy");

            for to in HostOs::all() {
                let mut s = session(to);
                s.apply(InputEvent::Intent {
                    intent: recognised,
                    seq: 1,
                });

                let expected_modifier = match to {
                    HostOs::MacOs => PhysicalKey::MetaLeft,
                    HostOs::Windows | HostOs::Linux => PhysicalKey::ControlLeft,
                };
                assert_eq!(
                    s.sink().key_calls(),
                    vec![
                        (expected_modifier, KeyState::Down),
                        (PhysicalKey::KeyC, KeyState::Down),
                        (PhysicalKey::KeyC, KeyState::Up),
                        (expected_modifier, KeyState::Up),
                    ],
                    "copy {from:?} -> {to:?} was delivered wrong"
                );
            }
        }
    }

    #[test]
    fn no_pair_ever_presses_a_windows_key_on_macos() {
        // The specific failure the operator asked about: Windows-specific identities
        // must not reach macOS. Meta is pressed on macOS only where macOS itself uses
        // Command, and never as a consequence of the controller being Windows.
        for from in HostOs::all() {
            for intent in intent::supported(from) {
                let Some(typed) = render(intent, from) else {
                    continue;
                };
                let Some(recognised) = detect(typed, from) else {
                    continue;
                };

                let mut s = session(HostOs::MacOs);
                s.apply(InputEvent::Intent {
                    intent: recognised,
                    seq: 1,
                });

                let pressed = s.sink().key_calls();
                if let Some(expected) = render(recognised, HostOs::MacOs) {
                    let wanted = expected.mods.contains(Modifiers::META);
                    let pressed_meta = pressed.iter().any(|(key, _)| {
                        matches!(key, PhysicalKey::MetaLeft | PhysicalKey::MetaRight)
                    });
                    assert_eq!(
                        pressed_meta, wanted,
                        "{intent:?} from {from:?} pressed Meta on macOS incorrectly"
                    );
                } else {
                    assert!(
                        pressed.is_empty(),
                        "{intent:?} from {from:?} was approximated on macOS"
                    );
                }
            }
        }
    }
}
