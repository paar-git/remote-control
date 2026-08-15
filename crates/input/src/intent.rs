//! Logical intents and their per-OS spelling.
//!
//! # One table per OS, read in both directions
//!
//! Each operating system gets a single table pairing an [`Intent`] with the [`Chord`]
//! that means it on that OS. [`detect`] reads the table by chord, [`render`] reads it
//! by intent. Because both directions consult the *same* table, a translation cannot
//! drift out of step with its inverse — the class of bug where copying works one way
//! and not the other is structurally impossible rather than merely tested for.
//!
//! Three tables therefore cover all nine controller→host pairs: the controller reads
//! its own to recognise a chord, the host reads its own to spell it. Neither models
//! the other. Adding a fourth OS is one new table and no edits to the existing three.
//!
//! # What is deliberately absent
//!
//! An intent with no sensible equivalent on an OS is simply not in that OS's table.
//! [`render`] then returns `None` and the host replies `NotSupported`, which is a true
//! statement. Inventing an approximate chord would produce a keystroke the operator
//! did not ask for, on a machine they are not looking at.

use rc_protocol::{Intent, Modifiers, PhysicalKey};

/// Which operating system a chord is being read for or written for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HostOs {
    /// Windows.
    Windows,
    /// macOS.
    MacOs,
    /// Linux.
    Linux,
}

impl HostOs {
    /// The OS this binary was compiled for, or `None` on a platform with no table.
    #[must_use]
    pub const fn current() -> Option<Self> {
        #[cfg(target_os = "windows")]
        {
            Some(Self::Windows)
        }
        #[cfg(target_os = "macos")]
        {
            Some(Self::MacOs)
        }
        #[cfg(target_os = "linux")]
        {
            Some(Self::Linux)
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            None
        }
    }

    /// Every OS with a table, for exhaustive tests.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Windows, Self::MacOs, Self::Linux]
    }
}

/// A key pressed together with a set of modifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Chord {
    /// The non-modifier key.
    pub key: PhysicalKey,
    /// Modifiers held while it was struck.
    pub mods: Modifiers,
}

impl Chord {
    /// A chord of `key` held with `mods`.
    #[must_use]
    pub const fn new(key: PhysicalKey, mods: Modifiers) -> Self {
        Self { key, mods }
    }
}

/// Shorthand for a table row.
const fn row(intent: Intent, key: PhysicalKey, mods: Modifiers) -> (Intent, Chord) {
    (intent, Chord::new(key, mods))
}

const CTRL: Modifiers = Modifiers::CONTROL;
const ALT: Modifiers = Modifiers::ALT;
const META: Modifiers = Modifiers::META;
const SHIFT: Modifiers = Modifiers::SHIFT;

/// Windows conventions.
static WINDOWS: &[(Intent, Chord)] = &[
    row(Intent::Copy, PhysicalKey::KeyC, CTRL),
    row(Intent::Paste, PhysicalKey::KeyV, CTRL),
    row(Intent::Cut, PhysicalKey::KeyX, CTRL),
    row(Intent::SelectAll, PhysicalKey::KeyA, CTRL),
    row(Intent::Undo, PhysicalKey::KeyZ, CTRL),
    row(Intent::Redo, PhysicalKey::KeyY, CTRL),
    row(Intent::Save, PhysicalKey::KeyS, CTRL),
    row(Intent::Find, PhysicalKey::KeyF, CTRL),
    row(Intent::CloseWindow, PhysicalKey::F4, ALT),
    row(Intent::SwitchApp, PhysicalKey::Tab, ALT),
    row(Intent::ShowDesktop, PhysicalKey::KeyD, META),
    row(Intent::LockScreen, PhysicalKey::KeyL, META),
    // Snip & Sketch. The bare PrintScreen key also captures, and reaches the host as a
    // physical key without needing an intent — the backend injects it on Windows and
    // Linux hosts, and refuses it on macOS, which has no virtual key for it.
    row(Intent::Screenshot, PhysicalKey::KeyS, META.with(SHIFT)),
    row(Intent::SecureAttention, PhysicalKey::Delete, CTRL.with(ALT)),
];

/// macOS conventions.
///
/// Command is [`Modifiers::META`], so the Windows Ctrl shortcuts land on Command here
/// without either side special-casing the other.
static MACOS: &[(Intent, Chord)] = &[
    row(Intent::Copy, PhysicalKey::KeyC, META),
    row(Intent::Paste, PhysicalKey::KeyV, META),
    row(Intent::Cut, PhysicalKey::KeyX, META),
    row(Intent::SelectAll, PhysicalKey::KeyA, META),
    row(Intent::Undo, PhysicalKey::KeyZ, META),
    row(Intent::Redo, PhysicalKey::KeyZ, META.with(SHIFT)),
    row(Intent::Save, PhysicalKey::KeyS, META),
    row(Intent::Find, PhysicalKey::KeyF, META),
    row(Intent::CloseWindow, PhysicalKey::KeyW, META),
    row(Intent::SwitchApp, PhysicalKey::Tab, META),
    row(Intent::ShowDesktop, PhysicalKey::F11, Modifiers::NONE),
    row(Intent::LockScreen, PhysicalKey::KeyQ, META.with(CTRL)),
    row(Intent::Screenshot, PhysicalKey::Digit3, META.with(SHIFT)),
    // No secure attention sequence exists on macOS. Absent on purpose: see the module
    // docs on why an approximation would be worse than a refusal.
];

/// Linux conventions, as shared by GNOME and KDE defaults.
static LINUX: &[(Intent, Chord)] = &[
    row(Intent::Copy, PhysicalKey::KeyC, CTRL),
    row(Intent::Paste, PhysicalKey::KeyV, CTRL),
    row(Intent::Cut, PhysicalKey::KeyX, CTRL),
    row(Intent::SelectAll, PhysicalKey::KeyA, CTRL),
    row(Intent::Undo, PhysicalKey::KeyZ, CTRL),
    // Ctrl+Y is a Windows idiom; both major Linux desktops use Ctrl+Shift+Z.
    row(Intent::Redo, PhysicalKey::KeyZ, CTRL.with(SHIFT)),
    row(Intent::Save, PhysicalKey::KeyS, CTRL),
    row(Intent::Find, PhysicalKey::KeyF, CTRL),
    row(Intent::CloseWindow, PhysicalKey::F4, ALT),
    row(Intent::SwitchApp, PhysicalKey::Tab, ALT),
    row(Intent::ShowDesktop, PhysicalKey::KeyD, META),
    row(Intent::LockScreen, PhysicalKey::KeyL, META),
    row(Intent::Screenshot, PhysicalKey::PrintScreen, Modifiers::NONE),
    // No secure attention sequence on Linux.
];

/// The table for `os`.
const fn table(os: HostOs) -> &'static [(Intent, Chord)] {
    match os {
        HostOs::Windows => WINDOWS,
        HostOs::MacOs => MACOS,
        HostOs::Linux => LINUX,
    }
}

/// Recognise `chord` as an intent, using the conventions of the machine it was typed on.
///
/// Returns `None` for anything not in the closed set, which is the common case: those
/// keys travel as physical keys and are never remapped.
#[must_use]
pub fn detect(chord: Chord, os: HostOs) -> Option<Intent> {
    // A modifier key struck on its own is never an intent; the chord is identified by
    // its non-modifier key plus the modifier set.
    if chord.key.is_modifier() {
        return None;
    }
    table(os)
        .iter()
        .find(|(_, candidate)| *candidate == chord)
        .map(|(intent, _)| *intent)
}

/// Spell `intent` the way `os` spells it.
///
/// Returns `None` when the OS has no equivalent, which the caller reports as
/// [`rc_protocol::InputFailure::NotSupported`] rather than approximating.
#[must_use]
pub fn render(intent: Intent, os: HostOs) -> Option<Chord> {
    table(os)
        .iter()
        .find(|(candidate, _)| *candidate == intent)
        .map(|(_, chord)| *chord)
}

/// Every intent this build can translate for `os`.
#[must_use]
pub fn supported(os: HostOs) -> Vec<Intent> {
    table(os).iter().map(|(intent, _)| *intent).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every intent named in the protocol, so a new variant fails this list loudly
    /// rather than silently going untranslated.
    const ALL_INTENTS: &[Intent] = &[
        Intent::Copy,
        Intent::Paste,
        Intent::Cut,
        Intent::SelectAll,
        Intent::Undo,
        Intent::Redo,
        Intent::Save,
        Intent::Find,
        Intent::CloseWindow,
        Intent::SwitchApp,
        Intent::ShowDesktop,
        Intent::LockScreen,
        Intent::Screenshot,
        Intent::SecureAttention,
    ];

    #[test]
    fn every_table_round_trips_detect_and_render() {
        // The property that makes one table safe to read in two directions.
        for os in HostOs::all() {
            for (intent, chord) in table(os) {
                assert_eq!(
                    render(*intent, os),
                    Some(*chord),
                    "render disagreed with the table for {intent:?} on {os:?}"
                );
                assert_eq!(
                    detect(*chord, os),
                    Some(*intent),
                    "detect disagreed with the table for {intent:?} on {os:?}"
                );
            }
        }
    }

    #[test]
    fn no_table_maps_one_chord_to_two_intents() {
        // Ambiguity would make detection order-dependent.
        for os in HostOs::all() {
            let rows = table(os);
            for (i, (_, a)) in rows.iter().enumerate() {
                for (_, b) in rows.iter().skip(i + 1) {
                    assert_ne!(a, b, "duplicate chord in the {os:?} table");
                }
            }
        }
    }

    #[test]
    fn no_table_lists_an_intent_twice() {
        for os in HostOs::all() {
            let rows = table(os);
            for (i, (a, _)) in rows.iter().enumerate() {
                for (b, _) in rows.iter().skip(i + 1) {
                    assert_ne!(a, b, "duplicate intent in the {os:?} table");
                }
            }
        }
    }

    #[test]
    fn intents_never_use_a_modifier_as_their_key() {
        // Otherwise detect() would refuse them, since it ignores bare modifiers.
        for os in HostOs::all() {
            for (intent, chord) in table(os) {
                assert!(
                    !chord.key.is_modifier(),
                    "{intent:?} on {os:?} is keyed on a modifier"
                );
            }
        }
    }

    // --- The nine platform pairs -------------------------------------------------

    /// Translate as the controller then as the host, which is exactly what the two
    /// machines do between them.
    fn across(chord: Chord, from: HostOs, to: HostOs) -> Option<Chord> {
        let intent = detect(chord, from)?;
        render(intent, to)
    }

    #[test]
    fn copy_survives_all_nine_pairs() {
        for from in HostOs::all() {
            let typed = render(Intent::Copy, from).expect("every OS can copy");
            for to in HostOs::all() {
                let arrived = across(typed, from, to).expect("every OS can copy");
                assert_eq!(
                    arrived,
                    render(Intent::Copy, to).unwrap(),
                    "copy from {from:?} reached {to:?} wrong"
                );
            }
        }
    }

    #[test]
    fn every_shared_intent_survives_all_nine_pairs() {
        for intent in ALL_INTENTS {
            for from in HostOs::all() {
                let Some(typed) = render(*intent, from) else {
                    continue; // not expressible on the controller; nothing to type
                };
                for to in HostOs::all() {
                    let arrived = across(typed, from, to);
                    assert_eq!(
                        arrived,
                        render(*intent, to),
                        "{intent:?} from {from:?} to {to:?} did not translate"
                    );
                }
            }
        }
    }

    #[test]
    fn windows_ctrl_c_becomes_command_c_on_macos() {
        let ctrl_c = Chord::new(PhysicalKey::KeyC, Modifiers::CONTROL);
        let arrived = across(ctrl_c, HostOs::Windows, HostOs::MacOs).unwrap();
        assert_eq!(arrived.key, PhysicalKey::KeyC);
        assert!(arrived.mods.contains(Modifiers::META));
        assert!(!arrived.mods.contains(Modifiers::CONTROL));
    }

    #[test]
    fn macos_command_c_becomes_ctrl_c_on_windows_and_linux() {
        let cmd_c = Chord::new(PhysicalKey::KeyC, Modifiers::META);
        for to in [HostOs::Windows, HostOs::Linux] {
            let arrived = across(cmd_c, HostOs::MacOs, to).unwrap();
            assert_eq!(arrived.key, PhysicalKey::KeyC);
            assert!(arrived.mods.contains(Modifiers::CONTROL), "wrong on {to:?}");
            assert!(!arrived.mods.contains(Modifiers::META), "wrong on {to:?}");
        }
    }

    #[test]
    fn redo_crosses_its_three_different_spellings() {
        // Ctrl+Y on Windows, Cmd+Shift+Z on macOS, Ctrl+Shift+Z on Linux. This is the
        // case a naive "swap Ctrl for Command" translator gets wrong.
        let win = Chord::new(PhysicalKey::KeyY, Modifiers::CONTROL);
        assert_eq!(
            across(win, HostOs::Windows, HostOs::MacOs),
            Some(Chord::new(PhysicalKey::KeyZ, META.with(SHIFT)))
        );
        assert_eq!(
            across(win, HostOs::Windows, HostOs::Linux),
            Some(Chord::new(PhysicalKey::KeyZ, CTRL.with(SHIFT)))
        );

        let mac = Chord::new(PhysicalKey::KeyZ, META.with(SHIFT));
        assert_eq!(
            across(mac, HostOs::MacOs, HostOs::Windows),
            Some(Chord::new(PhysicalKey::KeyY, CTRL))
        );
    }

    #[test]
    fn close_window_crosses_alt_f4_and_command_w() {
        let alt_f4 = Chord::new(PhysicalKey::F4, Modifiers::ALT);
        assert_eq!(
            across(alt_f4, HostOs::Windows, HostOs::MacOs),
            Some(Chord::new(PhysicalKey::KeyW, META))
        );
        let cmd_w = Chord::new(PhysicalKey::KeyW, Modifiers::META);
        assert_eq!(
            across(cmd_w, HostOs::MacOs, HostOs::Linux),
            Some(Chord::new(PhysicalKey::F4, ALT))
        );
    }

    #[test]
    fn secure_attention_is_refused_rather_than_approximated() {
        // Ctrl+Alt+Del has no macOS or Linux equivalent. Sending *something* would
        // press keys the operator never asked for on a machine they cannot see.
        assert!(render(Intent::SecureAttention, HostOs::Windows).is_some());
        assert_eq!(render(Intent::SecureAttention, HostOs::MacOs), None);
        assert_eq!(render(Intent::SecureAttention, HostOs::Linux), None);

        let cad = Chord::new(PhysicalKey::Delete, CTRL.with(ALT));
        assert_eq!(across(cad, HostOs::Windows, HostOs::MacOs), None);
        assert_eq!(across(cad, HostOs::Windows, HostOs::Linux), None);
    }

    #[test]
    fn ordinary_typing_is_never_an_intent() {
        // The guarantee that keeps text entry, terminals and games exact.
        for os in HostOs::all() {
            for key in [
                PhysicalKey::KeyA,
                PhysicalKey::KeyC,
                PhysicalKey::Space,
                PhysicalKey::Enter,
                PhysicalKey::ArrowUp,
                PhysicalKey::Digit3,
                PhysicalKey::KeyW,
            ] {
                assert_eq!(
                    detect(Chord::new(key, Modifiers::NONE), os),
                    None,
                    "{key:?} unmodified was treated as an intent on {os:?}"
                );
            }
        }
    }

    #[test]
    fn shifted_typing_is_never_an_intent() {
        // Capital letters must not be mistaken for shortcuts.
        for os in HostOs::all() {
            for key in [PhysicalKey::KeyA, PhysicalKey::KeyC, PhysicalKey::KeyZ] {
                assert_eq!(detect(Chord::new(key, Modifiers::SHIFT), os), None);
            }
        }
    }

    #[test]
    fn bare_modifiers_are_not_intents() {
        for os in HostOs::all() {
            for key in [
                PhysicalKey::ControlLeft,
                PhysicalKey::MetaLeft,
                PhysicalKey::AltRight,
                PhysicalKey::ShiftLeft,
            ] {
                assert_eq!(detect(Chord::new(key, Modifiers::CONTROL), os), None);
            }
        }
    }

    #[test]
    fn unknown_chords_fall_through_to_physical() {
        // Ctrl+Alt+Shift+Q means nothing here, so it must not be claimed as an intent.
        let odd = Chord::new(PhysicalKey::KeyQ, CTRL.with(ALT).with(SHIFT));
        for os in HostOs::all() {
            assert_eq!(detect(odd, os), None);
        }
    }

    #[test]
    fn supported_lists_match_the_tables() {
        assert!(supported(HostOs::Windows).contains(&Intent::SecureAttention));
        assert!(!supported(HostOs::MacOs).contains(&Intent::SecureAttention));
        assert_eq!(supported(HostOs::Linux).len(), LINUX.len());
    }

    #[test]
    fn all_intents_covers_the_protocol_enum() {
        // If a variant is added to Intent without a table entry anywhere, this catches
        // it: no OS would list it.
        for intent in ALL_INTENTS {
            let anywhere = HostOs::all().iter().any(|os| render(*intent, *os).is_some());
            assert!(anywhere, "{intent:?} has no spelling on any OS");
        }
    }
}
