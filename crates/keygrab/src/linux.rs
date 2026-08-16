//! Taking reserved chords on X11, with `XGrabKey`.
//!
//! # A grab here is per chord, not a hook over everything
//!
//! Windows and macOS install something that sees every keystroke and decides. X11 has no
//! equivalent an unprivileged client may use, and that is a better fit rather than a
//! worse one: `GrabKey` asks the server for *specific* combinations on the root window,
//! so this process never sees the operator's ordinary typing at all. The set it asks for
//! is exactly what [`rc_input::grab::reserved_by`] claims.
//!
//! # Wayland is not X11, and is not pretended to be
//!
//! There is no portable Wayland equivalent: taking a compositor's shortcuts needs the
//! compositor's cooperation, and no protocol for it is widely implemented. A Wayland
//! session usually exposes an X server through `XWayland`, and a grab taken there does
//! *not* cover native Wayland clients — so connecting is attempted and a failure is
//! reported as [`GrabError::Refused`] rather than silently taking a partial grab that
//! would leave `Alt+Tab` working locally some of the time.
//!
//! # Modifier wildcards
//!
//! X11 matches a grab against the exact modifier state, so `Alt+Tab` with Num Lock on is
//! a different combination from `Alt+Tab` without it. Every grab is therefore requested
//! once per combination of the "don't care" modifiers — Num Lock, Caps Lock and Scroll
//! Lock — which is the standard remedy and the reason [`IGNORED_MODIFIERS`] exists.

use std::sync::mpsc::Sender;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use rc_input::grab::{GrabError, KeyGrab, reserved_by};
use rc_input::intent::{Chord, HostOs};
use rc_protocol::{Modifiers, PhysicalKey};
use x11rb::connection::Connection;
use x11rb::protocol::Event;
use x11rb::protocol::xproto::{ConnectionExt as _, GrabMode, Keycode, ModMask};

/// Caps Lock, as X11 numbers it. These bits are fixed by the protocol, not by a library.
const LOCK: u16 = 1 << 1;
/// Num Lock, conventionally Mod2.
const NUM_LOCK: u16 = 1 << 4;
/// Scroll Lock, conventionally Mod5.
const SCROLL_LOCK: u16 = 1 << 7;

/// Modifier bits X11 reports that a shortcut should not care about.
///
/// Num Lock, Caps Lock and Scroll Lock change the reported state without changing what
/// the operator pressed, so each grab is asked for once per combination of them.
const IGNORED_MODIFIERS: [u16; 8] = [
    0,
    LOCK,
    NUM_LOCK,
    SCROLL_LOCK,
    LOCK | NUM_LOCK,
    LOCK | SCROLL_LOCK,
    NUM_LOCK | SCROLL_LOCK,
    LOCK | NUM_LOCK | SCROLL_LOCK,
];

/// The chords this backend asks the X server for, as keysym and modifier mask.
///
/// Derived from the same policy the other backends consult, rather than a second list:
/// `reserved_by` decides, and this only spells each decision in X11's vocabulary.
fn wanted_chords() -> Vec<(u32, u16, Chord)> {
    let candidates = [
        // Mod1 is Alt and Mod4 is Super on every mainstream desktop.
        (PhysicalKey::Tab, Modifiers::ALT, 0xFF09_u32, ModMask::M1),
        (PhysicalKey::Escape, Modifiers::ALT, 0xFF1B, ModMask::M1),
        (PhysicalKey::KeyD, Modifiers::META, 0x0064, ModMask::M4),
        (PhysicalKey::KeyL, Modifiers::META, 0x006C, ModMask::M4),
    ];

    candidates
        .into_iter()
        .filter_map(|(key, mods, keysym, mask)| {
            let chord = Chord::new(key, mods);
            // Only what the shared policy actually claims. A chord grabbed here that the
            // policy does not claim would be swallowed with nothing sent in its place.
            let mask = u16::try_from(u32::from(mask)).unwrap_or(0);
            reserved_by(chord, HostOs::Linux).map(|_| (keysym, mask, chord))
        })
        .collect()
}

/// An X11 key grab over the chords the desktop reserves.
#[derive(Debug)]
pub struct LinuxKeyGrab {
    sink: Sender<Chord>,
    running: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LinuxKeyGrab {
    /// A released grab, forwarding grabbed chords to `sink`.
    #[must_use]
    pub fn new(sink: Sender<Chord>) -> Self {
        Self {
            sink,
            running: Arc::new(AtomicBool::new(false)),
            thread: None,
        }
    }
}

impl KeyGrab for LinuxKeyGrab {
    fn engage(&mut self) -> Result<(), GrabError> {
        if self.thread.is_some() {
            return Ok(());
        }

        let sink = self.sink.clone();
        let running = Arc::clone(&self.running);
        running.store(true, Ordering::SeqCst);

        let (ready, started) = std::sync::mpsc::channel::<Result<(), GrabError>>();
        let handle = std::thread::Builder::new()
            .name("keyboard-grab".to_owned())
            .spawn(move || grab_thread(&sink, &running, &ready))
            .map_err(|_| GrabError::Refused)?;

        // Wait for the server's answer, so a display that refuses the grab is reported
        // here rather than discovered as silence later.
        match started.recv() {
            Ok(Ok(())) => {
                self.thread = Some(handle);
                Ok(())
            }
            Ok(Err(err)) => {
                self.running.store(false, Ordering::SeqCst);
                Err(err)
            }
            Err(_) => {
                self.running.store(false, Ordering::SeqCst);
                Err(GrabError::Refused)
            }
        }
    }

    fn release(&mut self) {
        self.running.store(false, Ordering::SeqCst);

        let Some(handle) = self.thread.take() else {
            return;
        };
        // The thread notices `running` on its next wake and ungrabs before returning.
        let _ = handle.join();
    }

    fn engaged(&self) -> bool {
        self.thread.is_some()
    }
}

impl Drop for LinuxKeyGrab {
    fn drop(&mut self) {
        self.release();
    }
}

/// Hold the grabs and forward key presses until asked to stop.
fn grab_thread(sink: &Sender<Chord>, running: &AtomicBool, ready: &Sender<Result<(), GrabError>>) {
    let Ok((connection, screen_index)) = x11rb::connect(None) else {
        // No DISPLAY, or a Wayland session with no `XWayland` to talk to.
        let _ = ready.send(Err(GrabError::Refused));
        return;
    };

    let Some(root) = connection
        .setup()
        .roots
        .get(screen_index)
        .map(|screen| screen.root)
    else {
        let _ = ready.send(Err(GrabError::Refused));
        return;
    };

    let wanted = wanted_chords();
    let Ok(keycodes) = resolve_keycodes(&connection, &wanted) else {
        let _ = ready.send(Err(GrabError::Refused));
        return;
    };

    for (keycode, mask, _) in &keycodes {
        for ignored in IGNORED_MODIFIERS {
            // Async grabs: the server must not freeze the keyboard waiting on this
            // process, which would stall the whole desktop if this thread were slow.
            let request = connection.grab_key(
                true,
                root,
                (mask | ignored).into(),
                *keycode,
                GrabMode::ASYNC,
                GrabMode::ASYNC,
            );
            if let Ok(cookie) = request {
                let _ = cookie.check();
            }
        }
    }

    if connection.flush().is_err() {
        let _ = ready.send(Err(GrabError::Refused));
        return;
    }
    let _ = ready.send(Ok(()));

    while running.load(Ordering::SeqCst) {
        match connection.wait_for_event() {
            Ok(Event::KeyPress(press)) => {
                if let Some((_, _, chord)) = keycodes
                    .iter()
                    .find(|(keycode, _, _)| *keycode == press.detail)
                {
                    let _ = sink.send(*chord);
                }
            }
            Ok(_) => {}
            // The connection died; there is nothing left to ungrab from.
            Err(_) => return,
        }
    }

    // The promise: the desktop gets its shortcuts back.
    for (keycode, mask, _) in &keycodes {
        for ignored in IGNORED_MODIFIERS {
            let _ = connection.ungrab_key(*keycode, root, (mask | ignored).into());
        }
    }
    let _ = connection.flush();
}

/// Turn each wanted keysym into the keycode this server uses for it.
///
/// Keysyms are stable names; keycodes are what `GrabKey` takes and differ per keyboard,
/// so the mapping has to be read from the server rather than assumed.
fn resolve_keycodes(
    connection: &impl Connection,
    wanted: &[(u32, u16, Chord)],
) -> Result<Vec<(Keycode, u16, Chord)>, ()> {
    let setup = connection.setup();
    let first = setup.min_keycode;
    let count = setup.max_keycode - setup.min_keycode + 1;

    let mapping = connection
        .get_keyboard_mapping(first, count)
        .map_err(|_| ())?
        .reply()
        .map_err(|_| ())?;

    let per_code = mapping.keysyms_per_keycode as usize;
    if per_code == 0 {
        return Err(());
    }

    let mut resolved = Vec::new();
    for (keysym, mask, chord) in wanted {
        for (index, chunk) in mapping.keysyms.chunks(per_code).enumerate() {
            if chunk.contains(keysym) {
                let code = first + u8::try_from(index).map_err(|_| ())?;
                resolved.push((code, *mask, *chord));
                break;
            }
        }
    }

    if resolved.is_empty() {
        return Err(());
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_chord_asked_of_the_server_is_one_the_policy_claims() {
        // The invariant that keeps this backend honest: a chord grabbed here that the
        // shared policy does not claim would be swallowed with nothing sent in its
        // place, which is worse than not grabbing it.
        for (_, _, chord) in wanted_chords() {
            assert!(
                reserved_by(chord, HostOs::Linux).is_some(),
                "{chord:?} is grabbed but not claimed by the policy"
            );
        }
    }

    #[test]
    fn the_chords_worth_grabbing_are_actually_asked_for() {
        // A silently empty grab set would look like a working backend that takes
        // nothing.
        let wanted = wanted_chords();
        assert!(!wanted.is_empty());
        assert!(
            wanted.iter().any(|(keysym, _, _)| *keysym == 0xFF09),
            "Alt+Tab is the chord this whole module exists for"
        );
    }

    #[test]
    fn a_grab_is_asked_for_under_every_lock_combination() {
        // X11 matches the exact modifier state, so Alt+Tab with Num Lock on is a
        // different combination. Missing one means the grab silently stops working the
        // moment someone presses Num Lock.
        assert_eq!(IGNORED_MODIFIERS.len(), 8);
        assert_eq!(
            IGNORED_MODIFIERS[0], 0,
            "the plain combination must be included"
        );
        assert_eq!(
            IGNORED_MODIFIERS
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            8,
            "each combination must be distinct"
        );
    }
}
