//! Taking reserved chords on macOS, with a `CGEventTap`.
//!
//! # Why a tap, and why it can be refused
//!
//! `Cmd+Tab` is handled by the window server before any ordinary application sees it.
//! The only way to get in front of that is a tap inserted at the HID level, and macOS
//! gates that behind the Accessibility grant in System Settings. A tap created without
//! it comes back null, which is reported as [`GrabError::Refused`] rather than as a tap
//! that silently observes nothing — an operator whose `Cmd+Tab` still switches their own
//! applications would otherwise conclude the remote session was broken.
//!
//! # Why a thread with a run loop
//!
//! A tap only delivers while its run loop is running, and the Tauri main thread's loop
//! is not one this crate should be attaching to. So the tap gets a thread of its own
//! whose only job is to run that loop, and [`CFRunLoop::stop`] is what ends it.
//!
//! # What the callback may not do
//!
//! It runs inside the window server's input path, ahead of every application on the
//! machine. Returning `None` swallows the event, so the decision is made by
//! [`rc_input::grab::disposition`] — tested — rather than here.

use std::sync::Mutex;
use std::sync::mpsc::Sender;

use core_foundation::runloop::{CFRunLoop, kCFRunLoopCommonModes};
use core_graphics::event::{
    CGEventFlags, CGEventTap, CGEventTapLocation, CGEventTapOptions, CGEventTapPlacement,
    CGEventType, EventField,
};
use rc_input::grab::{Disposition, GrabError, KeyGrab, disposition};
use rc_input::intent::{Chord, HostOs};
use rc_protocol::{Modifiers, PhysicalKey};

/// The run loop the tap is attached to, so it can be stopped from another thread.
///
/// `CFRunLoop` is documented as safe to send `stop` to from any thread, which is the
/// only thing done with it here.
static RUN_LOOP: Mutex<Option<CFRunLoop>> = Mutex::new(None);

/// A `CGEventTap` that takes the chords the window server reserves.
#[derive(Debug)]
pub struct MacosKeyGrab {
    sink: Sender<Chord>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl MacosKeyGrab {
    /// A released grab, forwarding grabbed chords to `sink`.
    #[must_use]
    pub const fn new(sink: Sender<Chord>) -> Self {
        Self { sink, thread: None }
    }
}

impl KeyGrab for MacosKeyGrab {
    fn engage(&mut self) -> Result<(), GrabError> {
        if self.thread.is_some() {
            return Ok(());
        }

        let sink = self.sink.clone();
        let (ready, started) = std::sync::mpsc::channel::<Result<(), GrabError>>();

        let handle = std::thread::Builder::new()
            .name("keyboard-grab".to_owned())
            .spawn(move || tap_thread(&sink, &ready))
            .map_err(|_| GrabError::Refused)?;

        // Wait for the thread to say whether the tap actually installed, so a missing
        // Accessibility grant is reported here rather than discovered as silence.
        match started.recv() {
            Ok(Ok(())) => {
                self.thread = Some(handle);
                Ok(())
            }
            Ok(Err(err)) => Err(err),
            Err(_) => Err(GrabError::Refused),
        }
    }

    fn release(&mut self) {
        let Some(handle) = self.thread.take() else {
            return;
        };

        if let Ok(mut slot) = RUN_LOOP.lock()
            && let Some(run_loop) = slot.take()
        {
            run_loop.stop();
        }

        // Joined rather than detached: the tap is not gone until its thread has dropped
        // it, and returning earlier would report a released grab that is still taking
        // the operator's keys.
        let _ = handle.join();
    }

    fn engaged(&self) -> bool {
        self.thread.is_some()
    }
}

impl Drop for MacosKeyGrab {
    fn drop(&mut self) {
        self.release();
    }
}

/// Install the tap, run its loop until stopped, then drop it.
fn tap_thread(sink: &Sender<Chord>, ready: &Sender<Result<(), GrabError>>) {
    let tap = CGEventTap::new(
        // HID level: ahead of the window server, which is the only place `Cmd+Tab` can
        // still be intercepted.
        CGEventTapLocation::HID,
        CGEventTapPlacement::HeadInsertEventTap,
        CGEventTapOptions::Default,
        vec![CGEventType::KeyDown],
        |_proxy, _event_type, event| {
            let code = event.get_integer_value_field(EventField::KEYBOARD_EVENT_KEYCODE);
            let Some(key) = reserved_key(code) else {
                return Some(event.clone());
            };

            let chord = Chord::new(key, modifiers_from(event.get_flags()));
            if disposition(chord, HostOs::MacOs, true) == Disposition::Forward {
                let _ = sink.send(chord);
                // Swallowed, so the window server never switches the local application.
                return None;
            }
            Some(event.clone())
        },
    );

    let Ok(tap) = tap else {
        // Almost always the missing Accessibility grant.
        let _ = ready.send(Err(GrabError::Refused));
        return;
    };

    let source = tap.mach_port.create_runloop_source(0);
    let Ok(source) = source else {
        let _ = ready.send(Err(GrabError::Refused));
        return;
    };

    let run_loop = CFRunLoop::get_current();
    // SAFETY: adding a source created above to the run loop of the thread it will be
    // serviced on.
    unsafe {
        run_loop.add_source(&source, kCFRunLoopCommonModes);
    }
    tap.enable();

    if let Ok(mut slot) = RUN_LOOP.lock() {
        *slot = Some(run_loop);
    }
    let _ = ready.send(Ok(()));

    // Returns when `release` stops the loop, after which the tap drops and the window
    // server has its shortcuts back.
    CFRunLoop::run_current();
}

/// The [`PhysicalKey`] for a `CGKeyCode`, for the few keys a grab cares about.
///
/// Deliberately not the whole keyboard: this runs in the window server's input path on
/// every keystroke, and the only codes that can lead anywhere are the ones
/// [`rc_input::grab::reserved_by`] might claim on macOS.
const fn reserved_key(code: i64) -> Option<PhysicalKey> {
    Some(match code {
        0x30 => PhysicalKey::Tab,
        0x35 => PhysicalKey::Escape,
        _ => return None,
    })
}

/// The protocol's modifiers for a tap's event flags.
///
/// `Command` becomes [`Modifiers::META`] and `Alternate` becomes [`Modifiers::ALT`],
/// which is the naming-by-role the protocol already uses: META is Command here and the
/// Windows key elsewhere.
fn modifiers_from(flags: CGEventFlags) -> Modifiers {
    let mut mods = Modifiers::NONE;
    if flags.contains(CGEventFlags::CGEventFlagShift) {
        mods = mods.with(Modifiers::SHIFT);
    }
    if flags.contains(CGEventFlags::CGEventFlagControl) {
        mods = mods.with(Modifiers::CONTROL);
    }
    if flags.contains(CGEventFlags::CGEventFlagAlternate) {
        mods = mods.with(Modifiers::ALT);
    }
    if flags.contains(CGEventFlags::CGEventFlagCommand) {
        mods = mods.with(Modifiers::META);
    }
    mods
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_keys_a_grab_can_claim_are_recognised() {
        assert_eq!(reserved_key(0x30), Some(PhysicalKey::Tab));
        assert_eq!(reserved_key(0x35), Some(PhysicalKey::Escape));
    }

    #[test]
    fn an_ordinary_letter_is_not_recognised_and_so_is_never_swallowed() {
        // 0x00 is kVK_ANSI_A. A grab that claimed it would stop the operator typing.
        assert_eq!(reserved_key(0x00), None);
        assert_eq!(reserved_key(0x31), None);
    }

    #[test]
    fn command_is_meta_because_the_protocol_names_modifiers_by_role() {
        // The whole point of naming by role: Command here is the Windows key elsewhere,
        // and the chord tables are written once against META rather than twice.
        let mods = modifiers_from(CGEventFlags::CGEventFlagCommand);
        assert!(mods.contains(Modifiers::META));
        assert!(!mods.contains(Modifiers::CONTROL));
    }

    #[test]
    fn option_is_alt_not_meta() {
        let mods = modifiers_from(CGEventFlags::CGEventFlagAlternate);
        assert!(mods.contains(Modifiers::ALT));
        assert!(!mods.contains(Modifiers::META));
    }

    #[test]
    fn held_modifiers_combine() {
        let mods =
            modifiers_from(CGEventFlags::CGEventFlagCommand | CGEventFlags::CGEventFlagShift);
        assert!(mods.contains(Modifiers::META));
        assert!(mods.contains(Modifiers::SHIFT));
        assert!(!mods.contains(Modifiers::ALT));
    }
}
