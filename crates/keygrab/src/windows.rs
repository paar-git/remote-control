//! Taking reserved chords on Windows, with a low-level keyboard hook.
//!
//! # Why a thread with a message loop
//!
//! `WH_KEYBOARD_LL` delivers its callback on the thread that installed the hook, and
//! only while that thread is pumping messages. The Tauri main thread has its own loop
//! and its own latency budget, and Windows silently uninstalls a low-level hook whose
//! callback takes longer than `LowLevelHooksTimeout`. So the hook gets a thread of its
//! own that does nothing else, and the callback does nothing but decide and forward.
//!
//! # Why leaking one is survivable, and still guarded against
//!
//! Windows removes a process's hooks when the process exits, so a crash cannot leave
//! the operator permanently unable to switch windows. That is the backstop, not the
//! plan: [`WindowsKeyGrab`] releases in `Drop`, and the thread unhooks before it
//! returns, so an ordinary panic or early return releases too.
//!
//! # What the callback may not do
//!
//! It runs inside the OS's input path, ahead of every other application on the machine.
//! It must not allocate where it can be helped, must not block, and must never call
//! back into anything that might take a lock the main thread holds. It reads two atomics
//! and pushes onto a channel.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};

use rc_protocol::{Modifiers, PhysicalKey};

use rc_input::grab::{Disposition, GrabError, KeyGrab, disposition};
use rc_input::intent::{Chord, HostOs};

use windows::Win32::Foundation::{LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, VIRTUAL_KEY, VK_CONTROL, VK_LWIN, VK_MENU, VK_RWIN, VK_SHIFT,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, DispatchMessageW, GetMessageW, HHOOK, KBDLLHOOKSTRUCT, MSG, PostThreadMessageW,
    SetWindowsHookExW, TranslateMessage, UnhookWindowsHookEx, WH_KEYBOARD_LL, WM_KEYDOWN, WM_QUIT,
    WM_SYSKEYDOWN,
};

/// Whether the hook should currently swallow anything.
///
/// Global because the callback is a bare `extern "system"` function with nowhere to put
/// state. An atomic rather than a lock: the callback runs in the OS input path, where
/// blocking on a lock the main thread holds would stall every keystroke on the machine.
static GRABBING: AtomicBool = AtomicBool::new(false);

/// Where grabbed chords go. Set once, before any hook is installed.
static SINK: OnceLock<std::sync::mpsc::Sender<Chord>> = OnceLock::new();

/// The hook thread's id, so it can be told to quit. Zero when no thread is running.
static HOOK_THREAD: AtomicIsize = AtomicIsize::new(0);

/// A low-level keyboard hook that takes the chords the desktop reserves.
#[derive(Debug)]
pub struct WindowsKeyGrab {
    thread: Option<std::thread::JoinHandle<()>>,
}

impl WindowsKeyGrab {
    /// A released grab, forwarding grabbed chords to `sink`.
    ///
    /// # Errors
    /// [`GrabError::Refused`] if a grab was already created in this process: the hook
    /// state is global, and a second one would silently steal the first one's chords.
    pub fn new(sink: std::sync::mpsc::Sender<Chord>) -> Result<Self, GrabError> {
        SINK.set(sink).map_err(|_| GrabError::Refused)?;
        Ok(Self { thread: None })
    }
}

impl KeyGrab for WindowsKeyGrab {
    fn engage(&mut self) -> Result<(), GrabError> {
        if self.thread.is_some() {
            return Ok(());
        }

        let (ready, started) = std::sync::mpsc::channel::<Result<(), GrabError>>();
        let handle = std::thread::Builder::new()
            .name("keyboard-grab".to_owned())
            .spawn(move || hook_thread(&ready))
            .map_err(|_| GrabError::Refused)?;

        // Wait for the thread to say whether the hook actually installed, so a refusal
        // is reported here rather than discovered as silence later.
        match started.recv() {
            Ok(Ok(())) => {
                GRABBING.store(true, Ordering::SeqCst);
                self.thread = Some(handle);
                Ok(())
            }
            Ok(Err(err)) => Err(err),
            Err(_) => Err(GrabError::Refused),
        }
    }

    fn release(&mut self) {
        GRABBING.store(false, Ordering::SeqCst);

        let Some(handle) = self.thread.take() else {
            return;
        };

        let thread_id = HOOK_THREAD.swap(0, Ordering::SeqCst);
        if let Ok(thread_id) = u32::try_from(thread_id)
            && thread_id != 0
        {
            // SAFETY: `thread_id` was published by the hook thread itself and is only
            // cleared here, so it names that thread or nothing. `WM_QUIT` ends its
            // message loop, after which it unhooks and returns.
            unsafe {
                let _ = PostThreadMessageW(thread_id, WM_QUIT, WPARAM(0), LPARAM(0));
            }
        }

        // Joined rather than detached: the hook is not gone until the thread has run
        // its unhook, and returning earlier would report a released grab that is still
        // taking the operator's keys.
        let _ = handle.join();
    }

    fn engaged(&self) -> bool {
        self.thread.is_some()
    }
}

impl Drop for WindowsKeyGrab {
    fn drop(&mut self) {
        self.release();
    }
}

/// Install the hook, pump messages until told to stop, then remove it.
fn hook_thread(ready: &std::sync::mpsc::Sender<Result<(), GrabError>>) {
    // SAFETY: a null module handle is what the documentation asks for with a hook
    // procedure inside this process, and `WH_KEYBOARD_LL` is a global hook so the
    // thread id is zero.
    let hook = unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_proc), None, 0) };

    let Ok(hook) = hook else {
        let _ = ready.send(Err(GrabError::Refused));
        return;
    };
    let hook: HHOOK = hook;

    // SAFETY: reading this thread's own id.
    let thread_id = unsafe { windows::Win32::System::Threading::GetCurrentThreadId() };
    // `isize` because the static must hold a sentinel zero as well as a thread id; a
    // `u32` thread id always fits, on 32- and 64-bit alike.
    HOOK_THREAD.store(isize::try_from(thread_id).unwrap_or(0), Ordering::SeqCst);
    let _ = ready.send(Ok(()));

    let mut message = MSG::default();
    // SAFETY: a standard message loop over this thread's own queue. `GetMessageW`
    // returns 0 on `WM_QUIT`, which is what `release` posts.
    unsafe {
        while GetMessageW(&raw mut message, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&raw const message);
            DispatchMessageW(&raw const message);
        }
    }

    // SAFETY: `hook` came from the matching `SetWindowsHookExW` on this thread and has
    // not been removed. This is the release the whole module promises.
    unsafe {
        let _ = UnhookWindowsHookEx(hook);
    }
}

/// The hook callback. Runs ahead of every other application on the machine.
///
/// Returning a non-zero value swallows the keystroke, which is why
/// [`super::disposition`] rather than this function decides: the rule is worth testing,
/// and it cannot be tested here.
unsafe extern "system" fn keyboard_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // Negative codes must be passed straight through, per the hook contract.
    if code < 0 || !GRABBING.load(Ordering::Relaxed) {
        // SAFETY: forwarding the arguments unchanged, which is always valid here.
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    }

    // `wparam` carries a window message here, which is always within `u32`.
    let message = u32::try_from(wparam.0).unwrap_or(0);
    let is_press = message == WM_KEYDOWN || message == WM_SYSKEYDOWN;
    // SAFETY: for a `WH_KEYBOARD_LL` hook with a non-negative code, `lparam` points to
    // a `KBDLLHOOKSTRUCT` owned by the OS for the duration of this call.
    let event = unsafe { &*(lparam.0 as *const KBDLLHOOKSTRUCT) };

    let Some(key) = reserved_key(event.vkCode) else {
        // SAFETY: as above.
        return unsafe { CallNextHookEx(None, code, wparam, lparam) };
    };

    let chord = Chord::new(key, held_modifiers());
    if disposition(chord, HostOs::Windows, true) == Disposition::Forward {
        // Only a press is forwarded: the remote end applies a reserved chord as one
        // action, and the matching release carries nothing further.
        if is_press && let Some(sink) = SINK.get() {
            let _ = sink.send(chord);
        }
        // Swallowed, so the local window manager never sees it.
        return LRESULT(1);
    }

    // SAFETY: as above.
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}

/// The [`PhysicalKey`] for a virtual-key code, for the few keys a grab cares about.
///
/// Deliberately not the whole keyboard: this runs in the OS input path on every
/// keystroke on the machine, and the only codes that can lead anywhere are the ones
/// [`super::reserved_by`] might claim.
const fn reserved_key(vk: u32) -> Option<PhysicalKey> {
    Some(match vk {
        0x09 => PhysicalKey::Tab,
        0x1B => PhysicalKey::Escape,
        0x2E => PhysicalKey::Delete,
        0x5B => PhysicalKey::MetaLeft,
        0x5C => PhysicalKey::MetaRight,
        _ => return None,
    })
}

/// Which modifiers are down right now.
fn held_modifiers() -> Modifiers {
    let mut mods = Modifiers::NONE;
    if is_down(VK_SHIFT) {
        mods = mods.with(Modifiers::SHIFT);
    }
    if is_down(VK_CONTROL) {
        mods = mods.with(Modifiers::CONTROL);
    }
    if is_down(VK_MENU) {
        mods = mods.with(Modifiers::ALT);
    }
    if is_down(VK_LWIN) || is_down(VK_RWIN) {
        mods = mods.with(Modifiers::META);
    }
    mods
}

/// Whether `key` is currently held.
fn is_down(key: VIRTUAL_KEY) -> bool {
    // SAFETY: reading global key state, valid to call from any thread.
    let state = unsafe { GetAsyncKeyState(i32::from(key.0)) };
    // The high bit means "down now"; the low bit means "pressed since last asked", which
    // is a different question and not the one being asked.
    state & (1 << 15) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_keys_a_grab_can_claim_are_recognised() {
        // This map runs on every keystroke on the machine; anything it does not need to
        // know is a cost paid in the OS input path for nothing.
        assert_eq!(reserved_key(0x09), Some(PhysicalKey::Tab));
        assert_eq!(reserved_key(0x1B), Some(PhysicalKey::Escape));
        assert_eq!(reserved_key(0x5B), Some(PhysicalKey::MetaLeft));
        assert_eq!(reserved_key(0x5C), Some(PhysicalKey::MetaRight));
        assert_eq!(reserved_key(0x2E), Some(PhysicalKey::Delete));
    }

    #[test]
    fn an_ordinary_letter_is_not_recognised_and_so_is_never_swallowed() {
        // 0x41 is VK_A. A grab that claimed it would stop the operator typing.
        assert_eq!(reserved_key(0x41), None);
        assert_eq!(reserved_key(0x20), None);
    }
}
