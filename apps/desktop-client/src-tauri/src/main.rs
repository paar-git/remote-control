//! Desktop client executable.
//!
//! A thin launcher: everything lives in the `rc_desktop_client_lib` library so that
//! the backend can be unit-tested without starting a webview.

// Suppress the extra console window on Windows release builds. The client is a GUI
// application; in debug builds the console is kept so logs stay visible.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    rc_desktop_client_lib::run();
}
