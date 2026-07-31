//! Tauri build script.
//!
//! Generates the capability schemas and embeds the application context (icons,
//! configuration, permissions) that `tauri::generate_context!` expands at compile
//! time.

fn main() {
    tauri_build::build();
}
