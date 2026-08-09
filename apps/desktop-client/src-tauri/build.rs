//! Tauri build script.
//!
//! Generates the capability schemas and embeds the application context (icons,
//! configuration, permissions) that `tauri::generate_context!` expands at compile
//! time, and bakes the trusted release-metadata verification keys into the
//! binary.

use std::path::Path;

/// File holding the trusted Ed25519 release-metadata public keys.
const KEYS_FILE: &str = "release-public-keys.txt";

/// Compile-time variable read by the updater's signature policy.
const KEYS_ENV: &str = "RC_UPDATE_MANIFEST_PUBLIC_KEYS_B64";

fn main() {
    embed_release_keys();
    tauri_build::build();
}

/// Make the trusted verification keys available to `option_env!` at compile time.
///
/// Without this a release build has no trusted key, the signature policy falls
/// back to `Required` with an empty keyring, and every update check fails. An
/// explicit environment variable still wins so CI can rotate keys without
/// editing the checked-in file.
fn embed_release_keys() {
    println!("cargo:rerun-if-changed={KEYS_FILE}");
    println!("cargo:rerun-if-env-changed={KEYS_ENV}");

    if let Ok(from_env) = std::env::var(KEYS_ENV)
        && !from_env.trim().is_empty()
    {
        println!("cargo:rustc-env={KEYS_ENV}={from_env}");
        return;
    }

    let Ok(contents) = std::fs::read_to_string(Path::new(KEYS_FILE)) else {
        println!("cargo:warning={KEYS_FILE} is missing; update checks will reject all metadata");
        return;
    };
    let keys = parse_keys(&contents);
    if keys.is_empty() {
        println!("cargo:warning={KEYS_FILE} lists no keys; update checks will reject all metadata");
        return;
    }
    println!("cargo:rustc-env={KEYS_ENV}={}", keys.join(","));
}

/// Collect base64 keys, discarding comments, blank lines and stray whitespace.
fn parse_keys(contents: &str) -> Vec<&str> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .flat_map(|line| line.split(','))
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .collect()
}
