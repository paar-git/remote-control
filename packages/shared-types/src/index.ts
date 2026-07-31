/**
 * `@rc/shared-types` — the TypeScript mirror of the Rust `rc-protocol` crate.
 *
 * Anything crossing the Tauri IPC boundary is parsed through a schema defined here.
 * The Rust side is the authority on the protocol; this package exists so the UI can
 * validate rather than assume, and so protocol changes surface as type errors.
 */

export * from './primitives.js';
export * from './connection.js';
export * from './devices.js';
