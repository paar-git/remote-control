//! Real pseudo-terminal sessions.
//!
//! ConPTY on Windows, `openpty` on Unix, through `portable-pty`. There is no simulated
//! shell anywhere in this crate: output comes from a real child process reading a real
//! terminal device, which is why ANSI colours, line editing, interactive prompts and
//! full-screen programs all work without special handling.
//!
//! # A PTY is one stream, not three
//!
//! A pseudo-terminal merges stdout and stderr by design — that is what makes it a
//! terminal rather than a pipe. [`rc_protocol::terminal::TerminalAgentMessage::Output`]
//! therefore carries one byte stream, and the client renders it as a terminal does.
//! Splitting them would require pipes, which would break every interactive program.
//!
//! # What this crate does not decide
//!
//! Authorization. A session reaches [`TerminalSession::spawn`] only after the caller has
//! checked the capability against the *live* connection, and elevation is a separate
//! decision made above this layer. This crate resolves a shell, spawns it, and moves
//! bytes.
//!
//! # Bounds
//!
//! Sessions per connection are capped, output is read in bounded chunks, and a session
//! that nobody reads applies backpressure rather than buffering without limit. A shell
//! printing an infinite stream must not be able to exhaust the agent's memory.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod error;
pub mod session;
pub mod shell;

pub use error::{Result, TerminalError};
pub use session::{OUTPUT_CHUNK_BYTES, TerminalRegistry, TerminalSession};
pub use shell::{ResolvedShell, resolve_shell};
