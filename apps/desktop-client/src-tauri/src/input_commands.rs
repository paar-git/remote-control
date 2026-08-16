//! Remote-desktop input: the client's send path.
//!
//! # Detection happens on the controller, rendering on the host
//!
//! The operator typed a chord their own machine's conventions taught them, so
//! [`classify`] recognises it against the *controller's* [`HostOs`] — never the host's.
//! The host then spells that meaning in its own native chord. Neither side models the
//! other's conventions, which is what makes all nine platform pairs three tables
//! rather than nine. See `crates/input/src/intent.rs` for the tables themselves.
//!
//! # `passthrough` is designed in now, not retrofitted
//!
//! A later task wires an operator-facing toggle to it. When set, a chord is always
//! sent as its physical key even when it is a recognised intent. `Ctrl+C` in a remote
//! terminal means SIGINT, not Copy — without this escape hatch a Windows or Linux
//! operator could never interrupt a process on a remote macOS host, because the chord
//! would be detected as `Copy` and rendered as `Cmd+C`.
//!
//! # Acknowledgements arrive out of band
//!
//! `MouseMove` and `Scroll` are never acknowledged — a round trip per sample would add
//! latency to every pointer motion for no safety gained. Discrete actions are, but not
//! synchronously with the command call: the host answers on its own schedule, and a
//! `Failed` acknowledgement (a revoked `control_input` grant, most notably) must reach
//! the operator rather than being read and dropped, since this client does not enforce
//! that permission itself. So acknowledgements are forwarded as a Tauri event, the same
//! out-of-band convention `video_commands` uses for `video://stream-ended`.

use std::sync::Arc;

use rc_input::intent::{Chord, HostOs, detect};
use rc_protocol::{
    InputAck, InputEvent, InputMessage, Intent, Modifiers, MouseButton, PhysicalKey,
};
use serde::Serialize;

use crate::AppState;
use crate::connection::{ConnectionManager, InputSink};

/// Event carrying an acknowledgement or a display-topology push from the input
/// channel, out of band from the command that triggered it.
///
/// Mirrors `video://stream-ended`: the webview cannot correlate this with a particular
/// `input_key` call by return value alone, since the host answers on its own schedule.
pub const INPUT_ACK_EVENT: &str = "input://ack";

/// Event announcing the host's current display arrangement, pushed unprompted and
/// again whenever it changes.
pub const INPUT_DISPLAYS_EVENT: &str = "input://displays";

/// Event reporting how far the host has got through the events sent to it.
///
/// Derived from [`InputAck::Applied`], which the host sends on its own schedule as a
/// watermark rather than per event. The gap between what has been issued here and what
/// the host has applied is the honest measure of input lag: a round-trip ping says the
/// *link* is healthy, which is a different question from whether the remote machine is
/// keeping up with the typing.
pub const INPUT_APPLIED_EVENT: &str = "input://applied";

/// How far the host has got through the input sent to it.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InputAppliedDto {
    /// Every event up to and including this sequence has been applied.
    pub watermark: u32,
    /// Events issued but not yet reported applied.
    pub outstanding: u32,
}

/// One acknowledgement from the host, as told to the webview.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InputAckDto {
    /// Which event this acknowledges.
    pub seq: u32,
    /// Whether the host applied it.
    pub ok: bool,
    /// Why it was refused, when `ok` is `false`. Never carries raw error detail.
    pub reason: Option<String>,
}

/// What a key event turned into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    /// A physical key, reproduced exactly on the host.
    Key(PhysicalKey),
    /// A semantic action, spelled by the host in its own chord.
    Intent(Intent),
    /// Nothing: this build does not carry that key.
    Nothing,
}

/// Decide what a key event should become.
///
/// Detection uses the *controller's* table, because the operator typed the chord their
/// own machine's conventions taught them. The host then renders that meaning in its own
/// chord. Neither side models the other, which is what makes all nine platform pairs
/// three tables rather than nine.
fn classify(code: &str, modifiers: Modifiers, passthrough: bool, os: HostOs) -> Sent {
    let Some(key) = PhysicalKey::from_w3c_code(code) else {
        return Sent::Nothing;
    };
    if passthrough {
        return Sent::Key(key);
    }
    match detect(Chord::new(key, modifiers), os) {
        Some(intent) => Sent::Intent(intent),
        None => Sent::Key(key),
    }
}

/// What `input_key` actually sent, so the interface can show the operator when a
/// chord was translated rather than typed literally.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeySent {
    /// The intent name (e.g. `"copy"`), when the chord was recognised and
    /// `passthrough` was off. `None` when the physical key was sent, or when this
    /// build does not carry the key at all.
    pub as_intent: Option<String>,
}

/// Move the pointer to `(x, y)`, normalised 0.0–1.0 of `display`.
///
/// Unacknowledged: see the module docs.
///
/// # Errors
/// A string safe to show the operator: nothing is connected, or the transport failed.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn input_pointer_move(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
    x: f32,
    y: f32,
    display: u8,
) -> Result<(), String> {
    let manager = connection(&state)?;
    let seq = manager.next_input_seq();
    manager
        .send_input(
            &InputEvent::MouseMove { x, y, display, seq },
            input_event_sink(app, &manager),
        )
        .await
        .map_err(|err| describe(&err))
}

/// Press or release a mouse button.
///
/// # Errors
/// A string safe to show the operator: nothing is connected, `button` is not a
/// recognised name, or the transport failed.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn input_pointer_button(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
    button: String,
    down: bool,
) -> Result<(), String> {
    let manager = connection(&state)?;
    let button = parse_button(&button)?;
    let seq = manager.next_input_seq();
    let event = if down {
        InputEvent::MouseDown { button, seq }
    } else {
        InputEvent::MouseUp { button, seq }
    };
    manager
        .send_input(&event, input_event_sink(app, &manager))
        .await
        .map_err(|err| describe(&err))
}

/// Scroll by a wheel delta.
///
/// Unacknowledged: see the module docs.
///
/// # Errors
/// A string safe to show the operator: nothing is connected, or the transport failed.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn input_scroll(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
    delta_x: f32,
    delta_y: f32,
) -> Result<(), String> {
    let manager = connection(&state)?;
    let seq = manager.next_input_seq();
    manager
        .send_input(
            &InputEvent::Scroll {
                delta_x,
                delta_y,
                seq,
            },
            input_event_sink(app, &manager),
        )
        .await
        .map_err(|err| describe(&err))
}

/// Press or release a key, identified by its W3C `KeyboardEvent.code`.
///
/// The load-bearing decision: this is where a chord becomes either a physical key or
/// an intent. With `passthrough` true it is *always* physical.
///
/// Only the press of a recognised chord sends anything for that chord's release —
/// once an intent has been dispatched to the host, its own release carries nothing
/// further to deliver, since the host applies an intent as one discrete action rather
/// than a press held down.
///
/// # Errors
/// A string safe to show the operator: nothing is connected, or the transport failed.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn input_key(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
    code: String,
    down: bool,
    repeat: bool,
    modifiers: u8,
    passthrough: bool,
) -> Result<KeySent, String> {
    let manager = connection(&state)?;
    // Every desktop target this client ships for has a table; a build with none is not
    // a supported target, so falling back to Windows costs nothing real.
    let os = HostOs::current().unwrap_or(HostOs::Windows);
    let sent = classify(
        &code,
        Modifiers::from_bits_truncate(modifiers),
        passthrough,
        os,
    );

    let (event, as_intent) = match sent {
        Sent::Key(key) => {
            let seq = manager.next_input_seq();
            let event = if down {
                InputEvent::KeyDown { key, repeat, seq }
            } else {
                InputEvent::KeyUp { key, seq }
            };
            (Some(event), None)
        }
        Sent::Intent(intent) => {
            let event = down.then(|| InputEvent::Intent {
                intent,
                seq: manager.next_input_seq(),
            });
            (event, Some(intent_name(intent)))
        }
        Sent::Nothing => (None, None),
    };

    if let Some(event) = event {
        manager
            .send_input(&event, input_event_sink(app, &manager))
            .await
            .map_err(|err| describe(&err))?;
    }

    Ok(KeySent { as_intent })
}

/// Parse a wire button name (`"left"`, `"right"`, …) into a [`MouseButton`].
fn parse_button(button: &str) -> Result<MouseButton, String> {
    serde_json::from_value(serde_json::Value::String(button.to_owned()))
        .map_err(|_| format!("unrecognised pointer button: {button}"))
}

/// An [`Intent`] as the `snake_case` string it already serialises to on the wire,
/// rather than a second hand-maintained list of names.
fn intent_name(intent: Intent) -> String {
    serde_json::to_value(intent)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

/// How many issued events the host has not yet reported applying.
///
/// Saturating on purpose: the watermark is the host's own count, and a host claiming to
/// have applied more than this connection ever issued means the two disagree. Reporting
/// a wrapped-around lag of four billion would be worse than reporting none.
const fn outstanding_after(issued: u32, watermark: u32) -> u32 {
    issued.saturating_sub(watermark)
}

/// A sink that forwards acknowledgements and display topology to the webview as
/// events, following the out-of-band convention documented at the top of this module.
fn input_event_sink(app: tauri::AppHandle, manager: &Arc<ConnectionManager>) -> InputSink {
    // Weak, deliberately: the sink outlives this call inside the channel reader task,
    // and an owning handle would keep the manager alive for as long as that task runs.
    let manager = Arc::downgrade(manager);

    Arc::new(move |message: InputMessage| {
        use tauri::Emitter as _;

        match message {
            InputMessage::Ack(InputAck::Ok { seq }) => {
                let _ = app.emit(
                    INPUT_ACK_EVENT,
                    InputAckDto {
                        seq,
                        ok: true,
                        reason: None,
                    },
                );
            }
            InputMessage::Ack(InputAck::Failed { seq, reason }) => {
                let _ = app.emit(
                    INPUT_ACK_EVENT,
                    InputAckDto {
                        seq,
                        ok: false,
                        reason: Some(reason.describe().to_owned()),
                    },
                );
            }
            InputMessage::Ack(InputAck::Applied { watermark }) => {
                // Saturating: the watermark is the host's count, and a host that has
                // applied more than this connection issued means the two disagree.
                // Reporting a wrapped-around lag would be worse than reporting none.
                let outstanding = manager.upgrade().map_or(0, |live| {
                    outstanding_after(live.input_seq_issued(), watermark)
                });
                let _ = app.emit(
                    INPUT_APPLIED_EVENT,
                    InputAppliedDto {
                        watermark,
                        outstanding,
                    },
                );
            }
            InputMessage::Displays { displays } => {
                let _ = app.emit(
                    INPUT_DISPLAYS_EVENT,
                    displays
                        .into_iter()
                        .map(crate::video_commands::DisplayInfoDto::from)
                        .collect::<Vec<_>>(),
                );
            }
            // A variant a newer agent knows and this build does not; ignored the same
            // way `read_frames_inner` ignores an unrecognised video message.
            _ => {}
        }
    })
}

/// The connection manager, or a message saying nothing is connected.
fn connection(state: &AppState) -> Result<Arc<ConnectionManager>, String> {
    state
        .connection
        .as_ref()
        .map(Arc::clone)
        .ok_or_else(|| "Connect to a server first.".to_owned())
}

/// Turn a transport failure into a sentence safe to show the operator.
fn describe(err: &rc_transport::TransportError) -> String {
    crate::commands::CommandError::from_transport(err).message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_known_chord_travels_as_an_intent_not_as_keys() {
        // The whole point of the layer: the controller says what it *meant*, and the
        // host spells it however that OS spells it.
        let sent = classify("KeyC", Modifiers::CONTROL, false, HostOs::Windows);
        assert_eq!(sent, Sent::Intent(Intent::Copy));
    }

    #[test]
    fn ordinary_typing_travels_as_a_physical_key() {
        // Text entry, terminals and games need the exact key, never a reinterpretation.
        let sent = classify("KeyC", Modifiers::NONE, false, HostOs::Windows);
        assert_eq!(sent, Sent::Key(PhysicalKey::KeyC));
    }

    #[test]
    fn passthrough_sends_the_literal_chord_even_when_it_is_a_known_intent() {
        // Ctrl+C in a remote terminal is SIGINT, not Copy. Without this an operator on
        // Windows or Linux could never interrupt a process on a remote macOS box,
        // because the chord would be detected as Copy and rendered as Cmd+C.
        let sent = classify("KeyC", Modifiers::CONTROL, true, HostOs::Windows);
        assert_eq!(sent, Sent::Key(PhysicalKey::KeyC));
    }

    #[test]
    fn an_unrecognised_code_is_dropped_rather_than_guessed() {
        // A key this build does not carry must not be delivered as some *other* key.
        assert_eq!(
            classify("Unidentified", Modifiers::NONE, false, HostOs::Windows),
            Sent::Nothing
        );
    }

    #[test]
    fn a_bare_modifier_is_a_physical_key_not_an_intent() {
        // Holding Ctrl on its own is a keypress; it must reach the host so the host's
        // own modifier state stays correct.
        let sent = classify("ControlLeft", Modifiers::CONTROL, false, HostOs::Windows);
        assert_eq!(sent, Sent::Key(PhysicalKey::ControlLeft));
    }

    #[test]
    fn button_names_parse_case_exactly_and_reject_the_unknown() {
        assert_eq!(parse_button("left"), Ok(MouseButton::Left));
        assert_eq!(parse_button("forward"), Ok(MouseButton::Forward));
        assert!(parse_button("stylus").is_err());
    }

    #[test]
    fn a_host_that_claims_more_than_was_sent_reports_no_lag_rather_than_wrapping() {
        // u32 subtraction underflows to ~4 billion, which would render as a session
        // billions of events behind rather than one that is simply keeping up.
        assert_eq!(outstanding_after(3, 900), 0);
    }

    #[test]
    fn outstanding_events_are_what_was_issued_beyond_the_watermark() {
        assert_eq!(outstanding_after(120, 100), 20);
        assert_eq!(outstanding_after(100, 100), 0);
    }

    #[test]
    fn an_intent_name_is_its_wire_name_not_a_debug_string() {
        assert_eq!(intent_name(Intent::Copy), "copy");
        assert_eq!(intent_name(Intent::SecureAttention), "secure_attention");
    }
}
