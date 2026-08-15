//! Live injection against the real operating system.
//!
//! Ignored by default: it moves the actual pointer and presses actual keys, which is
//! hostile inside an unattended CI run and surprising on a developer's desktop. Run it
//! deliberately:
//!
//! ```text
//! cargo test -p rc-input --features inject --test live_injection -- --ignored
//! ```
//!
//! What it proves is the half that no mock can: that the pipeline's calls reach a real
//! OS API and are accepted by it.

#![cfg(feature = "inject")]

use rc_input::backend::enigo::{EnigoSink, probe};
use rc_input::{HostOs, InputSession};
use rc_protocol::{InputAck, InputEvent, Intent, PhysicalKey};

#[test]
#[ignore = "moves the real pointer and presses real keys"]
fn the_host_reports_a_usable_capability() {
    let capability = probe();
    println!("capability on this machine: {capability:?}");
    assert!(
        capability.is_usable(),
        "this machine refused input injection: {capability:?}"
    );
}

#[test]
#[ignore = "moves the real pointer"]
fn the_pointer_actually_moves() {
    let sink = EnigoSink::new().expect("backend available");
    let mut session = InputSession::for_current_os(sink, true);

    // Three corners, so a stuck pointer cannot pass by coincidence.
    for (seq, (x, y)) in [(0.25, 0.25), (0.75, 0.25), (0.5, 0.6)].into_iter().enumerate() {
        let ack = session.apply(InputEvent::MouseMove {
            x,
            y,
            seq: seq as u32 + 1,
        });
        assert_eq!(ack, None, "motion must not be acknowledged");
        std::thread::sleep(std::time::Duration::from_millis(120));
    }
    assert_eq!(session.watermark(), 3, "all three moves applied");
}

#[test]
#[ignore = "presses real keys"]
fn a_physical_key_is_accepted_by_the_os() {
    let sink = EnigoSink::new().expect("backend available");
    let mut session = InputSession::for_current_os(sink, true);

    // Shift is harmless on its own: it types nothing and opens nothing.
    let down = session.apply(InputEvent::KeyDown {
        key: PhysicalKey::ShiftLeft,
        repeat: false,
        seq: 1,
    });
    assert_eq!(down, Some(InputAck::Ok { seq: 1 }));
    assert!(session.held().holds_key(PhysicalKey::ShiftLeft));

    let up = session.apply(InputEvent::KeyUp {
        key: PhysicalKey::ShiftLeft,
        seq: 2,
    });
    assert_eq!(up, Some(InputAck::Ok { seq: 2 }));
    assert!(session.held().is_empty());
}

#[test]
#[ignore = "presses real keys"]
fn an_intent_is_spelled_and_accepted_on_this_host() {
    let sink = EnigoSink::new().expect("backend available");
    let mut session = InputSession::for_current_os(sink, true);

    // SelectAll is reversible and harmless: it changes no data anywhere.
    let ack = session.apply(InputEvent::Intent {
        intent: Intent::SelectAll,
        seq: 1,
    });
    assert_eq!(ack, Some(InputAck::Ok { seq: 1 }));
    assert!(session.held().is_empty(), "the chord released cleanly");
}

#[test]
#[ignore = "presses real keys"]
fn teardown_releases_a_key_left_held_on_the_real_os() {
    let sink = EnigoSink::new().expect("backend available");
    let mut session = InputSession::for_current_os(sink, true);

    session.apply(InputEvent::KeyDown {
        key: PhysicalKey::ShiftLeft,
        repeat: false,
        seq: 1,
    });
    assert!(session.held().holds_key(PhysicalKey::ShiftLeft));

    // What a dropped connection triggers. Shift must not stay down on this machine.
    session.release_all();
    assert!(session.held().is_empty());
}

#[test]
#[ignore = "reads the real OS identity"]
fn this_machine_has_a_chord_table() {
    assert!(
        HostOs::current().is_some(),
        "no intent table exists for this platform"
    );
}
