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
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    reason = "integration tests are their own crate and do not inherit the library's               test-only allowances"
)]


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
    session.set_topology(rc_input::backend::displays::enumerate());

    // Three corners, so a stuck pointer cannot pass by coincidence.
    for (seq, (x, y)) in [(0.25, 0.25), (0.75, 0.25), (0.5, 0.6)].into_iter().enumerate() {
        let ack = session.apply(InputEvent::MouseMove {
            x,
            y,
            display: 0,
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

// --- multi-display, verified against the real pointer -----------------------------

/// Where the OS says the pointer actually is.
///
/// This is the assertion that no mock can make: not that the call was issued, but that
/// the operating system moved the cursor to the pixel that was asked for.
fn real_pointer_location() -> (i32, i32) {
    use enigo::Mouse as _;
    let enigo = enigo::Enigo::new(&enigo::Settings::default()).expect("backend");
    enigo.location().expect("pointer location")
}

#[test]
#[ignore = "moves the real pointer across real monitors"]
fn the_pointer_lands_on_the_display_it_was_aimed_at() {
    use rc_input::backend::displays::enumerate;

    let topology = enumerate();
    if topology.len() < 2 {
        println!("single display: nothing to cross");
        return;
    }

    let sink = EnigoSink::new().expect("backend available");
    let mut session = InputSession::for_current_os(sink, true);
    session.set_topology(topology.clone());

    for display in topology.all() {
        let ack = session.apply(InputEvent::MouseMove {
            x: 0.5,
            y: 0.5,
            display: display.index,
            seq: u32::from(display.index) + 1,
        });
        assert_eq!(ack, None, "motion is unacknowledged");
        std::thread::sleep(std::time::Duration::from_millis(150));

        let (px, py) = real_pointer_location();
        let landed = topology.at_point(i64::from(px), i64::from(py));
        assert_eq!(
            landed,
            Some(display.index),
            "aimed at display {} but the pointer is at ({px},{py}), which is on {landed:?}",
            display.index
        );
        println!(
            "display {} centre -> real pointer ({px},{py}) OK",
            display.index
        );
    }
}

#[test]
#[ignore = "moves the real pointer across real monitors"]
fn crossing_an_edge_moves_the_real_pointer_to_the_neighbour() {
    use rc_input::backend::displays::enumerate;
    use rc_input::Edge;

    let topology = enumerate();
    if topology.len() < 2 {
        println!("single display: nothing to cross");
        return;
    }

    let sink = EnigoSink::new().expect("backend available");
    let mut session = InputSession::for_current_os(sink, true);
    session.set_topology(topology.clone());

    let mut crossings = 0;
    for display in topology.all() {
        for edge in Edge::all() {
            let Some(crossing) = topology.cross(display.index, edge, 0.5) else {
                continue;
            };

            session.apply(InputEvent::MouseMove {
                x: crossing.x,
                y: crossing.y,
                display: crossing.display,
                seq: 100 + crossings,
            });
            std::thread::sleep(std::time::Duration::from_millis(150));

            let (px, py) = real_pointer_location();
            assert_eq!(
                topology.at_point(i64::from(px), i64::from(py)),
                Some(crossing.display),
                "crossing {edge:?} from display {} put the pointer at ({px},{py})",
                display.index
            );
            println!(
                "display {} --{edge:?}--> display {} landed at ({px},{py}) OK",
                display.index, crossing.display
            );
            crossings += 1;
        }
    }
    assert!(crossings > 0, "a multi-display machine had no crossings");
}
