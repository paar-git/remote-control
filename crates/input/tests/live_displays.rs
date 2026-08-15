//! Display enumeration against the real operating system.
//!
//! Not ignored: enumerating monitors is read-only and safe to run anywhere, including
//! CI. On a headless machine the topology is empty and the assertions below say so
//! rather than failing, so this is meaningful where there is a desktop and honest
//! where there is not.

#![cfg(feature = "inject")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    reason = "integration tests are their own crate and do not inherit the library's               test-only allowances"
)]

use rc_input::backend::displays::enumerate;
use rc_input::{DisplayTopology, Edge};

#[test]
fn this_machine_reports_a_coherent_display_arrangement() {
    let topology = enumerate();

    println!("displays found: {}", topology.len());
    for display in topology.all() {
        println!(
            "  [{}] {:>28}  {}x{}  @ ({},{})  scale {:.2}  {}Hz  {}",
            display.index,
            display.name,
            display.width,
            display.height,
            display.origin_x,
            display.origin_y,
            display.scale_factor,
            display.refresh_hz.unwrap_or(0),
            if display.primary { "PRIMARY" } else { "" },
        );
    }

    if topology.is_empty() {
        println!("no displays: headless machine, nothing further to check");
        return;
    }

    assert!(topology.primary().is_some(), "no primary display");

    // Every display must be locatable at its own centre, which exercises the same
    // bounds arithmetic the pointer uses.
    for display in topology.all() {
        let (gx, gy) = topology
            .to_global(display.index, 0.5, 0.5)
            .expect("centre of a known display");
        assert_eq!(
            topology.at_point(gx, gy),
            Some(display.index),
            "display {} did not contain its own centre",
            display.index
        );
    }
}

#[test]
fn adjacency_on_this_machine_is_symmetric() {
    let topology = enumerate();
    if topology.len() < 2 {
        println!("single display: no adjacency to check");
        return;
    }

    // If B is to the right of A, A must be to the left of B. An asymmetry would let
    // the pointer cross one way and be unable to come back.
    for display in topology.all() {
        for edge in Edge::all() {
            if let Some(neighbour) = topology.adjacent(display.index, edge) {
                let back = topology.adjacent(neighbour, edge.opposite());
                assert_eq!(
                    back,
                    Some(display.index),
                    "{} -> {neighbour} across {edge:?} did not reverse",
                    display.index
                );
            }
        }
    }
}

#[test]
fn every_crossing_on_this_machine_stays_on_screen() {
    let topology = enumerate();
    if topology.len() < 2 {
        println!("single display: no crossings to check");
        return;
    }

    for display in topology.all() {
        for edge in Edge::all() {
            for along in [0.0, 0.5, 1.0] {
                if let Some(crossing) = topology.cross(display.index, edge, along) {
                    assert!(topology.contains(crossing.display));
                    let (gx, gy) = topology
                        .to_global(crossing.display, crossing.x, crossing.y)
                        .expect("crossing lands on a known display");
                    assert_eq!(
                        topology.at_point(gx, gy),
                        Some(crossing.display),
                        "crossing {edge:?} from {} landed off screen",
                        display.index
                    );
                }
            }
        }
    }
}

#[test]
fn the_reported_virtual_desktop_encloses_every_display() {
    let topology = enumerate();
    if topology.is_empty() {
        return;
    }
    let (left, top, right, bottom) = topology.virtual_bounds().expect("displays exist");
    for display in topology.all() {
        assert!(i64::from(display.origin_x) >= left);
        assert!(i64::from(display.origin_y) >= top);
        assert!(i64::from(display.origin_x) + i64::from(display.width) <= right);
        assert!(i64::from(display.origin_y) + i64::from(display.height) <= bottom);
    }
}

#[test]
fn an_empty_topology_never_panics() {
    // The headless path, exercised explicitly rather than only when CI happens to be
    // headless.
    let empty = DisplayTopology::default();
    assert_eq!(empty.resolve(0), None);
    assert_eq!(empty.to_global(0, 0.5, 0.5), None);
    for edge in Edge::all() {
        assert_eq!(empty.cross(0, edge, 0.5), None);
    }
}
