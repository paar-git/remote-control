//! Capture against the real display server.
//!
//! Ignored by default: these need a desktop, and a headless CI container has none.
//! Run by hand with `cargo test -p rc-video --features capture -- --ignored --nocapture`.

#![cfg(feature = "capture")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    reason = "integration tests are their own crate and do not inherit the library's               test-only allowances"
)]

use rc_video::capture::{CaptureSource as _, xcap_source::XcapSource};

#[test]
#[ignore = "needs a real display server"]
fn displays_are_enumerated_and_ordered_left_to_right() {
    let source = XcapSource::new().expect("a desktop session");
    let displays = source.displays().expect("enumerate");
    assert!(!displays.is_empty(), "a desktop has at least one display");

    for (position, display) in displays.iter().enumerate() {
        assert_eq!(
            usize::from(display.index),
            position,
            "indices must be dense and in order"
        );
        assert!(display.width > 0 && display.height > 0);
        println!(
            "display {} {:?} {}x{} at ({},{}) primary={} {:?}Hz",
            display.index,
            display.name,
            display.width,
            display.height,
            display.origin_x,
            display.origin_y,
            display.primary,
            display.refresh_hz
        );
    }

    let mut sorted = displays.clone();
    sorted.sort_by_key(|d| (d.origin_x, d.origin_y));
    let order: Vec<u8> = sorted.iter().map(|d| d.index).collect();
    let expected: Vec<u8> = (0..u8::try_from(displays.len()).expect("few displays")).collect();
    assert_eq!(order, expected, "index order must follow position");
}

#[test]
#[ignore = "needs a real display server"]
fn a_captured_frame_is_the_size_the_display_advertised() {
    let mut source = XcapSource::new().expect("a desktop session");
    let displays = source.displays().expect("enumerate");
    let first = &displays[0];

    let frame = source.grab(first.index).expect("capture");

    assert_eq!(frame.width, first.width);
    assert_eq!(frame.height, first.height);
    assert_eq!(
        frame.rgba.len(),
        (frame.width as usize) * (frame.height as usize) * 4,
        "four bytes per pixel, no padding"
    );
    assert!(
        frame.rgba.iter().any(|&b| b != 0),
        "a real desktop is not uniformly black"
    );
}
