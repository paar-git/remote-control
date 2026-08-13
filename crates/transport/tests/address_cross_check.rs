//! The table the interface's address parser must agree with.
//!
//! `apps/desktop-client/src/address.ts` re-implements [`PeerAddress::from_str`] so a
//! typo is reported under the field rather than surfacing seconds later as a connection
//! failure. That duplication is deliberate and documented on both sides, but a second
//! implementation is only safe while the two agree.
//!
//! This file is the Rust half of that agreement: every case below is asserted verbatim
//! in `address.test.ts`. Changing one side's expectation without the other is what this
//! catches.
//!
//! The direction that matters is the interface being *stricter* than this. The backend
//! re-parses everything, so a lenient interface is merely untidy; a strict one refuses
//! an address that would have worked, and the user has no way around it.

// Integration tests assert against known-good values, so `unwrap` and `panic` are the
// clearest way to fail.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rc_transport::PeerAddress;

/// Parse and render, or `None` if it was refused.
fn canonical(input: &str) -> Option<String> {
    input.parse::<PeerAddress>().ok().map(|a| a.to_string())
}

#[test]
fn accepted_addresses_render_the_way_the_interface_expects() {
    for (input, expected) in [
        ("192.168.1.77", "192.168.1.77:7443"),
        ("192.168.1.77:9000", "192.168.1.77:9000"),
        ("[fe80::1]:9000", "[fe80::1]:9000"),
        ("work-laptop.local", "work-laptop.local:7443"),
        ("  192.168.1.77  ", "192.168.1.77:7443"),
        // Unbracketed and ambiguous: the whole string is the host, and rendering it
        // back adds the brackets that were missing. Not `fe80::1` on port 9000.
        ("fe80::1:9000", "[fe80::1:9000]:7443"),
        // Case is preserved rather than normalised. If one side lowercased and the
        // other did not, the same machine would key two rows in the recent list.
        ("WORK-Laptop.local", "WORK-Laptop.local:7443"),
    ] {
        assert_eq!(
            canonical(input).as_deref(),
            Some(expected),
            "input {input:?}"
        );
    }
}

#[test]
fn refused_addresses_are_refused_on_both_sides() {
    for input in [
        "",
        "https://192.168.1.77",
        // Zero means "any free port" to the operating system, so it is never a port to
        // dial.
        "192.168.1.77:0",
        "192.168.1.77:70000",
        // Brackets mean IPv6 specifically, not "a host, generously".
        "[192.168.1.77]:9000",
        "[fe80::1:9000",
        ":9000",
        "[]:9000",
        "192.168.1.77:",
        "192.168.1.77:https",
        "192.168.1.77/admin",
        "192.168.1.77?x=1",
        "work laptop",
    ] {
        assert_eq!(canonical(input), None, "input {input:?} must be refused");
    }
}

#[test]
fn the_length_limit_is_the_database_column_s_limit() {
    // 255 characters, matching the CHECK on `recent_connections.address`. An address
    // accepted here and rejected on save would fail after the connection succeeded.
    let fits = format!("{}.local", "a".repeat(249));
    let does_not = format!("{}.local", "a".repeat(250));

    assert_eq!(fits.len(), 255);
    assert!(
        canonical(&fits).is_some(),
        "255 characters must be accepted"
    );
    assert!(
        canonical(&does_not).is_none(),
        "256 characters must be refused"
    );
}
