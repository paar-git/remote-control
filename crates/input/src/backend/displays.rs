//! Enumerating the host's monitors.
//!
//! # One shape, three operating systems
//!
//! Windows, macOS and X11 expose displays through entirely different APIs, and they
//! disagree about almost everything: whether the primary display sits at the origin,
//! whether secondary monitors get negative coordinates, whether scaling is reported per
//! monitor or per session, and how a display is identified across a reconnect.
//!
//! The `display-info` crate normalises those three into one list of rectangles in a
//! shared virtual-desktop space, which is exactly what [`DisplayTopology`] needs. What
//! this module adds on top is the part that must not vary: a **stable index** and a
//! usable **name**.
//!
//! # Why indices are assigned rather than taken
//!
//! The OS-assigned identifier is a `u32` handle that means nothing to the protocol and
//! is not comparable across platforms. The wire uses a small `u8` index instead, and it
//! has to stay put: if unplugging a monitor renumbered the others, a session viewing
//! display 2 would silently jump to a different screen.
//!
//! So displays are sorted by position — left to right, then top to bottom — and indexed
//! in that order. That is stable for a fixed arrangement, matches the order a person
//! reading the layout would use, and changes only when the arrangement itself does.

use rc_protocol::desktop::DisplayInfo;

use crate::DisplayTopology;

/// Read the host's current display arrangement.
///
/// Returns an empty topology when the platform cannot enumerate — a headless server,
/// or a Wayland session with no portal. An empty topology is a truthful answer that
/// every caller already handles; guessing a single 1920×1080 display would put the
/// pointer in the wrong place on a real machine.
#[must_use]
pub fn enumerate() -> DisplayTopology {
    let Ok(found) = display_info::DisplayInfo::all() else {
        tracing::warn!("this host could not enumerate its displays");
        return DisplayTopology::default();
    };

    if found.is_empty() {
        tracing::warn!("this host reported no displays");
        return DisplayTopology::default();
    }

    // Left to right, then top to bottom: stable for a fixed arrangement, and the order
    // a person looking at the monitors would number them.
    let mut sorted = found;
    sorted.sort_by_key(|display| (display.x, display.y));

    let displays = sorted
        .iter()
        .enumerate()
        .take(usize::from(u8::MAX))
        .map(|(position, display)| DisplayInfo {
            // Saturating rather than wrapping: a machine with 256 monitors would
            // otherwise start reusing index 0.
            index: u8::try_from(position).unwrap_or(u8::MAX),
            name: display_name(display, position),
            width: display.width,
            height: display.height,
            scale_factor: display.scale_factor,
            origin_x: display.x,
            origin_y: display.y,
            primary: display.is_primary,
            // Zero means "not reported" on some platforms; carrying it through as a
            // real refresh rate would be a lie.
            refresh_hz: refresh_hz(display.frequency),
        })
        .collect();

    DisplayTopology::new(displays)
}

/// A reported refresh rate, or `None` when the platform did not supply one.
///
/// Zero means "not reported" on some platforms, and carrying it through as a real
/// refresh rate would be a lie a display picker would then show to the operator.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "guarded above: only finite positive rates reach the cast, and no display \
              reports a rate anywhere near u32::MAX"
)]
fn refresh_hz(frequency: f32) -> Option<u32> {
    (frequency.is_finite() && frequency > 0.0).then(|| frequency.round() as u32)
}

/// A name worth showing, falling back to a positional one.
///
/// Some platforms report an empty string, and others report an opaque device path.
/// Neither is useful in a display picker, so a plain ordinal is used instead.
fn display_name(display: &display_info::DisplayInfo, position: usize) -> String {
    let reported = display.friendly_name.trim();
    if reported.is_empty() || reported.starts_with("\\\\") {
        format!("Display {}", position + 1)
    } else {
        reported.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumeration_does_not_panic_on_this_machine() {
        // The value depends on what is plugged in, so only the fact that it completes
        // is asserted here. `live_displays.rs` checks the contents.
        let _ = enumerate();
    }

    #[test]
    fn whatever_is_enumerated_is_self_consistent() {
        let topology = enumerate();
        if topology.is_empty() {
            return; // headless build machine; nothing to check
        }

        // Indices must be unique, or `get` and `resolve` would be ambiguous.
        let mut indices: Vec<u8> = topology.all().iter().map(|d| d.index).collect();
        let count = indices.len();
        indices.sort_unstable();
        indices.dedup();
        assert_eq!(indices.len(), count, "duplicate display indices");

        // Exactly one primary, and every display has real extent.
        assert!(topology.primary().is_some());
        for display in topology.all() {
            assert!(display.width > 0 && display.height > 0, "{display:?}");
            assert!(display.scale_factor > 0.0, "{display:?}");
        }
    }
}
