//! Capture through `xcap`.
//!
//! # What this backend will and will not claim
//!
//! xcap supports Windows, macOS and X11, and has no Wayland path. A Wayland session
//! therefore gets a refusal naming Wayland rather than a stream of black frames, which
//! is the same choice the input backend makes there.
//!
//! Every xcap accessor returns a `Result`, including the ones that read like plain
//! properties, so a monitor that fails to describe itself is skipped rather than
//! reported with invented dimensions.

use rc_protocol::desktop::DisplayInfo;

use super::{CaptureSource, CapturedFrame};
use crate::{Result, VideoError};

/// Capture backed by the host's display server.
#[derive(Debug)]
pub struct XcapSource {
    _private: (),
}

impl XcapSource {
    /// Open the display server.
    ///
    /// # Errors
    /// If no display server is reachable, or the session is Wayland, which xcap cannot
    /// capture.
    pub fn new() -> Result<Self> {
        if is_wayland() {
            return Err(VideoError::Unsupported(
                "Wayland has no screen capture path in this build",
            ));
        }
        // Prove a display server answers now, rather than at the first frame.
        xcap::Monitor::all().map_err(|err| VideoError::Capture(err.to_string()))?;
        Ok(Self { _private: () })
    }

    /// Monitors, ordered left-to-right then top-to-bottom.
    ///
    /// The ordering is what makes the index stable: unplugging one monitor must not
    /// renumber the others and silently move the session to a different screen.
    fn ordered() -> Result<Vec<xcap::Monitor>> {
        let mut monitors =
            xcap::Monitor::all().map_err(|err| VideoError::Capture(err.to_string()))?;
        monitors
            .retain(|m| m.x().is_ok() && m.y().is_ok() && m.width().is_ok() && m.height().is_ok());
        monitors.sort_by_key(|m| (m.x().unwrap_or(0), m.y().unwrap_or(0)));
        Ok(monitors)
    }
}

impl CaptureSource for XcapSource {
    fn displays(&self) -> Result<Vec<DisplayInfo>> {
        let monitors = Self::ordered()?;
        let mut out = Vec::with_capacity(monitors.len());
        for (position, monitor) in monitors.iter().enumerate() {
            let Ok(index) = u8::try_from(position) else {
                break; // more than 255 displays; the protocol indexes with a u8
            };
            // Unreachable in practice: `ordered()` already retains only monitors whose
            // `width()` and `height()` both succeeded, so every index assigned below is
            // dense. Kept as a defensive guard against `ordered()`'s retain predicate
            // being loosened later without this call site being revisited — if that
            // happens, skipping (rather than assigning a bogus size) is still the
            // correct failure mode.
            let (Ok(width), Ok(height)) = (monitor.width(), monitor.height()) else {
                continue;
            };
            out.push(DisplayInfo {
                index,
                name: monitor
                    .name()
                    .unwrap_or_else(|_| format!("display {index}")),
                width,
                height,
                scale_factor: monitor.scale_factor().unwrap_or(1.0),
                origin_x: monitor.x().unwrap_or(0),
                origin_y: monitor.y().unwrap_or(0),
                primary: monitor.is_primary().unwrap_or(false),
                refresh_hz: monitor.frequency().ok().and_then(round_hz),
            });
        }
        Ok(out)
    }

    fn grab(&mut self, index: u8) -> Result<CapturedFrame> {
        let monitors = Self::ordered()?;
        let monitor = monitors
            .get(usize::from(index))
            .ok_or(VideoError::NoSuchDisplay(index))?;
        let image = monitor
            .capture_image()
            .map_err(|err| VideoError::Capture(err.to_string()))?;
        let width = image.width();
        let height = image.height();
        Ok(CapturedFrame {
            width,
            height,
            rgba: image.into_raw(),
        })
    }
}

/// Round a reported refresh rate, rejecting values that are not a sane frequency.
///
/// `frequency()` is an `f32` while `DisplayInfo::refresh_hz` is `Option<u32>`. A
/// nonsense reading becomes `None` rather than a nonsense integer: a display claiming
/// 0 Hz or NaN is a display that did not answer, and saying so is more use than
/// printing a number nobody should trust.
fn round_hz(hz: f32) -> Option<u32> {
    if !hz.is_finite() || hz <= 0.0 || hz > f32::from(u16::MAX) {
        return None;
    }
    // Bounded above by u16::MAX and below by zero, so this conversion cannot truncate
    // or wrap; the `as` cast is only to satisfy `try_from`'s signature, and the
    // subsequent `try_from` is the real (infallible-here) guard clippy asks for.
    #[allow(clippy::cast_possible_truncation)]
    let rounded = hz.round() as i64;
    // A positive-but-sub-0.5 reading (e.g. 0.3) passes the guard above but rounds to
    // zero. Zero is not a refresh rate any display has, so it means the same thing as
    // a failed reading: report it as `None`, not as `Some(0)`.
    if rounded == 0 {
        return None;
    }
    u32::try_from(rounded).ok()
}

/// Whether this looks like a Wayland session.
fn is_wayland() -> bool {
    cfg!(target_os = "linux")
        && std::env::var("XDG_SESSION_TYPE").is_ok_and(|kind| kind.eq_ignore_ascii_case("wayland"))
}

#[cfg(test)]
mod tests {
    use super::round_hz;

    #[test]
    fn an_unusable_refresh_reading_becomes_none_rather_than_zero() {
        // The field is Option<u32> precisely so "the display did not answer" is
        // expressible. Reporting 0 Hz would be inventing an answer.
        assert_eq!(round_hz(f32::NAN), None);
        assert_eq!(round_hz(0.0), None);
        assert_eq!(round_hz(-60.0), None);
        assert_eq!(
            round_hz(0.3),
            None,
            "rounds to zero, so it is not a refresh rate"
        );
        assert_eq!(round_hz(f32::INFINITY), None);
        assert_eq!(round_hz(60.0), Some(60));
        assert_eq!(round_hz(59.94), Some(60));
        assert_eq!(round_hz(119.88), Some(120));
    }
}
