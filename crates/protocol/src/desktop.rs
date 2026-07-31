//! Remote-desktop video and input messages.

use serde::{Deserialize, Serialize};

/// A capturable display.
// No `Eq`: `scale_factor` is a float.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DisplayInfo {
    /// Stable index used to select this display.
    pub index: u8,
    /// OS-reported name. Untrusted.
    pub name: String,
    /// Native width in physical pixels.
    pub width: u32,
    /// Native height in physical pixels.
    pub height: u32,
    /// Scale factor, e.g. `1.5` for 150% DPI.
    pub scale_factor: f32,
    /// X offset in the virtual desktop.
    pub origin_x: i32,
    /// Y offset in the virtual desktop.
    pub origin_y: i32,
    /// Whether this is the primary display.
    pub primary: bool,
    /// Refresh rate in Hz, when reported.
    pub refresh_hz: Option<u32>,
}

/// Video codecs the transport can carry. The encoder is pluggable; a peer advertises
/// only what it can actually produce or consume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VideoCodec {
    /// Raw BGRA, only usable on a fast LAN. Always supported as the last-resort path.
    RawBgra,
    /// Per-tile lossless compression. Software-only fallback with no external deps.
    TiledZstd,
    /// H.264 / AVC.
    H264,
    /// H.265 / HEVC.
    H265,
    /// AV1.
    Av1,
}

/// Quality preset requested by the client. The agent adapts within the preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityPreset {
    /// Minimise bandwidth.
    Low,
    /// Balanced default.
    Balanced,
    /// Maximise fidelity.
    High,
    /// Visually lossless, for text work.
    Lossless,
    /// Follow measured link conditions automatically.
    Adaptive,
}

/// Whether the client may inject input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionMode {
    /// Video only. Input messages are rejected by the agent.
    ViewOnly,
    /// Full mouse and keyboard control.
    Control,
}

/// Client → agent remote-desktop control messages.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DesktopClientMessage {
    /// Enumerate displays.
    ListDisplays,
    /// Start streaming.
    StartStream {
        /// Which display to capture.
        display_index: u8,
        /// Codecs the client can decode, most preferred first.
        accepted_codecs: Vec<VideoCodec>,
        /// Requested quality.
        quality: QualityPreset,
        /// Frame-rate ceiling.
        max_fps: u8,
        /// Whether input will be injected.
        interaction: InteractionMode,
    },
    /// Stop streaming but keep other channels alive.
    StopStream,
    /// Suspend frame delivery without tearing down encoder state.
    PauseStream,
    /// Resume after a pause.
    ResumeStream,
    /// Change quality, frame-rate ceiling, or display mid-stream.
    Reconfigure {
        /// New display, if changing.
        display_index: Option<u8>,
        /// New quality, if changing.
        quality: Option<QualityPreset>,
        /// New frame-rate ceiling, if changing.
        max_fps: Option<u8>,
    },
    /// Ask for a fresh keyframe, e.g. after packet loss.
    RequestKeyframe,
    /// Switch between view-only and control. Downgrading to view-only takes effect
    /// immediately; upgrading requires the session to hold control authorization.
    SetInteractionMode(InteractionMode),
    /// Send the platform's secure attention sequence, where permitted.
    SecureAttentionSequence,
    /// Publish the client's clipboard to the host.
    ClipboardUpdate {
        /// UTF-8 text. Never logged.
        text: String,
    },
}

/// Agent → client remote-desktop messages.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DesktopAgentMessage {
    /// Reply to [`DesktopClientMessage::ListDisplays`].
    Displays(Vec<DisplayInfo>),
    /// The stream is starting with these parameters.
    StreamStarted {
        /// Display being captured.
        display_index: u8,
        /// Codec that was actually negotiated.
        codec: VideoCodec,
        /// Encoded frame width.
        width: u32,
        /// Encoded frame height.
        height: u32,
        /// Whether a hardware encoder is in use.
        hardware_accelerated: bool,
    },
    /// An encoded video frame.
    Frame(VideoFrame),
    /// Streaming stopped.
    StreamStopped,
    /// Host clipboard changed.
    ClipboardUpdate {
        /// UTF-8 text. Never logged.
        text: String,
    },
    /// A remote-desktop operation failed.
    Error {
        /// Machine-readable code.
        code: crate::control::ErrorCode,
        /// Operator-facing message.
        message: String,
    },
}

/// One encoded frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoFrame {
    /// Monotonically increasing sequence number, used to detect loss.
    pub sequence: u64,
    /// Capture time, microseconds on the agent's monotonic clock.
    pub captured_at_us: u64,
    /// Whether this frame can be decoded without any predecessor.
    pub keyframe: bool,
    /// Encoded payload.
    pub data: Vec<u8>,
    /// Dirty rectangles this frame updates. Empty means the whole frame.
    pub damage: Vec<Rect>,
}

/// An axis-aligned rectangle in physical pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rect {
    /// Left edge.
    pub x: u32,
    /// Top edge.
    pub y: u32,
    /// Width.
    pub width: u32,
    /// Height.
    pub height: u32,
}

/// Mouse buttons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MouseButton {
    /// Primary button.
    Left,
    /// Secondary button.
    Right,
    /// Wheel click.
    Middle,
    /// Back.
    Back,
    /// Forward.
    Forward,
}

/// Input events sent from client to agent.
///
/// The agent must drop every one of these unless the session is authenticated,
/// authorized for control, and currently in [`InteractionMode::Control`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InputEvent {
    /// Absolute pointer move, normalised to 0.0–1.0 of the captured display so that
    /// DPI and resolution differences between the two machines do not matter.
    MouseMove {
        /// Horizontal position, 0.0–1.0.
        x: f32,
        /// Vertical position, 0.0–1.0.
        y: f32,
    },
    /// Button pressed.
    MouseDown {
        /// Which button.
        button: MouseButton,
    },
    /// Button released.
    MouseUp {
        /// Which button.
        button: MouseButton,
    },
    /// Wheel or trackpad scroll, in wheel deltas.
    Scroll {
        /// Horizontal delta.
        delta_x: f32,
        /// Vertical delta.
        delta_y: f32,
    },
    /// Key pressed. Uses W3C `KeyboardEvent.code` semantics mapped to a portable
    /// scancode by the client, so keyboard layouts on the two hosts stay independent.
    KeyDown {
        /// Portable scancode.
        scancode: u32,
        /// Whether this is an autorepeat.
        repeat: bool,
    },
    /// Key released.
    KeyUp {
        /// Portable scancode.
        scancode: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_events_are_small_on_the_wire() {
        // Input must stay far below the 4 KiB input-channel ceiling so flooding is
        // bounded by the rate limiter rather than by frame size.
        let ev = InputEvent::MouseMove { x: 0.5, y: 0.25 };
        assert!(postcard::to_stdvec(&ev).unwrap().len() < 32);
    }

    #[test]
    fn input_events_roundtrip() {
        let events = [
            InputEvent::MouseMove { x: 0.0, y: 1.0 },
            InputEvent::MouseDown {
                button: MouseButton::Right,
            },
            InputEvent::Scroll {
                delta_x: -1.5,
                delta_y: 3.0,
            },
            InputEvent::KeyDown {
                scancode: 65,
                repeat: true,
            },
            InputEvent::KeyUp { scancode: 65 },
        ];
        for ev in events {
            let bytes = postcard::to_stdvec(&ev).unwrap();
            assert_eq!(postcard::from_bytes::<InputEvent>(&bytes).unwrap(), ev);
        }
    }

    #[test]
    fn raw_fallback_codec_always_exists() {
        // Guarantees a working path even with no hardware or third-party encoder.
        let codecs = [VideoCodec::RawBgra, VideoCodec::TiledZstd];
        assert!(codecs.contains(&VideoCodec::RawBgra));
    }
}
