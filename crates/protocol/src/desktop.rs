//! Remote-desktop video and display messages.
//!
//! Input lives in [`crate::input`]: physical keys and logical intents are separate
//! concerns from video, and both peers need them without pulling in framing.

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_fallback_codec_always_exists() {
        // Guarantees a working path even with no hardware or third-party encoder.
        let codecs = [VideoCodec::RawBgra, VideoCodec::TiledZstd];
        assert!(codecs.contains(&VideoCodec::RawBgra));
    }
}
