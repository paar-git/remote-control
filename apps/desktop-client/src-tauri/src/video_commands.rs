//! Remote-desktop video: the client's receive path.
//!
//! # Frames never go through `app.emit`
//!
//! Tauri's event system JSON-serialises its payload; at 1080p that is roughly 8 MiB of
//! base64 per frame, built on the main thread. Frames are pushed instead over a
//! [`tauri::ipc::Channel`] carrying raw bytes ([`tauri::ipc::InvokeResponseBody::Raw`]),
//! which reach the webview with no serialisation step in between.
//!
//! # Wire format into the webview
//!
//! One message per changed region, little-endian:
//!
//! ```text
//! u32 x | u32 y | u32 width | u32 height | RGBA bytes (width * height * 4)
//! ```
//!
//! No compression — zstd tiling was already undone in Rust by [`rc_video::decode::Decoder`]
//! — and no structure beyond the header, so the frontend can blit straight into
//! `putImageData` without parsing anything.
//!
//! # Self-repair
//!
//! Tiles are differential: a dropped frame leaves the framebuffer permanently wrong
//! until a full refresh arrives. Rather than wait for a human to notice a torn screen,
//! the reader task watches [`rc_video::decode::Decoder::needs_keyframe`] and asks the
//! agent for one itself.

use std::sync::Arc;

use rc_protocol::desktop::{
    DesktopAgentMessage, DesktopClientMessage, DisplayInfo, InteractionMode, QualityPreset, Rect,
    VideoCodec,
};
use rc_security::Permission;
use rc_transport::ChannelReader;
use rc_video::decode::Decoder;
use serde::Serialize;
use tauri::Emitter as _;
use tauri::ipc::{Channel, InvokeResponseBody};

use crate::AppState;

/// Header bytes before a region's pixels: x, y, width, height, each `u32` little-endian.
const REGION_HEADER: usize = 16;

/// Event announcing that a stream's frame delivery has ended, for whichever reason.
///
/// Carried out of band from the pixel channel on purpose. The pixel channel is raw
/// bytes with no room for a message, and it must stay that way — Task 11's frontend
/// parser depends on it being exactly `x | y | width | height | pixels` with nothing
/// else ever mixed in. A JSON event fired once per stream, at its end, costs nothing
/// like the per-frame cost `app.emit` would: the reason `app.emit()` is banned
/// elsewhere in this file is that JSON-serialising an 8 MiB frame on the main thread
/// stalls it, and this is one small message at the end of a stream, not a frame.
pub const STREAM_ENDED_EVENT: &str = "video://stream-ended";

/// Why a stream stopped, for the surface that was showing it.
///
/// Without this, "the agent revoked `ViewScreen`", "the operator hung up" and "the
/// network dropped" are all the same thing to the webview: the frame channel simply
/// stops. Those need different responses (an explanation, a quiet return to idle, a
/// retry), so the difference has to be said out loud.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamEnded {
    /// Machine-readable, for the interface to branch on.
    pub code: String,
    /// Operator-facing sentence. Never carries raw error detail — that goes to the
    /// log, the same rule every other command in this codebase follows.
    pub message: String,
}

/// A capturable display, as reported to the webview.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DisplayInfoDto {
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
    /// Whether this is the primary display.
    pub primary: bool,
}

impl From<DisplayInfo> for DisplayInfoDto {
    fn from(display: DisplayInfo) -> Self {
        Self {
            index: display.index,
            name: display.name,
            width: display.width,
            height: display.height,
            scale_factor: display.scale_factor,
            primary: display.primary,
        }
    }
}

/// What the agent actually started, once negotiation is done.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamStartedDto {
    /// Display being captured.
    pub display_index: u8,
    /// Codec that was negotiated, as its wire name (e.g. `"raw_rgba"`).
    pub codec: String,
    /// Frame width in physical pixels.
    pub width: u32,
    /// Frame height in physical pixels.
    pub height: u32,
    /// Whether a hardware encoder is in use on the agent's side.
    pub hardware_accelerated: bool,
}

/// List the displays the connected agent can capture.
///
/// # Errors
/// A string safe to show the operator: nothing is connected, or the agent refused.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn video_list_displays(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<Vec<DisplayInfoDto>, String> {
    let manager = connection(&state)?;
    let displays = manager.video_list_displays().await.map_err(|err| {
        tracing::warn!(%err, "could not list displays");
        describe(&err)
    })?;
    Ok(displays.into_iter().map(Into::into).collect())
}

/// Start streaming a display, decoding frames in Rust and pushing changed regions to
/// `on_frame` as they land.
///
/// # Errors
/// A string safe to show the operator: nothing is connected, the agent refused (an
/// unauthorized session is exactly the case this must not swallow), or the negotiated
/// codec is not one this build decodes.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn video_start_stream(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
    display_index: u8,
    max_fps: u8,
    on_frame: Channel<InvokeResponseBody>,
) -> Result<StreamStartedDto, String> {
    state
        .require_permission(Permission::ViewScreen)
        .map_err(|err| err.message)?;
    let manager = connection(&state)?;

    let request = DesktopClientMessage::StartStream {
        display_index,
        // Compressed first: it is the better default on a real link. Raw stays
        // available because it is the only codec guaranteed to work with no
        // hardware or third-party encoder on either side.
        accepted_codecs: vec![VideoCodec::TiledZstd, VideoCodec::RawRgba],
        quality: QualityPreset::Balanced,
        max_fps,
        // This task is the receive path only; input injection is a separate concern.
        interaction: InteractionMode::ViewOnly,
    };

    let (reply, writer, reader) = manager
        .video_start_stream(&request)
        .await
        .map_err(|err| describe(&err))?;

    let DesktopAgentMessage::StreamStarted {
        display_index,
        codec,
        width,
        height,
        hardware_accelerated,
    } = reply
    else {
        return Err("the agent did not answer with StreamStarted".to_owned());
    };

    let decoder = Decoder::new(codec, width, height)
        .map_err(|err| format!("this build cannot decode that stream: {err}"))?;

    tokio::spawn(read_frames(app, reader, writer, on_frame, decoder, width));

    Ok(StreamStartedDto {
        display_index,
        codec: codec_name(codec),
        width,
        height,
        hardware_accelerated,
    })
}

/// Stop the current stream.
///
/// # Errors
/// A string safe to show the operator: nothing is connected, or nothing is streaming.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn video_stop_stream(state: tauri::State<'_, Arc<AppState>>) -> Result<(), String> {
    let manager = connection(&state)?;
    manager
        .video_stop_stream()
        .await
        .map_err(|err| describe(&err))
}

/// Ask the agent for a fresh keyframe, e.g. after the operator notices tearing.
///
/// # Errors
/// A string safe to show the operator: nothing is connected, or nothing is streaming.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn video_request_keyframe(state: tauri::State<'_, Arc<AppState>>) -> Result<(), String> {
    let manager = connection(&state)?;
    manager
        .video_request_keyframe()
        .await
        .map_err(|err| describe(&err))
}

/// Why the frame-reading task stopped.
///
/// Kept as data rather than decided inline, so the one part of `read_frames` that is
/// actually a decision — what to tell the operator — can be tested without standing
/// up a live channel or a `tauri::AppHandle`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EndReason {
    /// The agent sent `Error` mid-stream: a revoked grant, for instance.
    AgentError {
        /// The agent's own machine-readable code, carried through unchanged.
        code: String,
        /// The agent's own operator-facing message, carried through unchanged.
        message: String,
    },
    /// The agent sent `StreamStopped`: a clean, deliberate end.
    StreamStopped,
    /// The channel closed with no `StreamStopped` first — the peer is gone, not just
    /// done streaming.
    ChannelClosed,
    /// Reading or writing the channel failed at the transport level.
    TransportFailure,
    /// A frame could not be decoded or applied.
    DecodeFailure,
}

/// What a viewer should be told when a stream ends for `reason`.
///
/// A plain function on purpose: this is the entire decision `read_frames` makes about
/// what to say, separated from the awkward-to-test business of actually reading a
/// channel, so it can be tested directly.
fn ended_because(reason: &EndReason) -> StreamEnded {
    match reason {
        EndReason::AgentError { code, message } => StreamEnded {
            code: code.clone(),
            message: message.clone(),
        },
        EndReason::StreamStopped => StreamEnded {
            code: "stream_stopped".to_owned(),
            message: "Screen sharing stopped.".to_owned(),
        },
        EndReason::ChannelClosed => StreamEnded {
            code: "channel_closed".to_owned(),
            message: "The connection to the other device was lost.".to_owned(),
        },
        EndReason::TransportFailure => StreamEnded {
            code: "transport_failure".to_owned(),
            message: "The video stream failed. Check the connection and try again.".to_owned(),
        },
        EndReason::DecodeFailure => StreamEnded {
            code: "decode_failure".to_owned(),
            message: "The video stream sent a frame that could not be decoded.".to_owned(),
        },
    }
}

/// Read frames off `reader` until the stream ends, decoding each and pushing its
/// changed regions down `on_frame`.
///
/// Runs for the life of the stream. Whatever ends it — a clean stop, a mid-stream
/// `Error`, a closed channel, a transport failure, or a frame the decoder rejects —
/// the reason is announced on [`STREAM_ENDED_EVENT`] before this returns, so the
/// surface that was showing the stream can tell those apart rather than just seeing
/// pixels stop arriving.
async fn read_frames(
    app: tauri::AppHandle,
    mut reader: ChannelReader,
    writer: Arc<tokio::sync::Mutex<rc_transport::ChannelWriter>>,
    on_frame: Channel<InvokeResponseBody>,
    mut decoder: Decoder,
    width: u32,
) {
    let reason = read_frames_inner(&mut reader, &writer, &on_frame, &mut decoder, width).await;
    if let Some(reason) = reason
        && let Err(err) = app.emit(STREAM_ENDED_EVENT, ended_because(&reason))
    {
        tracing::debug!(%err, "could not announce that the video stream ended");
    }
}

/// The read loop itself. Returns the reason it stopped, or `None` when there is
/// nobody left to tell — the webview's own end of `on_frame` is what went away.
async fn read_frames_inner(
    reader: &mut ChannelReader,
    writer: &Arc<tokio::sync::Mutex<rc_transport::ChannelWriter>>,
    on_frame: &Channel<InvokeResponseBody>,
    decoder: &mut Decoder,
    width: u32,
) -> Option<EndReason> {
    loop {
        let message = match reader.next_message::<DesktopAgentMessage>().await {
            Ok(Some(message)) => message,
            Ok(None) => {
                tracing::debug!("the video channel closed");
                return Some(EndReason::ChannelClosed);
            }
            Err(err) => {
                tracing::debug!(%err, "the video channel failed");
                return Some(EndReason::TransportFailure);
            }
        };

        match message {
            DesktopAgentMessage::Frame(frame) => {
                match decoder.apply(&frame) {
                    Ok(rects) => {
                        for rect in &rects {
                            let pixels = cut_region(decoder.framebuffer(), width, rect);
                            let region = frame_region(rect, &pixels);
                            if on_frame.send(InvokeResponseBody::Raw(region)).is_err() {
                                // The webview side is gone; nobody is left to draw for,
                                // and nobody is left to hear the event either.
                                return None;
                            }
                        }
                    }
                    Err(err) => {
                        // Not a sequence gap, so a keyframe request would not fix it —
                        // this is a peer sending damage that does not fit the frame it
                        // described. Ending the stream and saying so beats limping on
                        // with a framebuffer that may already be wrong.
                        tracing::warn!(%err, "could not apply a video frame");
                        return Some(EndReason::DecodeFailure);
                    }
                }

                if decoder.needs_keyframe() {
                    let mut guard = writer.lock().await;
                    if let Err(err) = guard.send(&DesktopClientMessage::RequestKeyframe).await {
                        tracing::debug!(%err, "could not ask for a keyframe");
                        return Some(EndReason::TransportFailure);
                    }
                }
            }
            DesktopAgentMessage::StreamStopped => {
                tracing::debug!("the agent stopped the stream");
                return Some(EndReason::StreamStopped);
            }
            DesktopAgentMessage::Error { code, message } => {
                tracing::warn!(%message, "the agent reported a video error");
                return Some(EndReason::AgentError {
                    code: agent_error_code(code),
                    message,
                });
            }
            // Displays, StreamStarted and clipboard updates are not this loop's
            // concern; StreamStarted was already consumed before it started. Any
            // future variant is ignored the same way rather than treated as fatal.
            _ => {}
        }
    }
}

/// An agent [`rc_protocol::control::ErrorCode`] as the `snake_case` string it already
/// serialises to on the wire, rather than a second hand-maintained list of names.
fn agent_error_code(code: rc_protocol::control::ErrorCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "internal".to_owned())
}

/// Copy the pixels of `rect` out of an RGBA framebuffer `width` pixels wide.
fn cut_region(framebuffer: &[u8], width: u32, rect: &Rect) -> Vec<u8> {
    let stride = (width as usize) * 4;
    let run = (rect.width as usize) * 4;
    let mut out = Vec::with_capacity(run * (rect.height as usize));
    for row in 0..rect.height {
        let start = ((rect.y + row) as usize) * stride + (rect.x as usize) * 4;
        out.extend_from_slice(&framebuffer[start..start + run]);
    }
    out
}

/// Frame one region for the webview: position, size, then pixels.
fn frame_region(rect: &Rect, pixels: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(REGION_HEADER + pixels.len());
    message.extend_from_slice(&rect.x.to_le_bytes());
    message.extend_from_slice(&rect.y.to_le_bytes());
    message.extend_from_slice(&rect.width.to_le_bytes());
    message.extend_from_slice(&rect.height.to_le_bytes());
    message.extend_from_slice(pixels);
    message
}

/// The codec's wire name, for display in the frontend.
fn codec_name(codec: VideoCodec) -> String {
    match codec {
        VideoCodec::RawRgba => "raw_rgba",
        VideoCodec::TiledZstd => "tiled_zstd",
        VideoCodec::H264 => "h264",
        VideoCodec::H265 => "h265",
        VideoCodec::Av1 => "av1",
        // The enum is `#[non_exhaustive]` from this crate's point of view; a future
        // variant is reported honestly rather than panicking.
        _ => "unknown",
    }
    .to_owned()
}

/// The connection manager, or a message saying nothing is connected.
fn connection(state: &AppState) -> Result<Arc<crate::connection::ConnectionManager>, String> {
    state
        .connection
        .as_ref()
        .map(Arc::clone)
        .ok_or_else(|| "Connect to a server first.".to_owned())
}

/// Turn a transport failure into a sentence safe to show the operator.
///
/// Deliberately not silent: an `Error` reply from the agent — including one caused by a
/// session that lacks `ViewScreen` — must reach the caller rather than being swallowed,
/// since this client does not enforce that permission itself.
fn describe(err: &rc_transport::TransportError) -> String {
    crate::commands::CommandError::from_transport(err).message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_region_is_framed_with_its_position_then_its_pixels() {
        // The frontend blits straight from this, so the header has to be exact.
        let rect = Rect {
            x: 64,
            y: 128,
            width: 2,
            height: 1,
        };
        let pixels = [1u8, 2, 3, 4, 5, 6, 7, 8];

        let message = frame_region(&rect, &pixels);

        assert_eq!(&message[0..4], &64u32.to_le_bytes());
        assert_eq!(&message[4..8], &128u32.to_le_bytes());
        assert_eq!(&message[8..12], &2u32.to_le_bytes());
        assert_eq!(&message[12..16], &1u32.to_le_bytes());
        assert_eq!(&message[16..], &pixels);
        assert_eq!(message.len(), 16 + pixels.len());
    }

    #[test]
    fn regions_are_cut_from_the_framebuffer_at_the_right_offsets() {
        // Getting the stride wrong here shears the image, which looks like a codec
        // bug and is miserable to trace back to an arithmetic slip.
        let width = 4u32;
        let framebuffer: Vec<u8> = (0..(4 * 2 * 4))
            .map(|i: i32| u8::try_from(i).unwrap())
            .collect();
        let rect = Rect {
            x: 2,
            y: 1,
            width: 2,
            height: 1,
        };

        let cut = cut_region(&framebuffer, width, &rect);

        // Row 1 starts at 4 px * 4 B = 16; column 2 adds 8.
        assert_eq!(cut, framebuffer[24..32]);
    }

    #[test]
    fn a_mid_stream_agent_error_is_announced_with_the_agents_own_code() {
        // The finding this guards: an `Error` after streaming has started must reach
        // the surface showing the stream, carrying what the agent actually said —
        // not be logged and left as silence indistinguishable from a dead network.
        let reason = EndReason::AgentError {
            code: "permission_denied".to_owned(),
            message: "ViewScreen was revoked.".to_owned(),
        };

        let ended = ended_because(&reason);

        assert_eq!(ended.code, "permission_denied");
        assert_eq!(ended.message, "ViewScreen was revoked.");
    }

    #[test]
    fn every_termination_reason_gets_its_own_code() {
        // Distinct codes are the entire point: without them the interface cannot
        // tell "the agent hung up" apart from "the network died" apart from "the
        // decoder choked", even though the operator needs a different response to
        // each.
        let reasons = [
            EndReason::AgentError {
                code: "forbidden".to_owned(),
                message: "denied".to_owned(),
            },
            EndReason::StreamStopped,
            EndReason::ChannelClosed,
            EndReason::TransportFailure,
            EndReason::DecodeFailure,
        ];

        let codes: Vec<String> = reasons.iter().map(|r| ended_because(r).code).collect();
        let mut unique = codes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            codes.len(),
            "two reasons share a code: {codes:?}"
        );
    }

    #[test]
    fn an_agent_error_code_serialises_to_its_wire_name_rather_than_a_debug_string() {
        assert_eq!(
            agent_error_code(rc_protocol::control::ErrorCode::PermissionDenied),
            "permission_denied"
        );
        assert_eq!(
            agent_error_code(rc_protocol::control::ErrorCode::Forbidden),
            "forbidden"
        );
    }

    #[test]
    fn every_codec_reports_a_name_rather_than_panicking() {
        for codec in [
            VideoCodec::RawRgba,
            VideoCodec::TiledZstd,
            VideoCodec::H264,
            VideoCodec::H265,
            VideoCodec::Av1,
        ] {
            assert!(!codec_name(codec).is_empty());
        }
    }
}
