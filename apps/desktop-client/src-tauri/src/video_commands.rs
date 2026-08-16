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
use tauri::ipc::{Channel, InvokeResponseBody};

use crate::AppState;

/// Header bytes before a region's pixels: x, y, width, height, each `u32` little-endian.
const REGION_HEADER: usize = 16;

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

    tokio::spawn(read_frames(reader, writer, on_frame, decoder, width));

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

/// Read frames off `reader` until the stream ends, decoding each and pushing its
/// changed regions down `on_frame`.
///
/// Runs for the life of the stream. Ends on `StreamStopped`, on the channel closing, or
/// on the webview side of `on_frame` going away — there is nobody left to hand frames
/// to in any of those cases.
async fn read_frames(
    mut reader: ChannelReader,
    writer: Arc<tokio::sync::Mutex<rc_transport::ChannelWriter>>,
    on_frame: Channel<InvokeResponseBody>,
    mut decoder: Decoder,
    width: u32,
) {
    loop {
        let message = match reader.next_message::<DesktopAgentMessage>().await {
            Ok(Some(message)) => message,
            Ok(None) => {
                tracing::debug!("the video channel closed");
                return;
            }
            Err(err) => {
                tracing::debug!(%err, "the video channel failed");
                return;
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
                                // The webview side is gone; nobody is left to draw for.
                                return;
                            }
                        }
                    }
                    Err(err) => {
                        tracing::warn!(%err, "could not apply a video frame");
                    }
                }

                if decoder.needs_keyframe() {
                    let mut guard = writer.lock().await;
                    if let Err(err) = guard.send(&DesktopClientMessage::RequestKeyframe).await {
                        tracing::debug!(%err, "could not ask for a keyframe");
                        return;
                    }
                }
            }
            DesktopAgentMessage::StreamStopped => {
                tracing::debug!("the agent stopped the stream");
                return;
            }
            DesktopAgentMessage::Error { message, .. } => {
                tracing::warn!(%message, "the agent reported a video error");
                return;
            }
            // Displays, StreamStarted and clipboard updates are not this loop's
            // concern; StreamStarted was already consumed before it started. Any
            // future variant is ignored the same way rather than treated as fatal.
            _ => {}
        }
    }
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
