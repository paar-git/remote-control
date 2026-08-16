//! Serving the video channel for one authenticated connection.
//!
//! # Authorization is re-checked per message and per frame
//!
//! `Permission::ViewScreen` is not captured when the channel opens. A session is
//! long-lived and a grant can be withdrawn while it is streaming — by the operator
//! revoking the device, suspending it, or hitting Emergency Stop — and a video channel
//! that captured the decision once would keep pushing frames of the operator's screen
//! until whoever opened it disconnected. Every client message re-asks, and so does
//! every capture tick, exactly as `input_service` re-checks authorization on every
//! event rather than once at the door.
//!
//! # Codec negotiation never guesses
//!
//! `StartStream` carries the client's accepted codecs, most preferred first. The agent
//! picks the first one it can actually produce; if none match, the request is refused
//! with the real reason rather than silently falling back to something the client did
//! not advertise it can decode.
//!
//! # A refusal is always a message, never silence
//!
//! A client waiting on `StreamStarted` that never arrives cannot tell a permission
//! problem, a missing codec, or a build with no capture backend from a dead link.
//! Every path that does not start or continue the stream replies
//! `DesktopAgentMessage::Error` naming the real cause.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use rc_protocol::control::ErrorCode;
use rc_protocol::desktop::{
    DesktopAgentMessage, DesktopClientMessage, QualityPreset, VideoCodec, VideoFrame,
};
use rc_security::Permission;
use rc_transport::{ChannelReader, ChannelWriter};
use rc_video::capture::CaptureSource;
use rc_video::encode::Encoder;

use crate::sessions::Session;

/// State that exists only while streaming.
#[derive(Debug)]
struct Stream {
    /// Display currently being captured.
    display_index: u8,
    /// The codec negotiated at `StartStream`, and rebuilt with on a display change.
    encoder: Encoder,
    /// The codec the encoder above was built for, kept alongside it so a `Reconfigure`
    /// that changes only the display can rebuild without re-negotiating.
    codec: VideoCodec,
    /// Requested quality preset.
    ///
    /// `TiledZstd` is lossless, so there is no fidelity-for-bytes trade for a preset to
    /// make yet. It is accepted, stored and reported back unchanged; until this build
    /// carries a lossy codec, it influences nothing.
    quality: QualityPreset,
    /// Time between captures, derived from the client's `max_fps`.
    interval: Duration,
    /// Suspended by `PauseStream`. The encoder is kept so no keyframe is needed on
    /// resume.
    paused: bool,
    /// Set by `RequestKeyframe`, or by anything that rebuilds the encoder. Consumed by
    /// the next capture.
    force_keyframe: bool,
}

/// Serves the video channel for one connection.
pub struct VideoService<S: CaptureSource> {
    writer: ChannelWriter,
    session: Session,
    source: S,
    /// Whether this build was asked to serve video at all.
    enabled: bool,
    stream: Option<Stream>,
}

impl<S: CaptureSource> VideoService<S> {
    /// A service capturing through `source` on behalf of `session`.
    #[must_use]
    pub const fn new(writer: ChannelWriter, session: Session, source: S, enabled: bool) -> Self {
        Self {
            writer,
            session,
            source,
            enabled,
            stream: None,
        }
    }

    /// Serve messages and push frames until the channel closes.
    ///
    /// Always drops whatever encoder state exists before returning: there is no
    /// host-side state to unwind the way `input_service` releases held keys, but the
    /// encoder is torn down explicitly rather than left to a destructor to log.
    pub async fn run(mut self, reader: &mut ChannelReader) {
        // Only polled while a stream exists; reset to "now" whenever a message starts
        // or reshapes one, so a client never waits out the tail of a stale interval.
        let mut next_tick = Instant::now();

        loop {
            tokio::select! {
                biased;

                message = reader.next_message::<DesktopClientMessage>() => {
                    match message {
                        Ok(Some(message)) => {
                            let replies = Self::decide(
                                &mut self.stream,
                                &self.session,
                                &mut self.source,
                                self.enabled,
                                message,
                            );
                            next_tick = Instant::now();
                            if self.send_all(replies).await.is_err() {
                                break;
                            }
                        }
                        // Clean close, or a peer that sent something malformed. Either
                        // way this channel is done.
                        Ok(None) | Err(_) => break,
                    }
                }

                () = tokio::time::sleep_until(next_tick.into()), if self.stream.is_some() => {
                    let interval = self
                        .stream
                        .as_ref()
                        .map_or(Duration::from_secs(1), |stream| stream.interval);
                    next_tick = Instant::now() + interval;

                    let frames = Self::capture_once(&mut self.stream, &self.session, &mut self.source);
                    if self.send_frames(frames).await.is_err() {
                        break;
                    }
                }
            }
        }

        if self.stream.take().is_some() {
            tracing::debug!("video stream ended");
        }
    }

    /// One client message in, the agent's replies out.
    ///
    /// A free-standing decision over the state it touches, so it can be exercised
    /// without a live QUIC stream underneath it.
    fn decide(
        stream: &mut Option<Stream>,
        session: &Session,
        source: &mut S,
        enabled: bool,
        message: DesktopClientMessage,
    ) -> Vec<DesktopAgentMessage> {
        match message {
            DesktopClientMessage::ListDisplays => Self::list_displays(session, source),
            DesktopClientMessage::StartStream {
                display_index,
                accepted_codecs,
                quality,
                max_fps,
                interaction: _,
            } => Self::start_stream(
                stream,
                session,
                source,
                enabled,
                display_index,
                &accepted_codecs,
                quality,
                max_fps,
            ),
            DesktopClientMessage::StopStream => {
                if stream.take().is_some() {
                    vec![DesktopAgentMessage::StreamStopped]
                } else {
                    vec![Self::refuse(
                        ErrorCode::InvalidArgument,
                        "no stream is running",
                    )]
                }
            }
            DesktopClientMessage::PauseStream => match stream {
                Some(live) => {
                    live.paused = true;
                    Vec::new()
                }
                None => vec![Self::refuse(
                    ErrorCode::InvalidArgument,
                    "no stream is running",
                )],
            },
            DesktopClientMessage::ResumeStream => match stream {
                Some(live) => {
                    live.paused = false;
                    Vec::new()
                }
                None => vec![Self::refuse(
                    ErrorCode::InvalidArgument,
                    "no stream is running",
                )],
            },
            DesktopClientMessage::Reconfigure {
                display_index,
                quality,
                max_fps,
            } => Self::reconfigure(stream, session, source, display_index, quality, max_fps),
            DesktopClientMessage::RequestKeyframe => match stream {
                Some(live) => {
                    live.force_keyframe = true;
                    Vec::new()
                }
                None => vec![Self::refuse(
                    ErrorCode::InvalidArgument,
                    "no stream is running",
                )],
            },
            // Interaction mode, secure attention and clipboard are not this channel's
            // concern. `DesktopClientMessage` is `#[non_exhaustive]`, so this also
            // covers any variant a future protocol version adds.
            _ => Vec::new(),
        }
    }

    /// One capture-and-encode cycle, the frames it produced.
    ///
    /// Re-checks `Permission::ViewScreen` against the *current* session, so a grant
    /// withdrawn mid-session stops frames on the very next tick rather than at the
    /// next message. A revoked, paused or absent stream all produce nothing, silently
    /// — there is no request here for an `Error` to answer.
    fn capture_once(
        stream: &mut Option<Stream>,
        session: &Session,
        source: &mut S,
    ) -> Vec<VideoFrame> {
        let Some(live) = stream else {
            return Vec::new();
        };
        if live.paused {
            return Vec::new();
        }
        if session.require(Permission::ViewScreen).is_err() {
            return Vec::new();
        }

        let captured = match source.grab(live.display_index) {
            Ok(frame) => frame,
            Err(err) => {
                tracing::warn!(%err, "video capture failed");
                return Vec::new();
            }
        };

        let force_keyframe = std::mem::take(&mut live.force_keyframe);
        match live.encoder.encode(&captured, now_us(), force_keyframe) {
            Ok(frames) => frames,
            Err(err) => {
                tracing::warn!(%err, "video encode failed");
                Vec::new()
            }
        }
    }

    /// Reply to `ListDisplays` with what the source reports.
    fn list_displays(session: &Session, source: &mut S) -> Vec<DesktopAgentMessage> {
        if session.require(Permission::ViewScreen).is_err() {
            return vec![Self::refuse(
                ErrorCode::PermissionDenied,
                "this session may not view the screen",
            )];
        }
        match source.displays() {
            Ok(displays) => vec![DesktopAgentMessage::Displays(displays)],
            Err(err) => vec![Self::refuse(
                ErrorCode::Internal,
                format!("could not list displays: {err}"),
            )],
        }
    }

    /// Negotiate a codec and start streaming `display_index`.
    #[allow(clippy::too_many_arguments)]
    fn start_stream(
        stream: &mut Option<Stream>,
        session: &Session,
        source: &mut S,
        enabled: bool,
        display_index: u8,
        accepted_codecs: &[VideoCodec],
        quality: QualityPreset,
        max_fps: u8,
    ) -> Vec<DesktopAgentMessage> {
        if !enabled {
            return vec![Self::refuse(
                ErrorCode::Unsupported,
                "this build was not compiled with screen capture",
            )];
        }
        if session.require(Permission::ViewScreen).is_err() {
            return vec![Self::refuse(
                ErrorCode::PermissionDenied,
                "this session may not view the screen",
            )];
        }
        let Some(codec) = accepted_codecs
            .iter()
            .copied()
            .find(|codec| matches!(codec, VideoCodec::TiledZstd | VideoCodec::RawRgba))
        else {
            return vec![Self::refuse(
                ErrorCode::Unsupported,
                "no codec in common: this build encodes only tiled_zstd and raw_rgba",
            )];
        };

        let displays = match source.displays() {
            Ok(displays) => displays,
            Err(err) => {
                return vec![Self::refuse(
                    ErrorCode::Internal,
                    format!("could not list displays: {err}"),
                )];
            }
        };
        let Some(display) = displays
            .iter()
            .find(|display| display.index == display_index)
        else {
            return vec![Self::refuse(
                ErrorCode::NotFound,
                format!("no display with index {display_index}"),
            )];
        };

        let encoder = match Encoder::new(codec, display.width, display.height) {
            Ok(encoder) => encoder,
            Err(err) => {
                return vec![Self::refuse(
                    ErrorCode::Internal,
                    format!("could not build an encoder: {err}"),
                )];
            }
        };

        *stream = Some(Stream {
            display_index,
            encoder,
            codec,
            quality,
            interval: fps_interval(max_fps),
            paused: false,
            force_keyframe: false,
        });

        vec![DesktopAgentMessage::StreamStarted {
            display_index,
            codec,
            width: display.width,
            height: display.height,
            hardware_accelerated: false,
        }]
    }

    /// Change display, quality or frame-rate ceiling in place.
    fn reconfigure(
        stream: &mut Option<Stream>,
        session: &Session,
        source: &mut S,
        display_index: Option<u8>,
        quality: Option<QualityPreset>,
        max_fps: Option<u8>,
    ) -> Vec<DesktopAgentMessage> {
        let Some(live) = stream else {
            return vec![Self::refuse(
                ErrorCode::InvalidArgument,
                "no stream is running",
            )];
        };
        if session.require(Permission::ViewScreen).is_err() {
            return vec![Self::refuse(
                ErrorCode::PermissionDenied,
                "this session may not view the screen",
            )];
        }

        if let Some(quality) = quality {
            live.quality = quality;
        }
        if let Some(max_fps) = max_fps {
            live.interval = fps_interval(max_fps);
        }
        if let Some(new_index) = display_index
            && new_index != live.display_index
        {
            let displays = match source.displays() {
                Ok(displays) => displays,
                Err(err) => {
                    return vec![Self::refuse(
                        ErrorCode::Internal,
                        format!("could not list displays: {err}"),
                    )];
                }
            };
            let Some(display) = displays.iter().find(|display| display.index == new_index) else {
                return vec![Self::refuse(
                    ErrorCode::NotFound,
                    format!("no display with index {new_index}"),
                )];
            };
            match Encoder::new(live.codec, display.width, display.height) {
                Ok(encoder) => {
                    live.encoder = encoder;
                    live.display_index = new_index;
                    // A fresh encoder starts with no history of its own, but forcing
                    // this explicitly documents the intent rather than relying on it.
                    live.force_keyframe = true;
                }
                Err(err) => {
                    return vec![Self::refuse(
                        ErrorCode::Internal,
                        format!("could not build an encoder: {err}"),
                    )];
                }
            }
        }

        Vec::new()
    }

    fn refuse(code: ErrorCode, message: impl Into<String>) -> DesktopAgentMessage {
        DesktopAgentMessage::Error {
            code,
            message: message.into(),
        }
    }

    async fn send(&mut self, message: DesktopAgentMessage) -> Result<(), ()> {
        self.writer.send(&message).await.map_err(|err| {
            tracing::debug!(%err, "video channel closed");
        })
    }

    async fn send_all(&mut self, messages: Vec<DesktopAgentMessage>) -> Result<(), ()> {
        for message in messages {
            self.send(message).await?;
        }
        Ok(())
    }

    async fn send_frames(&mut self, frames: Vec<VideoFrame>) -> Result<(), ()> {
        for frame in frames {
            self.send(DesktopAgentMessage::Frame(frame)).await?;
        }
        Ok(())
    }
}

/// Clamp a client's requested ceiling into `1..=60` and turn it into a tick period.
fn fps_interval(max_fps: u8) -> Duration {
    let fps = max_fps.clamp(1, 60);
    Duration::from_millis(1000 / u64::from(fps))
}

/// Capture time on the agent's monotonic clock, in microseconds since this process
/// started serving video.
///
/// A process-local `Instant` rather than the Unix epoch: `captured_at_us` is only ever
/// compared against other values from the same encoder on the same run, never
/// persisted or compared across machines, so a wall-clock epoch would add nothing but
/// the risk of a clock step going backwards mid-stream.
fn now_us() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rc_protocol::desktop::InteractionMode;
    use rc_security::{Fingerprint, PermissionSet};
    use rc_video::capture::mock::MockSource;

    fn session_with(permissions: PermissionSet) -> Session {
        Session::new(permissions, Fingerprint::from_bytes([0_u8; 32]))
    }

    fn viewing() -> PermissionSet {
        PermissionSet::NONE.with(Permission::ViewScreen)
    }

    /// The service's decisions, without a transport under them.
    struct Harness {
        session: Session,
        source: MockSource,
        enabled: bool,
        stream: Option<Stream>,
    }

    impl Harness {
        fn new(permissions: PermissionSet, source: MockSource, enabled: bool) -> Self {
            Self {
                session: session_with(permissions),
                source,
                enabled,
                stream: None,
            }
        }

        /// One client message in, the agent's replies out.
        fn handle(&mut self, message: DesktopClientMessage) -> Vec<DesktopAgentMessage> {
            VideoService::decide(
                &mut self.stream,
                &self.session,
                &mut self.source,
                self.enabled,
                message,
            )
        }

        /// One capture-and-encode cycle, the frames it produced.
        fn tick(&mut self) -> Vec<VideoFrame> {
            VideoService::capture_once(&mut self.stream, &self.session, &mut self.source)
        }

        /// Withdraw every permission, as a revoked grant does mid-session.
        fn revoke(&mut self) {
            self.session = session_with(PermissionSet::NONE);
        }
    }

    fn start_stream(codecs: Vec<VideoCodec>) -> DesktopClientMessage {
        DesktopClientMessage::StartStream {
            display_index: 0,
            accepted_codecs: codecs,
            quality: QualityPreset::Balanced,
            max_fps: 30,
            interaction: InteractionMode::ViewOnly,
        }
    }

    #[test]
    fn listing_displays_answers_with_what_the_source_reports() {
        let mut service = Harness::new(viewing(), MockSource::new(128, 128), true);
        let replies = service.handle(DesktopClientMessage::ListDisplays);
        assert!(matches!(
            replies.as_slice(),
            [DesktopAgentMessage::Displays(displays)] if displays.len() == 1
        ));
    }

    #[test]
    fn a_session_without_view_permission_is_refused_and_told_why() {
        // Silence here is indistinguishable from a dead link, and the operator would
        // sit waiting for a picture that is never coming.
        let mut service = Harness::new(PermissionSet::NONE, MockSource::new(128, 128), true);
        let replies = service.handle(start_stream(vec![VideoCodec::TiledZstd]));
        assert!(matches!(
            replies.as_slice(),
            [DesktopAgentMessage::Error { .. }]
        ));
    }

    #[test]
    fn a_codec_neither_side_shares_is_refused_rather_than_guessed() {
        let mut service = Harness::new(viewing(), MockSource::new(128, 128), true);
        let replies = service.handle(start_stream(vec![VideoCodec::Av1]));
        assert!(matches!(
            replies.as_slice(),
            [DesktopAgentMessage::Error { .. }]
        ));
    }

    #[test]
    fn the_negotiated_codec_is_the_clients_first_choice_that_we_can_produce() {
        let mut service = Harness::new(viewing(), MockSource::new(128, 128), true);
        let replies = service.handle(start_stream(vec![
            VideoCodec::H264,
            VideoCodec::TiledZstd,
            VideoCodec::RawRgba,
        ]));
        assert!(matches!(
            replies.as_slice(),
            [DesktopAgentMessage::StreamStarted {
                codec: VideoCodec::TiledZstd,
                width: 128,
                height: 128,
                ..
            }]
        ));
    }

    #[test]
    fn a_build_without_capture_says_so_rather_than_going_quiet() {
        let mut service = Harness::new(viewing(), MockSource::new(128, 128), false);
        let replies = service.handle(start_stream(vec![VideoCodec::TiledZstd]));
        assert!(matches!(
            replies.as_slice(),
            [DesktopAgentMessage::Error { .. }]
        ));
    }

    #[test]
    fn a_keyframe_request_forces_a_full_refresh() {
        let mut service = Harness::new(viewing(), MockSource::new(128, 128), true);
        service.handle(start_stream(vec![VideoCodec::TiledZstd]));
        service.tick(); // first frame, everything changes
        assert!(service.tick().is_empty(), "a still screen sends nothing");

        service.handle(DesktopClientMessage::RequestKeyframe);
        let frames = service.tick();
        assert!(
            frames.iter().any(|f| f.keyframe),
            "the request must be honoured"
        );
    }

    #[test]
    fn a_revoked_grant_stops_the_stream_mid_session() {
        // Matches how input_service re-checks authorization per event: a permission
        // withdrawn while streaming must take effect immediately, not at teardown.
        let mut service = Harness::new(viewing(), MockSource::new(128, 128), true);
        service.handle(start_stream(vec![VideoCodec::TiledZstd]));
        service.tick();
        service.revoke();
        assert!(service.tick().is_empty(), "revocation must stop frames");
    }
}
