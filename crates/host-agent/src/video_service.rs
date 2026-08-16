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
//! # The clipboard rides this channel, and is its own grant
//!
//! `DesktopClientMessage::ClipboardUpdate` arrives here because the protocol puts it
//! here, so clipboard sharing lives for as long as the desktop channel does. It is
//! gated on `Permission::Clipboard` rather than on `ControlInput`: a clipboard carries
//! whatever its owner last copied, routinely a password or a key that was never on
//! screen, so being allowed to type on a machine says nothing about being allowed to
//! read that. Like every other grant here it is re-checked per message, never captured
//! when the channel opens.
//!
//! Both ends watch their own clipboard, so the naive arrangement never settles — see
//! [`rc_clipboard::ClipboardSync`], which holds the digest that breaks the echo.
//!
//! # A refusal is always a message, never silence
//!
//! A client waiting on `StreamStarted` that never arrives cannot tell a permission
//! problem, a missing codec, or a build with no capture backend from a dead link.
//! Every path that does not start or continue the stream replies
//! `DesktopAgentMessage::Error` naming the real cause.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use rc_clipboard::{ClipboardAccess, ClipboardSync};
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

/// How often the host's own clipboard is re-read while a desktop channel is open.
///
/// Polled rather than subscribed because no platform this ships for offers a portable
/// change notification. Half a second is below what a human notices between copying on
/// one machine and pasting on the other, and costs one small read in between.
const CLIPBOARD_POLL: Duration = Duration::from_millis(500);

/// Serves the video channel for one connection.
pub struct VideoService<S: CaptureSource> {
    writer: ChannelWriter,
    session: Session,
    source: S,
    /// Whether this build was asked to serve video at all.
    enabled: bool,
    stream: Option<Stream>,
    /// The machine's clipboard, when this build has one and the operator allowed it.
    ///
    /// A trait object rather than a second generic parameter: nothing here dispatches
    /// on the concrete type, and threading one more parameter through every caller and
    /// test would buy nothing.
    clipboard: Option<Box<dyn ClipboardAccess + Send>>,
    /// Whether the host's configuration allows clipboard sharing at all.
    ///
    /// Separate from the permission: the grant says this *session* may, the setting
    /// says this *machine* does. Both must agree.
    clipboard_enabled: bool,
    /// The digest that stops the two ends echoing a clipboard back and forth forever.
    clipboard_sync: ClipboardSync,
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
            clipboard: None,
            clipboard_enabled: false,
            clipboard_sync: ClipboardSync::new(),
        }
    }

    /// Serve the clipboard through `clipboard`, if the host's settings allow it.
    ///
    /// Left off by [`Self::new`] on purpose: a service that shares the clipboard by
    /// default would do so on every build that happened to link a backend, rather than
    /// because someone decided it should.
    #[must_use]
    pub fn with_clipboard(
        mut self,
        clipboard: Option<Box<dyn ClipboardAccess + Send>>,
        enabled: bool,
    ) -> Self {
        self.clipboard = clipboard;
        self.clipboard_enabled = enabled;
        self
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
        // Independent of the stream: a clipboard is worth sharing for as long as the
        // desktop channel is open, including before anyone starts watching the screen.
        let mut next_clipboard = Instant::now() + CLIPBOARD_POLL;

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
                                self.clipboard.as_mut(),
                                self.clipboard_enabled,
                                &mut self.clipboard_sync,
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

                () = tokio::time::sleep_until(next_clipboard.into()), if self.clipboard.is_some() => {
                    next_clipboard = Instant::now() + CLIPBOARD_POLL;

                    if let Some(update) = Self::poll_clipboard(
                        self.clipboard.as_mut(),
                        self.clipboard_enabled,
                        &mut self.clipboard_sync,
                        &self.session,
                    ) && self.send_all(vec![update]).await.is_err() {
                        break;
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
    #[allow(clippy::too_many_arguments)]
    fn decide(
        stream: &mut Option<Stream>,
        session: &Session,
        source: &mut S,
        enabled: bool,
        clipboard: Option<&mut Box<dyn ClipboardAccess + Send>>,
        clipboard_enabled: bool,
        clipboard_sync: &mut ClipboardSync,
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
            DesktopClientMessage::SetInteractionMode(_) => vec![Self::refuse(
                ErrorCode::Unsupported,
                "set_interaction_mode is not handled on the video channel in this build",
            )],
            DesktopClientMessage::SecureAttentionSequence => vec![Self::refuse(
                ErrorCode::Unsupported,
                "secure_attention_sequence is not handled on the video channel in this build",
            )],
            DesktopClientMessage::ClipboardUpdate { text } => {
                Self::apply_clipboard(clipboard, clipboard_enabled, clipboard_sync, session, &text)
            }
            // `DesktopClientMessage` is `#[non_exhaustive]`: this is now solely for a
            // variant a future protocol version adds that this build does not know
            // about yet, not for any variant named above.
            _ => vec![Self::refuse(
                ErrorCode::Unsupported,
                "this build does not understand that video-channel request",
            )],
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
            Err(err) => {
                tracing::warn!(%err, "could not enumerate displays");
                vec![Self::refuse(
                    ErrorCode::Internal,
                    "the display list could not be read",
                )]
            }
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
                tracing::warn!(%err, "could not enumerate displays");
                return vec![Self::refuse(
                    ErrorCode::Internal,
                    "the display list could not be read",
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
                tracing::warn!(%err, "could not build an encoder");
                return vec![Self::refuse(
                    ErrorCode::Internal,
                    "the encoder could not be started",
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
                    tracing::warn!(%err, "could not enumerate displays");
                    return vec![Self::refuse(
                        ErrorCode::Internal,
                        "the display list could not be read",
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
                    tracing::warn!(%err, "could not build an encoder");
                    return vec![Self::refuse(
                        ErrorCode::Internal,
                        "the encoder could not be started",
                    )];
                }
            }
        }

        Vec::new()
    }

    /// Write text the peer published onto this machine's clipboard.
    ///
    /// Refuses rather than ignores: a client that pasted into a session which may not
    /// share a clipboard needs to know its text went nowhere, not watch it vanish.
    fn apply_clipboard(
        clipboard: Option<&mut Box<dyn ClipboardAccess + Send>>,
        enabled: bool,
        sync: &mut ClipboardSync,
        session: &Session,
        text: &str,
    ) -> Vec<DesktopAgentMessage> {
        if session.require(Permission::Clipboard).is_err() {
            return vec![Self::refuse(
                ErrorCode::Forbidden,
                "this session may not share the clipboard",
            )];
        }
        if !enabled {
            return vec![Self::refuse(
                ErrorCode::Unsupported,
                "this machine has clipboard sharing turned off",
            )];
        }
        let Some(clipboard) = clipboard else {
            return vec![Self::refuse(
                ErrorCode::Unsupported,
                "this machine has no reachable clipboard",
            )];
        };
        // Oversized or empty text stops here, and so does anything this end already
        // holds -- which is what keeps a write from waking its own watcher.
        if !sync.should_apply(text) {
            return Vec::new();
        }
        match clipboard.write_text(text) {
            Ok(()) => Vec::new(),
            Err(err) => {
                tracing::debug!(%err, "the clipboard could not be written");
                vec![Self::refuse(
                    ErrorCode::Internal,
                    "the clipboard could not be written on this machine",
                )]
            }
        }
    }

    /// This machine's clipboard, if it has changed and the session may see it.
    ///
    /// Returns nothing at all in the ordinary case -- an unchanged clipboard is not
    /// news, and this is called on every poll tick.
    fn poll_clipboard(
        clipboard: Option<&mut Box<dyn ClipboardAccess + Send>>,
        enabled: bool,
        sync: &mut ClipboardSync,
        session: &Session,
    ) -> Option<DesktopAgentMessage> {
        if !enabled || session.require(Permission::Clipboard).is_err() {
            return None;
        }
        let text = clipboard?.read_text().ok()?;
        sync.should_publish(&text)
            .then_some(DesktopAgentMessage::ClipboardUpdate { text })
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

/// The capture source this build uses.
///
/// # Errors
/// If no display server is reachable, or this build has no capture backend.
#[cfg(feature = "inject")]
pub fn new_source() -> rc_video::Result<rc_video::capture::xcap_source::XcapSource> {
    rc_video::capture::xcap_source::XcapSource::new()
}

/// The capture source this build uses.
///
/// # Errors
/// Always: a build without the capture backend cannot serve video, and says so rather
/// than serving black frames.
#[cfg(not(feature = "inject"))]
pub fn new_source() -> rc_video::Result<rc_video::capture::mock::MockSource> {
    Err(rc_video::VideoError::Unsupported(
        "this build has no capture backend",
    ))
}

/// This machine's clipboard, or `None` where there is not one to reach.
///
/// `None` rather than an error: a host with no clipboard is a host that cannot share
/// one, which the service already reports per message. Failing to open it must not stop
/// a video channel that would otherwise work.
#[cfg(feature = "inject")]
#[must_use]
pub fn new_clipboard() -> Option<Box<dyn ClipboardAccess + Send>> {
    match rc_clipboard::SystemClipboard::open() {
        Ok(clipboard) => Some(Box::new(clipboard)),
        Err(err) => {
            tracing::info!(%err, "clipboard sharing is unavailable on this machine");
            None
        }
    }
}

/// This machine's clipboard, or `None` where there is not one to reach.
#[cfg(not(feature = "inject"))]
#[must_use]
pub const fn new_clipboard() -> Option<Box<dyn ClipboardAccess + Send>> {
    None
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
    use rc_protocol::desktop::{DisplayInfo, InteractionMode};
    use rc_security::{Fingerprint, PermissionSet};
    use rc_video::capture::CapturedFrame;
    use rc_video::capture::mock::MockSource;

    fn session_with(permissions: PermissionSet) -> Session {
        Session::new(permissions, Fingerprint::from_bytes([0_u8; 32]))
    }

    fn viewing() -> PermissionSet {
        PermissionSet::NONE.with(Permission::ViewScreen)
    }

    /// The service's decisions, without a transport under them.
    struct Harness<S: CaptureSource> {
        session: Session,
        source: S,
        enabled: bool,
        stream: Option<Stream>,
        clipboard: Option<Box<dyn ClipboardAccess + Send>>,
        clipboard_enabled: bool,
        clipboard_sync: ClipboardSync,
    }

    impl<S: CaptureSource> Harness<S> {
        fn new(permissions: PermissionSet, source: S, enabled: bool) -> Self {
            Self {
                session: session_with(permissions),
                source,
                enabled,
                stream: None,
                clipboard: None,
                clipboard_enabled: false,
                clipboard_sync: ClipboardSync::new(),
            }
        }

        /// Give this host a working clipboard the tests can inspect.
        fn with_clipboard(mut self, enabled: bool) -> Self {
            self.clipboard = Some(Box::new(rc_clipboard::MemoryClipboard::new()));
            self.clipboard_enabled = enabled;
            self
        }

        /// What is on this host's clipboard right now.
        fn clipboard_text(&mut self) -> Option<String> {
            self.clipboard.as_mut()?.read_text().ok()
        }

        /// Put text on this host's clipboard, as a user pressing Copy would.
        fn copy_locally(&mut self, text: &str) {
            self.clipboard
                .as_mut()
                .expect("this harness has a clipboard")
                .write_text(text)
                .expect("an in-memory clipboard always accepts a write");
        }

        /// One clipboard poll, and whatever it decided to publish.
        fn poll_clipboard(&mut self) -> Option<DesktopAgentMessage> {
            VideoService::<S>::poll_clipboard(
                self.clipboard.as_mut(),
                self.clipboard_enabled,
                &mut self.clipboard_sync,
                &self.session,
            )
        }

        /// One client message in, the agent's replies out.
        fn handle(&mut self, message: DesktopClientMessage) -> Vec<DesktopAgentMessage> {
            VideoService::decide(
                &mut self.stream,
                &self.session,
                &mut self.source,
                self.enabled,
                self.clipboard.as_mut(),
                self.clipboard_enabled,
                &mut self.clipboard_sync,
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

    /// A session allowed to share a clipboard, and to watch a screen.
    fn clipboard_session() -> PermissionSet {
        PermissionSet::NONE
            .with(Permission::ViewScreen)
            .with(Permission::Clipboard)
    }

    #[test]
    fn a_session_without_the_clipboard_grant_is_refused_not_ignored() {
        // Vanishing text is the worst outcome: the operator pasted, saw nothing happen,
        // and has no way to tell a refusal from a slow link.
        let mut harness = Harness::new(viewing(), MockSource::new(8, 8), true).with_clipboard(true);

        let replies = harness.handle(DesktopClientMessage::ClipboardUpdate {
            text: "secret".to_owned(),
        });

        assert!(matches!(
            replies.as_slice(),
            [DesktopAgentMessage::Error {
                code: ErrorCode::Forbidden,
                ..
            }]
        ));
        assert_eq!(
            harness.clipboard_text(),
            None,
            "nothing may reach the clipboard"
        );
    }

    #[test]
    fn a_machine_with_clipboard_sharing_turned_off_refuses_even_a_granted_session() {
        // The grant says this session may; the setting says this machine does. A
        // permission cannot override the machine's own configuration.
        let mut harness =
            Harness::new(clipboard_session(), MockSource::new(8, 8), true).with_clipboard(false);

        let replies = harness.handle(DesktopClientMessage::ClipboardUpdate {
            text: "secret".to_owned(),
        });

        assert!(matches!(
            replies.as_slice(),
            [DesktopAgentMessage::Error {
                code: ErrorCode::Unsupported,
                ..
            }]
        ));
    }

    #[test]
    fn a_granted_session_reaches_the_clipboard() {
        let mut harness =
            Harness::new(clipboard_session(), MockSource::new(8, 8), true).with_clipboard(true);

        let replies = harness.handle(DesktopClientMessage::ClipboardUpdate {
            text: "shared".to_owned(),
        });

        assert!(replies.is_empty(), "a successful write says nothing back");
        assert_eq!(harness.clipboard_text().as_deref(), Some("shared"));
    }

    #[test]
    fn text_the_client_sent_is_not_published_straight_back_to_it() {
        // The echo this whole design exists to stop: without it the host's own watcher
        // sees the write it just made and returns it to the sender, forever.
        let mut harness =
            Harness::new(clipboard_session(), MockSource::new(8, 8), true).with_clipboard(true);

        harness.handle(DesktopClientMessage::ClipboardUpdate {
            text: "round trip".to_owned(),
        });

        assert!(harness.poll_clipboard().is_none());
    }

    #[test]
    fn something_copied_on_the_host_is_published_once() {
        let mut harness =
            Harness::new(clipboard_session(), MockSource::new(8, 8), true).with_clipboard(true);
        harness.copy_locally("from the host");

        let first = harness.poll_clipboard();
        let second = harness.poll_clipboard();

        assert!(matches!(
            first,
            Some(DesktopAgentMessage::ClipboardUpdate { ref text }) if text == "from the host"
        ));
        assert!(second.is_none(), "an unchanged clipboard is not news");
    }

    #[test]
    fn the_host_clipboard_is_never_published_to_a_session_without_the_grant() {
        // The direction that leaks: this one sends the host's own copied text out.
        let mut harness = Harness::new(viewing(), MockSource::new(8, 8), true).with_clipboard(true);
        harness.copy_locally("a password");

        assert!(harness.poll_clipboard().is_none());
    }

    #[test]
    fn a_revoked_clipboard_grant_stops_publishing_mid_session() {
        // Authorization is re-asked per poll, exactly as it is per frame and per event.
        let mut harness =
            Harness::new(clipboard_session(), MockSource::new(8, 8), true).with_clipboard(true);
        harness.copy_locally("first");
        assert!(harness.poll_clipboard().is_some());

        harness.revoke();
        harness.copy_locally("second");

        assert!(harness.poll_clipboard().is_none());
    }

    /// Two displays of different sizes, so a `Reconfigure` onto another display can be
    /// distinguished from one that keeps reusing the encoder it started with: a stale
    /// 128x128 encoder fed a 64x64 frame would fail the size check inside `encode`
    /// rather than merely produce a wrong-looking picture.
    struct TwoDisplays {
        primary: MockSource,
        secondary: MockSource,
    }

    impl TwoDisplays {
        fn new() -> Self {
            Self {
                primary: MockSource::new(128, 128),
                secondary: MockSource::new(64, 64),
            }
        }
    }

    impl CaptureSource for TwoDisplays {
        fn displays(&self) -> rc_video::Result<Vec<DisplayInfo>> {
            let mut all = self.primary.displays()?;
            let mut rest = self.secondary.displays()?;
            for display in &mut rest {
                display.index = 1;
                display.name = "mock-secondary".to_owned();
                display.primary = false;
            }
            all.append(&mut rest);
            Ok(all)
        }

        fn grab(&mut self, index: u8) -> rc_video::Result<CapturedFrame> {
            match index {
                0 => self.primary.grab(0),
                1 => self.secondary.grab(0),
                other => Err(rc_video::VideoError::NoSuchDisplay(other)),
            }
        }
    }

    fn start_stream(codecs: Vec<VideoCodec>) -> DesktopClientMessage {
        start_stream_on(0, codecs)
    }

    fn start_stream_on(display_index: u8, codecs: Vec<VideoCodec>) -> DesktopClientMessage {
        DesktopClientMessage::StartStream {
            display_index,
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

    #[test]
    fn pausing_stops_frames_and_resuming_does_not_need_a_keyframe() {
        // Resuming must reuse the encoder. Forcing a full refresh on every resume
        // would turn a pause into a bandwidth spike on a link already under strain.
        let mut service = Harness::new(viewing(), MockSource::new(128, 128), true);
        service.handle(start_stream(vec![VideoCodec::TiledZstd]));
        service.tick(); // first frame, everything changes

        service.handle(DesktopClientMessage::PauseStream);
        assert!(service.tick().is_empty(), "a paused stream sends nothing");

        service.handle(DesktopClientMessage::ResumeStream);
        assert!(
            service.tick().is_empty(),
            "resuming an unchanged screen must not force a keyframe"
        );
    }

    #[test]
    fn reconfiguring_onto_another_display_rebuilds_the_encoder_and_forces_a_keyframe() {
        // The encoder is built for one frame size. Pointing a stale one at a
        // different-sized display corrupts every frame it produces, and the corruption
        // looks like a codec defect rather than a configuration one.
        let mut service = Harness::new(viewing(), TwoDisplays::new(), true);
        service.handle(start_stream_on(0, vec![VideoCodec::TiledZstd]));
        service.tick();
        assert!(
            service.tick().is_empty(),
            "an unchanged screen sends nothing before the switch"
        );

        let replies = service.handle(DesktopClientMessage::Reconfigure {
            display_index: Some(1),
            quality: None,
            max_fps: None,
        });
        assert!(
            replies.is_empty(),
            "reconfigure onto a valid display is quiet"
        );

        let frames = service.tick();
        assert!(
            !frames.is_empty(),
            "the newly built encoder must produce a frame, proving it was rebuilt for \
             the new display's size rather than reused"
        );
        assert!(
            frames.iter().all(|frame| frame.keyframe),
            "a display switch is a full refresh"
        );
    }

    #[test]
    fn stopping_ends_the_stream_and_a_later_tick_produces_nothing() {
        let mut service = Harness::new(viewing(), MockSource::new(128, 128), true);
        service.handle(start_stream(vec![VideoCodec::TiledZstd]));
        service.tick();

        let replies = service.handle(DesktopClientMessage::StopStream);
        assert!(matches!(
            replies.as_slice(),
            [DesktopAgentMessage::StreamStopped]
        ));

        // A still screen also sends nothing, so that alone would not distinguish a
        // stopped stream from a running, idle one. Asking for a keyframe does: a live
        // stream would honour it silently, but nothing should be left to ask.
        let keyframe_replies = service.handle(DesktopClientMessage::RequestKeyframe);
        assert!(
            matches!(
                keyframe_replies.as_slice(),
                [DesktopAgentMessage::Error { .. }]
            ),
            "no stream should remain to request a keyframe from"
        );

        assert!(
            service.tick().is_empty(),
            "a stopped stream must not keep producing frames"
        );
    }
}
