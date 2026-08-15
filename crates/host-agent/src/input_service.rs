//! Serving the input channel for one authenticated connection.
//!
//! # Authorization is re-checked on every event
//!
//! `control_input` is not captured when the channel opens. A session is long-lived and
//! a grant can be withdrawn while it is running — by the operator revoking the device,
//! suspending it, or hitting Emergency Stop — and an input channel that captured the
//! decision once would keep driving the machine until whoever opened it disconnected.
//! Every event therefore re-asks, exactly as the file and metrics services do.
//!
//! # An acknowledgement means the OS accepted it
//!
//! Discrete actions — clicks, keys, intents — are acknowledged only *after* the
//! injection call returns, and a refusal is reported with the reason the OS gave. The
//! controller logs from these acknowledgements rather than from having sent something,
//! so nothing can be recorded as successful before it happened.
//!
//! Motion and scroll are not acknowledged individually: a round trip per sample would
//! add a full RTT to pointer lag. Their progress is reported as a watermark instead,
//! and they are never logged as discrete successes, so there is nothing for them to
//! misreport.
//!
//! # Display topology is pushed, not polled
//!
//! Every coordinate the controller sends is a fraction of a *particular* monitor, so a
//! viewer working from a stale arrangement aims at the wrong screen. The host therefore
//! re-enumerates on a timer and pushes the list whenever it differs — a monitor plugged
//! in, unplugged, rearranged, rescaled or made primary all reach the viewer without it
//! having to ask, and without restarting the session.
//!
//! Polling on the host rather than the controller keeps the authority where the
//! knowledge is, and means one enumeration serves every connected viewer.
//!
//! # The channel is drained even when the session may not use it
//!
//! A view-only session's events are answered with `ViewOnly` rather than ignored. A
//! client waiting on an acknowledgement that never comes looks identical to a hung
//! link, and would leave the operator unable to tell a permission problem from a
//! network one.

use rc_input::{HostOs, InputSession, InputSink};
use rc_protocol::{InputAck, InputEvent, InputMessage};
use rc_security::Permission;
use rc_transport::{ChannelReader, ChannelWriter};

use crate::sessions::Session;

/// Read the host's monitors, or an empty arrangement where that is impossible.
fn enumerate_displays() -> rc_input::DisplayTopology {
    #[cfg(feature = "inject")]
    {
        rc_input::backend::displays::enumerate()
    }
    #[cfg(not(feature = "inject"))]
    {
        rc_input::DisplayTopology::default()
    }
}

/// How often the applied-motion watermark is reported, in milliseconds.
///
/// Frequent enough to drive a responsiveness indicator, rare enough that it costs
/// nothing next to the motion stream it describes.
const WATERMARK_INTERVAL_MS: u64 = 250;

/// How often the host re-reads its display arrangement, in milliseconds.
///
/// Enumeration is cheap but not free, and monitors are hotplugged by hand, so a rate
/// that feels immediate to a person is far more often than needed.
const DISPLAY_POLL_MS: u64 = 2000;

/// Serves the input channel for one connection.
pub struct InputService<S: InputSink> {
    writer: ChannelWriter,
    session: Session,
    input: InputSession<S>,
    /// Whether this build was asked to serve input at all.
    enabled: bool,
}

impl<S: InputSink> InputService<S> {
    /// A service injecting through `sink` on behalf of `session`.
    pub fn new(writer: ChannelWriter, session: Session, sink: S, enabled: bool) -> Self {
        // The session starts able to control; each event re-checks the live grant, so
        // this is only the initial state rather than the authority.
        let mut input = InputSession::new(sink, HostOs::current(), true);
        input.set_topology(enumerate_displays());
        Self {
            writer,
            session,
            input,
            enabled,
        }
    }

    /// Apply events until the channel closes.
    ///
    /// Always releases whatever is still held before returning: a connection dropped
    /// mid-chord must not leave a modifier jammed down on this machine.
    pub async fn run(mut self, reader: &mut ChannelReader) {
        let mut watermark_timer = tokio::time::interval(std::time::Duration::from_millis(
            WATERMARK_INTERVAL_MS,
        ));
        watermark_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let mut display_timer =
            tokio::time::interval(std::time::Duration::from_millis(DISPLAY_POLL_MS));
        display_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let mut reported = 0_u32;

        // The viewer needs the arrangement before it can send a single coordinate, so
        // it is sent unprompted rather than waiting to be asked.
        if self.send_displays().await.is_err() {
            return;
        }

        loop {
            tokio::select! {
                biased;

                event = reader.next_message::<InputEvent>() => {
                    match event {
                        Ok(Some(event)) => {
                            if self.dispatch(event).await.is_err() {
                                break;
                            }
                        }
                        // Clean close, or a peer that sent something malformed. Either
                        // way this channel is done.
                        Ok(None) | Err(_) => break,
                    }
                }

                _ = display_timer.tick() => {
                    let current = enumerate_displays();
                    if current != *self.input.topology() {
                        tracing::info!(
                            displays = current.len(),
                            "the host display arrangement changed"
                        );
                        self.input.set_topology(current);
                        if self.send_displays().await.is_err() {
                            break;
                        }
                    }
                }

                _ = watermark_timer.tick() => {
                    let current = self.input.watermark();
                    if current != reported {
                        reported = current;
                        if self.send(InputMessage::Ack(InputAck::Applied {
                            watermark: current,
                        })).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }

        // The guarantee that outlives the connection.
        self.input.release_all();
    }

    /// Apply one event and send whatever it produced.
    async fn dispatch(&mut self, event: InputEvent) -> Result<(), ()> {
        // A display request is answered with the arrangement rather than an ack: the
        // list *is* the reply.
        if matches!(event, InputEvent::ListDisplays { .. }) {
            return self.send_displays().await;
        }

        match self.handle(event) {
            Some(ack) => self.send(InputMessage::Ack(ack)).await,
            None => Ok(()),
        }
    }

    /// Send the current arrangement.
    async fn send_displays(&mut self) -> Result<(), ()> {
        let displays = self.input.topology().all().to_vec();
        self.send(InputMessage::Displays { displays }).await
    }

    async fn send(&mut self, message: InputMessage) -> Result<(), ()> {
        self.writer.send(&message).await.map_err(|err| {
            tracing::debug!(%err, "input channel closed");
        })
    }

    /// Apply one event, returning the acknowledgement to send, if any.
    fn handle(&mut self, event: InputEvent) -> Option<InputAck> {
        let seq = event.seq();
        let acknowledged = event.is_acknowledged();

        if !self.enabled {
            return acknowledged.then_some(InputAck::Failed {
                seq,
                reason: rc_protocol::InputFailure::Unavailable,
            });
        }

        // Re-checked per event, deliberately: see the module docs.
        if self.session.require(Permission::ControlInput).is_err() {
            return acknowledged.then_some(InputAck::Failed {
                seq,
                reason: rc_protocol::InputFailure::ViewOnly,
            });
        }

        let ack = self.input.apply(event);

        // Logged from the outcome, never from having received the event. A refusal is
        // recorded as a refusal, with the reason the OS actually gave.
        match ack {
            Some(InputAck::Failed { reason, .. }) => {
                tracing::warn!(seq, ?reason, "input event refused");
            }
            Some(InputAck::Ok { .. }) => {
                tracing::trace!(seq, "input event applied");
            }
            _ => {}
        }

        ack
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rc_input::backend::mock::MockSink;
    use rc_protocol::{InputFailure, Intent, MouseButton, PhysicalKey};
    use rc_security::{Fingerprint, PermissionSet};

    fn session_with(permissions: PermissionSet) -> Session {
        Session::new(permissions, Fingerprint::from_bytes([0_u8; 32]))
    }

    /// The service without its transport, which is what `handle` actually needs.
    struct Harness {
        session: Session,
        input: InputSession<MockSink>,
        enabled: bool,
    }

    impl Harness {
        fn new(permissions: PermissionSet, os: HostOs, enabled: bool) -> Self {
            Self {
                session: session_with(permissions),
                input: {
                    let mut input = InputSession::new(MockSink::new(), Some(os), true);
                    input.set_topology(one_display());
                    input
                },
                enabled,
            }
        }

        /// Mirrors `InputService::handle`, which cannot be built without a live QUIC
        /// stream. The branching under test is this decision, not the transport.
        fn handle(&mut self, event: InputEvent) -> Option<InputAck> {
            let seq = event.seq();
            let acknowledged = event.is_acknowledged();

            if !self.enabled {
                return acknowledged.then_some(InputAck::Failed {
                    seq,
                    reason: InputFailure::Unavailable,
                });
            }
            if self.session.require(Permission::ControlInput).is_err() {
                return acknowledged.then_some(InputAck::Failed {
                    seq,
                    reason: InputFailure::ViewOnly,
                });
            }
            self.input.apply(event)
        }
    }

    /// A single 1080p primary, which is all these permission tests need.
    fn one_display() -> rc_input::DisplayTopology {
        rc_input::DisplayTopology::new(vec![rc_protocol::desktop::DisplayInfo {
            index: 0,
            name: "Primary".to_owned(),
            width: 1920,
            height: 1080,
            scale_factor: 1.0,
            origin_x: 0,
            origin_y: 0,
            primary: true,
            refresh_hz: Some(60),
        }])
    }

    fn controlling() -> PermissionSet {
        PermissionSet::NONE.with(Permission::ControlInput)
    }

    #[test]
    fn a_permitted_click_is_applied_and_acknowledged() {
        let mut h = Harness::new(controlling(), HostOs::Windows, true);
        let ack = h.handle(InputEvent::MouseDown {
            button: MouseButton::Left,
            seq: 1,
        });
        assert_eq!(ack, Some(InputAck::Ok { seq: 1 }));
        assert_eq!(h.input.sink().calls().len(), 1);
    }

    #[test]
    fn a_session_without_control_is_refused_and_told_why() {
        let mut h = Harness::new(PermissionSet::NONE, HostOs::Windows, true);
        let ack = h.handle(InputEvent::MouseDown {
            button: MouseButton::Left,
            seq: 1,
        });
        assert_eq!(
            ack,
            Some(InputAck::Failed {
                seq: 1,
                reason: InputFailure::ViewOnly
            })
        );
        // The refusal must be total: nothing reached the machine.
        assert!(h.input.sink().calls().is_empty());
    }

    #[test]
    fn a_revoked_grant_stops_input_mid_session() {
        // The reason authorization is re-checked per event rather than captured.
        let mut h = Harness::new(controlling(), HostOs::Windows, true);
        assert_eq!(
            h.handle(InputEvent::KeyDown {
                key: PhysicalKey::KeyA,
                repeat: false,
                seq: 1
            }),
            Some(InputAck::Ok { seq: 1 })
        );

        h.session = session_with(PermissionSet::NONE);

        assert_eq!(
            h.handle(InputEvent::KeyDown {
                key: PhysicalKey::KeyB,
                repeat: false,
                seq: 2
            }),
            Some(InputAck::Failed {
                seq: 2,
                reason: InputFailure::ViewOnly
            })
        );
        assert_eq!(h.input.sink().calls().len(), 1, "only the first key landed");
    }

    #[test]
    fn a_build_without_input_says_so_rather_than_going_quiet() {
        let mut h = Harness::new(controlling(), HostOs::Windows, false);
        assert_eq!(
            h.handle(InputEvent::MouseDown {
                button: MouseButton::Left,
                seq: 1
            }),
            Some(InputAck::Failed {
                seq: 1,
                reason: InputFailure::Unavailable
            })
        );
    }

    #[test]
    fn refused_motion_is_not_acknowledged_and_does_not_advance_the_watermark() {
        // Motion carries no ack, so a view-only session must not appear to be moving
        // the pointer.
        let mut h = Harness::new(PermissionSet::NONE, HostOs::Windows, true);
        assert_eq!(h.handle(InputEvent::MouseMove { x: 0.5, y: 0.5, display: 0, seq: 1 }), None);
        assert_eq!(h.input.watermark(), 0);
        assert!(h.input.sink().calls().is_empty());
    }

    #[test]
    fn permitted_motion_advances_the_watermark_without_an_ack() {
        let mut h = Harness::new(controlling(), HostOs::Windows, true);
        assert_eq!(h.handle(InputEvent::MouseMove { x: 0.5, y: 0.5, display: 0, seq: 6 }), None);
        assert_eq!(h.input.watermark(), 6);
    }

    #[test]
    fn an_intent_is_spelled_for_this_host_not_the_controller() {
        let mut h = Harness::new(controlling(), HostOs::MacOs, true);
        h.handle(InputEvent::Intent {
            intent: Intent::Copy,
            seq: 1,
        });
        let keys = h.input.sink().key_calls();
        assert_eq!(keys.first().map(|(key, _)| *key), Some(PhysicalKey::MetaLeft));
    }

    #[test]
    fn an_unsupported_intent_is_refused_with_its_real_reason() {
        let mut h = Harness::new(controlling(), HostOs::Linux, true);
        assert_eq!(
            h.handle(InputEvent::Intent {
                intent: Intent::SecureAttention,
                seq: 1
            }),
            Some(InputAck::Failed {
                seq: 1,
                reason: InputFailure::NotSupported
            })
        );
    }
}
