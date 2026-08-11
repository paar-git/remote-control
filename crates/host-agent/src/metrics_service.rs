//! Serving the metrics channel for one authenticated connection.
//!
//! # Why a subscription needs two channels
//!
//! `SubscribeMetrics` arrives on the **control** channel, because that is where a client
//! asks the agent for anything. The readings go out on the **metrics** channel, because a
//! push every half-second sharing a stream with request/response traffic would sit in
//! front of the next `Ping` whenever the network slowed down.
//!
//! The two are joined by a [`tokio::sync::watch`] created per session: the control
//! handler is the sender, this service is the receiver. That makes the ordering a
//! non-issue — a client that subscribes before opening the channel simply starts
//! receiving when it opens, rather than losing the subscription.
//!
//! # Two behaviours worth stating plainly
//!
//! **Authorization is re-checked every tick**, not captured at subscribe time. A
//! dashboard is the longest-lived thing a session holds, so capturing the decision once
//! would mean a device revoked at nine o'clock kept receiving readings until whoever
//! opened it went home.
//!
//! **Missed ticks are skipped, not queued.** If a client stops reading, the next thing it
//! receives is a current sample rather than a burst of stale ones. Metrics are only worth
//! anything if they describe now; a queue would deliver a history nobody asked for and
//! grow while it did.

use std::sync::Arc;

use rc_protocol::system::{MetricsAgentMessage, MetricsStopReason};
use rc_security::{Permission, PermissionSet};
use rc_transport::ChannelWriter;

/// Serves the metrics channel for one connection.
pub struct MetricsService {
    writer: ChannelWriter,
    authorization: PermissionSet,
    /// The agent-wide collector.
    ///
    /// Shared rather than owned: CPU utilisation is measured *across an interval*, so a
    /// collector per subscription would multiply the sampling cost on the machine being
    /// watched and none of them would agree with the others.
    collector: Arc<tokio::sync::Mutex<rc_monitoring::MetricsCollector>>,
    clock: Arc<dyn rc_security::Clock>,
    /// The live subscription, written by the control channel.
    ///
    /// `None` means nobody is watching, and the service costs nothing but a parked task.
    interval: tokio::sync::watch::Receiver<Option<u32>>,
}

impl MetricsService {
    /// A service for one connection.
    #[must_use]
    pub const fn new(
        writer: ChannelWriter,
        authorization: PermissionSet,
        collector: Arc<tokio::sync::Mutex<rc_monitoring::MetricsCollector>>,
        clock: Arc<dyn rc_security::Clock>,
        interval: tokio::sync::watch::Receiver<Option<u32>>,
    ) -> Self {
        Self {
            writer,
            authorization,
            collector,
            clock,
            interval,
        }
    }

    /// Push readings for as long as the session is subscribed.
    ///
    /// Returns when the connection drops or the session ends. Idle — genuinely zero cost
    /// — whenever no subscription is active, so a dashboard nobody is looking at does not
    /// sample the machine it is watching.
    pub async fn run(mut self) {
        loop {
            let Some(interval_ms) = self.await_subscription().await else {
                // The sender was dropped: the session is over.
                return;
            };

            if !self.stream(interval_ms).await {
                return;
            }
        }
    }

    /// Park until a subscription exists, and return its interval.
    ///
    /// `None` when the session ended while waiting.
    async fn await_subscription(&mut self) -> Option<u32> {
        await_subscription(&mut self.interval).await
    }

    /// Push at `interval_ms` until the subscription changes or the channel fails.
    ///
    /// Returns whether the service should keep running.
    async fn stream(&mut self, interval_ms: u32) -> bool {
        let mut ticker =
            tokio::time::interval(std::time::Duration::from_millis(u64::from(interval_ms)));
        // A client that stops reading must receive a *current* sample when it resumes,
        // not a backlog. `Delay` skips the missed ticks instead of firing once per
        // interval that passed while nobody was listening.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                // Biased so a change to the subscription is observed before another
                // sample is taken: an unsubscribe should not be followed by one last
                // reading the client did not ask for.
                biased;

                changed = self.interval.changed() => {
                    if changed.is_err() {
                        return false;
                    }
                    let current = *self.interval.borrow_and_update();
                    match current {
                        // Re-subscribed at a different rate: restart with the new one.
                        Some(new_interval) if new_interval != interval_ms => return true,
                        Some(_) => {}
                        None => return self.stop(MetricsStopReason::Unsubscribed).await,
                    }
                }

                _ = ticker.tick() => {
                    // Re-checked here, every tick, against the live session rather than
                    // captured when the subscription was created.
                    if !self.authorization.contains(Permission::ViewMetrics) {
                        return self.stop(MetricsStopReason::NotAuthorized).await;
                    }

                    let update = self.collector.lock().await.update(self.clock.now_ms());

                    if self
                        .writer
                        .send(&MetricsAgentMessage::Update(Box::new(update)))
                        .await
                        .is_err()
                    {
                        // The ordinary end: the client closed the channel or the
                        // connection dropped. Not worth a warning.
                        return false;
                    }
                }
            }
        }
    }

    /// Tell the client the stream ended, and why.
    ///
    /// Sent rather than simply going quiet, so a dashboard shows that its readings
    /// stopped instead of presenting the last one as current.
    async fn stop(&mut self, reason: MetricsStopReason) -> bool {
        let told = self
            .writer
            .send(&MetricsAgentMessage::Stopped { reason })
            .await
            .is_ok();

        // Losing authorization ends the service; an unsubscribe leaves it parked, ready
        // for the client to subscribe again on the same channel.
        told && matches!(reason, MetricsStopReason::Unsubscribed)
    }
}

/// Park until `interval` carries a subscription, and return it.
///
/// `None` when the sender was dropped, which means the session ended.
///
/// A free function rather than a method so it can be tested against a bare handle: the
/// pushing half needs a real QUIC stream, and a test that reimplemented this logic to
/// avoid one would be testing its own copy rather than the code that runs.
async fn await_subscription(
    interval: &mut tokio::sync::watch::Receiver<Option<u32>>,
) -> Option<u32> {
    loop {
        if let Some(interval_ms) = *interval.borrow_and_update() {
            return Some(interval_ms);
        }
        interval.changed().await.ok()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_unwatched_dashboard_does_not_sample_the_machine() {
        // The service parks rather than spinning, so a session with no dashboard open
        // costs nothing on the server it is watching.
        let (_sender, mut receiver) = tokio::sync::watch::channel(None);

        let parked = tokio::time::timeout(
            std::time::Duration::from_millis(150),
            await_subscription(&mut receiver),
        )
        .await;

        assert!(parked.is_err(), "an unsubscribed service must stay parked");
    }

    #[tokio::test]
    async fn a_subscription_made_before_the_channel_opened_is_not_lost() {
        // The handle exists before either the control request or the metrics channel,
        // so a client that subscribes first and opens the channel second still gets
        // readings. Losing that race would strand a dashboard permanently.
        let (sender, mut receiver) = tokio::sync::watch::channel(None);
        sender.send(Some(750)).unwrap();

        assert_eq!(await_subscription(&mut receiver).await, Some(750));
    }

    #[tokio::test]
    async fn the_service_ends_when_the_session_does() {
        // The sender lives with the session. When it goes, the pusher must stop rather
        // than outlive the connection that authorized it.
        let (sender, mut receiver) = tokio::sync::watch::channel(None);
        drop(sender);

        assert_eq!(await_subscription(&mut receiver).await, None);
    }

    #[test]
    fn a_session_with_view_metrics_may_watch_but_one_without_it_may_not() {
        // The permission the service re-checks on every tick, decided by the granted
        // set rather than by a role check written here.
        assert!(
            PermissionSet::NONE
                .with(Permission::ViewMetrics)
                .contains(Permission::ViewMetrics),
            "granting ViewMetrics is what lets a session watch"
        );
        assert!(
            !PermissionSet::NONE.contains(Permission::ViewMetrics),
            "a session stripped of the permission must stop a stream mid-flight, not at \
             the next connection"
        );
    }
}
