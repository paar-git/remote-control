//! The host side of the desktop application: accepting incoming connections.
//!
//! One program is both controller and controlled. The controlling half lives in
//! [`crate::connection`]; this is the half that answers the door.
//!
//! # What is here and what is not
//!
//! The *rule* for who may come in — a pinned peer, an unattended password, or a human
//! answering a prompt — is not here. It lives in `rc_host_agent::access` and is shared
//! with the standalone service, so the two cannot drift into deciding differently. This
//! module supplies that rule with the two things it cannot have on its own: somewhere
//! to put the question ([`TauriPrompt`]) and a listener to receive connections
//! ([`HostRuntime`]).
//!
//! # The prompt is a window, so the answer arrives out of band
//!
//! `AcceptPrompt::ask` is called on the connection's task and must return a decision,
//! but the decision is made by someone clicking a button in a webview. The two are
//! joined by a [`tokio::sync::oneshot`] and a request id: `ask` parks on the receiver,
//! `answer_accept_request` resolves the sender, and the id is what stops an answer to
//! one request being applied to another.
//!
//! Every way that can fail resolves to [`AcceptDecision::Dismiss`]:
//!
//! * nobody answers within [`ACCEPT_TIMEOUT`];
//! * the window closes, dropping the sender;
//! * an answer arrives naming a different request.
//!
//! Dismiss is the safe direction, and it is what an unattended machine does.
//!
//! # Why the window is behind a trait
//!
//! Nothing in this module names a Tauri type. [`DialogChannel`] is how a raised request
//! reaches a window, and [`crate::host_events`] is the only place that implements it
//! against a real one.
//!
//! That is not architectural taste, it is what makes this module testable at all. On
//! Windows, linking Tauri's window code into a binary requires a manifest asking for
//! comctl32 version 6: `TaskDialogIndirect`, `SetWindowSubclass`, `RemoveWindowSubclass`
//! and `DefSubclassProc` do not exist in the 5.82 copy in System32. The application
//! binary gets that manifest from `tauri-build`; a `cargo test` harness does not, and
//! fails to start with `STATUS_ENTRYPOINT_NOT_FOUND` before a single test runs.
//! Holding an `AppHandle` in a field the tests construct is enough to keep that code
//! reachable and drag it in. Behind a trait object, it stays out of the test binary.

use std::sync::Arc;
use std::time::Duration;

use rc_host_agent::{AcceptAnswer, AcceptDecision, AcceptPrompt, AcceptRequest};
use rc_security::PermissionSet;
use serde::Serialize;
use tokio::sync::{Mutex, oneshot};

/// How long a request waits for a human before it is dismissed.
///
/// A connection parked on a dialog holds a task, a QUIC connection and an unfinished
/// authorisation decision. Thirty seconds is long enough for someone who is at the
/// machine and short enough that someone who is not does not leave the door ajar.
pub const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);

/// The event the webview listens on to raise the Accept dialog.
pub const ACCEPT_REQUEST_EVENT: &str = "rc://accept-request";

/// The event the webview listens on to take the dialog back down.
///
/// Emitted when a request stops being answerable — a timeout, or the connection going
/// away — so a dialog cannot sit on screen inviting a click that would land on nothing.
pub const ACCEPT_RESOLVED_EVENT: &str = "rc://accept-resolved";

/// An accept request in the shape the webview receives it.
///
/// A separate type from [`AcceptRequest`] because this one crosses the IPC boundary and
/// must be camelCase, and because pinning it here means a field added to the internal
/// type does not silently start being sent to the webview.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AcceptRequestDto {
    /// Correlates the answer with the connection waiting on it.
    pub request_id: String,
    /// The address the connection came from.
    pub address: String,
    /// The identity the peer proved, as lowercase hex. Shown so a human can compare it
    /// against what the other machine displays.
    pub identity_fingerprint: String,
    /// The device id derived from that identity.
    pub device_id: String,
    /// The name the peer reported. Untrusted; the interface sanitises it again.
    pub machine_name: String,
    /// The operating system the peer reported. Untrusted.
    pub os_family: String,
    /// Whether this device is already trusted. It is being asked anyway, which is what
    /// trust without unattended access means.
    pub trusted: bool,
}

impl From<&AcceptRequest> for AcceptRequestDto {
    fn from(request: &AcceptRequest) -> Self {
        Self {
            request_id: request.request_id.clone(),
            address: request.address.clone(),
            identity_fingerprint: request.identity_fingerprint.to_hex(),
            device_id: request.device_id.clone(),
            machine_name: request.machine_name.clone(),
            os_family: request.os_family.clone(),
            trusted: request.trusted,
        }
    }
}

/// Where a raised accept request is announced, and where its withdrawal is announced.
///
/// Implemented against a real window by [`crate::host_events::WindowChannel`]. A prompt
/// with no channel attached still parks and still times out, so a request nobody can be
/// shown is dismissed rather than held open.
pub trait DialogChannel: Send + Sync {
    /// A request is now waiting for an answer.
    fn raised(&self, request: &AcceptRequestDto);
    /// The request that was waiting is no longer answerable.
    fn resolved(&self);
}

/// A request waiting on a human.
struct Pending {
    request: AcceptRequest,
    /// Resolved by `answer_accept_request`. Dropped on timeout, which is what makes a
    /// late answer land on a closed channel rather than on the next request.
    answer: oneshot::Sender<AcceptDecision>,
}

/// An [`AcceptPrompt`] backed by a Tauri window.
pub struct TauriPrompt {
    /// The one request that can be outstanding. See [`TauriPrompt::ask`].
    pending: Mutex<Option<Pending>>,
    /// Where a raised request is announced.
    ///
    /// Set once, from the Tauri `setup` hook: the state this prompt lives in is built
    /// before there is a window to announce into. Never set in tests, which drive
    /// [`TauriPrompt::ask`] directly and assert on the decision rather than on a window.
    channel: std::sync::OnceLock<Arc<dyn DialogChannel>>,
    /// Overridable so a test does not have to wait out the real one.
    timeout: Duration,
}

impl std::fmt::Debug for TauriPrompt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No pending request and no app handle: the request carries a peer-supplied
        // machine name and a fingerprint, neither of which belongs in a log line
        // written by accident.
        formatter
            .debug_struct("TauriPrompt")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl TauriPrompt {
    /// A prompt with nowhere to raise its dialog yet. See [`TauriPrompt::attach`].
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            pending: Mutex::new(None),
            channel: std::sync::OnceLock::new(),
            timeout: ACCEPT_TIMEOUT,
        })
    }

    /// Give the prompt a window to raise its dialog in.
    ///
    /// Called once, from Tauri's `setup` hook. Calling it again is ignored rather than
    /// an error: the first window is the one the user is looking at, and silently
    /// re-pointing the dialog at a later one would send a request somewhere nobody is
    /// watching.
    pub fn attach(&self, channel: Arc<dyn DialogChannel>) {
        if self.channel.set(channel).is_err() {
            tracing::warn!("the accept prompt already has a window; ignoring the second");
        }
    }

    /// A prompt with no window, for tests.
    #[cfg(test)]
    #[must_use]
    pub fn for_tests() -> Arc<Self> {
        Self::new()
    }

    /// The request currently waiting on a human, if any.
    ///
    /// The webview polls this on startup so a dialog raised before the window was ready
    /// is not lost — an event fired at a webview that is not listening yet goes nowhere.
    pub async fn pending(&self) -> Option<AcceptRequestDto> {
        self.pending
            .lock()
            .await
            .as_ref()
            .map(|pending| AcceptRequestDto::from(&pending.request))
    }

    /// Answer the pending request.
    ///
    /// Returns whether an answer was delivered. `false` means there was nothing waiting,
    /// or what was waiting was a different request — a stale dialog answering after its
    /// own request timed out. Neither is an error the user should see; both mean the
    /// click had no effect because the connection it referred to is gone.
    pub async fn answer(&self, request_id: &str, decision: AcceptDecision) -> bool {
        let mut slot = self.pending.lock().await;

        // Checked before taking, so an answer naming a different request leaves the
        // genuine pending request in place rather than discarding it.
        if slot
            .as_ref()
            .is_none_or(|p| p.request.request_id != request_id)
        {
            return false;
        }

        let Some(pending) = slot.take() else {
            return false;
        };
        // A send failure means `ask` has already given up and gone; the decision is
        // simply too late, which is the same outcome as never having answered.
        pending.answer.send(decision).is_ok()
    }

    /// Tell the window a request has appeared.
    fn announce_raised(&self, request: &AcceptRequestDto) {
        // Before `attach`, or in tests: nowhere to announce into. The request still
        // parks and still times out, so a dialog that never appears is dismissed rather
        // than held open.
        if let Some(channel) = self.channel.get() {
            channel.raised(request);
        }
    }

    /// Tell the window the request is no longer answerable.
    fn announce_resolved(&self) {
        if let Some(channel) = self.channel.get() {
            channel.resolved();
        }
    }
}

#[async_trait::async_trait]
impl AcceptPrompt for TauriPrompt {
    async fn ask(&self, request: AcceptRequest) -> AcceptAnswer {
        let request_id = request.request_id.clone();
        let dismissed = || AcceptAnswer {
            request_id: request_id.clone(),
            decision: AcceptDecision::Dismiss,
        };

        let (sender, receiver) = oneshot::channel();

        {
            let mut slot = self.pending.lock().await;
            if slot.is_some() {
                // There is one slot because there can be one dialog. `authorize_connection`
                // is what *enforces* the one-at-a-time rule — it holds a gate across this
                // whole call, so in production a second request cannot arrive here at all.
                // This is not a second policy that could disagree with that one; it is the
                // only honest thing a single slot can do if the invariant is ever broken,
                // and it fails in the same direction.
                tracing::warn!(
                    "an accept request arrived while one was already pending; dismissing it"
                );
                return dismissed();
            }
            let dto = AcceptRequestDto::from(&request);
            *slot = Some(Pending {
                request,
                answer: sender,
            });
            // Announced while the lock is held so the webview cannot be told about a
            // request that has already been answered by the time it hears about it.
            self.announce_raised(&dto);
        }

        let decision = match tokio::time::timeout(self.timeout, receiver).await {
            Ok(Ok(decision)) => decision,
            // The sender was dropped: the window closed, or the slot was cleared.
            Ok(Err(_)) => AcceptDecision::Dismiss,
            Err(_) => {
                tracing::info!("an accept request timed out with nobody answering; dismissing");
                AcceptDecision::Dismiss
            }
        };

        // Clear the slot only if it still holds *this* request. A later request that
        // has already claimed the slot must not be evicted by an earlier one finishing.
        {
            let mut slot = self.pending.lock().await;
            if slot
                .as_ref()
                .is_some_and(|p| p.request.request_id == request_id)
            {
                *slot = None;
            }
        }
        self.announce_resolved();

        AcceptAnswer {
            request_id,
            decision,
        }
    }
}

/// The listener and everything it needs.
///
/// Owns the running QUIC listener, if one is running. Starting and stopping it is what
/// "accepting" means at the network layer; the decision layer refuses independently
/// when the setting is off, so the two together fail closed rather than relying on
/// either alone.
pub struct HostRuntime {
    /// The prompt, shared with the running listener.
    prompt: Arc<TauriPrompt>,
    /// Cancels the running listener. `None` when nothing is listening.
    listener: Mutex<Option<ListenerHandle>>,
    /// The live sessions of the running listener, if one is running.
    ///
    /// Borrowed from the agent rather than kept separately: a second list of who is
    /// connected is a second answer that can disagree with the first, and the one thing
    /// this display must never do is say nobody is controlling the machine while
    /// somebody is.
    sessions: Mutex<Option<Arc<rc_host_agent::sessions::SessionRegistry>>>,
}

/// A running listener and the switch that stops it.
struct ListenerHandle {
    shutdown: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
    port: u16,
}

impl HostRuntime {
    /// A runtime with nothing listening yet.
    #[must_use]
    pub fn new(prompt: Arc<TauriPrompt>) -> Self {
        Self {
            prompt,
            listener: Mutex::new(None),
            sessions: Mutex::new(None),
        }
    }

    /// The prompt this runtime answers with.
    #[must_use]
    pub fn prompt(&self) -> &Arc<TauriPrompt> {
        &self.prompt
    }

    /// Whether a listener is currently bound.
    pub async fn is_listening(&self) -> bool {
        self.listener.lock().await.is_some()
    }

    /// The port a listener is bound to, if one is.
    pub async fn listening_port(&self) -> Option<u16> {
        self.listener.lock().await.as_ref().map(|l| l.port)
    }

    /// Sessions currently controlling this machine.
    ///
    /// Empty when nothing is listening, which is the truth rather than a placeholder:
    /// a machine that is not accepting cannot be being controlled.
    pub async fn inbound_sessions(&self) -> Vec<rc_host_agent::sessions::LiveSession> {
        self.sessions
            .lock()
            .await
            .as_ref()
            .map(|registry| registry.list())
            .unwrap_or_default()
    }

    /// End one session controlling this machine.
    ///
    /// Reports whether it was there to end rather than always succeeding.
    pub async fn disconnect_inbound(&self, session_id: rc_protocol::SessionId) -> bool {
        let registry = self.sessions.lock().await.clone();
        registry.is_some_and(|registry| registry.end(session_id))
    }

    /// End every session controlling this machine, returning how many were ended.
    pub async fn disconnect_all_inbound(&self) -> usize {
        let registry = self.sessions.lock().await.clone();
        registry.map_or(0, |registry| registry.end_all())
    }

    /// Stop the listener, if one is running.
    ///
    /// Waits for it to finish so a subsequent start cannot race the old one for the
    /// port and report a bind failure that is really just a slow shutdown.
    pub async fn stop(&self) {
        // Cleared first: a stopped listener has no sessions, and reporting the last
        // ones it had would be a display of connections that no longer exist.
        self.sessions.lock().await.take();

        let handle = self.listener.lock().await.take();
        if let Some(handle) = handle {
            // A send failure means the task has already ended, which is the state being
            // asked for.
            let _ = handle.shutdown.send(());
            if let Err(err) = handle.task.await {
                tracing::warn!(%err, "the listener task did not stop cleanly");
            }
            tracing::info!("stopped accepting incoming connections");
        }
    }

    /// Start a listener on `port`, replacing any already running.
    ///
    /// # Errors
    /// If the socket cannot be bound — most often because something else already holds
    /// the port, which the user needs to be told rather than left wondering why nothing
    /// connects.
    pub async fn start(
        self: &Arc<Self>,
        identity: Arc<rc_security::DeviceIdentity>,
        database: &rc_storage::Database,
        port: u16,
    ) -> anyhow::Result<()> {
        self.stop().await;

        let mut config = rc_host_agent::config::AgentConfig::default();
        config.network.listen_port = port;

        let server = Arc::new(rc_host_agent::server::AgentServer::new(
            identity,
            config,
            database,
            Arc::clone(&self.prompt) as Arc<dyn AcceptPrompt>,
        ));

        let (shutdown, on_shutdown) = oneshot::channel();
        let ready = server.listener_ready();
        *self.sessions.lock().await = Some(server.sessions());

        let task = tokio::spawn(async move {
            if let Err(err) = server
                .run(async move {
                    let _ = on_shutdown.await;
                })
                .await
            {
                tracing::error!(%err, "the incoming-connection listener stopped");
            }
        });

        // The bind happens inside the task, so its failure has to be observed rather
        // than returned. Reporting success before the socket exists would tell the user
        // they are reachable when they are not.
        for _ in 0..100 {
            if ready.load(std::sync::atomic::Ordering::Acquire) {
                *self.listener.lock().await = Some(ListenerHandle {
                    shutdown,
                    task,
                    port,
                });
                tracing::info!(port, "accepting incoming connections");
                return Ok(());
            }
            if task.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        task.abort();
        anyhow::bail!("could not listen on port {port}; something else may be using it")
    }
}

/// Turn the permission names the webview sent into a set.
///
/// Returns `None` for a name this build does not know, rather than dropping it: a
/// request to grant something unrecognised is not a request to grant one thing fewer.
#[must_use]
pub fn permissions_from_names(names: &[String]) -> Option<PermissionSet> {
    names.iter().try_fold(PermissionSet::NONE, |set, name| {
        rc_security::Permission::ALL
            .into_iter()
            .find(|permission| permission.name() == name)
            .map(|permission| set.with(permission))
    })
}

/// The names of the permissions in `set`, for the webview.
#[must_use]
pub fn permission_names(set: PermissionSet) -> Vec<String> {
    set.iter().map(|p| p.name().to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rc_host_agent::{AcceptDecision, AcceptPrompt, TrustChoice};
    use rc_security::{Permission, PermissionSet};

    use super::*;

    fn test_request() -> AcceptRequest {
        AcceptRequest {
            request_id: "r1".to_owned(),
            address: "192.168.1.77:7443".to_owned(),
            identity_fingerprint: rc_security::Fingerprint::from_bytes([7u8; 32]),
            device_id: "dev-test".to_owned(),
            machine_name: "WORK-LAPTOP".to_owned(),
            os_family: "windows".to_owned(),
            trusted: false,
        }
    }

    fn request_named(id: &str) -> AcceptRequest {
        AcceptRequest {
            request_id: id.to_owned(),
            ..test_request()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_prompt_nobody_answers_becomes_a_dismissal() {
        // An unattended machine must close its own door. Blocking forever would hold
        // the connection, the task and an undecided authorisation open indefinitely.
        let prompt = TauriPrompt::for_tests();

        let answer = prompt.ask(test_request()).await;

        assert_eq!(answer.decision, AcceptDecision::Dismiss);
        assert_eq!(answer.request_id, "r1", "the answer names its own request");
    }

    #[tokio::test(start_paused = true)]
    async fn a_timed_out_request_stops_being_answerable() {
        // The slot must be cleared, or the next connection would find it occupied and
        // be dismissed because of a dialog nobody is looking at any more.
        let prompt = TauriPrompt::for_tests();

        prompt.ask(test_request()).await;

        assert!(prompt.pending().await.is_none(), "the slot must be free");
        assert!(
            !prompt
                .answer(
                    "r1",
                    AcceptDecision::Accept {
                        permissions: PermissionSet::ALL,
                        trust: TrustChoice::Once
                    }
                )
                .await,
            "a late answer to a timed-out request must not be delivered"
        );
    }

    #[tokio::test]
    async fn an_answer_is_delivered_with_exactly_the_permissions_it_carried() {
        // The dangerous direction is widening. A grant of one permission must arrive as
        // one permission, not as whatever the dialog defaulted to.
        let prompt = TauriPrompt::for_tests();
        let granted = PermissionSet::NONE.with(Permission::ViewMetrics);

        let asking = tokio::spawn({
            let prompt = Arc::clone(&prompt);
            async move { prompt.ask(test_request()).await }
        });

        // Wait for the request to occupy the slot rather than guessing at a delay.
        while prompt.pending().await.is_none() {
            tokio::task::yield_now().await;
        }
        assert!(
            prompt
                .answer(
                    "r1",
                    AcceptDecision::Accept {
                        permissions: granted,
                        trust: TrustChoice::Once
                    }
                )
                .await
        );

        let answer = asking.await.unwrap();
        assert_eq!(
            answer.decision,
            AcceptDecision::Accept {
                permissions: granted,
                trust: TrustChoice::Once
            }
        );
        assert_eq!(answer.request_id, "r1");
    }

    #[tokio::test]
    async fn an_answer_naming_a_different_request_is_not_applied() {
        // The answer comes back from a window, not from the connection. Without the id
        // check, a stale dialog could grant a peer the permissions a human approved for
        // a different one.
        let prompt = TauriPrompt::for_tests();

        let asking = tokio::spawn({
            let prompt = Arc::clone(&prompt);
            async move { prompt.ask(request_named("genuine")).await }
        });
        while prompt.pending().await.is_none() {
            tokio::task::yield_now().await;
        }

        assert!(
            !prompt
                .answer(
                    "stale",
                    AcceptDecision::Accept {
                        permissions: PermissionSet::ALL,
                        trust: TrustChoice::Once
                    }
                )
                .await,
            "an answer to another request must be refused"
        );
        assert!(
            prompt.pending().await.is_some(),
            "and must leave the genuine request waiting, not discard it"
        );

        assert!(prompt.answer("genuine", AcceptDecision::Dismiss).await);
        assert_eq!(asking.await.unwrap().decision, AcceptDecision::Dismiss);
    }

    #[tokio::test]
    async fn a_second_request_while_one_is_open_is_dismissed_immediately() {
        // Stacking dialogs would let anyone with the address bury the machine in
        // prompts until one is clicked by accident.
        let prompt = TauriPrompt::for_tests();
        let first = tokio::spawn({
            let prompt = Arc::clone(&prompt);
            async move { prompt.ask(request_named("first")).await }
        });
        while prompt.pending().await.is_none() {
            tokio::task::yield_now().await;
        }

        let second =
            tokio::time::timeout(Duration::from_secs(1), prompt.ask(request_named("second")))
                .await
                .expect("the second request must be refused at once, not queued");

        assert_eq!(second.decision, AcceptDecision::Dismiss);
        assert_eq!(second.request_id, "second");
        assert_eq!(
            prompt.pending().await.map(|p| p.request_id),
            Some("first".to_owned()),
            "the first request must still be the one on screen"
        );
        first.abort();
    }

    #[tokio::test]
    async fn the_request_the_window_receives_carries_no_more_than_it_needs() {
        let prompt = TauriPrompt::for_tests();
        let asking = tokio::spawn({
            let prompt = Arc::clone(&prompt);
            async move { prompt.ask(test_request()).await }
        });
        while prompt.pending().await.is_none() {
            tokio::task::yield_now().await;
        }

        let dto = prompt.pending().await.unwrap();
        assert_eq!(
            dto.identity_fingerprint.len(),
            64,
            "the identity reaches the UI whole -- it is compared by eye, so a              truncated one would be compared against nothing"
        );
        assert_eq!(dto.machine_name, "WORK-LAPTOP");

        let json = serde_json::to_value(&dto).unwrap();
        for key in [
            "requestId",
            "address",
            "identityFingerprint",
            "deviceId",
            "machineName",
            "osFamily",
            "trusted",
        ] {
            assert!(json.get(key).is_some(), "missing key {key}");
        }
        assert_eq!(
            json.as_object().unwrap().len(),
            7,
            "nothing beyond those seven fields may cross the boundary, got {json}"
        );

        asking.abort();
    }

    #[test]
    fn an_unknown_permission_name_is_refused_rather_than_dropped() {
        // Granting three of four requested permissions silently would be a different,
        // narrower decision than the one that was asked for.
        assert_eq!(
            permissions_from_names(&["view_metrics".to_owned()]),
            Some(PermissionSet::NONE.with(Permission::ViewMetrics))
        );
        assert_eq!(
            permissions_from_names(&["view_metrics".to_owned(), "launch_missiles".to_owned()]),
            None
        );
    }

    #[test]
    fn permission_names_round_trip() {
        for set in [
            PermissionSet::NONE,
            PermissionSet::ALL,
            PermissionSet::NONE.with(Permission::TransferFiles),
        ] {
            assert_eq!(permissions_from_names(&permission_names(set)), Some(set));
        }
    }

    #[tokio::test]
    async fn nothing_is_listening_until_it_is_started() {
        let runtime = HostRuntime::new(TauriPrompt::for_tests());
        assert!(!runtime.is_listening().await);
        assert_eq!(runtime.listening_port().await, None);
        // Stopping something that is not running is not an error: the caller wanted it
        // stopped and it already is.
        runtime.stop().await;
    }
}
