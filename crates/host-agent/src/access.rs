//! Deciding what an incoming connection may do.
//!
//! Three ways in, checked in a fixed order, and the order is the design:
//!
//! 1. **A pinned peer.** The user has already decided about this machine. If the
//!    fingerprint does not match the pin, the connection is refused outright — never
//!    handed to the Accept dialog, because an identity change must not be reachable by
//!    a routine click.
//! 2. **An unattended password**, if the connection offered one. A wrong password is a
//!    refusal, not a fallback to the dialog: falling back would let anyone with the
//!    address raise a prompt on someone's screen by guessing, and would make a wrong
//!    password indistinguishable from no password.
//! 3. **A human.** The dialog, with the timeout and the default both set to Dismiss.
//!
//! Nothing here talks to a network or a window. The prompt is a trait so the whole
//! decision can be tested against a scripted answer, and so the desktop application
//! and the service can present it differently without either owning the rule.

use async_trait::async_trait;
use rc_security::{Clock, Fingerprint, PermissionSet, Throttle};
use rc_storage::{RecentRepository, SettingsRepository};
use rc_transport::PeerAddress;
use tokio::sync::Mutex;

use crate::error::Result;

/// What the person at the keyboard is shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptRequest {
    /// Correlates the dialog with the connection waiting on it.
    ///
    /// The answer arrives from a window, not from the connection, so without this an
    /// answer could be applied to whichever request happened to be open.
    pub request_id: String,
    /// The address the connection came from, as it will be displayed.
    pub address: String,
    /// The peer's certificate fingerprint, taken from the TLS connection.
    pub fingerprint: Fingerprint,
    /// The name the peer reported. Untrusted, and displayed as such.
    pub machine_name: String,
}

/// What they decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptDecision {
    /// Accept, granting exactly these permissions.
    Accept(PermissionSet),
    /// Refuse. Also what a timeout, an Escape and a closed window mean.
    Dismiss,
}

/// An answer to a specific [`AcceptRequest`].
///
/// Carries back the ID it answers, so `authorize_connection` can tell a genuine answer
/// to the request it is holding open from a stale answer to some other request — a
/// dismissed dialog that finally reports in, or an answer meant for a request that has
/// since been superseded. A prompt implementation gets this ID from the
/// [`AcceptRequest`] it was shown; nothing here trusts an ID the peer could supply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptAnswer {
    /// The [`AcceptRequest::request_id`] this answers.
    pub request_id: String,
    /// What the human decided.
    pub decision: AcceptDecision,
}

/// Asks a human.
#[async_trait]
pub trait AcceptPrompt: Send + Sync {
    /// Show the request and return the answer.
    ///
    /// Implementations must return [`AcceptDecision::Dismiss`] on a timeout rather than
    /// blocking forever: a connection held open waiting for someone who went home is a
    /// resource leak with an authorisation decision attached. The returned
    /// [`AcceptAnswer::request_id`] must be `request.request_id` — echoing it back is
    /// what lets the caller detect a stale or misrouted answer.
    async fn ask(&self, request: AcceptRequest) -> AcceptAnswer;
}

/// An incoming connection, after TLS and before any authorisation.
#[derive(Debug, Clone)]
pub struct ConnectionRequest {
    /// The address the peer connected from.
    pub address: PeerAddress,
    /// The peer's certificate fingerprint, taken from the TLS connection.
    pub fingerprint: Fingerprint,
    /// The name the peer reported. Untrusted, and displayed as such.
    pub machine_name: String,
    /// The unattended password the peer offered, if it offered one.
    pub unattended_password: Option<String>,
}

/// Why a connection was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// A human said no, or said nothing for long enough.
    Dismissed,
    /// This machine is not accepting connections at all.
    NotAccepting,
    /// A pinned peer presented a different certificate.
    IdentityChanged,
    /// An unattended password was offered and was wrong, or none is configured.
    WrongPassword,
    /// Too many wrong passwords; the lockout is in force.
    TooManyAttempts,
}

/// The outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorization {
    /// Proceed, holding exactly these permissions for the whole session.
    Granted(PermissionSet),
    /// Do not proceed.
    Refused(RefusalReason),
}

/// Everything the decision reads or writes.
pub struct AccessDeps<'a> {
    /// This machine's own settings: whether it accepts connections, and unattended
    /// access.
    pub settings: &'a SettingsRepository,
    /// Machines this installation has connected to, including any pinned identity.
    pub recent: &'a RecentRepository,
    /// Asks a human when neither a pin nor a password settles the decision.
    pub prompt: &'a dyn AcceptPrompt,
    /// Rate-limits unattended-password attempts, keyed by address.
    pub throttle: &'a Mutex<Throttle>,
    /// The source of "now" for the throttle.
    pub clock: &'a dyn Clock,
}

/// Decide what an incoming connection may do.
pub async fn authorize_connection(
    request: &ConnectionRequest,
    deps: &AccessDeps<'_>,
) -> Result<Authorization> {
    // Read once. Two reads could straddle a settings change and decide against two
    // different configurations within one connection.
    let settings = deps.settings.load().await?;
    if !settings.accepting {
        return Ok(Authorization::Refused(RefusalReason::NotAccepting));
    }

    let key = request.address.to_string();

    // 1. A decision the user already made about this machine.
    if let Some(entry) = deps.recent.find(&key).await?
        && let Some(pinned) = entry.pinned_fingerprint
    {
        // `ct_eq`, not `==`. The crate provides it precisely so no comparison of an
        // identity anywhere in the tree is the one that leaks a timing signal.
        return Ok(if pinned.ct_eq(&request.fingerprint) {
            Authorization::Granted(entry.pinned_permissions)
        } else {
            Authorization::Refused(RefusalReason::IdentityChanged)
        });
    }

    // 2. An unattended password, if one was offered.
    if let Some(offered) = request.unattended_password.as_deref() {
        // Checked before hashing, so a lockout cannot be turned into a
        // work-amplification vector.
        {
            let throttle = deps.throttle.lock().await;
            if throttle.check(&key, deps.clock).is_err() {
                return Ok(Authorization::Refused(RefusalReason::TooManyAttempts));
            }
        }

        let stored = deps.settings.unattended_credential().await?;
        let permitted = settings.unattended_permissions;

        let verified = if let Some(credential) = &stored {
            credential.verify(offered).is_ok()
        } else {
            // A full dummy hash, so "no unattended access configured" and "wrong
            // password" cost the same and answer the same. Otherwise the timing
            // discloses whether unattended access exists.
            let _ = rc_security::password::verify_against_nothing(
                offered,
                rc_security::HashingPolicy::PRODUCTION,
            );
            false
        };

        let mut throttle = deps.throttle.lock().await;
        return Ok(if verified {
            throttle.record_success(&key, deps.clock);
            Authorization::Granted(permitted)
        } else {
            throttle.record_failure(&key, deps.clock);
            Authorization::Refused(RefusalReason::WrongPassword)
        });
    }

    // 3. Ask a human.
    //
    // Generated here, never accepted from the peer or from any caller-supplied value:
    // it exists only to match this specific answer back to this specific request.
    let request_id = uuid::Uuid::new_v4().to_string();
    let answer = deps
        .prompt
        .ask(AcceptRequest {
            request_id: request_id.clone(),
            address: key,
            fingerprint: request.fingerprint,
            machine_name: request.machine_name.clone(),
        })
        .await;

    // An answer to a different request — stale, from a dialog that timed out, or
    // otherwise misrouted — must never be applied here, no matter what it says. This
    // is checked before looking at the decision at all: a mismatched Accept is refused
    // exactly like a mismatched Dismiss, so there is no path from "wrong ID" to
    // "granted anyway".
    if answer.request_id != request_id {
        return Ok(Authorization::Refused(RefusalReason::Dismissed));
    }

    Ok(match answer.decision {
        // Accepting with nothing ticked is a session that can do nothing and that
        // nobody can see. Refusing says the same thing more clearly.
        AcceptDecision::Accept(granted) if !granted.is_empty() => Authorization::Granted(granted),
        _ => Authorization::Refused(RefusalReason::Dismissed),
    })
}

#[cfg(test)]
mod tests {
    use rc_security::{
        HashingPolicy, OsRandom, PasswordCredential, Permission, PermissionSet, Throttle,
    };
    use rc_storage::{RecentRepository, SettingsRepository};
    use rc_transport::PeerAddress;

    use super::*;

    /// A prompt that answers however the test says, and counts how often it was asked.
    ///
    /// By default it echoes back the real `request_id` it was shown, like a correct
    /// implementation must. [`ScriptedPrompt::stale`] builds one that answers with a
    /// different ID instead, standing in for a dialog answering out of turn.
    struct ScriptedPrompt {
        answer: AcceptDecision,
        /// `None` echoes the request's own ID, as a correct prompt does. `Some` forces
        /// a mismatched answer, simulating a stale or misrouted response.
        respond_with: Option<String>,
        asked: std::sync::atomic::AtomicUsize,
    }

    impl ScriptedPrompt {
        fn new(answer: AcceptDecision) -> Self {
            Self {
                answer,
                respond_with: None,
                asked: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        /// A prompt whose answer always carries `wrong_request_id`, regardless of what
        /// request it was actually shown.
        fn stale(answer: AcceptDecision, wrong_request_id: impl Into<String>) -> Self {
            Self {
                answer,
                respond_with: Some(wrong_request_id.into()),
                asked: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn asked(&self) -> usize {
            self.asked.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl AcceptPrompt for ScriptedPrompt {
        async fn ask(&self, request: AcceptRequest) -> AcceptAnswer {
            self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let request_id = self.respond_with.clone().unwrap_or(request.request_id);
            AcceptAnswer {
                request_id,
                decision: self.answer,
            }
        }
    }

    fn request(password: Option<&str>) -> ConnectionRequest {
        ConnectionRequest {
            address: "192.168.1.77".parse::<PeerAddress>().unwrap(),
            fingerprint: Fingerprint::from_bytes([7u8; 32]),
            machine_name: "WORK-LAPTOP".to_owned(),
            unattended_password: password.map(str::to_owned),
        }
    }

    /// Everything `authorize_connection` needs, built fresh for each test.
    struct Harness {
        settings: SettingsRepository,
        recent: RecentRepository,
        prompt: ScriptedPrompt,
        throttle: Mutex<Throttle>,
        clock: rc_security::clock::TestClock,
        // Kept alive for the lifetime of the harness: the repositories borrow its pool.
        _database: rc_storage::Database,
    }

    impl Harness {
        async fn new(prompt: ScriptedPrompt) -> Self {
            let database = rc_storage::Database::open_in_memory()
                .await
                .expect("an in-memory database must always open and migrate cleanly");
            let settings = SettingsRepository::new(&database);
            let recent = RecentRepository::new(&database);
            Self {
                settings,
                recent,
                prompt,
                throttle: Mutex::new(Throttle::with_defaults()),
                clock: rc_security::clock::TestClock::default(),
                _database: database,
            }
        }

        fn settings(&self) -> &SettingsRepository {
            &self.settings
        }

        fn recent(&self) -> &RecentRepository {
            &self.recent
        }

        fn prompt(&self) -> &ScriptedPrompt {
            &self.prompt
        }

        async fn set_unattended(&self, password: &str, permissions: PermissionSet) {
            let credential =
                PasswordCredential::create(password, HashingPolicy::FAST_FOR_TESTS, &OsRandom)
                    .expect("a password meeting the policy must hash successfully");
            self.settings
                .set_unattended(Some(&credential), permissions)
                .await
                .expect("storing the unattended credential must succeed");
        }

        async fn authorize(&self, request: ConnectionRequest) -> Result<Authorization> {
            let deps = AccessDeps {
                settings: &self.settings,
                recent: &self.recent,
                prompt: &self.prompt,
                throttle: &self.throttle,
                clock: &self.clock,
            };
            authorize_connection(&request, &deps).await
        }
    }

    #[tokio::test]
    async fn a_dismissed_connection_is_refused_and_grants_nothing() {
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        let outcome = harness.authorize(request(None)).await.unwrap();
        assert_eq!(outcome, Authorization::Refused(RefusalReason::Dismissed));
    }

    #[tokio::test]
    async fn an_accepted_connection_gets_exactly_what_the_human_ticked() {
        let granted = PermissionSet::NONE.with(Permission::ViewMetrics);
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept(granted))).await;
        let outcome = harness.authorize(request(None)).await.unwrap();
        assert_eq!(outcome, Authorization::Granted(granted));
    }

    #[tokio::test]
    async fn a_machine_not_accepting_connections_is_never_prompted() {
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept(
            PermissionSet::ALL,
        )))
        .await;
        harness.settings().set_accepting(false).await.unwrap();

        let outcome = harness.authorize(request(None)).await.unwrap();
        assert_eq!(outcome, Authorization::Refused(RefusalReason::NotAccepting));
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn an_always_allow_peer_skips_the_prompt() {
        let granted = PermissionSet::NONE.with(Permission::TransferFiles);
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness
            .recent()
            .record("192.168.1.77:7443", "WORK-LAPTOP", 1_000)
            .await
            .unwrap();
        harness
            .recent()
            .set_always_allow(
                "192.168.1.77:7443",
                Some(Fingerprint::from_bytes([7u8; 32])),
                granted,
            )
            .await
            .unwrap();

        let outcome = harness.authorize(request(None)).await.unwrap();
        assert_eq!(outcome, Authorization::Granted(granted));
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn a_pinned_peer_presenting_a_different_fingerprint_is_refused_not_prompted() {
        // This is the loudest failure the system has. Falling back to the Accept
        // dialog would turn an identity change into a routine click.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept(
            PermissionSet::ALL,
        )))
        .await;
        harness
            .recent()
            .record("192.168.1.77:7443", "WORK-LAPTOP", 1_000)
            .await
            .unwrap();
        harness
            .recent()
            .set_always_allow(
                "192.168.1.77:7443",
                Some(Fingerprint::from_bytes([99u8; 32])),
                PermissionSet::ALL,
            )
            .await
            .unwrap();

        let outcome = harness.authorize(request(None)).await.unwrap();
        assert_eq!(
            outcome,
            Authorization::Refused(RefusalReason::IdentityChanged)
        );
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn a_correct_unattended_password_skips_the_prompt() {
        let granted = PermissionSet::NONE.with(Permission::ControlInput);
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness
            .set_unattended("correct horse battery", granted)
            .await;

        let outcome = harness
            .authorize(request(Some("correct horse battery")))
            .await
            .unwrap();
        assert_eq!(outcome, Authorization::Granted(granted));
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn a_wrong_unattended_password_is_refused_without_falling_back_to_the_prompt() {
        // Falling back would make a wrong password indistinguishable from no password
        // and would let an attacker convert a guess into a prompt on someone's screen.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept(
            PermissionSet::ALL,
        )))
        .await;
        harness
            .set_unattended("correct horse battery", PermissionSet::ALL)
            .await;

        let outcome = harness
            .authorize(request(Some("wrong password here")))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            Authorization::Refused(RefusalReason::WrongPassword)
        );
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn a_password_offered_when_none_is_configured_is_refused_identically() {
        // The answer must not disclose whether unattended access exists.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept(
            PermissionSet::ALL,
        )))
        .await;
        let outcome = harness
            .authorize(request(Some("anything at all")))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            Authorization::Refused(RefusalReason::WrongPassword)
        );
    }

    #[tokio::test]
    async fn repeated_wrong_passwords_lock_out_before_hashing() {
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness
            .set_unattended("correct horse battery", PermissionSet::ALL)
            .await;

        for _ in 0..5 {
            let _ = harness
                .authorize(request(Some("wrong password here")))
                .await
                .unwrap();
        }
        let outcome = harness
            .authorize(request(Some("correct horse battery")))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            Authorization::Refused(RefusalReason::TooManyAttempts)
        );
    }

    #[tokio::test]
    async fn no_password_offered_still_reaches_the_prompt_when_unattended_is_configured() {
        // Configuring unattended access adds a second way in; it does not remove the
        // first.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept(
            PermissionSet::ALL,
        )))
        .await;
        harness
            .set_unattended("correct horse battery", PermissionSet::ALL)
            .await;

        let outcome = harness.authorize(request(None)).await.unwrap();
        assert_eq!(outcome, Authorization::Granted(PermissionSet::ALL));
        assert_eq!(harness.prompt().asked(), 1);
    }

    #[tokio::test]
    async fn accepting_with_nothing_ticked_is_a_refusal_not_an_empty_session() {
        // A session that may do nothing is a connection nobody can use and nobody can
        // see. Saying no is clearer.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept(
            PermissionSet::NONE,
        )))
        .await;
        let outcome = harness.authorize(request(None)).await.unwrap();
        assert_eq!(outcome, Authorization::Refused(RefusalReason::Dismissed));
    }

    #[tokio::test]
    async fn a_stale_answer_with_the_wrong_request_id_is_never_applied() {
        // The dangerous direction: a human said Accept(ALL), but not to *this*
        // request — a dialog that timed out, or an answer meant for a different,
        // superseded connection. Applying it anyway would grant a peer permissions a
        // human approved for someone else. The correlation ID exists to make this
        // path structurally unreachable, not merely unlikely.
        let harness = Harness::new(ScriptedPrompt::stale(
            AcceptDecision::Accept(PermissionSet::ALL),
            "not-the-request-that-is-pending",
        ))
        .await;

        let outcome = harness.authorize(request(None)).await.unwrap();
        assert_eq!(outcome, Authorization::Refused(RefusalReason::Dismissed));
        assert_eq!(
            harness.prompt().asked(),
            1,
            "the prompt was reached; its mismatched answer must simply not count"
        );
    }
}
