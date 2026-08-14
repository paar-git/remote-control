//! Deciding what an incoming connection may do.
//!
//! Three ways in, checked in a fixed order, and the order is the design:
//!
//! 1. **A trusted device.** Found by the identity the peer *proved* by completing TLS —
//!    see [`rc_security::certificate`] — never by the address it arrived from. A device
//!    marked for unattended access is admitted with exactly what it was granted. A
//!    device that is merely trusted still reaches the dialog, because remembering a
//!    machine and letting it in unasked are different decisions.
//! 2. **An unattended password**, if the connection offered one. A wrong password is a
//!    refusal, not a fallback to the dialog: falling back would let anyone with the
//!    address raise a prompt on someone's screen by guessing, and would make a wrong
//!    password indistinguishable from no password.
//! 3. **A human.** The dialog, with the timeout and the default both set to Dismiss, and
//!    at most one dialog pending at a time — a second connection arriving while one is
//!    open is refused immediately, without ever reaching the prompt.
//!
//! # Why the identity and not the address
//!
//! An address is not an identity. Trust keyed on one means "whatever answers at this
//! name", and it stops meaning anything the moment a trusted machine moves. Trust keyed
//! on a certificate breaks on the far side's first renewal, which is an ordinary
//! maintenance event. Keyed on the identity key behind that certificate, both problems
//! go away, and the peer still cannot lie about which device it is.
//!
//! The address keeps exactly one job: if a stranger answers where a trusted device used
//! to, that is refused as [`RefusalReason::IdentityChanged`] rather than prompted. A
//! substituted machine must not arrive as a routine click on a dialog people answer
//! several times a day.
//!
//! Nothing here talks to a network or a window. The prompt is a trait so the whole
//! decision can be tested against a scripted answer, and so the desktop application
//! and the service can present it differently without either owning the rule.

use async_trait::async_trait;
use rc_protocol::control::WireRefusal;
use rc_security::{Clock, Fingerprint, Permission, PermissionSet, Throttle};
use rc_storage::{NewTrustedDevice, SettingsRepository, TrustRepository};
use rc_transport::{PeerAddress, PeerIdentity};
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
    /// The identity the peer proved. Shown so a human can compare it across two screens.
    pub identity_fingerprint: Fingerprint,
    /// The device id derived from that identity, in the form the interface displays.
    pub device_id: String,
    /// The name the peer reported. Untrusted, and displayed as such.
    pub machine_name: String,
    /// The operating system the peer reported. Untrusted, and displayed as such.
    pub os_family: String,
    /// Whether this device is already trusted, so a returning machine does not look like
    /// a stranger. It is being asked anyway, which is what trust without unattended
    /// access means.
    pub trusted: bool,
}

/// How much of this decision outlives the connection it was made for.
///
/// Three outcomes rather than a boolean, because "let this machine in now", "remember
/// this machine" and "let this machine in without asking me again" are three different
/// commitments, and collapsing any two of them loses the one that matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustChoice {
    /// This connection only. Nothing is persisted, so there is nothing to reconnect
    /// against afterwards.
    Once,
    /// Remember the device, and keep asking. It appears in My Devices with the
    /// permissions it was given, and every later connection still raises the dialog.
    Remember,
    /// Remember the device and stop asking. Reachable only through a deliberate second
    /// step in the dialog, never from its primary buttons.
    RememberUnattended,
}

/// What they decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptDecision {
    /// Accept, granting exactly these permissions and persisting exactly this much.
    Accept {
        /// What this session may do. [`rc_security::Permission::Administer`] is stripped
        /// from whatever arrives here — see [`authorize_connection`].
        permissions: PermissionSet,
        /// What, if anything, outlives the connection.
        trust: TrustChoice,
    },
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
    ///
    /// This must be the address the user *dialled*, not the peer's remote socket address
    /// read off the QUIC connection, whose port is ephemeral. Admission no longer turns
    /// on this value — the identity does — but the identity-change check below does, and
    /// building it from an ephemeral port would mean that check never fired.
    pub address: PeerAddress,
    /// Who the peer is, established from the certificate it presented. **The trust key.**
    pub identity: PeerIdentity,
    /// The name the peer reported. Untrusted, and displayed as such.
    pub machine_name: String,
    /// The operating system the peer reported. Untrusted, and displayed as such.
    pub os_family: String,
    /// The unattended password the peer offered, if it offered one.
    pub unattended_password: Option<String>,
}

/// Why a connection was refused.
///
/// Local-only. See the `impl From<RefusalReason> for WireRefusal` below for what is
/// safe to tell the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// A human said no, or said nothing for long enough.
    Dismissed,
    /// This machine is not accepting connections at all.
    NotAccepting,
    /// A different device is answering where a trusted one used to.
    IdentityChanged,
    /// The device is trusted, but temporarily disabled.
    Suspended,
    /// An unattended password was offered and was wrong, or none is configured.
    WrongPassword,
    /// Too many wrong passwords; the lockout is in force.
    TooManyAttempts,
}

/// The refusal reason as reported to the peer.
///
/// Defined in `rc-protocol` — see [`rc_protocol::control::WireRefusal`] — because it
/// travels on the wire and the protocol crate must not depend on this one. This impl is
/// what performs the coarsening: a dismissal, a wrong password and a lockout must be
/// indistinguishable from outside, or a peer that could tell them apart could use the
/// response itself as an oracle for whether unattended access is configured, or as a
/// way to count its own attempts against the lockout. [`RefusalReason`] stays available
/// in full for the local log, where the distinction is the entire point.
///
/// A separate type rather than a same-valued convention on `RefusalReason` itself, so
/// the coarsening is enforced by the type checker at the point something is put on the
/// wire, not by every future call site remembering to collapse the fine-grained reason
/// correctly.
impl From<RefusalReason> for WireRefusal {
    fn from(reason: RefusalReason) -> Self {
        match reason {
            RefusalReason::NotAccepting => Self::NotAccepting,
            RefusalReason::IdentityChanged => Self::IdentityChanged,
            // `Suspended` joins these three rather than being reported distinctly: a
            // peer that could tell "suspended" from "rejected" would learn that it is
            // known to this machine, which is precisely what a device someone has just
            // disabled must not be able to confirm.
            RefusalReason::Dismissed
            | RefusalReason::WrongPassword
            | RefusalReason::TooManyAttempts
            | RefusalReason::Suspended => Self::Rejected,
        }
    }
}

/// The outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorization {
    /// Proceed, holding exactly these permissions for the whole session.
    Granted(PermissionSet),
    /// Do not proceed.
    Refused(RefusalReason),
}

/// Turn a set of permissions into the outcome, refusing rather than granting an empty
/// set.
///
/// A session that may do nothing is a connection nobody can use and nobody can see;
/// refusing says the same thing more clearly. Every door in `authorize_connection` that
/// can grant something funnels through here rather than re-deriving the check itself —
/// this check very nearly stayed specific to the human branch alone, which is exactly
/// how a future fourth way in would miss it too.
fn grant_or_refuse(permissions: PermissionSet) -> Authorization {
    if permissions.is_empty() {
        Authorization::Refused(RefusalReason::Dismissed)
    } else {
        Authorization::Granted(permissions)
    }
}

/// Everything the decision reads or writes.
pub struct AccessDeps<'a> {
    /// This machine's own settings: whether it accepts connections, and unattended
    /// access.
    pub settings: &'a SettingsRepository,
    /// Devices a human has decided to remember, keyed on the identity each proved.
    pub trust: &'a TrustRepository,
    /// Asks a human when neither a pin nor a password settles the decision.
    pub prompt: &'a dyn AcceptPrompt,
    /// Rate-limits unattended-password attempts, keyed by address.
    pub throttle: &'a Mutex<Throttle>,
    /// The source of "now" for the throttle.
    pub clock: &'a dyn Clock,
    /// Held for as long as one Accept dialog is open.
    ///
    /// Enforced here, in the decision layer, rather than left to whatever eventually
    /// implements [`AcceptPrompt`]: it is testable with no window involved, and a rule
    /// that lived only as a doc comment is how "at most one dialog pending" went
    /// missing before. Shared across every connection this process is deciding, so it
    /// must be constructed once and passed to every call, never created fresh per
    /// call.
    pub pending_dialog: &'a Mutex<()>,
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

    // The address the user dialled — see the doc comment on `ConnectionRequest::address`
    // for why this must never be built from a peer's ephemeral remote socket address.
    let key = request.address.to_string();
    let identity = request.identity.identity_fingerprint;

    // 1. A decision a human already took about *this device*, found by the identity it
    //    proved rather than by the address it arrived from.
    if let Some(device) = deps.trust.find(identity).await? {
        if device.suspended {
            return Ok(Authorization::Refused(RefusalReason::Suspended));
        }
        if device.unattended {
            deps.trust
                .record_connection(identity, &key, deps.clock.now_ms())
                .await?;
            return Ok(grant_or_refuse(device.permissions));
        }
        // Trusted, but not for unattended access. That is a decision to remember the
        // machine, not a decision to let it in unasked, so it falls through to the
        // human below — carrying the fact that it is known.
    } else if let Some(known) = deps.trust.find_by_address(&key).await?
        && !known.identity_fingerprint.ct_eq(&identity)
    {
        // Something else is answering where a trusted device used to. That is either a
        // reinstall or a substitution; both need a deliberate decision, and the dialog
        // is the wrong place to take it because it is a thing people click through many
        // times a day. `ct_eq`, not `==`, so no identity comparison in the tree is the
        // one that leaks a timing signal.
        return Ok(Authorization::Refused(RefusalReason::IdentityChanged));
    }

    // 2. An unattended password, if one was offered.
    if let Some(offered) = request.unattended_password.as_deref() {
        // One guard held across the whole check-hash-record sequence, not two
        // separate lock scopes. Two scopes let N concurrent attempts against the same
        // address all pass `check` before any of them reached `record_failure`, so
        // the lockout only bounded strictly sequential guessing — and every one of
        // those N concurrent guesses still paid for a full Argon2id hash first, which
        // is exactly the work-amplification the lockout exists to prevent.
        let mut throttle = deps.throttle.lock().await;
        if throttle.check(&key, deps.clock).is_err() {
            return Ok(Authorization::Refused(RefusalReason::TooManyAttempts));
        }

        let stored = deps.settings.unattended_credential().await?;
        let permitted = settings.unattended_permissions;

        // An over-long password is rejected the same way whether or not a credential
        // is configured, checked before either branch below. `PasswordCredential::verify`
        // already rejects an over-long password before hashing; if the no-credential
        // branch still ran its dummy hash for the same over-long input, the two paths
        // would diverge in timing for that one input shape — a fast refusal only when
        // unattended access exists, which is the exact disclosure the dummy hash below
        // exists to prevent, inverted.
        let verified = if offered.len() > rc_security::password::MAX_PASSWORD_BYTES {
            false
        } else if let Some(credential) = &stored {
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

        return Ok(if verified {
            throttle.record_success(&key, deps.clock);
            grant_or_refuse(permitted)
        } else {
            throttle.record_failure(&key, deps.clock);
            Authorization::Refused(RefusalReason::WrongPassword)
        });
    }

    // 3. Ask a human — but only if no dialog is already pending. A second connection
    // arriving while one is open is refused immediately, without ever reaching the
    // prompt: see the doc comment on `AccessDeps::pending_dialog`.
    let Ok(_dialog_slot) = deps.pending_dialog.try_lock() else {
        return Ok(Authorization::Refused(RefusalReason::Dismissed));
    };

    // Generated here, never accepted from the peer or from any caller-supplied value:
    // it exists only to match this specific answer back to this specific request.
    let request_id = uuid::Uuid::new_v4().to_string();
    let trusted = deps.trust.find(identity).await?.is_some();
    let answer = deps
        .prompt
        .ask(AcceptRequest {
            request_id: request_id.clone(),
            address: key.clone(),
            identity_fingerprint: identity,
            device_id: request.identity.device_id.to_canonical_string(),
            machine_name: request.machine_name.clone(),
            os_family: request.os_family.clone(),
            trusted,
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

    let AcceptDecision::Accept { permissions, trust } = answer.decision else {
        return Ok(Authorization::Refused(RefusalReason::Dismissed));
    };

    // Authority over the trust database is never conferred by this dialog. Stripped
    // here, in one place, rather than trusted not to be set by whatever implements the
    // prompt — a window, in production, and one that could acquire the checkbox by
    // accident. Administrator is granted from a device's own settings, behind a
    // confirmation that names it.
    let permissions = permissions.without(Permission::Administer);

    let outcome = grant_or_refuse(permissions);

    // Only a grant is remembered. Persisting a refusal would create a trust row for a
    // device the human just turned away, and `Once` persists nothing by construction:
    // there is then nothing for a later connection to match against.
    if let Authorization::Granted(granted) = outcome
        && matches!(
            trust,
            TrustChoice::Remember | TrustChoice::RememberUnattended
        )
    {
        deps.trust
            .trust(&NewTrustedDevice {
                identity_fingerprint: identity,
                device_id: request.identity.device_id.to_canonical_string(),
                display_name: request.machine_name.clone(),
                os_family: request.os_family.clone(),
                address: key,
                permissions: granted,
                unattended: matches!(trust, TrustChoice::RememberUnattended),
                now_ms: deps.clock.now_ms(),
            })
            .await?;
    }

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use rc_security::{
        HashingPolicy, OsRandom, PasswordCredential, Permission, PermissionSet, Throttle,
    };
    use rc_storage::{NewTrustedDevice, SettingsRepository, TrustRepository};
    use rc_transport::{PeerAddress, PeerIdentity};

    use super::*;

    /// A device, and a second one that is emphatically not it.
    ///
    /// The certificate and identity fingerprints differ from each other as well as
    /// between the two devices, so a test cannot pass by the code comparing the wrong
    /// one of the pair.
    fn identity_a() -> PeerIdentity {
        PeerIdentity {
            certificate_fingerprint: Fingerprint::from_bytes([1u8; 32]),
            identity_fingerprint: Fingerprint::from_bytes([7u8; 32]),
            device_id: rc_protocol::DeviceId::from_uuid(uuid::Uuid::from_u128(1)),
        }
    }

    fn identity_b() -> PeerIdentity {
        PeerIdentity {
            certificate_fingerprint: Fingerprint::from_bytes([2u8; 32]),
            identity_fingerprint: Fingerprint::from_bytes([8u8; 32]),
            device_id: rc_protocol::DeviceId::from_uuid(uuid::Uuid::from_u128(2)),
        }
    }

    fn request_from(identity: PeerIdentity, password: Option<&str>) -> ConnectionRequest {
        ConnectionRequest {
            address: "192.168.1.77:7443".parse::<PeerAddress>().unwrap(),
            identity,
            machine_name: "WORK-LAPTOP".to_owned(),
            os_family: "windows".to_owned(),
            unattended_password: password.map(str::to_owned),
        }
    }

    /// The most the Accept dialog can confer: every session permission, and never
    /// `Administer`. Tests deliberately *offer* `PermissionSet::ALL` and expect this
    /// back, which is what proves the stripping happens rather than being assumed.
    const SESSION_PERMISSIONS: PermissionSet = PermissionSet::ALL.without(Permission::Administer);

    /// Shorthand for the common accept: everything ticked, nothing remembered.
    const fn accept_once(permissions: PermissionSet) -> AcceptDecision {
        AcceptDecision::Accept {
            permissions,
            trust: TrustChoice::Once,
        }
    }

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
        /// The last request it was shown, so a test can assert what the human would
        /// actually have seen rather than only what came back.
        seen: std::sync::Mutex<Option<AcceptRequest>>,
    }

    impl ScriptedPrompt {
        fn new(answer: AcceptDecision) -> Self {
            Self {
                answer,
                respond_with: None,
                asked: std::sync::atomic::AtomicUsize::new(0),
                seen: std::sync::Mutex::new(None),
            }
        }

        /// A prompt whose answer always carries `wrong_request_id`, regardless of what
        /// request it was actually shown.
        fn stale(answer: AcceptDecision, wrong_request_id: impl Into<String>) -> Self {
            Self {
                answer,
                respond_with: Some(wrong_request_id.into()),
                asked: std::sync::atomic::AtomicUsize::new(0),
                seen: std::sync::Mutex::new(None),
            }
        }

        fn asked(&self) -> usize {
            self.asked.load(std::sync::atomic::Ordering::SeqCst)
        }

        /// What the human was actually shown, if anything.
        fn last_request(&self) -> Option<AcceptRequest> {
            self.seen.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl AcceptPrompt for ScriptedPrompt {
        async fn ask(&self, request: AcceptRequest) -> AcceptAnswer {
            self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.seen.lock().unwrap() = Some(request.clone());
            let request_id = self.respond_with.clone().unwrap_or(request.request_id);
            AcceptAnswer {
                request_id,
                decision: self.answer,
            }
        }
    }

    /// A prompt that blocks inside `ask` until told to proceed, so a test can hold a
    /// connection at "dialog open" for as long as it needs to.
    struct BlockingPrompt {
        answer: AcceptDecision,
        calls: std::sync::atomic::AtomicUsize,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    impl BlockingPrompt {
        fn new(answer: AcceptDecision) -> Self {
            Self {
                answer,
                calls: std::sync::atomic::AtomicUsize::new(0),
                entered: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }

        /// Resolves once `ask` has actually been entered at least once. `Notify`
        /// keeps a single permit, so this cannot miss a notification sent just
        /// before it starts waiting.
        async fn wait_until_entered(&self) {
            self.entered.notified().await;
        }

        /// Let a blocked `ask` call return.
        fn release(&self) {
            self.release.notify_one();
        }
    }

    #[async_trait::async_trait]
    impl AcceptPrompt for BlockingPrompt {
        async fn ask(&self, request: AcceptRequest) -> AcceptAnswer {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.entered.notify_one();
            self.release.notified().await;
            AcceptAnswer {
                request_id: request.request_id,
                decision: self.answer,
            }
        }
    }

    /// Everything `authorize_connection` needs, built fresh for each test.
    ///
    /// Generic over the prompt so tests can substitute [`BlockingPrompt`] for the
    /// concurrency tests without duplicating the harness.
    struct Harness<P: AcceptPrompt> {
        settings: SettingsRepository,
        trust: TrustRepository,
        prompt: P,
        throttle: Mutex<Throttle>,
        clock: rc_security::clock::TestClock,
        pending_dialog: Mutex<()>,
        // Kept alive for the lifetime of the harness: the repositories borrow its pool.
        _database: rc_storage::Database,
    }

    impl<P: AcceptPrompt> Harness<P> {
        async fn new(prompt: P) -> Self {
            let database = rc_storage::Database::open_in_memory()
                .await
                .expect("an in-memory database must always open and migrate cleanly");
            let settings = SettingsRepository::new(&database);
            let trust = TrustRepository::new(&database);
            Self {
                settings,
                trust,
                prompt,
                throttle: Mutex::new(Throttle::with_defaults()),
                clock: rc_security::clock::TestClock::default(),
                pending_dialog: Mutex::new(()),
                _database: database,
            }
        }

        fn settings(&self) -> &SettingsRepository {
            &self.settings
        }

        fn trust(&self) -> &TrustRepository {
            &self.trust
        }

        /// Seed a trusted device, as a human accepting-and-trusting would have.
        async fn trust_device(
            &self,
            identity: PeerIdentity,
            permissions: PermissionSet,
            unattended: bool,
        ) {
            self.trust
                .trust(&NewTrustedDevice {
                    identity_fingerprint: identity.identity_fingerprint,
                    device_id: identity.device_id.to_canonical_string(),
                    display_name: "WORK-LAPTOP".to_owned(),
                    os_family: "windows".to_owned(),
                    address: "192.168.1.77:7443".to_owned(),
                    permissions,
                    unattended,
                    now_ms: 1_000,
                })
                .await
                .expect("seeding a trusted device must succeed");
        }

        fn prompt(&self) -> &P {
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
                trust: &self.trust,
                prompt: &self.prompt,
                throttle: &self.throttle,
                clock: &self.clock,
                pending_dialog: &self.pending_dialog,
            };
            authorize_connection(&request, &deps).await
        }
    }

    #[tokio::test]
    async fn a_dismissed_connection_is_refused_and_grants_nothing() {
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        let outcome = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();
        assert_eq!(outcome, Authorization::Refused(RefusalReason::Dismissed));
    }

    #[tokio::test]
    async fn an_accepted_connection_gets_exactly_what_the_human_ticked() {
        let granted = PermissionSet::NONE.with(Permission::ViewMetrics);
        let harness = Harness::new(ScriptedPrompt::new(accept_once(granted))).await;
        let outcome = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();
        assert_eq!(outcome, Authorization::Granted(granted));
    }

    #[tokio::test]
    async fn a_machine_not_accepting_connections_is_never_prompted() {
        let harness = Harness::new(ScriptedPrompt::new(accept_once(PermissionSet::ALL))).await;
        harness.settings().set_accepting(false).await.unwrap();

        let outcome = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();
        assert_eq!(outcome, Authorization::Refused(RefusalReason::NotAccepting));
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn an_unattended_device_is_admitted_with_exactly_what_it_was_granted() {
        let granted = PermissionSet::NONE.with(Permission::TransferFiles);
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness.trust_device(identity_a(), granted, true).await;

        let outcome = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();

        assert_eq!(outcome, Authorization::Granted(granted));
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn a_trusted_device_without_unattended_access_still_reaches_the_prompt() {
        // Trust Device and Allow Unattended Access are different decisions. Remembering
        // a machine must not quietly stop it asking.
        let harness = Harness::new(ScriptedPrompt::new(accept_once(PermissionSet::ALL))).await;
        harness
            .trust_device(identity_a(), PermissionSet::ALL, false)
            .await;

        let outcome = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();

        assert_eq!(outcome, Authorization::Granted(SESSION_PERMISSIONS));
        assert_eq!(harness.prompt().asked(), 1, "it must still have been asked");
    }

    #[tokio::test]
    async fn the_prompt_is_told_the_device_is_already_trusted() {
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness
            .trust_device(identity_a(), PermissionSet::ALL, false)
            .await;

        let _ = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();

        let seen = harness.prompt().last_request().expect("it was asked");
        assert!(
            seen.trusted,
            "a returning device must not look like a stranger"
        );
        assert_eq!(
            seen.identity_fingerprint,
            identity_a().identity_fingerprint,
            "and the human is shown the identity that was actually proved"
        );
    }

    #[tokio::test]
    async fn a_stranger_is_not_told_the_machine_knows_anyone() {
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;

        let _ = harness
            .authorize(request_from(identity_b(), None))
            .await
            .unwrap();

        let seen = harness.prompt().last_request().expect("it was asked");
        assert!(!seen.trusted);
    }

    #[tokio::test]
    async fn a_different_device_cannot_use_another_devices_authorization() {
        // The property the whole change exists for. Device A has unattended access;
        // device B presents its own key and is a stranger, not an heir.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness
            .trust_device(identity_a(), PermissionSet::ALL, true)
            .await;

        let outcome = harness
            .authorize(request_from(identity_b(), None))
            .await
            .unwrap();

        assert_ne!(
            outcome,
            Authorization::Granted(PermissionSet::ALL),
            "device B must never be admitted under device A's grant"
        );
    }

    #[tokio::test]
    async fn a_stranger_at_a_trusted_devices_address_is_refused_not_prompted() {
        // The loudest failure the system has, re-anchored. The machine answering at a
        // trusted address is not the machine that was trusted, and that question must
        // not arrive as a routine click.
        let harness = Harness::new(ScriptedPrompt::new(accept_once(PermissionSet::ALL))).await;
        harness
            .trust_device(identity_a(), PermissionSet::ALL, true)
            .await;

        let outcome = harness
            .authorize(request_from(identity_b(), None))
            .await
            .unwrap();

        assert_eq!(
            outcome,
            Authorization::Refused(RefusalReason::IdentityChanged)
        );
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn a_renewed_certificate_does_not_break_trust() {
        // An ordinary maintenance event on the far side. The certificate differs; the
        // identity does not; the device is still the device. Under the old certificate
        // pin this was the loudest refusal the system had.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness
            .trust_device(identity_a(), PermissionSet::ALL, true)
            .await;

        let renewed = PeerIdentity {
            certificate_fingerprint: Fingerprint::from_bytes([99u8; 32]),
            ..identity_a()
        };
        let outcome = harness
            .authorize(request_from(renewed, None))
            .await
            .unwrap();

        assert_eq!(outcome, Authorization::Granted(PermissionSet::ALL));
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn a_suspended_device_is_refused_and_never_prompted() {
        let harness = Harness::new(ScriptedPrompt::new(accept_once(PermissionSet::ALL))).await;
        harness
            .trust_device(identity_a(), PermissionSet::ALL, true)
            .await;
        harness
            .trust()
            .set_suspended(identity_a().identity_fingerprint, true)
            .await
            .unwrap();

        let outcome = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();

        assert_eq!(outcome, Authorization::Refused(RefusalReason::Suspended));
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn a_revoked_device_cannot_reconnect_unattended() {
        // Revocation has to invalidate the authorization, not merely hide a row: the
        // device connects again and is treated as the stranger it now is.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness
            .trust_device(identity_a(), PermissionSet::ALL, true)
            .await;
        harness
            .trust()
            .revoke(identity_a().identity_fingerprint)
            .await
            .unwrap();

        let outcome = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();

        assert_eq!(
            outcome,
            Authorization::Refused(RefusalReason::Dismissed),
            "with the grant gone it is a stranger, and the scripted human said no"
        );
        assert_eq!(
            harness.prompt().asked(),
            1,
            "it reached the dialog rather than being let in"
        );
    }

    #[tokio::test]
    async fn an_unattended_device_granted_nothing_is_refused_not_given_an_empty_session() {
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness
            .trust_device(identity_a(), PermissionSet::NONE, true)
            .await;

        let outcome = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();

        assert_eq!(outcome, Authorization::Refused(RefusalReason::Dismissed));
        assert_eq!(
            harness.prompt().asked(),
            0,
            "an empty unattended grant must not fall back to the dialog either"
        );
    }

    #[tokio::test]
    async fn an_unattended_connection_updates_where_and_when_but_grants_nothing_new() {
        let granted = PermissionSet::NONE.with(Permission::ViewMetrics);
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness.trust_device(identity_a(), granted, true).await;

        let _ = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();

        let stored = harness
            .trust()
            .find(identity_a().identity_fingerprint)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.permissions, granted, "reconnecting must not widen");
        assert_eq!(stored.last_address.as_deref(), Some("192.168.1.77:7443"));
        assert!(stored.last_connected_ms.is_some());
    }

    #[tokio::test]
    async fn allow_once_persists_nothing() {
        let harness = Harness::new(ScriptedPrompt::new(accept_once(PermissionSet::ALL))).await;

        let outcome = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();

        assert_eq!(outcome, Authorization::Granted(SESSION_PERMISSIONS));
        assert!(
            harness.trust().list().await.unwrap().is_empty(),
            "Accept Once must leave nothing behind to reconnect against"
        );
    }

    #[tokio::test]
    async fn trust_device_persists_without_granting_unattended_access() {
        let granted = PermissionSet::NONE.with(Permission::ViewMetrics);
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept {
            permissions: granted,
            trust: TrustChoice::Remember,
        }))
        .await;

        let _ = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();

        let stored = harness
            .trust()
            .find(identity_a().identity_fingerprint)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.permissions, granted);
        assert!(
            !stored.unattended,
            "remembering a machine is not the same as letting it in unasked"
        );
    }

    #[tokio::test]
    async fn allow_unattended_access_persists_the_access_too() {
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept {
            permissions: PermissionSet::ALL,
            trust: TrustChoice::RememberUnattended,
        }))
        .await;

        let _ = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();

        let stored = harness
            .trust()
            .find(identity_a().identity_fingerprint)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.unattended);
    }

    #[tokio::test]
    async fn a_refused_connection_is_never_remembered() {
        // Persisting on a refusal would create a trust row for a device the human had
        // just turned away -- and, if it carried unattended access, would let the next
        // connection in without anyone being asked at all.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;

        let _ = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();

        assert!(harness.trust().list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn accepting_nothing_while_asking_to_remember_stores_nothing() {
        // An empty grant is a refusal, and a refusal is not remembered -- so the two
        // rules have to compose rather than the trust write happening first.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept {
            permissions: PermissionSet::NONE,
            trust: TrustChoice::RememberUnattended,
        }))
        .await;

        let outcome = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();

        assert_eq!(outcome, Authorization::Refused(RefusalReason::Dismissed));
        assert!(harness.trust().list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn administrator_is_never_reachable_from_the_accept_dialog() {
        // Whatever the dialog returns, the Administer bit must not survive it -- neither
        // into the session nor into the stored grant. The dialog is clicked many times a
        // day; authority over the trust database is not something it may confer.
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Accept {
            permissions: PermissionSet::ALL,
            trust: TrustChoice::RememberUnattended,
        }))
        .await;

        let outcome = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();

        let Authorization::Granted(granted) = outcome else {
            panic!("expected a grant, got {outcome:?}")
        };
        assert!(!granted.contains(Permission::Administer));
        let stored = harness
            .trust()
            .find(identity_a().identity_fingerprint)
            .await
            .unwrap()
            .unwrap();
        assert!(!stored.permissions.contains(Permission::Administer));
    }

    #[tokio::test]
    async fn an_unattended_device_granted_administrator_keeps_it() {
        // The complement of the test above: Administer is stripped from what the *dialog*
        // returns, not from a grant a human made deliberately in the device's settings.
        let granted = PermissionSet::NONE
            .with(Permission::ViewMetrics)
            .with(Permission::Administer);
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness.trust_device(identity_a(), granted, true).await;

        let outcome = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();

        assert_eq!(outcome, Authorization::Granted(granted));
    }

    #[tokio::test]
    async fn a_correct_unattended_password_skips_the_prompt() {
        let granted = PermissionSet::NONE.with(Permission::ControlInput);
        let harness = Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await;
        harness
            .set_unattended("correct horse battery", granted)
            .await;

        let outcome = harness
            .authorize(request_from(identity_a(), Some("correct horse battery")))
            .await
            .unwrap();
        assert_eq!(outcome, Authorization::Granted(granted));
        assert_eq!(harness.prompt().asked(), 0);
    }

    #[tokio::test]
    async fn an_unattended_credential_with_no_permissions_is_refused_not_granted_an_empty_session()
    {
        let harness = Harness::new(ScriptedPrompt::new(accept_once(PermissionSet::ALL))).await;
        harness
            .set_unattended("correct horse battery", PermissionSet::NONE)
            .await;

        let outcome = harness
            .authorize(request_from(identity_a(), Some("correct horse battery")))
            .await
            .unwrap();
        assert_eq!(outcome, Authorization::Refused(RefusalReason::Dismissed));
        assert_eq!(
            harness.prompt().asked(),
            0,
            "an empty unattended grant must not fall back to the dialog either"
        );
    }

    #[tokio::test]
    async fn a_wrong_unattended_password_is_refused_without_falling_back_to_the_prompt() {
        // Falling back would make a wrong password indistinguishable from no password
        // and would let an attacker convert a guess into a prompt on someone's screen.
        let harness = Harness::new(ScriptedPrompt::new(accept_once(PermissionSet::ALL))).await;
        harness
            .set_unattended("correct horse battery", PermissionSet::ALL)
            .await;

        let outcome = harness
            .authorize(request_from(identity_a(), Some("wrong password here")))
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
        let harness = Harness::new(ScriptedPrompt::new(accept_once(PermissionSet::ALL))).await;
        let outcome = harness
            .authorize(request_from(identity_a(), Some("anything at all")))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            Authorization::Refused(RefusalReason::WrongPassword)
        );
    }

    #[tokio::test]
    async fn an_overlong_password_is_rejected_quickly_when_no_credential_is_configured() {
        // `PasswordCredential::verify` already rejects an over-long password before
        // hashing. If the no-credential branch still ran its full Argon2id dummy hash
        // for the same input, an over-long guess would take measurably longer when
        // unattended access is *not* configured than when it is -- the disclosure the
        // dummy hash exists to prevent, inverted, for this one input shape. Argon2id
        // at production cost (m=19 MiB, t=2) takes tens of milliseconds; a length
        // check takes microseconds, so a generous bound distinguishes the two without
        // being sensitive to ordinary scheduling jitter.
        let overlong = "a".repeat(rc_security::password::MAX_PASSWORD_BYTES + 1);
        let harness = Harness::new(ScriptedPrompt::new(accept_once(PermissionSet::ALL))).await;

        let started = std::time::Instant::now();
        let outcome = harness
            .authorize(request_from(identity_a(), Some(&overlong)))
            .await
            .unwrap();
        let elapsed = started.elapsed();

        assert_eq!(
            outcome,
            Authorization::Refused(RefusalReason::WrongPassword)
        );
        assert!(
            elapsed < std::time::Duration::from_millis(20),
            "an over-long password must be rejected without hashing; took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn an_overlong_password_is_rejected_quickly_when_a_credential_is_configured() {
        // The credentialed path must behave the same way: this is the equal-cost half
        // of the same guarantee, not just a regression guard on the branch above.
        let overlong = "a".repeat(rc_security::password::MAX_PASSWORD_BYTES + 1);
        let harness = Harness::new(ScriptedPrompt::new(accept_once(PermissionSet::ALL))).await;
        harness
            .set_unattended("correct horse battery", PermissionSet::ALL)
            .await;

        let started = std::time::Instant::now();
        let outcome = harness
            .authorize(request_from(identity_a(), Some(&overlong)))
            .await
            .unwrap();
        let elapsed = started.elapsed();

        assert_eq!(
            outcome,
            Authorization::Refused(RefusalReason::WrongPassword)
        );
        assert!(
            elapsed < std::time::Duration::from_millis(20),
            "an over-long password must be rejected without hashing; took {elapsed:?}"
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
                .authorize(request_from(identity_a(), Some("wrong password here")))
                .await
                .unwrap();
        }
        let outcome = harness
            .authorize(request_from(identity_a(), Some("correct horse battery")))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            Authorization::Refused(RefusalReason::TooManyAttempts)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_lockout_bounds_concurrent_attempts_against_one_address() {
        // If the throttle's check and its recording of the failure are not atomic
        // together, every one of several concurrent attempts can pass `check` before
        // any of them reaches `record_failure`, so all of them pay for a full
        // Argon2id hash regardless of the lockout -- exactly the work-amplification
        // the throttle exists to prevent.
        //
        // With the default policy (`free_attempts = 2`), fully-serialized attempts
        // give a deterministic split regardless of arrival order: the first three
        // reach verification (and are refused as `WrongPassword`, since the password
        // offered is wrong), and the lockout applies to the third of them, so the
        // remaining two never reach verification at all and are refused as
        // `TooManyAttempts` before any hashing.
        let harness =
            std::sync::Arc::new(Harness::new(ScriptedPrompt::new(AcceptDecision::Dismiss)).await);
        harness
            .set_unattended("correct horse battery", PermissionSet::ALL)
            .await;

        let mut handles = Vec::new();
        for _ in 0..5 {
            let harness = std::sync::Arc::clone(&harness);
            handles.push(tokio::spawn(async move {
                harness
                    .authorize(request_from(identity_a(), Some("wrong password here")))
                    .await
                    .unwrap()
            }));
        }

        let mut wrong_password = 0;
        let mut too_many_attempts = 0;
        for handle in handles {
            match handle.await.unwrap() {
                Authorization::Refused(RefusalReason::WrongPassword) => wrong_password += 1,
                Authorization::Refused(RefusalReason::TooManyAttempts) => too_many_attempts += 1,
                other => panic!("unexpected outcome: {other:?}"),
            }
        }

        assert_eq!(
            wrong_password, 3,
            "the lockout must bound how many concurrent guesses ever reach hashing, \
             not merely how many arrive sequentially"
        );
        assert_eq!(too_many_attempts, 2);
    }

    #[tokio::test]
    async fn no_password_offered_still_reaches_the_prompt_when_unattended_is_configured() {
        // Configuring unattended access adds a second way in; it does not remove the
        // first.
        let harness = Harness::new(ScriptedPrompt::new(accept_once(PermissionSet::ALL))).await;
        harness
            .set_unattended("correct horse battery", PermissionSet::ALL)
            .await;

        let outcome = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();
        assert_eq!(outcome, Authorization::Granted(SESSION_PERMISSIONS));
        assert_eq!(harness.prompt().asked(), 1);
    }

    #[tokio::test]
    async fn accepting_with_nothing_ticked_is_a_refusal_not_an_empty_session() {
        // A session that may do nothing is a connection nobody can use and nobody can
        // see. Saying no is clearer.
        let harness = Harness::new(ScriptedPrompt::new(accept_once(PermissionSet::NONE))).await;
        let outcome = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();
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
            accept_once(PermissionSet::ALL),
            "not-the-request-that-is-pending",
        ))
        .await;

        let outcome = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();
        assert_eq!(outcome, Authorization::Refused(RefusalReason::Dismissed));
        assert_eq!(
            harness.prompt().asked(),
            1,
            "the prompt was reached; its mismatched answer must simply not count"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_second_connection_is_refused_while_a_dialog_is_pending() {
        let harness = std::sync::Arc::new(
            Harness::new(BlockingPrompt::new(accept_once(PermissionSet::ALL))).await,
        );

        // Start the first connection; it blocks inside `ask` until released, so the
        // pending slot stays held.
        let first = {
            let harness = std::sync::Arc::clone(&harness);
            tokio::spawn(async move {
                harness
                    .authorize(request_from(identity_a(), None))
                    .await
                    .unwrap()
            })
        };
        harness.prompt().wait_until_entered().await;

        // A second connection arriving now must be refused immediately, without ever
        // reaching the prompt.
        let second = harness
            .authorize(request_from(identity_a(), None))
            .await
            .unwrap();
        assert_eq!(second, Authorization::Refused(RefusalReason::Dismissed));
        assert_eq!(
            harness.prompt().calls(),
            1,
            "the second connection must never reach the prompt"
        );

        harness.prompt().release();
        let first_outcome = first.await.unwrap();
        assert_eq!(first_outcome, Authorization::Granted(SESSION_PERMISSIONS));
    }

    #[test]
    fn a_wire_refusal_does_not_distinguish_a_wrong_password_from_a_dismissal() {
        // Both must look the same to the peer, or the answer becomes an oracle for
        // whether unattended access is configured. They are distinguished only in the
        // receiving machine's own log.
        assert_eq!(
            WireRefusal::from(RefusalReason::Dismissed),
            WireRefusal::Rejected
        );
        assert_eq!(
            WireRefusal::from(RefusalReason::WrongPassword),
            WireRefusal::Rejected
        );
        assert_eq!(
            WireRefusal::from(RefusalReason::TooManyAttempts),
            WireRefusal::Rejected
        );
    }

    #[test]
    fn not_accepting_and_identity_changed_are_reported_distinctly() {
        // These two need different remedies, so telling them apart helps the person
        // connecting and discloses nothing they could not already observe.
        assert_eq!(
            WireRefusal::from(RefusalReason::NotAccepting),
            WireRefusal::NotAccepting
        );
        assert_eq!(
            WireRefusal::from(RefusalReason::IdentityChanged),
            WireRefusal::IdentityChanged
        );
    }
}
