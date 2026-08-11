//! Live sessions: the concurrency cap, and what the operator can see.
//!
//! # Why a reservation rather than a counter
//!
//! The cap has to be taken **before** authentication, and released however the session
//! ends — including when the handling task panics or is cancelled mid-await. A bare
//! counter incremented on success and decremented on the way out leaks a slot every
//! time an error path forgets to decrement, and the failure mode is an agent that
//! refuses every connection until it is restarted.
//!
//! [`SessionSlot`] instead owns the reservation and releases it in `Drop`, so there is
//! no path out of a session that does not free its slot.
//!
//! # What is recorded
//!
//! Only what the operator needs in order to recognise a session and end it: which
//! device, which role, where from, when it started and when it was last active. No
//! message content, and no credential — there is no session credential to record,
//! because a session is authenticated by its TLS connection rather than by a bearer
//! value.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rc_protocol::{DeviceId, SessionId};
use rc_security::PermissionSet;

/// A session as the operator sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveSession {
    /// Identifier assigned at authentication.
    pub session_id: SessionId,
    /// Which trusted device is connected.
    pub device_id: DeviceId,
    /// What that device is permitted to do.
    pub permissions: PermissionSet,
    /// Peer address, host only.
    pub source: String,
    /// When the session was admitted, milliseconds since the Unix epoch.
    pub started_at_ms: i64,
    /// When the last request arrived.
    pub last_active_ms: i64,
}

/// Every live session, with a hard cap on how many there may be.
#[derive(Debug)]
pub struct SessionRegistry {
    max_sessions: usize,
    /// Reservations, including connections that are authenticating and so are not yet
    /// in `sessions`. This is what the cap is enforced against.
    reserved: AtomicUsize,
    sessions: Mutex<Vec<LiveSession>>,
}

impl SessionRegistry {
    /// A registry admitting at most `max_sessions` concurrent sessions.
    #[must_use]
    pub fn new(max_sessions: usize) -> Self {
        Self {
            // A cap of zero would mean an agent that accepts nothing, which is never
            // what an operator means by it; configuration validation rejects it, and
            // this is a second line so the value can never be load-bearing.
            max_sessions: max_sessions.max(1),
            reserved: AtomicUsize::new(0),
            sessions: Mutex::new(Vec::new()),
        }
    }

    /// The configured cap.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.max_sessions
    }

    /// Take a slot, or `None` if the agent is already at its cap.
    ///
    /// The returned slot releases itself when dropped.
    pub fn reserve(self: &Arc<Self>) -> Option<SessionSlot> {
        // Compare-and-swap rather than "read, check, increment": two connections
        // arriving together must not both observe room for the last slot.
        let mut current = self.reserved.load(Ordering::Acquire);
        loop {
            if current >= self.max_sessions {
                return None;
            }
            match self.reserved.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(SessionSlot {
                        registry: Arc::clone(self),
                        session_id: Mutex::new(None),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    /// How many slots are currently taken, authenticating connections included.
    #[must_use]
    pub fn reserved_count(&self) -> usize {
        self.reserved.load(Ordering::Acquire)
    }

    /// Every authenticated session, newest first.
    #[must_use]
    pub fn list(&self) -> Vec<LiveSession> {
        let mut sessions = self
            .sessions
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        sessions.sort_by_key(|session| std::cmp::Reverse(session.started_at_ms));
        sessions
    }

    fn insert(&self, session: LiveSession) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.push(session);
        }
    }

    fn remove(&self, session_id: SessionId) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|s| s.session_id != session_id);
        }
    }

    fn touch(&self, session_id: SessionId, now_ms: i64) {
        if let Ok(mut sessions) = self.sessions.lock()
            && let Some(session) = sessions.iter_mut().find(|s| s.session_id == session_id)
        {
            session.last_active_ms = now_ms;
        }
    }

    fn release(&self) {
        // Saturating: an underflow would silently raise the cap, which is the one
        // direction this must never move in.
        let _ = self
            .reserved
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_sub(1))
            });
    }
}

/// One reservation against the session cap.
///
/// Releasing on `Drop` is the point: there is no early return, error path or
/// cancellation that can leak the slot.
#[derive(Debug)]
pub struct SessionSlot {
    registry: Arc<SessionRegistry>,
    /// Set once the connection authenticates. A reservation that never gets this far
    /// still occupied a slot and still releases it.
    session_id: Mutex<Option<SessionId>>,
}

impl SessionSlot {
    /// Record that this reservation became an authenticated session.
    pub fn activate(
        &self,
        session_id: SessionId,
        device_id: DeviceId,
        permissions: PermissionSet,
        source: SocketAddr,
        now_ms: i64,
    ) {
        if let Ok(mut slot) = self.session_id.lock() {
            *slot = Some(session_id);
        }
        self.registry.insert(LiveSession {
            session_id,
            device_id,
            permissions,
            source: source.ip().to_string(),
            started_at_ms: now_ms,
            last_active_ms: now_ms,
        });
    }

    /// Note that the session did something, for the idle display.
    pub fn touch(&self, now_ms: i64) {
        if let Ok(slot) = self.session_id.lock()
            && let Some(session_id) = *slot
        {
            self.registry.touch(session_id, now_ms);
        }
    }
}

impl Drop for SessionSlot {
    fn drop(&mut self) {
        if let Ok(slot) = self.session_id.lock()
            && let Some(session_id) = *slot
        {
            self.registry.remove(session_id);
        }
        self.registry.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry(cap: usize) -> Arc<SessionRegistry> {
        Arc::new(SessionRegistry::new(cap))
    }

    fn address() -> SocketAddr {
        "10.0.0.5:40000".parse().unwrap()
    }

    #[test]
    fn reservations_are_capped() {
        let registry = registry(2);

        let first = registry.reserve().expect("the first fits");
        let second = registry.reserve().expect("the second fits");
        assert!(registry.reserve().is_none(), "the third must be refused");

        drop(first);
        assert!(
            registry.reserve().is_some(),
            "a released slot must be reusable"
        );
        drop(second);
    }

    #[test]
    fn a_slot_is_released_even_if_the_session_never_authenticated() {
        // The failure this prevents: a connection refused at the handshake leaking a
        // slot, until the agent refuses everything and has to be restarted.
        let registry = registry(1);
        {
            let _slot = registry.reserve().unwrap();
            assert_eq!(registry.reserved_count(), 1);
        }
        assert_eq!(registry.reserved_count(), 0);
        assert!(registry.reserve().is_some());
    }

    #[test]
    fn an_authenticated_session_appears_in_the_list_and_leaves_on_drop() {
        let registry = registry(4);
        let slot = registry.reserve().unwrap();
        let session_id = SessionId::generate();

        slot.activate(
            session_id,
            DeviceId::generate(),
            PermissionSet::ALL,
            address(),
            1_000,
        );

        assert_eq!(
            registry
                .list()
                .iter()
                .map(|s| s.session_id)
                .collect::<Vec<_>>(),
            vec![session_id]
        );

        drop(slot);
        assert!(registry.list().is_empty());
    }

    #[test]
    fn activity_updates_the_last_active_time() {
        let registry = registry(4);
        let slot = registry.reserve().unwrap();
        let session_id = SessionId::generate();

        slot.activate(
            session_id,
            DeviceId::generate(),
            PermissionSet::ALL,
            address(),
            1_000,
        );
        slot.touch(5_000);

        let session = registry.list().into_iter().next().unwrap();
        assert_eq!(session.started_at_ms, 1_000);
        assert_eq!(session.last_active_ms, 5_000);
    }

    #[test]
    fn a_session_records_no_credential() {
        // There is nothing bearer-shaped to record: a session is authenticated by its
        // TLS connection. This pins that the type never grows such a field.
        let registry = registry(1);
        let slot = registry.reserve().unwrap();
        slot.activate(
            SessionId::generate(),
            DeviceId::generate(),
            PermissionSet::ALL,
            address(),
            1,
        );

        let rendered = format!("{:?}", registry.list());
        for forbidden in ["token", "secret", "password", "key"] {
            assert!(
                !rendered.to_lowercase().contains(forbidden),
                "a live session must not carry a {forbidden}"
            );
        }
    }

    #[test]
    fn sessions_are_listed_newest_first() {
        let registry = registry(4);
        let older = registry.reserve().unwrap();
        let newer = registry.reserve().unwrap();

        let old_id = SessionId::generate();
        let new_id = SessionId::generate();
        older.activate(
            old_id,
            DeviceId::generate(),
            PermissionSet::ALL,
            address(),
            1_000,
        );
        newer.activate(
            new_id,
            DeviceId::generate(),
            PermissionSet::ALL,
            address(),
            9_000,
        );

        let listed = registry.list();
        assert_eq!(listed[0].session_id, new_id);
        assert_eq!(listed[1].session_id, old_id);
    }

    #[test]
    fn a_cap_of_zero_is_treated_as_one_rather_than_refusing_everything() {
        // Configuration validation rejects zero; this is the second line, so the value
        // can never silently mean "accept nothing".
        let registry = registry(0);
        assert_eq!(registry.capacity(), 1);
        assert!(registry.reserve().is_some());
    }

    #[test]
    fn concurrent_reservations_never_exceed_the_cap() {
        // Two connections arriving together must not both take the last slot.
        let registry = registry(8);
        let mut handles = Vec::new();

        for _ in 0..16 {
            let registry = Arc::clone(&registry);
            handles.push(std::thread::spawn(move || registry.reserve()));
        }

        let slots: Vec<_> = handles
            .into_iter()
            .filter_map(|handle| handle.join().unwrap())
            .collect();

        assert_eq!(slots.len(), 8, "exactly the cap must be handed out");
        assert_eq!(registry.reserved_count(), 8);
    }
}
