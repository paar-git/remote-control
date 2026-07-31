//! The owner account: creation, authentication, throttling and hash upgrades.
//!
//! # Authentication flow
//!
//! [`OwnerRepository::authenticate`] performs, in this order:
//!
//! 1. **Throttle check.** A locked-out account is refused before any hashing, so
//!    lockout is not itself a way to make the server do expensive work.
//! 2. **Account lookup.** If the account does not exist, a dummy Argon2id hash is
//!    computed anyway ([`rc_security::password::verify_against_nothing`]) so the
//!    response time does not reveal whether it exists, and the *same* error is
//!    returned.
//! 3. **Verification.** Constant-time inside Argon2.
//! 4. **Bookkeeping.** Success clears the failure counter and records the login;
//!    failure increments it and may set a lockout.
//! 5. **Upgrade check.** If the stored hash was made with weaker parameters than
//!    current policy, it is transparently rehashed — this is the only moment the
//!    plaintext is available to do so.
//!
//! There is no default password and no way to create an account without supplying
//! one.

use rc_security::clock::{Clock, RandomSource};
use rc_security::error::SecurityError;
use rc_security::password::{self, HashingPolicy, OwnerCredential};
use rc_security::permissions::Role;
use rc_security::throttle::Throttle;

use crate::error::{Result, StorageError};
use crate::models::OwnerAccountRow;

/// Maximum accepted username length.
const MAX_USERNAME_BYTES: usize = 64;

/// A successful authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedOwner {
    /// Account identifier.
    pub account_id: String,
    /// Login name.
    pub username: String,
    /// Role. Always [`Role::Owner`] in v1.
    pub role: Role,
    /// Whether the stored password hash was upgraded during this login.
    pub password_hash_upgraded: bool,
}

/// Reads and writes the owner account.
///
/// Holds the login [`Throttle`] so lockout state survives across calls within a
/// process. Restarting the agent resets in-memory lockouts, but the persisted
/// `failed_login_count` and `locked_until_ms` columns carry the state forward.
#[derive(Debug)]
pub struct OwnerRepository {
    pool: sqlx::Pool<sqlx::Sqlite>,
    throttle: std::sync::Mutex<Throttle>,
    policy: HashingPolicy,
}

impl OwnerRepository {
    /// A repository over `database` using the production hashing policy.
    #[must_use]
    pub fn new(database: &crate::Database) -> Self {
        Self::with_policy(database, HashingPolicy::PRODUCTION)
    }

    /// A repository using explicit hashing parameters.
    ///
    /// Tests pass [`HashingPolicy::FAST_FOR_TESTS`] so the suite does not spend a
    /// second per login.
    #[must_use]
    pub fn with_policy(database: &crate::Database, policy: HashingPolicy) -> Self {
        Self {
            pool: database.pool().clone(),
            throttle: std::sync::Mutex::new(Throttle::with_defaults()),
            policy,
        }
    }

    /// Whether an owner account exists yet. Drives the first-run wizard.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn exists(&self) -> Result<bool> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM owner_account")
            .fetch_one(&self.pool)
            .await?;
        Ok(count > 0)
    }

    /// Create the owner account.
    ///
    /// # Errors
    /// [`StorageError::Conflict`] if an account already exists — there is exactly one
    /// owner in v1, and silently creating a second would be a privilege-escalation
    /// path. [`StorageError::Invalid`] for a bad username, or a wrapped
    /// [`SecurityError::WeakPassword`] for a bad password.
    pub async fn create(
        &self,
        username: &str,
        password: &str,
        clock: &dyn Clock,
        rng: &dyn RandomSource,
    ) -> Result<String> {
        validate_username(username)?;

        if self.exists().await? {
            return Err(StorageError::Conflict);
        }

        let credential = OwnerCredential::create(password, self.policy, rng)
            .map_err(|err| security_to_storage(&err))?;

        let account_id = rc_protocol::UserId::generate().to_canonical_string();
        let now = clock.now_ms();

        sqlx::query(
            "INSERT INTO owner_account (
                 id, username, password_hash, role, created_at_ms,
                 password_hash_memory_kib, password_hash_iterations,
                 password_hash_parallelism, password_changed_at_ms
             ) VALUES (?, ?, ?, 'owner', ?, ?, ?, ?, ?)",
        )
        .bind(&account_id)
        .bind(username)
        .bind(credential.expose_phc_for_storage())
        .bind(now)
        .bind(i64::from(self.policy.memory_kib))
        .bind(i64::from(self.policy.iterations))
        .bind(i64::from(self.policy.parallelism))
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(account_id)
    }

    /// Authenticate the owner.
    ///
    /// # Errors
    /// * [`SecurityError::Throttled`] when locked out.
    /// * [`SecurityError::InvalidCredentials`] for a wrong password **or** an unknown
    ///   account — deliberately identical.
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
        clock: &dyn Clock,
    ) -> Result<std::result::Result<AuthenticatedOwner, SecurityError>> {
        // 1. Throttle first, so lockout costs nothing to enforce.
        if let Err(err) = self.check_throttle(username, clock) {
            return Ok(Err(err));
        }

        // 2. Look the account up.
        let row: Option<OwnerAccountRow> =
            sqlx::query_as("SELECT * FROM owner_account WHERE username = ?")
                .bind(username)
                .fetch_optional(&self.pool)
                .await?;

        let Some(account) = row else {
            // Spend comparable work and return the identical error, so a missing
            // account is indistinguishable from a wrong password.
            // `verify_against_nothing` cannot succeed — it has no stored hash to match
            // against — but it is spelled as a total match rather than an `expect_err`
            // so that no future change to it can turn this branch into a panic on the
            // unauthenticated login path.
            let err = password::verify_against_nothing(password, self.policy)
                .err()
                .unwrap_or(SecurityError::InvalidCredentials);
            self.record_failure(username, clock);
            return Ok(Err(err));
        };

        // A lockout persisted from a previous process run still applies.
        if account.is_locked_at(clock.now_ms()) {
            let remaining = account
                .locked_until_ms
                .unwrap_or_default()
                .saturating_sub(clock.now_ms())
                .unsigned_abs()
                .div_ceil(1000)
                .max(1);
            return Ok(Err(SecurityError::Throttled {
                retry_after_secs: remaining,
            }));
        }

        // 3. Verify.
        let credential = OwnerCredential::from_phc(account.password_hash.clone())
            .map_err(|err| security_to_storage(&err))?;

        if credential.verify(password).is_err() {
            self.record_failure(username, clock);
            self.persist_failure(&account.id, clock).await?;
            return Ok(Err(SecurityError::InvalidCredentials));
        }

        // 4. Success: clear counters.
        self.record_success(username, clock);

        // 5. Upgrade the hash if policy has moved on. This is the only point at which
        // the plaintext is available to rehash with.
        let mut upgraded = false;
        if credential.needs_rehash(self.policy) || !credential.is_argon2id() {
            if let Ok(new_credential) =
                OwnerCredential::create(password, self.policy, &rc_security::OsRandom)
            {
                self.store_upgraded_hash(&account.id, &new_credential, clock)
                    .await?;
                upgraded = true;
            } else {
                // A failed upgrade must not fail the login: the existing hash is
                // still valid, just weaker than we would now choose.
                tracing::warn!("could not upgrade the owner password hash");
            }
        }

        self.record_login(&account.id, clock).await?;

        let role = Role::from_name(&account.role)
            .ok_or(StorageError::MalformedColumn { column: "role" })?;

        Ok(Ok(AuthenticatedOwner {
            account_id: account.id,
            username: account.username,
            role,
            password_hash_upgraded: upgraded,
        }))
    }

    /// Change the owner's password. Requires the current one.
    ///
    /// # Errors
    /// [`SecurityError::InvalidCredentials`] if the current password is wrong.
    pub async fn change_password(
        &self,
        username: &str,
        current_password: &str,
        new_password: &str,
        clock: &dyn Clock,
        rng: &dyn RandomSource,
    ) -> Result<std::result::Result<(), SecurityError>> {
        let row: Option<OwnerAccountRow> =
            sqlx::query_as("SELECT * FROM owner_account WHERE username = ?")
                .bind(username)
                .fetch_optional(&self.pool)
                .await?;

        let Some(account) = row else {
            return Ok(Err(SecurityError::InvalidCredentials));
        };

        let credential = OwnerCredential::from_phc(account.password_hash.clone())
            .map_err(|err| security_to_storage(&err))?;
        if credential.verify(current_password).is_err() {
            self.record_failure(username, clock);
            return Ok(Err(SecurityError::InvalidCredentials));
        }

        let new_credential = match OwnerCredential::create(new_password, self.policy, rng) {
            Ok(credential) => credential,
            Err(err) => return Ok(Err(err)),
        };

        self.store_upgraded_hash(&account.id, &new_credential, clock)
            .await?;
        Ok(Ok(()))
    }

    /// Current failure count recorded for `username`, in memory.
    #[must_use]
    pub fn failure_count(&self, username: &str) -> u32 {
        self.throttle
            .lock()
            .map_or(0, |t| t.failure_count(username))
    }

    fn check_throttle(
        &self,
        username: &str,
        clock: &dyn Clock,
    ) -> std::result::Result<(), SecurityError> {
        match self.throttle.lock() {
            Ok(throttle) => throttle.check(username, clock),
            // A poisoned throttle means a previous holder panicked. Failing closed is
            // the safe choice: better to refuse a login than to disable throttling.
            Err(_) => Err(SecurityError::Throttled {
                retry_after_secs: 60,
            }),
        }
    }

    fn record_failure(&self, username: &str, clock: &dyn Clock) {
        if let Ok(mut throttle) = self.throttle.lock() {
            throttle.record_failure(username, clock);
        }
    }

    fn record_success(&self, username: &str, clock: &dyn Clock) {
        if let Ok(mut throttle) = self.throttle.lock() {
            throttle.record_success(username, clock);
        }
    }

    /// Mirror the in-memory failure state into the database so it survives a restart.
    async fn persist_failure(&self, account_id: &str, clock: &dyn Clock) -> Result<()> {
        let now = clock.now_ms();
        let policy = rc_security::ThrottlePolicy::default();

        // Read-modify-write within one statement so concurrent failures cannot lose a
        // count.
        sqlx::query(
            "UPDATE owner_account
             SET failed_login_count = failed_login_count + 1,
                 locked_until_ms = CASE
                     WHEN failed_login_count + 1 > ?
                     THEN ? + MIN(?, ? * (1 << MIN(30, failed_login_count - ?))) * 1000
                     ELSE locked_until_ms
                 END
             WHERE id = ?",
        )
        .bind(i64::from(policy.free_attempts))
        .bind(now)
        .bind(i64::try_from(policy.max_lockout_secs).unwrap_or(i64::MAX))
        .bind(i64::try_from(policy.base_lockout_secs).unwrap_or(1))
        .bind(i64::from(policy.free_attempts))
        .bind(account_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn record_login(&self, account_id: &str, clock: &dyn Clock) -> Result<()> {
        sqlx::query(
            "UPDATE owner_account
             SET last_login_at_ms = ?, failed_login_count = 0, locked_until_ms = NULL
             WHERE id = ?",
        )
        .bind(clock.now_ms())
        .bind(account_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn store_upgraded_hash(
        &self,
        account_id: &str,
        credential: &OwnerCredential,
        clock: &dyn Clock,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE owner_account
             SET password_hash = ?,
                 password_hash_memory_kib = ?,
                 password_hash_iterations = ?,
                 password_hash_parallelism = ?,
                 password_changed_at_ms = ?
             WHERE id = ?",
        )
        .bind(credential.expose_phc_for_storage())
        .bind(i64::from(self.policy.memory_kib))
        .bind(i64::from(self.policy.iterations))
        .bind(i64::from(self.policy.parallelism))
        .bind(clock.now_ms())
        .bind(account_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

/// Reject usernames that are unusable or would be confusing to store.
fn validate_username(username: &str) -> Result<()> {
    if username.trim().is_empty() {
        return Err(StorageError::Invalid {
            field: "username",
            reason: "must not be empty",
        });
    }
    if username.len() > MAX_USERNAME_BYTES {
        return Err(StorageError::Invalid {
            field: "username",
            reason: "is too long",
        });
    }
    if username != username.trim() {
        return Err(StorageError::Invalid {
            field: "username",
            reason: "must not have leading or trailing whitespace",
        });
    }
    if username.chars().any(char::is_control) {
        return Err(StorageError::Invalid {
            field: "username",
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

/// Map a security error into the storage error space, preserving password-policy
/// detail that the caller needs to show the user.
fn security_to_storage(err: &SecurityError) -> StorageError {
    match *err {
        SecurityError::WeakPassword { reason } => StorageError::Invalid {
            field: "password",
            reason,
        },
        _ => StorageError::Invalid {
            field: "password",
            reason: "could not be processed",
        },
    }
}
