-- Phase 2: device identity anchoring, permission roles and pairing audit.
--
-- Additive only. Every statement is an ADD COLUMN or a CREATE; nothing is dropped,
-- renamed or rewritten, so applying this to a populated database cannot lose data.
--
-- Why these columns exist
-- ----------------------
-- `identity_fingerprint` is the durable trust anchor. It is the SHA-256 of the peer's
-- Ed25519 identity public key, which does NOT change when the peer renews its TLS
-- certificate. `certificate_fingerprint` (added in 0001) is the current credential and
-- IS expected to change on renewal. Keeping both is what lets the agent distinguish
-- "this device rotated its certificate" (fine, verify the identity key still matches)
-- from "this is a different device claiming the same name" (hard failure).

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- trusted_device: identity anchoring, roles and authentication history.
-- ---------------------------------------------------------------------------

-- SHA-256 of the identity public key. Empty string means "not yet backfilled",
-- which only occurs for rows written before this migration; there are none in a
-- released build, but the default keeps the ALTER valid.
ALTER TABLE trusted_device ADD COLUMN identity_fingerprint TEXT NOT NULL DEFAULT '';

-- Permission role granted at pairing time. Constrained by application code rather
-- than a CHECK, because adding a role later must not require rewriting the table.
ALTER TABLE trusted_device ADD COLUMN permission_role TEXT NOT NULL DEFAULT 'owner';

-- Comma-separated capability names granted at pairing time. Recorded so a later
-- narrowing of what a role means cannot silently widen an existing device's access.
ALTER TABLE trusted_device ADD COLUMN granted_capabilities TEXT NOT NULL DEFAULT '';

-- Certificate generation counter, so a stale cached credential is detectable without
-- comparing bytes.
ALTER TABLE trusted_device ADD COLUMN certificate_version INTEGER NOT NULL DEFAULT 1;

-- Last time this device completed mutual authentication. Distinct from
-- last_connected_at_ms, which Phase 3 updates on transport connect.
ALTER TABLE trusted_device ADD COLUMN last_authenticated_at_ms INTEGER;

-- Short transcript digest of the pairing exchange that created this trust, for
-- correlating the two sides' audit logs. Not a secret and not a proof.
ALTER TABLE trusted_device ADD COLUMN pairing_transcript_digest TEXT;

-- Identity lookups happen on every connection attempt.
CREATE INDEX idx_trusted_device_identity ON trusted_device (identity_fingerprint);

-- ---------------------------------------------------------------------------
-- pairing_code: link a code to the session and outcome it belonged to.
-- ---------------------------------------------------------------------------

-- The in-memory pairing session this row records. Sessions do not survive an agent
-- restart by design, so this is for audit correlation only.
ALTER TABLE pairing_code ADD COLUMN pairing_session_id TEXT;

-- 'open' | 'consumed' | 'expired' | 'attempts_exhausted' | 'cancelled'
ALTER TABLE pairing_code ADD COLUMN outcome TEXT NOT NULL DEFAULT 'open';

-- Device that ultimately paired using this code, when one did.
ALTER TABLE pairing_code ADD COLUMN paired_device_id TEXT;

CREATE INDEX idx_pairing_code_session ON pairing_code (pairing_session_id);

-- ---------------------------------------------------------------------------
-- owner_account: password-hash upgrade tracking.
-- ---------------------------------------------------------------------------

-- Argon2id parameters the stored hash was created with, so a policy increase can be
-- detected and the hash transparently upgraded on the next successful login.
ALTER TABLE owner_account ADD COLUMN password_hash_memory_kib INTEGER NOT NULL DEFAULT 0;
ALTER TABLE owner_account ADD COLUMN password_hash_iterations INTEGER NOT NULL DEFAULT 0;
ALTER TABLE owner_account ADD COLUMN password_hash_parallelism INTEGER NOT NULL DEFAULT 0;
ALTER TABLE owner_account ADD COLUMN password_changed_at_ms INTEGER;
