-- Initial schema.
--
-- Applies to both the client-side and agent-side databases; each side uses the
-- subset of tables relevant to it. Every migration in this project is additive:
-- destructive changes must ship as an explicit, separately-invoked maintenance
-- command, never as an automatic migration.
--
-- Storage rules enforced here:
--   * No table stores a password, token, or private key in plaintext.
--   * `owner_account.password_hash` holds an Argon2id PHC string, never a password.
--   * Session tokens are stored only as a hash, so database theft does not yield a
--     usable bearer credential.

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- Owner account (client side). Exactly one row is expected in v1.
-- ---------------------------------------------------------------------------
CREATE TABLE owner_account (
    id                     TEXT    PRIMARY KEY,
    username               TEXT    NOT NULL UNIQUE,
    -- Argon2id PHC string, e.g. "$argon2id$v=19$m=65536,t=3,p=4$...".
    password_hash          TEXT    NOT NULL,
    -- 'owner' is the only role in v1; the column exists so adding roles later is
    -- an additive migration.
    role                   TEXT    NOT NULL DEFAULT 'owner'
                                   CHECK (role IN ('owner')),
    created_at_ms          INTEGER NOT NULL,
    last_login_at_ms       INTEGER,
    failed_login_count     INTEGER NOT NULL DEFAULT 0,
    -- Non-null while the account is throttled after repeated failures.
    locked_until_ms        INTEGER,
    -- OS credential / biometric unlock opt-in.
    os_unlock_enabled      INTEGER NOT NULL DEFAULT 0 CHECK (os_unlock_enabled IN (0, 1)),
    auto_lock_after_secs   INTEGER NOT NULL DEFAULT 900
                                   CHECK (auto_lock_after_secs BETWEEN 0 AND 86400)
) STRICT;

-- ---------------------------------------------------------------------------
-- This installation's own cryptographic identity.
-- The private key is NOT stored here; it lives in an OS-protected keystore
-- (DPAPI / Credential Manager on Windows, 0600 file under the agent's data dir on
-- Linux). Only the public parts and a locator are kept.
-- ---------------------------------------------------------------------------
CREATE TABLE local_identity (
    id                     INTEGER PRIMARY KEY CHECK (id = 1),
    device_id              TEXT    NOT NULL,
    display_name           TEXT    NOT NULL,
    -- Lowercase hex SHA-256 over the certificate DER.
    certificate_fingerprint TEXT   NOT NULL,
    -- Lowercase hex Ed25519 public key.
    identity_public_key    TEXT    NOT NULL,
    certificate_pem        TEXT    NOT NULL,
    -- Opaque handle understood by the platform keystore; never the key itself.
    private_key_ref        TEXT    NOT NULL,
    created_at_ms          INTEGER NOT NULL,
    rotated_at_ms          INTEGER
) STRICT;

-- ---------------------------------------------------------------------------
-- Saved devices (client side) and authorized clients (agent side).
-- ---------------------------------------------------------------------------
CREATE TABLE trusted_device (
    device_id              TEXT    PRIMARY KEY,
    -- 'agent' rows are servers this client may connect to.
    -- 'client' rows are clients this agent will accept connections from.
    peer_role              TEXT    NOT NULL CHECK (peer_role IN ('agent', 'client')),
    -- User-editable label shown in the device list.
    display_name           TEXT    NOT NULL,
    hostname               TEXT    NOT NULL DEFAULT '',
    os_family              TEXT    NOT NULL DEFAULT 'unknown'
                                   CHECK (os_family IN ('windows', 'linux', 'macos', 'unknown')),
    os_version             TEXT    NOT NULL DEFAULT '',
    -- Pinned. A mismatch at connect time is a hard, user-visible failure.
    certificate_fingerprint TEXT   NOT NULL,
    identity_public_key    TEXT    NOT NULL,
    paired_at_ms           INTEGER NOT NULL,
    last_connected_at_ms   INTEGER,
    last_known_address     TEXT,
    last_known_port        INTEGER CHECK (last_known_port IS NULL
                                          OR last_known_port BETWEEN 1 AND 65535),
    -- Operator-configured fallback endpoint reachable from outside the LAN.
    remote_endpoint        TEXT,
    wake_on_lan_mac        TEXT,
    favorite               INTEGER NOT NULL DEFAULT 0 CHECK (favorite IN (0, 1)),
    -- Revoked devices are retained, not deleted, so the audit trail stays intact.
    revoked                INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
    revoked_at_ms          INTEGER,
    -- JSON blob of per-device connection preferences, validated by the app layer.
    preferences_json       TEXT    NOT NULL DEFAULT '{}'
) STRICT;

CREATE INDEX idx_trusted_device_role      ON trusted_device (peer_role, revoked);
CREATE INDEX idx_trusted_device_last_conn ON trusted_device (last_connected_at_ms DESC);
CREATE UNIQUE INDEX idx_trusted_device_fingerprint ON trusted_device (certificate_fingerprint);

-- ---------------------------------------------------------------------------
-- Pairing codes issued by an agent. Single-use and short-lived.
-- Only a hash of the code is stored, so reading the database does not reveal an
-- active code.
-- ---------------------------------------------------------------------------
CREATE TABLE pairing_code (
    id                     TEXT    PRIMARY KEY,
    code_hash              TEXT    NOT NULL,
    -- Per-code random salt, so identical codes do not produce identical hashes.
    code_salt              TEXT    NOT NULL,
    created_at_ms          INTEGER NOT NULL,
    expires_at_ms          INTEGER NOT NULL,
    -- Set the moment the code is successfully used; enforces single use.
    consumed_at_ms         INTEGER,
    attempt_count          INTEGER NOT NULL DEFAULT 0,
    max_attempts           INTEGER NOT NULL DEFAULT 5,
    CHECK (expires_at_ms > created_at_ms)
) STRICT;

CREATE INDEX idx_pairing_code_expiry ON pairing_code (expires_at_ms);

-- ---------------------------------------------------------------------------
-- Application session tokens. Stored hashed; the plaintext token exists only in
-- memory and in the client's OS keystore.
-- ---------------------------------------------------------------------------
CREATE TABLE session_token (
    id                     TEXT    PRIMARY KEY,
    account_id             TEXT    NOT NULL REFERENCES owner_account (id) ON DELETE CASCADE,
    device_id              TEXT,
    token_kind             TEXT    NOT NULL CHECK (token_kind IN ('access', 'refresh')),
    token_hash             TEXT    NOT NULL UNIQUE,
    issued_at_ms           INTEGER NOT NULL,
    expires_at_ms          INTEGER NOT NULL,
    -- Set when a refresh token is exchanged, to detect token replay: presenting an
    -- already-rotated refresh token invalidates the whole chain.
    rotated_at_ms          INTEGER,
    revoked_at_ms          INTEGER,
    -- Links a rotated refresh token to its successor.
    replaced_by_id         TEXT    REFERENCES session_token (id) ON DELETE SET NULL,
    CHECK (expires_at_ms > issued_at_ms)
) STRICT;

CREATE INDEX idx_session_token_account ON session_token (account_id, token_kind);
CREATE INDEX idx_session_token_expiry  ON session_token (expires_at_ms);

-- ---------------------------------------------------------------------------
-- Connection history, powering "last connected" and the Activity page.
-- ---------------------------------------------------------------------------
CREATE TABLE connection_event (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id              TEXT    NOT NULL,
    occurred_at_ms         INTEGER NOT NULL,
    event                  TEXT    NOT NULL CHECK (event IN (
                                       'connect_started', 'connected', 'auth_failed',
                                       'identity_mismatch', 'disconnected',
                                       'reconnect_attempt', 'reconnect_succeeded',
                                       'reconnect_abandoned')),
    -- 'lan_direct', 'p2p', 'relay'
    network_mode           TEXT,
    remote_address         TEXT,
    latency_ms             INTEGER,
    detail                 TEXT
) STRICT;

CREATE INDEX idx_connection_event_time   ON connection_event (occurred_at_ms DESC);
CREATE INDEX idx_connection_event_device ON connection_event (device_id, occurred_at_ms DESC);

-- ---------------------------------------------------------------------------
-- Audit log. Append-only by convention; the application never issues UPDATE or
-- DELETE against it outside of the explicit retention-pruning command.
--
-- `metadata_json` is sanitised before insertion: no passwords, tokens, clipboard
-- contents, file contents, or command text.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_event (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at_ms         INTEGER NOT NULL,
    category               TEXT    NOT NULL CHECK (category IN (
                                       'auth', 'pairing', 'connection', 'file_transfer',
                                       'privileged_action', 'power', 'permission',
                                       'device_revocation', 'agent_update', 'config')),
    action                 TEXT    NOT NULL,
    result                 TEXT    NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
    actor_account_id       TEXT,
    actor_device_id        TEXT,
    target_device_id       TEXT,
    session_id             TEXT,
    metadata_json          TEXT    NOT NULL DEFAULT '{}'
) STRICT;

CREATE INDEX idx_audit_event_time     ON audit_event (occurred_at_ms DESC);
CREATE INDEX idx_audit_event_category ON audit_event (category, occurred_at_ms DESC);

-- ---------------------------------------------------------------------------
-- Resumable file transfers. Survives client and agent restarts.
-- ---------------------------------------------------------------------------
CREATE TABLE transfer_state (
    transfer_id            TEXT    PRIMARY KEY,
    device_id              TEXT    NOT NULL,
    direction              TEXT    NOT NULL CHECK (direction IN ('upload', 'download')),
    source_path            TEXT    NOT NULL,
    destination_path       TEXT    NOT NULL,
    total_bytes            INTEGER NOT NULL CHECK (total_bytes >= 0),
    transferred_bytes      INTEGER NOT NULL DEFAULT 0 CHECK (transferred_bytes >= 0),
    checksum_algorithm     TEXT    NOT NULL DEFAULT 'blake3',
    expected_checksum      TEXT,
    status                 TEXT    NOT NULL CHECK (status IN (
                                       'queued', 'active', 'paused', 'completed',
                                       'failed', 'cancelled')),
    created_at_ms          INTEGER NOT NULL,
    updated_at_ms          INTEGER NOT NULL,
    error_message          TEXT,
    CHECK (transferred_bytes <= total_bytes)
) STRICT;

CREATE INDEX idx_transfer_state_status ON transfer_state (status, created_at_ms);

-- ---------------------------------------------------------------------------
-- Key/value settings. Values are JSON and validated by the config layer before
-- being written; the schema only guarantees the key is unique.
-- ---------------------------------------------------------------------------
CREATE TABLE app_setting (
    key                    TEXT    PRIMARY KEY,
    value_json             TEXT    NOT NULL,
    updated_at_ms          INTEGER NOT NULL
) STRICT;
