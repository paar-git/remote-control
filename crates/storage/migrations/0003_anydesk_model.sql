-- The AnyDesk access model.
--
-- This migration is deliberately destructive, and it is the only one that is. The
-- owner account, the pairing history, the audit trail and the trusted-device table
-- describe a model the product no longer has; carrying them forward would leave rows
-- that nothing reads and that imply guarantees nothing enforces.
--
-- The additive-only policy resumes after this migration. Nothing has shipped, so no
-- installed database is being destroyed.
--
-- Table names below are singular (owner_account, pairing_code, audit_event,
-- trusted_device), matching 0001_initial.sql and 0002_pairing_and_trust.sql. `IF
-- EXISTS` makes a name mismatch here silently do nothing, which would defeat the
-- point of this migration, so the names are checked against the two migrations that
-- created them rather than guessed.
--
-- session_token is dropped alongside owner_account: its only column of substance,
-- account_id, is a foreign key into owner_account, and it has no reader or writer
-- anywhere in the codebase. Left in place it would be a table describing a login
-- session for an account type that no longer exists, referencing a table that no
-- longer exists.

DROP TABLE IF EXISTS session_token;
DROP TABLE IF EXISTS owner_account;
DROP TABLE IF EXISTS pairing_code;
DROP TABLE IF EXISTS audit_event;
DROP TABLE IF EXISTS trusted_device;

-- Machines this one has connected to.
--
-- The address is the key because the address is what the user types. A machine that
-- moves to a new address is a new row, which is correct: the user reaches it by a
-- different name and its pinned fingerprint has to be re-decided.
CREATE TABLE recent_connections (
    address              TEXT    NOT NULL PRIMARY KEY,
    machine_name         TEXT    NOT NULL,
    last_connected_ms    INTEGER NOT NULL,
    -- Set only when the user ticked "always allow". NULL means every connection to
    -- this machine still raises the Accept dialog.
    pinned_fingerprint   TEXT,
    -- The permissions an always-allow connection receives. Meaningless, and required
    -- to be zero, when pinned_fingerprint is NULL.
    pinned_permissions   INTEGER NOT NULL DEFAULT 0,

    CHECK (length(address) BETWEEN 1 AND 255),
    CHECK (length(machine_name) BETWEEN 1 AND 255),
    CHECK (last_connected_ms > 0),
    CHECK (pinned_permissions BETWEEN 0 AND 7),
    CHECK (pinned_fingerprint IS NOT NULL OR pinned_permissions = 0)
) STRICT;

CREATE INDEX idx_recent_connections_last_connected
    ON recent_connections (last_connected_ms DESC);

-- This machine's own settings. Exactly one row, pinned by the CHECK on id.
CREATE TABLE host_settings (
    id                     INTEGER NOT NULL PRIMARY KEY,
    accepting              INTEGER NOT NULL DEFAULT 1,
    listen_port            INTEGER NOT NULL DEFAULT 7443,
    machine_name           TEXT    NOT NULL,
    -- Argon2id PHC string. NULL means unattended access is not configured, which is
    -- a different state from "configured with a weak password" and is the default.
    unattended_phc         TEXT,
    unattended_permissions INTEGER NOT NULL DEFAULT 0,

    CHECK (id = 1),
    CHECK (accepting IN (0, 1)),
    CHECK (listen_port BETWEEN 1 AND 65535),
    CHECK (length(machine_name) BETWEEN 1 AND 255),
    CHECK (unattended_permissions BETWEEN 0 AND 7),
    CHECK (unattended_phc IS NOT NULL OR unattended_permissions = 0)
) STRICT;
