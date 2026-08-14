-- Device-identity trust.
--
-- Persistent access moves off the address it was typed at and onto the device identity
-- it was granted to. The trust key is the SHA-256 of a peer's Ed25519 identity public
-- key, read from the certificate it presents (see `rc-security`'s `certificate` module)
-- and therefore proved by the TLS handshake rather than claimed in a message body.
--
-- This migration drops two columns, which breaks the additive-only policy that 0003
-- reinstated. It is done once, for one reason: `recent_connections.pinned_fingerprint`
-- holds a *certificate* digest, and the identity behind it was never recorded, so the
-- new key cannot be derived from the old row. Carrying the columns forward would leave
-- a second, address-keyed answer to "may this device in?", which is exactly the defect
-- being removed. Anything currently pinned has to be trusted once more.

-- Devices a human has decided to remember.
--
-- Keyed on the identity, not the address: a device reached at a new address is the same
-- device and keeps its grant, and a different device answering at a familiar address is
-- a stranger rather than an heir to one.
CREATE TABLE trusted_devices (
    identity_fingerprint TEXT    NOT NULL PRIMARY KEY,
    -- The peer's self-reported device id. Display only; never used to decide anything.
    device_id            TEXT    NOT NULL,
    display_name         TEXT    NOT NULL,
    os_family            TEXT    NOT NULL,
    -- Where it last connected from. Shown to the operator, and used to detect a
    -- different device answering at a trusted device's address. NEVER authenticates.
    last_address         TEXT,
    added_ms             INTEGER NOT NULL,
    last_connected_ms    INTEGER,
    -- How the device gets in: may it reconnect without anyone approving?
    unattended           INTEGER NOT NULL DEFAULT 0,
    -- Temporarily refused, with the row and every setting on it retained.
    suspended            INTEGER NOT NULL DEFAULT 0,
    -- What an admitted session may do, including bit 4, Administer. Separate from
    -- `unattended` on purpose: how a device gets in says nothing about what it may do
    -- once in, and the two are written by different methods so they cannot move
    -- together by accident.
    permissions          INTEGER NOT NULL DEFAULT 0,

    CHECK (length(identity_fingerprint) = 64),
    CHECK (length(device_id) BETWEEN 1 AND 128),
    CHECK (length(display_name) BETWEEN 1 AND 255),
    CHECK (length(os_family) BETWEEN 1 AND 32),
    CHECK (last_address IS NULL OR length(last_address) BETWEEN 1 AND 255),
    CHECK (added_ms > 0),
    CHECK (last_connected_ms IS NULL OR last_connected_ms > 0),
    CHECK (unattended IN (0, 1)),
    CHECK (suspended IN (0, 1)),
    CHECK (permissions BETWEEN 0 AND 15)
) STRICT;

CREATE INDEX idx_trusted_devices_last_address ON trusted_devices (last_address);

-- What happened, so the Sessions page can show it. Capped by the writer on every
-- insert rather than by a job, so an unattended machine cannot grow it without bound.
--
-- session_id and identity_fingerprint are both nullable because a connection that was
-- refused has neither, and a refusal is exactly the thing an operator most wants to see
-- in the list.
CREATE TABLE session_history (
    id                   INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    session_id           TEXT,
    identity_fingerprint TEXT,
    device_name          TEXT    NOT NULL,
    direction            TEXT    NOT NULL,
    address              TEXT    NOT NULL,
    started_ms           INTEGER NOT NULL,
    ended_ms             INTEGER,
    permissions          INTEGER NOT NULL DEFAULT 0,
    outcome              TEXT    NOT NULL,
    end_reason           TEXT,

    CHECK (identity_fingerprint IS NULL OR length(identity_fingerprint) = 64),
    CHECK (length(device_name) BETWEEN 1 AND 255),
    CHECK (direction IN ('incoming', 'outgoing')),
    CHECK (length(address) BETWEEN 1 AND 255),
    CHECK (started_ms > 0),
    CHECK (ended_ms IS NULL OR ended_ms >= started_ms),
    CHECK (permissions BETWEEN 0 AND 15),
    CHECK (outcome IN ('completed', 'refused', 'failed'))
) STRICT;

CREATE INDEX idx_session_history_started ON session_history (started_ms DESC);

-- Unattended permissions may now carry the Administer bit, so the bound widens from 7
-- to 15. SQLite cannot alter a CHECK in place, so the single-row table is rebuilt and
-- the row carried across verbatim. Nothing is re-decided by this.
CREATE TABLE host_settings_new (
    id                     INTEGER NOT NULL PRIMARY KEY,
    accepting              INTEGER NOT NULL DEFAULT 1,
    listen_port            INTEGER NOT NULL DEFAULT 7443,
    machine_name           TEXT    NOT NULL,
    unattended_phc         TEXT,
    unattended_permissions INTEGER NOT NULL DEFAULT 0,

    CHECK (id = 1),
    CHECK (accepting IN (0, 1)),
    CHECK (listen_port BETWEEN 1 AND 65535),
    CHECK (length(machine_name) BETWEEN 1 AND 255),
    CHECK (unattended_permissions BETWEEN 0 AND 15),
    CHECK (unattended_phc IS NOT NULL OR unattended_permissions = 0)
) STRICT;

INSERT INTO host_settings_new
    (id, accepting, listen_port, machine_name, unattended_phc, unattended_permissions)
SELECT id, accepting, listen_port, machine_name, unattended_phc, unattended_permissions
FROM host_settings;

DROP TABLE host_settings;
ALTER TABLE host_settings_new RENAME TO host_settings;

-- recent_connections keeps its address key -- it is the outgoing dial history, and the
-- address is what the user types. The two pin columns go; an identity the client records
-- on first connection and verifies on every later one replaces them.
CREATE TABLE recent_connections_new (
    address           TEXT    NOT NULL PRIMARY KEY,
    machine_name      TEXT    NOT NULL,
    last_connected_ms INTEGER NOT NULL,
    -- Recorded on the first successful outgoing connection and compared thereafter, so
    -- the client pins an identity rather than a certificate that will be renewed.
    known_identity    TEXT,

    CHECK (length(address) BETWEEN 1 AND 255),
    CHECK (length(machine_name) BETWEEN 1 AND 255),
    CHECK (last_connected_ms > 0),
    CHECK (known_identity IS NULL OR length(known_identity) = 64)
) STRICT;

INSERT INTO recent_connections_new (address, machine_name, last_connected_ms)
SELECT address, machine_name, last_connected_ms FROM recent_connections;

DROP TABLE recent_connections;
ALTER TABLE recent_connections_new RENAME TO recent_connections;

CREATE INDEX idx_recent_connections_last_connected
    ON recent_connections (last_connected_ms DESC);
