-- Room for the ViewScreen permission.
--
-- Watching a remote screen becomes its own grant rather than something implied by being
-- allowed to move the pointer. It takes bit 5, so every stored permission bound widens
-- from 15 to 31. The existing four bits keep their meanings and their positions, so no
-- row is reinterpreted: a device trusted before this migration reads back with exactly
-- the permissions it was given, and without the new one.
--
-- That is the intended direction. A device trusted to read a CPU graph must not silently
-- gain the ability to watch the desk it sits on, so this fails closed and every device
-- that should see a screen has to be granted it deliberately.
--
-- SQLite cannot alter a CHECK in place, so each affected table is rebuilt and its rows
-- carried across verbatim, exactly as 0004 did when it widened the same bound from 7 to
-- 15. Nothing is re-decided here.

-- Devices a human has decided to remember.
CREATE TABLE trusted_devices_new (
    identity_fingerprint TEXT    NOT NULL PRIMARY KEY,
    device_id            TEXT    NOT NULL,
    display_name         TEXT    NOT NULL,
    os_family            TEXT    NOT NULL,
    last_address         TEXT,
    added_ms             INTEGER NOT NULL,
    last_connected_ms    INTEGER,
    unattended           INTEGER NOT NULL DEFAULT 0,
    suspended            INTEGER NOT NULL DEFAULT 0,
    -- Now bits 1-5: ControlInput, TransferFiles, ViewMetrics, Administer, ViewScreen.
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
    CHECK (permissions BETWEEN 0 AND 31)
) STRICT;

INSERT INTO trusted_devices_new
    (identity_fingerprint, device_id, display_name, os_family, last_address, added_ms,
     last_connected_ms, unattended, suspended, permissions)
SELECT
     identity_fingerprint, device_id, display_name, os_family, last_address, added_ms,
     last_connected_ms, unattended, suspended, permissions
FROM trusted_devices;

DROP TABLE trusted_devices;
ALTER TABLE trusted_devices_new RENAME TO trusted_devices;

CREATE INDEX idx_trusted_devices_last_address ON trusted_devices (last_address);

-- What happened, so the Sessions page can show it.
CREATE TABLE session_history_new (
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
    CHECK (permissions BETWEEN 0 AND 31),
    CHECK (outcome IN ('completed', 'refused', 'failed'))
) STRICT;

-- The id is carried across so history rows keep their identity and ordering.
INSERT INTO session_history_new
    (id, session_id, identity_fingerprint, device_name, direction, address, started_ms,
     ended_ms, permissions, outcome, end_reason)
SELECT
     id, session_id, identity_fingerprint, device_name, direction, address, started_ms,
     ended_ms, permissions, outcome, end_reason
FROM session_history;

DROP TABLE session_history;
ALTER TABLE session_history_new RENAME TO session_history;

CREATE INDEX idx_session_history_started ON session_history (started_ms DESC);

-- The unattended grant, which is the one this change most exists for: it is applied
-- with no human present to notice what it now covers.
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
    CHECK (unattended_permissions BETWEEN 0 AND 31),
    CHECK (unattended_phc IS NOT NULL OR unattended_permissions = 0)
) STRICT;

INSERT INTO host_settings_new
    (id, accepting, listen_port, machine_name, unattended_phc, unattended_permissions)
SELECT id, accepting, listen_port, machine_name, unattended_phc, unattended_permissions
FROM host_settings;

DROP TABLE host_settings;
ALTER TABLE host_settings_new RENAME TO host_settings;
