//! Schema-level checks that do not belong to a single repository.
//!
//! Repository behaviour is exercised in each repository's own test module
//! (`recent.rs`, `settings.rs`). What lives here is the shape of the schema itself:
//! which tables exist after migration, and that the `CHECK` constraints reject what
//! they are supposed to.

use crate::test_support::temp_database;

/// Every table this build's schema defines, after the destructive migration.
///
/// Pinned by name so a future migration that silently fails to drop an old table — the
/// exact bug this migration's own `DROP TABLE` statements had to be checked against —
/// is caught here rather than discovered later.
#[tokio::test]
async fn the_schema_holds_exactly_the_tables_this_build_knows_about() {
    let database = temp_database().await;

    let mut tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != '_sqlx_migrations'
         ORDER BY name",
    )
    .fetch_all(database.pool())
    .await
    .unwrap();
    tables.sort();

    let mut expected = vec![
        "app_setting",
        "connection_event",
        "host_settings",
        "local_identity",
        "recent_connections",
        "session_history",
        "transfer_state",
        "trusted_devices",
    ];
    expected.sort_unstable();

    assert_eq!(tables, expected, "got tables: {tables:?}");

    // `trusted_device` (singular) was the old model's table and is still gone.
    // `trusted_devices` (plural) is this build's, keyed on a device identity, and is
    // expected above -- the two are different tables answering different questions.
    for gone in [
        "owner_account",
        "owner_accounts",
        "pairing_codes",
        "audit_event",
        "audit_events",
        "trusted_device",
        "session_token",
        "recent_connections_new",
        "host_settings_new",
    ] {
        assert!(!tables.contains(&gone.to_string()), "{gone} must be gone");
    }
}

#[tokio::test]
async fn a_recent_connection_cannot_hold_a_malformed_identity() {
    // The column is a pin, and a pin that is not a whole fingerprint could never match
    // anything -- so it is refused at the schema rather than surfacing later as a
    // device that mysteriously never verifies.
    let database = temp_database().await;

    let err = sqlx::query(
        "INSERT INTO recent_connections
             (address, machine_name, last_connected_ms, known_identity)
         VALUES ('10.0.0.1', 'BOX', 1, 'too-short')",
    )
    .execute(database.pool())
    .await
    .unwrap_err();

    assert!(
        format!("{err}").to_uppercase().contains("CHECK"),
        "got: {err}"
    );
}

#[tokio::test]
async fn a_trusted_device_cannot_hold_a_permission_bit_this_build_does_not_know() {
    // Five permissions occupy bits 1-5. A row carrying bit 6 is not a grant with one
    // extra permission, it is a value this build cannot interpret, and `from_bits`
    // refuses it -- so the schema refuses to store one in the first place.
    let database = temp_database().await;

    let err = sqlx::query(
        "INSERT INTO trusted_devices
             (identity_fingerprint, device_id, display_name, os_family, added_ms, permissions)
         VALUES (?, 'dev', 'Box', 'linux', 1, 32)",
    )
    .bind("a".repeat(64))
    .execute(database.pool())
    .await
    .unwrap_err();

    assert!(
        format!("{err}").to_uppercase().contains("CHECK"),
        "got: {err}"
    );
}

#[tokio::test]
async fn unattended_permissions_may_now_carry_the_administer_bit() {
    // The bound widened from 7 to 15 with the fourth permission. If the rebuild in
    // migration 0004 had not carried the new CHECK, this write would fail.
    let database = temp_database().await;

    sqlx::query(
        "INSERT INTO host_settings (id, machine_name, unattended_phc, unattended_permissions)
         VALUES (1, 'box', 'not-a-real-phc', 15)",
    )
    .execute(database.pool())
    .await
    .unwrap();
}

#[tokio::test]
async fn a_session_history_row_must_say_which_way_it_went() {
    let database = temp_database().await;

    let err = sqlx::query(
        "INSERT INTO session_history
             (device_name, direction, address, started_ms, outcome)
         VALUES ('Box', 'sideways', '10.0.0.1:7443', 1, 'completed')",
    )
    .execute(database.pool())
    .await
    .unwrap_err();

    assert!(
        format!("{err}").to_uppercase().contains("CHECK"),
        "got: {err}"
    );
}

#[tokio::test]
async fn host_settings_admits_only_one_row() {
    let database = temp_database().await;

    sqlx::query("INSERT INTO host_settings (id, machine_name) VALUES (1, 'first')")
        .execute(database.pool())
        .await
        .unwrap();

    let err = sqlx::query("INSERT INTO host_settings (id, machine_name) VALUES (2, 'second')")
        .execute(database.pool())
        .await
        .unwrap_err();

    assert!(
        format!("{err}").to_uppercase().contains("CHECK"),
        "got: {err}"
    );
}

#[tokio::test]
async fn host_settings_cannot_carry_unattended_permissions_without_a_password() {
    let database = temp_database().await;

    let err = sqlx::query(
        "INSERT INTO host_settings (id, machine_name, unattended_phc, unattended_permissions)
         VALUES (1, 'BOX', NULL, 1)",
    )
    .execute(database.pool())
    .await
    .unwrap_err();

    assert!(
        format!("{err}").to_uppercase().contains("CHECK"),
        "got: {err}"
    );
}
