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
        "transfer_state",
    ];
    expected.sort_unstable();

    assert_eq!(tables, expected, "got tables: {tables:?}");

    for gone in [
        "owner_account",
        "owner_accounts",
        "pairing_codes",
        "audit_event",
        "audit_events",
        "trusted_device",
        "trusted_devices",
        "session_token",
    ] {
        assert!(!tables.contains(&gone.to_string()), "{gone} must be gone");
    }
}

#[tokio::test]
async fn a_recent_connection_cannot_carry_permissions_without_a_pin() {
    let database = temp_database().await;

    let err = sqlx::query(
        "INSERT INTO recent_connections
             (address, machine_name, last_connected_ms, pinned_fingerprint, pinned_permissions)
         VALUES ('10.0.0.1', 'BOX', 1, NULL, 1)",
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
