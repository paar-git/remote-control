//! Shared test scaffolding for this crate's own test modules.

use crate::Database;

/// A freshly migrated, private in-memory database, for tests.
///
/// Built on [`Database::open_in_memory`], which every test in this crate already uses
/// to run every migration on open — this is the one place that construction happens,
/// so there is no second way to build a test database.
pub(crate) async fn temp_database() -> Database {
    Database::open_in_memory()
        .await
        .expect("an in-memory database must always open and migrate cleanly")
}
