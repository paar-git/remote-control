//! Typed storage errors.

/// Errors raised by the persistence layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StorageError {
    /// The database could not be opened or created.
    #[error("could not open database")]
    Open(#[source] sqlx::Error),

    /// A migration failed to apply.
    #[error("database migration failed")]
    Migrate(#[source] sqlx::migrate::MigrateError),

    /// The on-disk schema is newer than this build understands. Continuing could
    /// corrupt data, so the caller must upgrade instead.
    #[error("database schema version {found} is newer than the supported version {supported}")]
    SchemaTooNew {
        /// Version found on disk.
        found: i64,
        /// Highest version this build ships migrations for.
        supported: i64,
    },

    /// A query failed.
    #[error("database query failed")]
    Query(#[source] sqlx::Error),

    /// The requested row does not exist.
    #[error("record not found")]
    NotFound,

    /// A uniqueness constraint was violated, e.g. pairing a device twice.
    #[error("record already exists")]
    Conflict,

    /// A stored JSON column could not be parsed into its expected shape.
    #[error("stored value for `{column}` is malformed")]
    MalformedColumn {
        /// Which column.
        column: &'static str,
    },

    /// A value failed validation before being written.
    #[error("invalid value for `{field}`: {reason}")]
    Invalid {
        /// Which field.
        field: &'static str,
        /// Why it was rejected.
        reason: &'static str,
    },
}

impl From<sqlx::Error> for StorageError {
    fn from(err: sqlx::Error) -> Self {
        match &err {
            sqlx::Error::RowNotFound => Self::NotFound,
            sqlx::Error::Database(db) if db.is_unique_violation() => Self::Conflict,
            _ => Self::Query(err),
        }
    }
}

/// Convenience result alias for storage operations.
pub type Result<T> = std::result::Result<T, StorageError>;
