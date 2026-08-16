//! Row types mapping onto the schema.
//!
//! `recent.rs` and `settings.rs` each define their own raw row struct, matching the
//! precedent the deleted trust/owner/audit repositories set: a row type stays next to
//! the single repository that reads it rather than being centralised here. Nothing is
//! shared across repositories in the current schema, so this module currently has no
//! content of its own — it is kept as the place a future shared row type would go.
