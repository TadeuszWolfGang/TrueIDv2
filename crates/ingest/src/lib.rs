//! Shared ingestion traits for adapter implementations.

use anyhow::Result;
use trueid_common::model::IdentityEvent;

/// Common interface for ingestion adapters.
pub trait IngestAdapter {
    /// Fetches identity events from the underlying source.
    ///
    /// Parameters: none.
    /// Returns: list of parsed `IdentityEvent` values or an error.
    fn ingest(&self) -> Result<Vec<IdentityEvent>>;
}
