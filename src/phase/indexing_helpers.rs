//! Shared helpers for indexing-related operations.

use crate::indexer::FileIndex;

/// Log statistics about incremental scanning.
pub(crate) fn log_incremental_stats(index: &FileIndex, previous_hash_store_exists: bool) {
    if previous_hash_store_exists {
        let unchanged_count = index
            .files
            .iter()
            .filter(|f| f.hash.as_ref().is_some())
            .count();
        tracing::info!(
            "Incremental scan: {} total files, {} unchanged from previous scan",
            index.files.len(),
            unchanged_count
        );
    }
}
