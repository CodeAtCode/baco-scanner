use super::{PhaseContext, PhaseError, ScanPhase};
use crate::findings::VulnerabilityFinding;
use crate::incremental_scan::FileHashStore;
use crate::indexer::FileIndex;
use async_trait::async_trait;
use std::path::PathBuf;

use super::indexing_helpers::log_incremental_stats;

pub struct IndexingPhase;

#[async_trait]
impl ScanPhase for IndexingPhase {
    fn name(&self) -> &'static str {
        "Indexing"
    }

    fn order(&self) -> u8 {
        1
    }

    async fn execute(
        &self,
        ctx: &mut PhaseContext,
    ) -> Result<Vec<VulnerabilityFinding>, PhaseError> {
        tracing::info!("Running indexing phase on {:?}", ctx.scanner.target_path);

        // Check if incremental scanning is enabled
        let enable_incremental = ctx
            .scanner
            .config
            .scanner
            .performance
            .enable_incremental_scan;

        // Try to load previous hash store for incremental scanning
        let hash_store_path =
            PathBuf::from(&ctx.scanner.config.output.dir).join("file_hashes.json");

        let previous_hash_store = if enable_incremental && hash_store_path.exists() {
            match FileHashStore::load(&hash_store_path.to_string_lossy()) {
                Ok(store) => {
                    tracing::info!("Loaded previous hash store with {} entries", store.len());
                    Some(store)
                }
                Err(e) => {
                    tracing::warn!("Failed to load previous hash store: {}, starting fresh", e);
                    None
                }
            }
        } else {
            if !enable_incremental {
                tracing::info!("Incremental scanning is disabled, skipping hash store load");
            }
            None
        };

        // Run incremental indexing
        let (index, hash_store) = match FileIndex::index_project_incremental(
            ctx.scanner.target_path.to_str().unwrap_or("."),
            &ctx.scanner.config.project.languages,
            ctx.scanner.config.scanner.max_file_size_kb * 1024,
            &ctx.scanner.config.scanner.exclude_paths,
            Some(ctx.pb),
        ) {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!("Indexing failed: {}. Skipping phase.", e);
                return Err(PhaseError {
                    phase_name: "Indexing",
                    message: format!("Failed to index project: {}", e),
                });
            }
        };

        // Save hash store for future incremental scans (only if enabled)
        if enable_incremental {
            if let Some(parent) = hash_store_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = hash_store.save(&hash_store_path.to_string_lossy()) {
                tracing::warn!("Failed to save hash store: {}", e);
            } else {
                tracing::info!("Saved hash store with {} entries", hash_store.len());
            }

            // Log statistics about incremental scanning
            log_incremental_stats(&index, previous_hash_store.is_some());
        } else {
            tracing::info!("Incremental scanning is disabled, skipping hash store save");
        }

        Ok(Vec::new())
    }

    fn is_enabled(&self, _ctx: &PhaseContext) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phase::helpers::setup_test_phase_context;

    #[test]
    fn test_indexing_phase_creation() {
        let phase = IndexingPhase;
        assert_eq!(phase.name(), "Indexing");
        assert_eq!(phase.order(), 1);
    }

    #[test]
    fn test_is_enabled_always_true() {
        let (_, ctx) = setup_test_phase_context();
        let phase = IndexingPhase;
        assert!(phase.is_enabled(&ctx));
    }

    #[tokio::test]
    async fn test_execute_without_incremental() {
        let (_temp, mut ctx) = setup_test_phase_context();
        let phase = IndexingPhase;
        let result = phase.execute(&mut ctx).await;
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_execute_with_incremental_disabled() {
        let (_temp, mut ctx) = setup_test_phase_context();
        let phase = IndexingPhase;
        let result = phase.execute(&mut ctx).await;
        assert!(result.is_ok());
    }
}
