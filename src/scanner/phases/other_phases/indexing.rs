use std::path::PathBuf;

use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::scanner::phases::PhaseConfig;

/// Run indexing phase (phase 1 of 24).
pub async fn run_indexing(
    _scanner: &crate::scanner::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        findings,
        pb,
        analyzed_files,
        metrics_tracker: _,
        target_path,
        config,
        project_stack: _,
    } = cfg;

    // Index the project with incremental scanning
    tracing::info!("Running indexing phase on {:?}", target_path);

    // Try to load previous hash store for incremental scanning
    let hash_store_path = PathBuf::from(&config.output.dir).join("file_hashes.json");
    let _previous_hash_store = if hash_store_path.exists() {
        match crate::incremental_scan::FileHashStore::load(&hash_store_path.to_string_lossy()) {
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
        None
    };

    // Run incremental indexing
    let (index, hash_store) = match crate::indexer::FileIndex::index_project_incremental(
        target_path.to_str().unwrap_or("."),
        &config.project.languages,
        config.scanner.max_file_size_kb * 1024,
        &config.scanner.exclude_paths,
        Some(pb),
        config.scanner.performance.enable_file_filtering,
    ) {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!("Indexing failed: {}. Skipping phase.", e);
            return Ok((findings, analyzed_files.to_vec()));
        }
    };

    // Save hash store for future incremental scans
    if let Some(parent) = hash_store_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = hash_store.save(&hash_store_path.to_string_lossy()) {
        tracing::warn!("Failed to save hash store: {}", e);
    } else {
        tracing::info!("Saved hash store with {} entries", hash_store.len());
    }

    // Log statistics about incremental scanning
    if _previous_hash_store.is_some() {
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

    Ok((findings, analyzed_files.to_vec()))
}
