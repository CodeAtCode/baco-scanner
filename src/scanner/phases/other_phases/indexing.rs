use std::path::PathBuf;

use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::scanner::phases::PhaseConfig;

/// Run indexing phase (phase 1 of 23).
pub async fn run_indexing(
    scanner: &crate::scanner::Scanner,
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

    // Run incremental indexing
    let (index, _hash_store) = match crate::indexer::FileIndex::index_project_incremental(
        target_path.to_str().unwrap_or("."),
        &config.project.languages,
        config.scanner.max_file_size_kb * 1024,
        &config.scanner.exclude_paths,
        Some(pb),
    ) {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!("Indexing failed: {}. Skipping phase.", e);
            return Ok((findings, analyzed_files.to_vec()));
        }
    };

    // Extract framework hooks from language-matched files and save hook map
    // Skip entirely if no hook_registry config is provided
    let _hook_map = if !config.knowledge.hook_registry.is_empty() {
        let mut hook_map: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();

        for file_info in &index.files {
            // Only process files whose language has a hook_registry config entry
            let lang = file_info.language.to_lowercase();
            if let Some(lang_cfg) = config.knowledge.hook_registry.get(&lang) {
                if let Ok(content) = std::fs::read_to_string(&file_info.path) {
                    let registrations = crate::hook_registry::extract_hooks(&content, lang_cfg);
                    if !registrations.is_empty() {
                        let path_str = file_info.path.to_string_lossy().to_string();
                        let handlers: Vec<String> =
                            registrations.into_iter().map(|r| r.handler).collect();
                        hook_map.insert(path_str, handlers);
                    }
                }
            }
            // Also check .phtml extension as PHP alias
            if file_info
                .path
                .extension()
                .map(|e| e.to_string_lossy().to_lowercase())
                == Some("phtml".to_string())
            {
                if let Some(lang_cfg) = config.knowledge.hook_registry.get("php") {
                    if let Ok(content) = std::fs::read_to_string(&file_info.path) {
                        let registrations = crate::hook_registry::extract_hooks(&content, lang_cfg);
                        if !registrations.is_empty() {
                            let path_str = file_info.path.to_string_lossy().to_string();
                            let handlers: Vec<String> =
                                registrations.into_iter().map(|r| r.handler).collect();
                            hook_map.insert(path_str, handlers);
                        }
                    }
                }
            }
        }

        // Save hook map if non-empty
        if !hook_map.is_empty() {
            let hook_map_path =
                crate::hook_registry::hook_map_path(PathBuf::from(&config.output.dir).as_path());
            if let Some(parent) = hook_map_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = crate::hook_registry::save_hook_map(&hook_map_path, &hook_map) {
                tracing::warn!("Failed to save hook map: {}", e);
            } else {
                tracing::info!("Saved hook map with {} entries", hook_map.len());
            }
        }

        hook_map
    } else {
        std::collections::HashMap::new()
    };

    // Record what the indexer actually matched. The summary reports this as
    // "indexed", and the field existed but nothing ever wrote it, so the line
    // always read 0.
    scanner
        .state
        .send_modify(|s| s.files_scanned = index.files.len());

    Ok((findings, analyzed_files.to_vec()))
}
