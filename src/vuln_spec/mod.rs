//! VulInSpec: Specification-guided vulnerability detection.
//!
//! This module implements the VulInSpec approach (arXiv:2511.04014) which:
//! 1. Extracts security specifications from historical vulnerabilities/patches
//! 2. Builds a specification knowledge base with general and domain-specific specs
//! 3. Uses RAG retrieval to find relevant past cases and specifications
//! 4. Enhances LLM discovery phase to reason about expected safe behaviors
//!
//! All features are disabled by default and must be explicitly enabled via config.

use std::sync::atomic::{AtomicBool, Ordering};

pub mod extractor;
pub mod retriever;
pub mod schema;

// Re-export main types for convenience
pub use retriever::{
    add_specs_to_index, build_embedding_index, clear_index, cosine_similarity, generate_embedding,
    get_index_stats, hybrid_search, reciprocal_rank_fusion, retrieve_relevant_specs,
    retrieve_with_domain_filter, Bm25Index, EMBEDDING_DIM,
};
pub use schema::{DomainCategory, SecuritySpecification, SpecificationSource, VulnSpecConfig};

/// Initialization flag for the spec index
static INDEX_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the specification index from config
///
/// Idempotent: if already initialized, returns current doc count without rebuilding.
/// Returns the number of specifications loaded (0 if disabled or file empty/missing).
pub fn initialize_spec_index(config: &VulnSpecConfig) -> usize {
    // Idempotency guard
    if INDEX_INITIALIZED.load(Ordering::SeqCst) {
        // Return current doc count
        return retriever::get_index_stats().num_documents;
    }

    if !config.enabled {
        return 0;
    }

    // Try to load specs from DB file
    let specs: Vec<SecuritySpecification> = if std::path::Path::new(&config.db_path).exists() {
        match std::fs::read_to_string(&config.db_path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(specs) => specs,
                Err(e) => {
                    tracing::warn!("Failed to parse vuln_spec DB at {}: {}", config.db_path, e);
                    Vec::new()
                }
            },
            Err(e) => {
                tracing::debug!("Failed to read vuln_spec DB at {}: {}", config.db_path, e);
                Vec::new()
            }
        }
    } else {
        tracing::debug!("VulnSpec DB file not found at {}", config.db_path);
        Vec::new()
    };

    if specs.is_empty() {
        return 0;
    }

    // Build the embedding index
    match retriever::build_embedding_index(&specs) {
        Ok(()) => {
            INDEX_INITIALIZED.store(true, Ordering::SeqCst);
            tracing::info!(
                "Initialized VulInSpec index with {} specifications",
                specs.len()
            );
            specs.len()
        }
        Err(e) => {
            tracing::warn!("Failed to build embedding index: {}", e);
            0
        }
    }
}

/// Clear the initialization flag (called when index is cleared)
pub fn reset_init_flag() {
    INDEX_INITIALIZED.store(false, Ordering::SeqCst);
}
