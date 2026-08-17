//! VulInSpec configuration module.
//!
//! Provides configuration types and defaults for the vulnerability specification
//! extraction and retrieval system.

use crate::vuln_spec::schema::VulnSpecConfig;

/// Default path for the specification database
pub const DEFAULT_SPEC_DB_PATH: &str = "baco-output/vuln_spec_db.json";

/// Default top-k results for RAG retrieval
pub const DEFAULT_RAG_TOP_K: usize = 5;

/// Default similarity threshold for specification matching
pub const DEFAULT_SIMILARITY_THRESHOLD: f64 = 0.6;

/// Create default VulnSpecConfig
pub fn default_vuln_spec_config() -> VulnSpecConfig {
    VulnSpecConfig {
        enabled: false,
        db_path: DEFAULT_SPEC_DB_PATH.to_string(),
        auto_extract_from_patches: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = default_vuln_spec_config();

        assert!(!config.enabled, "Should be disabled by default");
        assert_eq!(config.db_path, DEFAULT_SPEC_DB_PATH);
        assert!(!config.auto_extract_from_patches);
    }
}
