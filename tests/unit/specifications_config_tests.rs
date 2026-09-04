//! Unit tests for config::specifications module

use baco::config::specifications::{default_vuln_spec_config, DEFAULT_SPEC_DB_PATH};

// ============================================================================
// default_vuln_spec_config() Tests
// ============================================================================

#[test]
fn test_default_config() {
    let config = default_vuln_spec_config();

    assert!(!config.enabled, "Should be disabled by default");
    assert_eq!(config.db_path, DEFAULT_SPEC_DB_PATH);
    assert!(!config.auto_extract_from_patches);
}
