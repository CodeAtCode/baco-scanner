//! Unit tests for config::specifications module

use baco::config::specifications::{
    DEFAULT_SPEC_DB_PATH, default_vuln_spec_config, resolve_spec_db_path,
};

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

/// The default database path is relative, so it must be joined to the configured
/// output directory instead of being read from wherever the process happens to
/// run.
#[test]
fn a_relative_db_path_is_rooted_under_the_output_directory() {
    assert_eq!(
        resolve_spec_db_path(DEFAULT_SPEC_DB_PATH, "/tmp/baco-output"),
        "/tmp/baco-output/vuln_spec_db.json"
    );
    assert_eq!(
        resolve_spec_db_path("specs/db.json", "out/"),
        "out/specs/db.json"
    );
}

#[test]
fn an_absolute_or_unset_db_path_is_left_alone() {
    assert_eq!(
        resolve_spec_db_path("/var/lib/baco/db.json", "out"),
        "/var/lib/baco/db.json"
    );
    assert_eq!(resolve_spec_db_path("db.json", ""), "db.json");
    assert_eq!(resolve_spec_db_path("db.json", "   "), "db.json");
    assert_eq!(resolve_spec_db_path("", "out"), "");
}
