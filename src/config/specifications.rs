//! VulInSpec configuration module.
//!
//! Provides configuration types and defaults for the vulnerability specification
//! extraction and retrieval system.

use crate::vuln_spec::schema::VulnSpecConfig;

/// Default path for the specification database, relative to the configured
/// output directory.
pub const DEFAULT_SPEC_DB_PATH: &str = "vuln_spec_db.json";

/// Resolve the specification database path against the configured output
/// directory.
///
/// The default is a relative path, so an unmodified configuration would read and
/// write the database relative to the process CWD — wherever the scanner happened
/// to be run from. An absolute path, or an empty output directory, is returned
/// unchanged.
pub fn resolve_spec_db_path(db_path: &str, output_dir: &str) -> String {
    let output_dir = output_dir.trim().trim_end_matches('/');
    if db_path.is_empty() || output_dir.is_empty() || std::path::Path::new(db_path).is_absolute() {
        return db_path.to_string();
    }
    format!("{output_dir}/{db_path}")
}

/// Create default VulnSpecConfig
pub fn default_vuln_spec_config() -> VulnSpecConfig {
    VulnSpecConfig {
        enabled: false,
        db_path: DEFAULT_SPEC_DB_PATH.to_string(),
        auto_extract_from_patches: false,
    }
}
