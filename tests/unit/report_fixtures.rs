//! Shared fixtures for report tests.
//!
//! This module consolidates duplicate test fixture code across report test files
//! to reduce maintenance overhead and ensure consistency.
//!
//! # Usage
//!
//! ```rust,ignore
//! use tests::unit::report_fixtures::make_finding;
//!
//! #[test]
//! fn test_something() {
//!     let finding = make_finding("f1", Severity::High, "src/test.rs", Some(10));
//! }
//! ```

use baco::findings::Severity;
use baco::root_cause_dedup::GlobalFpStore;
use tempfile::tempdir;

pub use crate::fixtures::create_test_finding_central as create_test_finding;
pub use crate::fixtures::make_finding_report as make_finding;

/// Create a temporary directory for scan data
pub fn create_temp_scan_dir() -> tempfile::TempDir {
    tempdir().expect("Failed to create temporary directory")
}

/// Create a test GlobalFpStore in a temporary directory
pub fn create_test_fp_store() -> GlobalFpStore {
    let temp_dir = create_temp_scan_dir();
    let fp_path = temp_dir.path().join("fp_store.json");
    GlobalFpStore::with_path(&fp_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_finding_basic() {
        let finding = make_finding("test-1", Severity::High, "src/test.rs", Some(42));

        assert_eq!(finding.id, "test-1");
        assert_eq!(finding.title, "Finding test-1");
        assert_eq!(finding.file_path, "src/test.rs");
        assert_eq!(finding.line_number, Some(42));
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn test_make_finding_without_line() {
        let finding = make_finding("test-2", Severity::Critical, "src/main.rs", None);

        assert_eq!(finding.id, "test-2");
        assert!(finding.line_number.is_none());
    }
}
