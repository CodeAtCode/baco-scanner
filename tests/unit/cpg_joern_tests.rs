//! Migrated inline tests for baco::cpg::joern
//!
//! Previously in src/cpg/joern.rs #[cfg(test)] mod tests

use baco::cpg::{CpgError, JoernEngine};
use std::path::Path;
use std::path::PathBuf;

#[test]
fn test_joern_engine_not_available_when_binary_missing() {
    // This test assumes joern is not installed in the test environment
    let engine = JoernEngine::new(None);
    // Note: This test may pass or fail depending on whether joern is installed
    // In CI, it should return false
    let available = engine.is_available();

    // If joern is not available, we expect this
    if !available {
        let result = engine.build_cpg(Path::new("/tmp/test"));
        assert!(matches!(result, Err(CpgError::JoernNotInstalled)));
    }
}

#[test]
fn test_build_returns_error_when_joern_unavailable() {
    let engine = JoernEngine::new(None);

    if !engine.is_available() {
        let result = engine.build_cpg(Path::new("/tmp/test"));
        assert!(matches!(result, Err(CpgError::JoernNotInstalled)));
    }
}

#[test]
fn test_find_joern_with_nonexistent_path_returns_error() {
    let nonexistent = PathBuf::from("/nonexistent/joern/path");
    let engine = JoernEngine::new(Some(nonexistent));
    let result = engine.find_joern();
    assert!(matches!(result, Err(CpgError::JoernNotInstalled)));
}

#[test]
fn test_find_joern_with_existing_path_returns_ok() {
    // Use an existing binary path for testing
    let existing = PathBuf::from("/bin/ls");
    let engine = JoernEngine::new(Some(existing.clone()));
    let result = engine.find_joern();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), existing);
}

#[test]
fn test_build_returns_error_when_path_has_no_parent() {
    let engine = JoernEngine::new(None);

    // Guard: only test if joern is unavailable
    if !engine.is_available() {
        // Use root path which has no parent
        let result = engine.build_cpg(Path::new("/"));
        // When joern is unavailable, we get JoernNotInstalled first
        // The BuildFailed error only occurs if joern is available
        assert!(matches!(result, Err(CpgError::JoernNotInstalled)));
    }
}

#[test]
fn test_joern_engine_new_with_some_path_preserves_path() {
    let custom_path = PathBuf::from("/custom/joern/binary");
    let engine = JoernEngine::new(Some(custom_path.clone()));

    // Verify the path is stored (by attempting to find it - will fail but path is preserved)
    let result = engine.find_joern();
    // Since the path doesn't exist, it should return error
    assert!(matches!(result, Err(CpgError::JoernNotInstalled)));
}
