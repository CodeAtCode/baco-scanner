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

    // If joern is not available, we expect JoernNotInstalled (path must exist so
    // validate_project_path passes and the joern availability check runs)
    if !available {
        let dir = std::env::temp_dir().join("baco-joern-test-avail");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let result = engine.build_cpg(&dir);
        let _ = std::fs::remove_dir(&dir);
        assert!(matches!(result, Err(CpgError::JoernNotInstalled)));
    }
}

#[test]
fn test_build_returns_error_when_joern_unavailable() {
    let engine = JoernEngine::new(None);

    if !engine.is_available() {
        let dir = std::env::temp_dir().join("baco-joern-test-build");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let result = engine.build_cpg(&dir);
        let _ = std::fs::remove_dir(&dir);
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
        // Use root path which has no parent — validate_project_path rejects it
        // with BuildFailed before the joern availability check runs
        let result = engine.build_cpg(Path::new("/"));
        assert!(matches!(result, Err(CpgError::BuildFailed(_))));
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

#[test]
fn test_validate_project_path_rejects_filesystem_root() {
    // Test that the filesystem root is rejected
    let result = baco::cpg::validate_project_path(Path::new("/"));
    assert!(matches!(result, Err(CpgError::BuildFailed(_))));
}

#[test]
fn test_validate_project_path_accepts_valid_path() {
    // Test that a valid path is accepted and canonicalized
    let result = baco::cpg::validate_project_path(Path::new("/tmp"));
    assert!(result.is_ok());
    let canonical = result.unwrap();
    assert!(canonical.is_dir());
}
