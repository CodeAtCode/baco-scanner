//! Regression tests for scanner.max_file_size_kb validation
//!
//! These tests verify that ScannerConfig::validate() rejects invalid
//! max_file_size_kb values that would cause runtime failures:
//! - value = 0 → would filter out all non-empty files
//! - value > u64::MAX / 1024 → would overflow on * 1024 multiplication

use baco::config::{ScannerConfig, ScannerSettings};
use tempfile::TempDir;

// ============================================================================
// Test Fixtures
// ============================================================================

/// Create a minimal valid ScannerConfig with a temporary project directory
fn create_minimal_config(max_file_size_kb: u64) -> (ScannerConfig, TempDir) {
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let config = ScannerConfig {
        project: baco::config::ProjectConfig {
            name: "test".to_string(),
            path: temp_dir.path().to_string_lossy().to_string(),
            languages: vec!["rust".to_string()],
        },
        scanner: ScannerSettings {
            max_file_size_kb,
            ..Default::default()
        },
        ..Default::default()
    };
    (config, temp_dir)
}

// ============================================================================
// Test Cases: Invalid Values (Must Return Err)
// ============================================================================

#[test]
fn test_max_file_size_kb_zero_rejected() {
    // Zero would cause max-bytes filter = 0, skipping all non-empty files
    let (config, _temp_dir) = create_minimal_config(0);
    let result = config.validate();

    assert!(
        result.is_err(),
        "max_file_size_kb = 0 should be rejected, got Ok"
    );
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("scanner.max_file_size_kb"),
        "error should name the field: {}",
        err_msg
    );
    assert!(
        err_msg.contains("0"),
        "error should mention the bad value: {}",
        err_msg
    );
    assert!(
        err_msg.contains("> 0") || err_msg.contains("must be"),
        "error should explain the valid range: {}",
        err_msg
    );
}

#[test]
fn test_max_file_size_kb_u64_max_rejected() {
    // u64::MAX would overflow on * 1024 multiplication
    let (config, _temp_dir) = create_minimal_config(u64::MAX);
    let result = config.validate();

    assert!(
        result.is_err(),
        "max_file_size_kb = u64::MAX should be rejected, got Ok"
    );
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("scanner.max_file_size_kb"),
        "error should name the field: {}",
        err_msg
    );
    assert!(
        err_msg.contains("u64::MAX") || err_msg.contains("18446744073709551615"),
        "error should mention the bad value: {}",
        err_msg
    );
    assert!(
        err_msg.contains("overflow") || err_msg.contains("<="),
        "error should explain the overflow risk: {}",
        err_msg
    );
}

// ============================================================================
// Test Cases: Valid Values (Must Return Ok)
// ============================================================================

#[test]
fn test_max_file_size_kb_default_accepts() {
    // Default value 512 should be valid
    let (config, _temp_dir) = create_minimal_config(512);
    let result = config.validate();

    assert!(
        result.is_ok(),
        "max_file_size_kb = 512 (default) should be accepted: {:?}",
        result.err()
    );
}

#[test]
fn test_max_file_size_kb_upper_boundary_accepts() {
    // u64::MAX / 1024 is the exact boundary where * 1024 still fits
    let boundary = u64::MAX / 1024;
    let (config, _temp_dir) = create_minimal_config(boundary);
    let result = config.validate();

    assert!(
        result.is_ok(),
        "max_file_size_kb = {} (exact upper boundary) should be accepted: {:?}",
        boundary,
        result.err()
    );
}

#[test]
fn test_max_file_size_kb_just_over_boundary_rejected() {
    // One over the boundary should overflow
    let over_boundary = (u64::MAX / 1024) + 1;
    let (config, _temp_dir) = create_minimal_config(over_boundary);
    let result = config.validate();

    assert!(
        result.is_err(),
        "max_file_size_kb = {} (one over boundary) should be rejected, got Ok",
        over_boundary
    );
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("overflow") || err_msg.contains("<="),
        "error should explain the overflow risk: {}",
        err_msg
    );
}

// ============================================================================
// Mutation Teeth Tests
// ============================================================================

/// This test verifies the validation logic actually exists.
/// If the range check is disabled/commented out, this test FAILS.
///
/// To verify teeth: comment out the range check in validate(), run this test,
/// it should fail. Restore the check, run again, it should pass.
#[test]
fn test_validation_logic_exists_zero_case() {
    let (config, _temp_dir) = create_minimal_config(0);
    let result = config.validate();

    // This assertion will fail if the validation check is removed
    assert!(
        result.is_err(),
        "VALIDATION LOGIC MISSING: max_file_size_kb = 0 was accepted!"
    );
}

#[test]
fn test_validation_logic_exists_overflow_case() {
    let (config, _temp_dir) = create_minimal_config(u64::MAX);
    let result = config.validate();

    // This assertion will fail if the validation check is removed
    assert!(
        result.is_err(),
        "VALIDATION LOGIC MISSING: max_file_size_kb = u64::MAX was accepted!"
    );
}
