//! Comprehensive unit tests for staging::error module
//!
//! Tests cover:
//! - StagingError Display implementations (all variants)
//! - AutoPatchError Display implementations (all variants)
//! - PatchValidationResult (default, success, failure, clone)
//! - PatchValidationResult conversion to scanner_types

use baco::staging::error::{AutoPatchError, PatchValidationResult, StagingError};

// ============================================================================
// StagingError Tests
// ============================================================================

#[test]
fn test_staging_error_worktree_create_display() {
    let err = StagingError::WorktreeCreate("test error".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Failed to create worktree"));
    assert!(display.contains("test error"));
}

#[test]
fn test_staging_error_patch_apply_display() {
    let err = StagingError::PatchApply("patch failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Failed to apply patch"));
    assert!(display.contains("patch failed"));
}

#[test]
fn test_staging_error_validation_display() {
    let err = StagingError::Validation("validation failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Validation failed"));
    assert!(display.contains("validation failed"));
}

#[test]
fn test_staging_error_cleanup_display() {
    let err = StagingError::Cleanup("cleanup failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Cleanup failed"));
    assert!(display.contains("cleanup failed"));
}

#[test]
fn test_staging_error_rollback_display() {
    let err = StagingError::Rollback("rollback failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Rollback failed"));
    assert!(display.contains("rollback failed"));
}

#[test]
fn test_staging_error_git_error_display() {
    let err = StagingError::GitError("git error".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Git command failed"));
    assert!(display.contains("git error"));
}

// ============================================================================
// AutoPatchError Tests
// ============================================================================

#[test]
fn test_auto_patch_error_generation_display() {
    let err = AutoPatchError::Generation("generation failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Failed to generate patch"));
    assert!(display.contains("generation failed"));
}

#[test]
fn test_auto_patch_error_apply_display() {
    let err = AutoPatchError::Apply("apply failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Failed to apply patch"));
    assert!(display.contains("apply failed"));
}

#[test]
fn test_auto_patch_error_validation_display() {
    let err = AutoPatchError::Validation("validation failed".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Validation failed"));
    assert!(display.contains("validation failed"));
}

#[test]
fn test_auto_patch_error_staging_display() {
    let err = AutoPatchError::Staging("staging error".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Staging error"));
    assert!(display.contains("staging error"));
}

#[test]
fn test_auto_patch_error_no_llm_client_display() {
    let err = AutoPatchError::NoLlmClient;
    let display = format!("{}", err);
    assert!(display.contains("No LLM client configured"));
}

// ============================================================================
// PatchValidationResult Tests
// ============================================================================

#[test]
fn test_patch_validation_result_default() {
    let result = PatchValidationResult::default();
    assert!(result.compiles);
    assert!(result.tests_pass);
    assert_eq!(result.warnings, 0);
    assert!(result.error_message.is_none());
}

#[test]
fn test_patch_validation_result_success() {
    let result = PatchValidationResult::success();
    assert!(result.compiles);
    assert!(result.tests_pass);
    assert_eq!(result.warnings, 0);
    assert!(result.error_message.is_none());
}

#[test]
fn test_patch_validation_result_failure() {
    let result = PatchValidationResult::failure("test error");
    assert!(!result.compiles);
    assert!(!result.tests_pass);
    assert_eq!(result.warnings, 0);
    assert_eq!(result.error_message, Some("test error".to_string()));
}

#[test]
fn test_patch_validation_result_clone() {
    let result1 = PatchValidationResult {
        compiles: true,
        tests_pass: false,
        warnings: 5,
        error_message: Some("error".to_string()),
    };
    let result2 = result1.clone();
    assert_eq!(result1, result2);
}

// ============================================================================
// Conversion Tests
// ============================================================================

#[test]
fn test_patch_validation_result_conversion() {
    let result = PatchValidationResult {
        compiles: true,
        tests_pass: false,
        warnings: 3,
        error_message: Some("conversion test".to_string()),
    };

    let converted: baco::scanner_types::patch::PatchValidationResult = result.into();
    assert!(converted.compiles);
    assert!(!converted.tests_pass);
    assert_eq!(converted.warnings, 3);
    assert_eq!(converted.error_message, Some("conversion test".to_string()));
}
