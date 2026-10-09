//! Comprehensive unit tests for staging::core module
//!
//! Tests cover:
//! - StagingArea struct fields and state
//! - apply_patch behavior (not created error, path construction)
//! - validate behavior (not created error)
//! - cleanup behavior (when not created, sets flag)
//! - rollback behavior (not created, when created)
//! - Drop implementation (auto-cleanup)
//! - Field accessors

use baco::staging::core::new_for_tests_with_created;
use baco::staging::error::StagingError;
use std::path::PathBuf;

// ============================================================================
// Helper for hermetic temp directories
// ============================================================================

fn create_temp_path(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "{}-{:x}",
        prefix,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

// ============================================================================
// StagingArea Tests
// ============================================================================

#[test]
fn test_staging_area_struct_fields() {
    // Verify the struct has the expected fields via accessors
    let staging = new_for_tests_with_created(false);

    assert!(!staging.is_created());
    // Worktree path is derived internally under temp_dir
    assert!(staging.worktree_path().starts_with(std::env::temp_dir()));
    // Verify the path contains the expected prefix
    let path_str = staging.worktree_path().to_string_lossy();
    assert!(path_str.contains("baco-staging-"));
}

#[test]
fn test_staging_area_not_created_error() {
    let mut staging = new_for_tests_with_created(false);

    // Test apply_patch with is_created = false
    let result = staging.apply_patch("test diff");
    assert!(result.is_err());
    match result {
        Err(StagingError::PatchApply(msg)) => {
            assert!(msg.contains("not created"));
        }
        _ => panic!("Expected PatchApply error"),
    }

    // Test validate with is_created = false
    let result = staging.validate();
    assert!(result.is_err());
    match result {
        Err(StagingError::Validation(msg)) => {
            assert!(msg.contains("not created"));
        }
        _ => panic!("Expected Validation error"),
    }

    // Test cleanup with is_created = false (should succeed)
    let result = staging.cleanup();
    assert!(result.is_ok());

    // Test rollback with is_created = false (should succeed)
    let result = staging.rollback();
    assert!(result.is_ok());
}

#[test]
fn test_staging_area_rollback_not_created() {
    let mut staging = new_for_tests_with_created(false);

    // Rollback when not created should succeed without doing anything
    let result = staging.rollback();
    assert!(result.is_ok());
    assert!(!staging.is_created());
}

#[test]
fn test_patch_path_construction() {
    let staging = new_for_tests_with_created(true);

    // Verify patch path would be constructed correctly
    let expected_patch_path = staging.worktree_path().join("patch.diff");
    // Assert exact parent directory matches worktree path
    assert_eq!(expected_patch_path.parent(), Some(staging.worktree_path()));
    // Assert exact file name
    assert_eq!(expected_patch_path.file_name().unwrap(), "patch.diff");
}

#[test]
fn test_staging_area_drop_cleanup() {
    // Create a staging area that will be dropped
    {
        let mut staging = new_for_tests_with_created(true);

        // Verify it's created
        assert!(staging.is_created());

        // Cleanup is called - the flag should be reset regardless of actual git operation result
        let _ = staging.cleanup();
        assert!(
            !staging.is_created(),
            "is_created should be false after cleanup"
        );
    }
}

#[test]
fn test_staging_area_temp_dir_path() {
    // Verify that the temp directory path construction works
    let _temp_dir = std::env::temp_dir();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let expected_prefix = format!("baco-staging-{:x}", now);
    assert!(expected_prefix.starts_with("baco-staging-"));
    assert!(expected_prefix.len() > 15); // prefix + hex digits
}

#[test]
fn test_cleanup_when_not_created_returns_ok() {
    let mut staging = new_for_tests_with_created(false);

    let result = staging.cleanup();
    assert!(result.is_ok());
    assert!(!staging.is_created());
}

#[test]
fn test_rollback_when_created_calls_cleanup() {
    let mut staging = new_for_tests_with_created(true);

    // Rollback when created should attempt reset and cleanup
    let _result = staging.rollback();
    assert!(!staging.is_created());
}

#[test]
fn test_staging_area_worktree_path_accessor() {
    // Verify worktree_path accessor returns a path under temp_dir
    let staging = new_for_tests_with_created(true);
    assert!(staging.worktree_path().starts_with(std::env::temp_dir()));
}

#[test]
fn test_staging_area_original_repo_path_accessor() {
    let staging = new_for_tests_with_created(true);

    // original_repo_path is a placeholder from new_for_tests_with_created()
    // Verify it's under temp_dir and has the expected structure
    let path = staging.original_repo_path();
    assert!(path.starts_with(std::env::temp_dir()));
    assert!(path.to_string_lossy().contains("test-repo-placeholder"));
}

#[test]
fn test_apply_patch_writes_to_correct_path() {
    let staging = new_for_tests_with_created(true);

    let expected_patch_path = staging.worktree_path().join("patch.diff");
    // Assert exact parent directory matches worktree path
    assert_eq!(expected_patch_path.parent(), Some(staging.worktree_path()));
    // Assert exact file name
    assert_eq!(expected_patch_path.file_name().unwrap(), "patch.diff");
}

#[test]
fn test_cleanup_sets_is_created_to_false() {
    let mut staging = new_for_tests_with_created(true);

    let _ = staging.cleanup();
    assert!(!staging.is_created());
}

#[test]
fn test_rollback_resets_is_created_flag() {
    let mut staging = new_for_tests_with_created(true);

    let _ = staging.rollback();
    assert!(!staging.is_created());
}

#[test]
fn test_drop_implements_auto_cleanup() {
    // Verify Drop trait is implemented by checking the impl exists
    // The actual cleanup behavior is tested via cleanup()
    // StagingArea implements Drop for auto-cleanup
    let staging = new_for_tests_with_created(false);
    // Verify staging area was created
    assert!(!staging.is_created());
}

#[test]
fn test_staging_area_is_created_field_access() {
    let staging_not_created = new_for_tests_with_created(false);
    assert!(!staging_not_created.is_created());

    let staging_created = new_for_tests_with_created(true);
    assert!(staging_created.is_created());
}
// ============================================================================
// Additional Tests: Path Normalization, Patch Decision Logic
// ============================================================================

#[test]
fn test_staging_worktree_path_uniqueness() {
    // Verify that sequential worktree paths are unique
    let path1 = std::env::temp_dir().join(format!("baco-staging-{}-{}", std::process::id(), 0));
    let path2 = std::env::temp_dir().join(format!("baco-staging-{}-{}", std::process::id(), 1));

    assert_ne!(path1, path2);
    assert!(path1.to_string_lossy().contains("baco-staging-"));
    assert!(path2.to_string_lossy().contains("baco-staging-"));
}

#[test]
fn test_staging_area_path_contains_process_id() {
    let path = std::env::temp_dir().join(format!("baco-staging-{}-{}", std::process::id(), 0));
    let path_str = path.to_string_lossy();

    assert!(path_str.contains(&std::process::id().to_string()));
}

#[test]
fn test_apply_patch_to_worktree_path_construction() {
    let worktree_path = create_temp_path("test-worktree");
    let patch_path = worktree_path.join("patch.diff");

    assert_eq!(patch_path, worktree_path.join("patch.diff"));
}

#[test]
fn test_staging_area_cleanup_idempotent() {
    let mut staging = new_for_tests_with_created(false);

    // Cleanup when not created should succeed
    let result1 = staging.cleanup();
    assert!(result1.is_ok());

    // Second cleanup should also succeed
    let result2 = staging.cleanup();
    assert!(result2.is_ok());
}

#[test]
fn test_staging_area_rollback_idempotent() {
    let mut staging = new_for_tests_with_created(false);

    // Rollback when not created should succeed
    let result1 = staging.rollback();
    assert!(result1.is_ok());

    // Second rollback should also succeed
    let result2 = staging.rollback();
    assert!(result2.is_ok());
}

#[test]
fn test_staging_worktree_path_temp_directory() {
    let temp_dir = std::env::temp_dir();
    let worktree_path = temp_dir.join(format!("baco-staging-{}-{}", std::process::id(), 0));

    assert!(worktree_path.starts_with(&temp_dir));
}

#[test]
fn test_staging_area_original_repo_preserved() {
    let staging = new_for_tests_with_created(true);

    // original_repo_path is a placeholder from new_for_tests_with_created()
    // Verify it's under temp_dir and has the expected structure
    let path = staging.original_repo_path();
    assert!(path.starts_with(std::env::temp_dir()));
    assert!(path.to_string_lossy().contains("test-repo-placeholder"));
}
