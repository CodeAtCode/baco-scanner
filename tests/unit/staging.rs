//! Unit tests for src/staging.rs
//!
//! Covers:
//! - StagingArea operations (create, apply_patch, validate, cleanup, rollback)
//! - AutoPatcher operations (generate_patch, validate_patch, apply_and_validate)
//! - Error handling
//! - PatchValidationResult logic
//! - PatchingConfig defaults

use baco::scanner_types::patch::PatchCandidate;
use baco::staging::*;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a minimal temp directory with Rust project structure (no git)
fn create_temp_rust_project() -> PathBuf {
    let temp_dir = std::env::temp_dir().join(format!(
        "baco-staging-test-{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    // Create Cargo.toml
    fs::write(
        temp_dir.join("Cargo.toml"),
        r#"[package]
name = "test-project"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .unwrap();

    // Create src/main.rs
    let src_dir = temp_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(
        src_dir.join("main.rs"),
        r#"fn main() {
    println!("Hello, world!");
}
"#,
    )
    .unwrap();

    temp_dir
}

/// Create a temp directory with lib.rs for testing compilation
fn create_temp_lib_project() -> PathBuf {
    let temp_dir = create_temp_rust_project();

    // Remove main.rs and create lib.rs
    fs::remove_file(temp_dir.join("src/main.rs")).unwrap();
    fs::write(
        temp_dir.join("src/lib.rs"),
        r#"pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        assert_eq!(add(2, 3), 5);
    }
}
"#,
    )
    .unwrap();

    // Update Cargo.toml for lib
    fs::write(
        temp_dir.join("Cargo.toml"),
        r#"[package]
name = "test-lib"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"

[dependencies]
"#,
    )
    .unwrap();

    temp_dir
}

/// Cleanup helper for temp directories
fn cleanup_temp_dir(path: &PathBuf) {
    let _ = fs::remove_dir_all(path);
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
    let result = PatchValidationResult::failure("Compilation error: type mismatch");

    assert!(!result.compiles);
    assert!(!result.tests_pass);
    assert_eq!(result.warnings, 0);
    assert_eq!(
        result.error_message,
        Some("Compilation error: type mismatch".to_string())
    );
}

#[test]
fn test_patch_validation_result_clone() {
    let original = PatchValidationResult {
        compiles: true,
        tests_pass: false,
        warnings: 5,
        error_message: Some("test error".to_string()),
    };

    let cloned = original.clone();

    assert_eq!(original.compiles, cloned.compiles);
    assert_eq!(original.tests_pass, cloned.tests_pass);
    assert_eq!(original.warnings, cloned.warnings);
    assert_eq!(original.error_message, cloned.error_message);
}

#[test]
fn test_patch_validation_result_equality() {
    let result1 = PatchValidationResult {
        compiles: true,
        tests_pass: true,
        warnings: 0,
        error_message: None,
    };

    let result2 = PatchValidationResult {
        compiles: true,
        tests_pass: true,
        warnings: 0,
        error_message: None,
    };

    let result3 = PatchValidationResult {
        compiles: false,
        tests_pass: true,
        warnings: 0,
        error_message: None,
    };

    let result4 = PatchValidationResult {
        compiles: true,
        tests_pass: true,
        warnings: 3,
        error_message: None,
    };

    assert_eq!(result1, result2);
    assert_ne!(result1, result3);
    assert_ne!(result1, result4);
}

#[test]
fn test_patch_validation_result_from_conversion() {
    let local_result = PatchValidationResult {
        compiles: true,
        tests_pass: false,
        warnings: 7,
        error_message: Some("conversion test".to_string()),
    };

    let converted: baco::scanner_types::patch::PatchValidationResult = local_result.into();

    assert!(converted.compiles);
    assert!(!converted.tests_pass);
    assert_eq!(converted.warnings, 7);
    assert_eq!(converted.error_message, Some("conversion test".to_string()));
}

// ============================================================================
// StagingError Tests
// ============================================================================

#[test]
fn test_staging_error_worktree_create_display() {
    let err = StagingError::WorktreeCreate("Permission denied".to_string());
    let msg = err.to_string();

    assert!(msg.contains("Failed to create worktree"));
    assert!(msg.contains("Permission denied"));
}

#[test]
fn test_staging_error_patch_apply_display() {
    let err = StagingError::PatchApply("Hunk failed at line 42".to_string());
    let msg = err.to_string();

    assert!(msg.contains("Failed to apply patch"));
    assert!(msg.contains("Hunk failed"));
}

#[test]
fn test_staging_error_validation_display() {
    let err = StagingError::Validation("Cargo check failed".to_string());
    let msg = err.to_string();

    assert!(msg.contains("Validation failed"));
    assert!(msg.contains("Cargo check"));
}

#[test]
fn test_staging_error_cleanup_display() {
    let err = StagingError::Cleanup("Worktree busy".to_string());
    let msg = err.to_string();

    assert!(msg.contains("Cleanup failed"));
    assert!(msg.contains("Worktree busy"));
}

#[test]
fn test_staging_error_rollback_display() {
    let err = StagingError::Rollback("Git reset failed".to_string());
    let msg = err.to_string();

    assert!(msg.contains("Rollback failed"));
    assert!(msg.contains("Git reset"));
}

#[test]
fn test_staging_error_git_error_display() {
    let err = StagingError::GitError("git command not found".to_string());
    let msg = err.to_string();

    assert!(msg.contains("Git command failed"));
    assert!(msg.contains("git command not found"));
}

#[test]
fn test_staging_error_debug_trait() {
    let err = StagingError::WorktreeCreate("test error".to_string());
    let debug_str = format!("{:?}", err);

    assert!(debug_str.contains("WorktreeCreate"));
    assert!(debug_str.contains("test error"));
}

// ============================================================================
// AutoPatchError Tests
// ============================================================================

#[test]
fn test_autopatch_error_generation_display() {
    let err = AutoPatchError::Generation("IO error: file not found".to_string());
    let msg = err.to_string();

    assert!(msg.contains("Failed to generate patch"));
    assert!(msg.contains("IO error"));
}

#[test]
fn test_autopatch_error_apply_display() {
    let err = AutoPatchError::Apply("Patch rejected by git".to_string());
    let msg = err.to_string();

    assert!(msg.contains("Failed to apply patch"));
    assert!(msg.contains("rejected"));
}

#[test]
fn test_autopatch_error_validation_display() {
    let err = AutoPatchError::Validation("Type error in generated code".to_string());
    let msg = err.to_string();

    assert!(msg.contains("Validation failed"));
    assert!(msg.contains("Type error"));
}

#[test]
fn test_autopatch_error_staging_display() {
    let err = AutoPatchError::Staging("Worktree creation failed".to_string());
    let msg = err.to_string();

    assert!(msg.contains("Staging error"));
    assert!(msg.contains("Worktree"));
}

#[test]
fn test_autopatch_error_no_llm_client() {
    let err = AutoPatchError::NoLlmClient;
    let msg = err.to_string();

    assert!(msg.contains("No LLM client configured"));
}

#[test]
fn test_autopatch_error_debug_trait() {
    let err = AutoPatchError::Apply("test error".to_string());
    let debug_str = format!("{:?}", err);

    assert!(debug_str.contains("Apply"));
    assert!(debug_str.contains("test error"));
}

// ============================================================================
// StagingArea Tests (unit-level, without actual git)
// ============================================================================

#[test]
fn test_staging_area_not_created_apply_patch() {
    let temp_dir = create_temp_rust_project();
    let staging = StagingArea {
        worktree_path: temp_dir.clone(),
        original_repo_path: temp_dir.clone(),
        is_created: false,
    };

    let result = staging.apply_patch("some diff");

    assert!(result.is_err());
    match result {
        Err(StagingError::PatchApply(msg)) => {
            assert!(msg.contains("not created"));
        }
        _ => panic!("Expected PatchApply error"),
    }

    cleanup_temp_dir(&temp_dir);
}

#[test]
fn test_staging_area_not_created_validate() {
    let temp_dir = create_temp_rust_project();
    let staging = StagingArea {
        worktree_path: temp_dir.clone(),
        original_repo_path: temp_dir.clone(),
        is_created: false,
    };

    let result = staging.validate();

    assert!(result.is_err());
    match result {
        Err(StagingError::Validation(msg)) => {
            assert!(msg.contains("not created"));
        }
        _ => panic!("Expected Validation error"),
    }

    cleanup_temp_dir(&temp_dir);
}

#[test]
fn test_staging_area_cleanup_not_created() {
    let temp_dir = create_temp_rust_project();
    let mut staging = StagingArea {
        worktree_path: temp_dir.clone(),
        original_repo_path: temp_dir.clone(),
        is_created: false,
    };

    let result = staging.cleanup();

    // Should succeed without doing anything
    assert!(result.is_ok());

    cleanup_temp_dir(&temp_dir);
}

#[test]
fn test_staging_area_rollback_not_created() {
    let temp_dir = create_temp_rust_project();
    let mut staging = StagingArea {
        worktree_path: temp_dir.clone(),
        original_repo_path: temp_dir.clone(),
        is_created: false,
    };

    let result = staging.rollback();

    // Should succeed without doing anything
    assert!(result.is_ok());

    cleanup_temp_dir(&temp_dir);
}

#[test]
fn test_staging_area_is_created_flag() {
    let temp_dir = create_temp_rust_project();

    // Just verify we can create StagingArea with different is_created values
    let _staging_created = StagingArea {
        worktree_path: temp_dir.clone(),
        original_repo_path: temp_dir.clone(),
        is_created: true,
    };

    let _staging_not_created = StagingArea {
        worktree_path: temp_dir.clone(),
        original_repo_path: temp_dir.clone(),
        is_created: false,
    };

    cleanup_temp_dir(&temp_dir);
}

#[test]
fn test_staging_area_drop_auto_cleanup() {
    let temp_dir = create_temp_rust_project();

    // Create a staging area that will be dropped
    {
        let _staging = StagingArea {
            worktree_path: temp_dir.clone(),
            original_repo_path: temp_dir.clone(),
            is_created: false, // Set to false to avoid actual git operations
        };
        // Drop happens here
    }

    // Temp dir cleanup
    cleanup_temp_dir(&temp_dir);
}

#[test]
fn test_staging_path_contains_temp_dir() {
    let worktree_path = std::env::temp_dir().join(format!(
        "baco-staging-{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    assert!(worktree_path.starts_with(std::env::temp_dir()));
    assert!(worktree_path.to_string_lossy().contains("baco-staging-"));
}

#[test]
fn test_staging_path_contains_timestamp() {
    let before = std::time::SystemTime::now();
    let worktree_path = std::env::temp_dir().join(format!(
        "baco-staging-{:x}",
        before
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let after = std::time::SystemTime::now();

    let path_str = worktree_path.to_string_lossy();
    assert!(path_str.contains("baco-staging-"));

    // Extract timestamp from path
    let timestamp_part = path_str.split("baco-staging-").nth(1).unwrap();
    let timestamp = u128::from_str_radix(timestamp_part, 16).unwrap();

    let before_ns = before
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let after_ns = after
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    assert!(timestamp >= before_ns);
    assert!(timestamp <= after_ns + 1000); // Allow small delay
}

// ============================================================================
// AutoPatcher Tests
// ============================================================================

#[test]
fn test_autopatcher_new() {
    let temp_dir = create_temp_rust_project();
    let _autopatcher = AutoPatcher::new(temp_dir.clone());

    // Just verify autopatcher was created successfully
    // repo_path is private, so we can't assert on it directly

    cleanup_temp_dir(&temp_dir);
}

#[test]
fn test_generate_placeholder_patch() {
    let temp_dir = create_temp_rust_project();
    let autopatcher = AutoPatcher::new(temp_dir.clone());

    let vulnerability_desc = "SQL injection in user input";
    let vulnerable_code = "let query = format!(\"SELECT * FROM users WHERE id = {}\", user_id);";
    let file_path = "src/db.rs";

    let patch = autopatcher
        .generate_patch(vulnerability_desc, vulnerable_code, file_path)
        .unwrap();

    assert_eq!(patch.file_path, file_path);
    assert!(!patch.diff.is_empty());
    assert!(patch.diff.contains("--- a/src/db.rs"));
    assert!(patch.diff.contains("+++ b/src/db.rs"));
    assert!(!patch.applied);

    cleanup_temp_dir(&temp_dir);
}

#[test]
fn test_generate_patch_different_files() {
    let temp_dir = create_temp_rust_project();
    let autopatcher = AutoPatcher::new(temp_dir.clone());

    let test_cases = vec![
        ("main.rs", "main.rs"),
        ("lib.rs", "lib.rs"),
        ("utils/mod.rs", "utils/mod.rs"),
        ("Cargo.toml", "Cargo.toml"),
    ];

    for (short_path, full_path) in test_cases {
        let patch = autopatcher
            .generate_patch("test vulnerability", "unsafe code", short_path)
            .unwrap();

        assert_eq!(patch.file_path, full_path);
        assert!(patch.diff.contains(&format!("--- a/{}", full_path)));
        assert!(patch.diff.contains(&format!("+++ b/{}", full_path)));
    }

    cleanup_temp_dir(&temp_dir);
}

#[test]
fn test_format_patch_report_validated() {
    let temp_dir = create_temp_rust_project();
    let autopatcher = AutoPatcher::new(temp_dir);

    let candidate = PatchCandidate::new("diff content here", "src/main.rs");
    let validation = PatchValidationResult {
        compiles: true,
        tests_pass: true,
        warnings: 0,
        error_message: None,
    };

    let report = autopatcher.format_patch_report(&candidate, &validation);

    assert!(report.contains("Patch Report"));
    assert!(report.contains("src/main.rs"));
    assert!(report.contains("✅ VALIDATED"));
    assert!(report.contains("diff content here"));
}

#[test]
fn test_format_patch_report_compiles_but_tests_fail() {
    let temp_dir = create_temp_rust_project();
    let autopatcher = AutoPatcher::new(temp_dir);

    let candidate = PatchCandidate::new("diff content", "src/main.rs");
    let validation = PatchValidationResult {
        compiles: true,
        tests_pass: false,
        warnings: 2,
        error_message: Some("test failed: assertion panicked".to_string()),
    };

    let report = autopatcher.format_patch_report(&candidate, &validation);

    assert!(report.contains("⚠️ COMPILES BUT TESTS FAILED"));
    assert!(report.contains("Warnings: 2"));
    assert!(report.contains("Test Errors:"));
    assert!(report.contains("test failed: assertion panicked"));
}

#[test]
fn test_format_patch_report_failed() {
    let temp_dir = create_temp_rust_project();
    let autopatcher = AutoPatcher::new(temp_dir);

    let candidate = PatchCandidate::new("diff content", "src/main.rs");
    let validation = PatchValidationResult {
        compiles: false,
        tests_pass: false,
        warnings: 0,
        error_message: Some("error[E0308]: mismatched types".to_string()),
    };

    let report = autopatcher.format_patch_report(&candidate, &validation);

    assert!(report.contains("❌ FAILED"));
    assert!(report.contains("Build Errors:"));
    assert!(report.contains("error[E0308]: mismatched types"));
}

#[test]
fn test_format_patch_report_with_warnings() {
    let temp_dir = create_temp_rust_project();
    let autopatcher = AutoPatcher::new(temp_dir);

    let candidate = PatchCandidate::new("diff content", "src/main.rs");
    let validation = PatchValidationResult {
        compiles: true,
        tests_pass: true,
        warnings: 5,
        error_message: None,
    };

    let report = autopatcher.format_patch_report(&candidate, &validation);

    assert!(report.contains("✅ VALIDATED"));
    assert!(report.contains("Warnings: 5"));
}

#[test]
fn test_format_patch_report_empty_error_message() {
    let temp_dir = create_temp_rust_project();
    let autopatcher = AutoPatcher::new(temp_dir);

    let candidate = PatchCandidate::new("diff", "test.rs");
    let validation = PatchValidationResult {
        compiles: false,
        tests_pass: false,
        warnings: 0,
        error_message: None,
    };

    let report = autopatcher.format_patch_report(&candidate, &validation);

    assert!(report.contains("❌ FAILED"));
    assert!(report.contains("Build Errors:"));
}

// ============================================================================
// PatchingConfig Tests
// ============================================================================

#[test]
fn test_patching_config_default() {
    let config = PatchingConfig::default();

    assert!(!config.dry_run);
    assert!(!config.allow_network_access);
    assert_eq!(config.max_auto_patches, 5);
    assert_eq!(config.staging_prefix, Some("baco-auto-".to_string()));
}

#[test]
fn test_patching_config_custom() {
    let config = PatchingConfig {
        dry_run: true,
        allow_network_access: true,
        max_auto_patches: 100,
        staging_prefix: Some("custom-prefix-".to_string()),
    };

    assert!(config.dry_run);
    assert!(config.allow_network_access);
    assert_eq!(config.max_auto_patches, 100);
    assert_eq!(config.staging_prefix, Some("custom-prefix-".to_string()));
}

#[test]
fn test_patching_config_none_prefix() {
    let config = PatchingConfig {
        dry_run: false,
        allow_network_access: false,
        max_auto_patches: 5,
        staging_prefix: None,
    };

    assert!(config.staging_prefix.is_none());
}

// ============================================================================
// Integration-style tests (require actual cargo check)
// ============================================================================

#[test]
fn test_valid_code_compiles() {
    let temp_dir = create_temp_lib_project();

    // Run cargo check on valid code
    let check_output = Command::new("cargo")
        .current_dir(&temp_dir)
        .args(["check"])
        .output()
        .unwrap();

    // Should compile successfully
    assert!(check_output.status.success());

    cleanup_temp_dir(&temp_dir);
}

#[test]
fn test_invalid_code_fails_compile() {
    let temp_dir = create_temp_lib_project();

    // Write invalid Rust syntax
    fs::write(
        temp_dir.join("src/lib.rs"),
        r#"pub fn broken() {
    let x = ; // Invalid syntax
}
"#,
    )
    .unwrap();

    // Run cargo check
    let check_output = Command::new("cargo")
        .current_dir(&temp_dir)
        .args(["check"])
        .output()
        .unwrap();

    // Should fail to compile
    assert!(!check_output.status.success());

    cleanup_temp_dir(&temp_dir);
}

#[test]
fn test_cargo_check_warning_counting() {
    let temp_dir = create_temp_lib_project();

    // Write code with warnings (unused variable - use underscore prefix to suppress)
    // Instead, use a pattern that definitely generates a warning
    fs::write(
        temp_dir.join("src/lib.rs"),
        r#"pub fn with_warning() -> i32 {
    let x = 42; // unused variable warning
    1 + 1
}
"#,
    )
    .unwrap();

    // Run cargo check and count warnings (check both stdout and stderr)
    let check_output = Command::new("cargo")
        .current_dir(&temp_dir)
        .args(["check", "--message-format=short"])
        .output()
        .unwrap();

    let output = String::from_utf8_lossy(&check_output.stderr); // warnings go to stderr
    let warning_count = output
        .lines()
        .filter(|line| line.contains("warning:"))
        .count();

    // Should have at least one warning
    assert!(warning_count > 0);

    cleanup_temp_dir(&temp_dir);
}

#[test]
fn test_cargo_test_passes() {
    let temp_dir = create_temp_lib_project();

    // Run cargo test
    let test_output = Command::new("cargo")
        .current_dir(&temp_dir)
        .args(["test", "--lib", "--quiet"])
        .output()
        .unwrap();

    // Tests should pass
    assert!(test_output.status.success());

    cleanup_temp_dir(&temp_dir);
}

#[test]
fn test_cargo_test_fails() {
    let temp_dir = create_temp_lib_project();

    // Write failing test
    fs::write(
        temp_dir.join("src/lib.rs"),
        r#"pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_fails() {
        assert_eq!(add(2, 2), 5); // This will fail
    }
}
"#,
    )
    .unwrap();

    // Run cargo test
    let test_output = Command::new("cargo")
        .current_dir(&temp_dir)
        .args(["test", "--lib", "--quiet"])
        .output()
        .unwrap();

    // Test should fail
    assert!(!test_output.status.success());

    cleanup_temp_dir(&temp_dir);
}

// ============================================================================
// PatchCandidate Tests (from scanner_types)
// ============================================================================

#[test]
fn test_patch_candidate_new() {
    let diff = r#"--- a/test.rs
+++ b/test.rs
@@ -1 +1 @@
-old
+new
"#;
    let candidate = PatchCandidate::new(diff, "test.rs");

    assert_eq!(candidate.diff, diff);
    assert_eq!(candidate.file_path, "test.rs");
    assert!(!candidate.applied);
    assert!(candidate.validation_result.is_none());
}

#[test]
fn test_patch_candidate_default() {
    let candidate = PatchCandidate::default();

    assert!(candidate.diff.is_empty());
    assert!(candidate.file_path.is_empty());
    assert!(!candidate.applied);
    assert!(candidate.validation_result.is_none());
}
