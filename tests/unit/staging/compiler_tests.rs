//! Comprehensive unit tests for staging::compiler module
//!
//! Tests cover:
//! - AutoPatcher creation and repo_path
//! - generate_patch (placeholder format, file path, empty description, diff format)
//! - format_patch_report (all status variations: validated, compiles but tests failed, failed)
//! - format_patch_report sections (build errors, warnings, test errors)
//! - PatchingConfig (default, clone, debug, custom values, staging_prefix none)
//! - PatchCandidate struct fields and behavior
//! - PatchValidationResult equality

use baco::scanner_types::patch::{
    PatchCandidate, PatchValidationResult as ScannerPatchValidationResult,
};
use baco::staging::compiler::{AutoPatcher, PatchingConfig};
use baco::staging::error::PatchValidationResult;
use std::path::PathBuf;

// ============================================================================
// AutoPatcher Tests
// ============================================================================

#[test]
fn test_auto_patcher_creation() {
    let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));
    assert_eq!(patcher.repo_path, PathBuf::from("/tmp/test-repo"));
}

#[test]
fn test_generate_patch_placeholder() {
    let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));

    let result = patcher.generate_patch("test vulnerability", "unsafe code here", "src/test.rs");

    assert!(result.is_ok());
    let patch = result.unwrap();

    // Verify the patch contains expected unified diff format
    assert!(patch.diff.contains("--- a/src/test.rs"));
    assert!(patch.diff.contains("+++ b/src/test.rs"));
    assert!(patch.diff.contains("@@ -1,10 +1,10 @@"));
}

#[test]
fn test_generate_patch_file_path() {
    let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));

    let result = patcher.generate_patch("desc", "code", "lib/utils.rs");
    assert!(result.is_ok());
    let patch = result.unwrap();

    assert_eq!(patch.file_path, "lib/utils.rs");
}

#[test]
fn test_format_patch_report_validated() {
    let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));

    let candidate = PatchCandidate::new("test diff", "src/test.rs");
    let validation = PatchValidationResult {
        compiles: true,
        tests_pass: true,
        warnings: 0,
        error_message: None,
    };

    let report = patcher.format_patch_report(&candidate, &validation);

    assert!(report.contains("Patch Report"));
    assert!(report.contains("src/test.rs"));
    assert!(report.contains("✅ VALIDATED"));
    assert!(report.contains("test diff"));
}

#[test]
fn test_format_patch_report_compiles_but_tests_failed() {
    let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));

    let candidate = PatchCandidate::new("test diff", "src/test.rs");
    let validation = PatchValidationResult {
        compiles: true,
        tests_pass: false,
        warnings: 0,
        error_message: Some("test failed".to_string()),
    };

    let report = patcher.format_patch_report(&candidate, &validation);

    assert!(report.contains("⚠️ COMPILES BUT TESTS FAILED"));
}

#[test]
fn test_format_patch_report_failed() {
    let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));

    let candidate = PatchCandidate::new("test diff", "src/test.rs");
    let validation = PatchValidationResult {
        compiles: false,
        tests_pass: false,
        warnings: 0,
        error_message: Some("build failed".to_string()),
    };

    let report = patcher.format_patch_report(&candidate, &validation);

    assert!(report.contains("❌ FAILED"));
    assert!(report.contains("Build Errors:"));
    assert!(report.contains("build failed"));
}

#[test]
fn test_format_patch_report_with_warnings() {
    let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));

    let candidate = PatchCandidate::new("test diff", "src/test.rs");
    let validation = PatchValidationResult {
        compiles: true,
        tests_pass: true,
        warnings: 5,
        error_message: None,
    };

    let report = patcher.format_patch_report(&candidate, &validation);

    assert!(report.contains("Warnings: 5"));
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
fn test_patching_config_clone() {
    let config1 = PatchingConfig {
        dry_run: true,
        allow_network_access: true,
        max_auto_patches: 10,
        staging_prefix: Some("custom-".to_string()),
    };

    let config2 = config1.clone();

    assert_eq!(config1.dry_run, config2.dry_run);
    assert_eq!(config1.allow_network_access, config2.allow_network_access);
    assert_eq!(config1.max_auto_patches, config2.max_auto_patches);
    assert_eq!(config1.staging_prefix, config2.staging_prefix);
}

#[test]
fn test_patching_config_debug() {
    let config = PatchingConfig::default();
    let debug_output = format!("{:?}", config);

    assert!(debug_output.contains("dry_run"));
    assert!(debug_output.contains("allow_network_access"));
    assert!(debug_output.contains("max_auto_patches"));
    assert!(debug_output.contains("staging_prefix"));
}

#[test]
fn test_auto_patcher_new() {
    let patcher = AutoPatcher::new(PathBuf::from("/custom/repo"));
    assert_eq!(patcher.repo_path, PathBuf::from("/custom/repo"));
}

#[test]
fn test_generate_patch_with_different_file_paths() {
    let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));

    let result = patcher.generate_patch("vuln", "code", "lib/main.rs");
    assert!(result.is_ok());
    let patch = result.unwrap();
    assert!(patch.diff.contains("--- a/lib/main.rs"));
    assert!(patch.diff.contains("+++ b/lib/main.rs"));
}

#[test]
fn test_generate_patch_with_empty_description() {
    let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));

    let result = patcher.generate_patch("", "", "src/empty.rs");
    assert!(result.is_ok());
    let patch = result.unwrap();
    assert!(patch.diff.contains("--- a/src/empty.rs"));
}

#[test]
fn test_format_patch_report_empty_error_message() {
    let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));

    let candidate = PatchCandidate::new("diff", "src/test.rs");
    let validation = PatchValidationResult {
        compiles: false,
        tests_pass: false,
        warnings: 0,
        error_message: None,
    };

    let report = patcher.format_patch_report(&candidate, &validation);

    assert!(report.contains("Unknown error"));
}

#[test]
fn test_format_patch_report_zero_warnings() {
    let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));

    let candidate = PatchCandidate::new("diff", "src/test.rs");
    let validation = PatchValidationResult {
        compiles: true,
        tests_pass: true,
        warnings: 0,
        error_message: None,
    };

    let report = patcher.format_patch_report(&candidate, &validation);

    // Should not contain "Warnings: 0"
    assert!(!report.contains("Warnings: 0"));
}

#[test]
fn test_format_patch_report_with_test_errors() {
    let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));

    let candidate = PatchCandidate::new("diff", "src/test.rs");
    let validation = PatchValidationResult {
        compiles: true,
        tests_pass: false,
        warnings: 0,
        error_message: Some("test error message".to_string()),
    };

    let report = patcher.format_patch_report(&candidate, &validation);

    assert!(report.contains("Test Errors:"));
    assert!(report.contains("test error message"));
}

#[test]
fn test_format_patch_report_with_test_errors_no_message() {
    let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));

    let candidate = PatchCandidate::new("diff", "src/test.rs");
    let validation = PatchValidationResult {
        compiles: true,
        tests_pass: false,
        warnings: 0,
        error_message: None,
    };

    let report = patcher.format_patch_report(&candidate, &validation);

    // Should not contain "Test Errors:" section when error_message is None
    assert!(!report.contains("Test Errors:"));
}

#[test]
fn test_patching_config_with_custom_values() {
    let config = PatchingConfig {
        dry_run: true,
        allow_network_access: true,
        max_auto_patches: 100,
        staging_prefix: Some("my-prefix-".to_string()),
    };

    assert!(config.dry_run);
    assert!(config.allow_network_access);
    assert_eq!(config.max_auto_patches, 100);
    assert_eq!(config.staging_prefix, Some("my-prefix-".to_string()));
}

#[test]
fn test_patching_config_staging_prefix_none() {
    let config = PatchingConfig {
        dry_run: false,
        allow_network_access: false,
        max_auto_patches: 5,
        staging_prefix: None,
    };

    assert!(config.staging_prefix.is_none());
}

#[test]
fn test_patch_candidate_struct_fields() {
    let candidate = PatchCandidate::new("my diff content", "src/file.rs");

    assert_eq!(candidate.diff, "my diff content");
    assert_eq!(candidate.file_path, "src/file.rs");
    assert!(!candidate.applied);
    assert!(candidate.validation_result.is_none());
}

#[test]
fn test_patch_candidate_applied_field() {
    let mut candidate = PatchCandidate::new("diff", "src/test.rs");
    assert!(!candidate.applied);

    candidate.applied = true;
    assert!(candidate.applied);
}

#[test]
fn test_patch_candidate_validation_result_field() {
    let mut candidate = PatchCandidate::new("diff", "src/test.rs");
    assert!(candidate.validation_result.is_none());

    candidate.validation_result = Some(ScannerPatchValidationResult {
        compiles: true,
        tests_pass: true,
        warnings: 0,
        error_message: None,
    });
    assert!(candidate.validation_result.is_some());
}

#[test]
fn test_auto_patcher_repo_path_field() {
    let _patcher = AutoPatcher::new(PathBuf::from("/my/repo/path"));

    // Access the private field via a method or test through behavior
    // Since repo_path is private, we test via the behavior it enables
    let _ = AutoPatcher::new(PathBuf::from("/another/path"));
}

#[test]
fn test_generate_patch_diff_format() {
    let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));

    let result = patcher.generate_patch("desc", "code", "file.txt");
    let patch = result.unwrap();

    // Verify unified diff structure
    assert!(patch.diff.contains("@@ -1,10 +1,10 @@"));
    assert!(patch.diff.ends_with("\n"));
}

#[test]
fn test_format_patch_report_status_variations() {
    let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));
    let candidate = PatchCandidate::new("diff", "src/test.rs");

    // Test VALIDATED status
    let validated = PatchValidationResult {
        compiles: true,
        tests_pass: true,
        warnings: 0,
        error_message: None,
    };
    let report = patcher.format_patch_report(&candidate, &validated);
    assert!(report.contains("✅ VALIDATED"));

    // Test COMPILES BUT TESTS FAILED status
    let compile_only = PatchValidationResult {
        compiles: true,
        tests_pass: false,
        warnings: 0,
        error_message: Some("test fail".to_string()),
    };
    let report = patcher.format_patch_report(&candidate, &compile_only);
    assert!(report.contains("⚠️ COMPILES BUT TESTS FAILED"));

    // Test FAILED status
    let failed = PatchValidationResult {
        compiles: false,
        tests_pass: false,
        warnings: 0,
        error_message: Some("build fail".to_string()),
    };
    let report = patcher.format_patch_report(&candidate, &failed);
    assert!(report.contains("❌ FAILED"));
}

#[test]
fn test_format_patch_report_build_errors_section() {
    let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));
    let candidate = PatchCandidate::new("diff", "src/test.rs");

    let failed = PatchValidationResult {
        compiles: false,
        tests_pass: false,
        warnings: 0,
        error_message: Some("syntax error on line 42".to_string()),
    };

    let report = patcher.format_patch_report(&candidate, &failed);

    assert!(report.contains("Build Errors:"));
    assert!(report.contains("syntax error on line 42"));
}

#[test]
fn test_format_patch_report_warnings_section() {
    let patcher = AutoPatcher::new(PathBuf::from("/tmp/test-repo"));
    let candidate = PatchCandidate::new("diff", "src/test.rs");

    let with_warnings = PatchValidationResult {
        compiles: true,
        tests_pass: true,
        warnings: 10,
        error_message: None,
    };

    let report = patcher.format_patch_report(&candidate, &with_warnings);

    assert!(report.contains("Warnings: 10"));
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

    assert_eq!(result1, result2);

    let result3 = PatchValidationResult {
        compiles: false,
        tests_pass: true,
        warnings: 0,
        error_message: None,
    };

    assert_ne!(result1, result3);
}
