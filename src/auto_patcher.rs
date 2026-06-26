//! Auto-Patcher Module
//!
//! Generates and validates unified diff patches for vulnerability fixes.
//! Uses StagingArea for safe validation in isolated git worktrees.

use crate::scanner_types::PatchCandidate;
use crate::staging::{PatchValidationResult, StagingArea};
use std::path::PathBuf;
use std::string::String;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AutoPatchError {
    #[error("Failed to generate patch: {0}")]
    Generation(String),
    #[error("Failed to apply patch: {0}")]
    Apply(String),
    #[error("Validation failed: {0}")]
    Validation(String),
    #[error("Staging error: {0}")]
    Staging(String),
    #[error("No LLM client configured")]
    NoLlmClient,
}

pub type Result<T> = std::result::Result<T, AutoPatchError>;

pub struct AutoPatcher {
    repo_path: PathBuf,
}

impl AutoPatcher {
    pub fn new(repo_path: PathBuf) -> Self {
        Self { repo_path }
    }

    /// Generate a patch for fixing a vulnerability
    ///
    /// In production, this would call the LLM to generate the fix.
    /// The prompt guides the LLM to produce a unified diff.
    pub fn generate_patch(
        &self,
        _vulnerability_description: &str,
        _vulnerable_code: &str,
        file_path: &str,
    ) -> Result<PatchCandidate> {
        // In production, this would call the LLM with a prompt like:
        // let prompt = format!(
        //     "Generate a unified diff to fix the following vulnerability:\n\
        //      Description: {}\n\
        //      File: {}\n\
        //      Vulnerable code:\n\
        //      ```\n\
        //      {}\n\
        //      ```\n\
        //      Provide only the unified diff as output.",
        //     vulnerability_description, file_path, vulnerable_code
        // );

        // For now, generate a placeholder that indicates where the fix would go
        // In production, this would be replaced by actual LLM-generated diff
        let diff = format!(
            "--- a/{}\n\
             +++ b/{}\n\
             @@ -1,10 +1,10 @@\n\
             \n",
            file_path, file_path
        );

        Ok(PatchCandidate::new(&diff, file_path))
    }

    /// Validate a patch by applying it in a staging worktree and running checks
    pub fn validate_patch(&self, candidate: &PatchCandidate) -> Result<PatchValidationResult> {
        let mut staging = StagingArea::create(&self.repo_path)
            .map_err(|e| AutoPatchError::Staging(e.to_string()))?;

        // Apply the patch
        if let Err(e) = staging.apply_patch(&candidate.diff) {
            let _ = staging.rollback();
            return Ok(PatchValidationResult::failure(&format!(
                "Patch application failed: {}",
                e
            )));
        }

        // Validate in staging worktree
        let result = staging.validate();

        // Always cleanup
        let mut staging = staging;
        let _ = staging.cleanup();

        match result {
            Ok(validation) => Ok(validation),
            Err(e) => Ok(PatchValidationResult::failure(&format!(
                "Validation failed: {}",
                e
            ))),
        }
    }

    /// Format a patch report with validation results
    pub fn format_patch_report(
        &self,
        candidate: &PatchCandidate,
        validation: &PatchValidationResult,
    ) -> String {
        let status = if validation.compiles && validation.tests_pass {
            "✅ VALIDATED"
        } else if validation.compiles {
            "⚠️ COMPILES BUT TESTS FAILED"
        } else {
            "❌ FAILED"
        };

        let mut report = format!(
            "Patch Report\n\
             ============\n\
             File: {}\n\
             Status: {}\n\
             \n\
             Diff:\n\
             {}\n",
            candidate.file_path, status, candidate.diff
        );

        if !validation.compiles {
            report.push_str(&format!(
                "Build Errors:\n{}\n",
                validation
                    .error_message
                    .as_deref()
                    .unwrap_or("Unknown error")
            ));
        }

        if validation.warnings > 0 {
            report.push_str(&format!("Warnings: {}\n", validation.warnings));
        }

        if !validation.tests_pass && validation.error_message.is_some() {
            report.push_str(&format!(
                "Test Errors:\n{}\n",
                validation.error_message.as_ref().unwrap_or(&String::new())
            ));
        }

        report
    }

    /// Apply and validate a patch in one step
    pub fn apply_and_validate(
        &self,
        candidate: &mut PatchCandidate,
    ) -> Result<PatchValidationResult> {
        let staging = StagingArea::create(&self.repo_path)
            .map_err(|e| AutoPatchError::Staging(e.to_string()))?;

        if let Err(e) = staging.apply_patch(&candidate.diff) {
            let mut staging = staging;
            let _ = staging.rollback();
            let validation = PatchValidationResult::failure(&format!("Apply failed: {}", e));
            candidate.validation_result = Some(validation.clone().into());
            return Ok(validation);
        }

        let validation = staging
            .validate()
            .map_err(|e| AutoPatchError::Validation(e.to_string()))?;

        let mut staging = staging;
        if validation.compiles && validation.tests_pass {
            staging
                .cleanup()
                .map_err(|e| AutoPatchError::Staging(e.to_string()))?;
            candidate.applied = true;
        } else {
            let _ = staging.rollback();
        }

        candidate.validation_result = Some(validation.clone().into());
        Ok(validation)
    }

    /// Execute batch auto-patching on multiple findings
    pub fn execute_batch(
        &self,
        findings: &[crate::findings::VulnerabilityFinding],
        config: &PatchingConfig,
    ) -> Result<Vec<crate::findings::VulnerabilityFinding>> {
        let mut patched_findings = Vec::new();
        let mut patch_count = 0;

        for finding in findings {
            if patch_count >= config.max_auto_patches {
                tracing::info!(
                    "Reached max auto-patches ({}), stopping",
                    config.max_auto_patches
                );
                break;
            }

            // Skip findings without code snippet
            let Some(code_snippet) = &finding.code_snippet else {
                continue;
            };

            // Generate patch
            let patch = self.generate_patch(&finding.title, code_snippet, &finding.file_path)?;

            // Validate patch
            let validation = self.validate_patch(&patch)?;

            if validation.compiles && validation.tests_pass {
                tracing::info!(
                    "Auto-patch validated for finding {} (file: {})",
                    finding.id,
                    finding.file_path
                );
                patched_findings.push(finding.clone());
                patch_count += 1;
            } else {
                tracing::warn!(
                    "Auto-patch validation failed for finding {}: {}",
                    finding.id,
                    validation
                        .error_message
                        .as_deref()
                        .unwrap_or("unknown error")
                );
                // Keep the finding even if patch failed - manual review needed
                patched_findings.push(finding.clone());
            }
        }

        Ok(patched_findings)
    }
}

/// Configuration for auto-patching
#[derive(Debug, Clone)]
pub struct PatchingConfig {
    pub dry_run: bool,
    pub allow_network_access: bool,
    pub max_auto_patches: usize,
    pub staging_prefix: Option<String>,
}

impl Default for PatchingConfig {
    fn default() -> Self {
        Self {
            dry_run: false,
            allow_network_access: false,
            max_auto_patches: 5,
            staging_prefix: Some("baco-auto-".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    /// Create a simple temp directory with basic Rust project structure (no git)
    fn create_temp_dir_with_project() -> PathBuf {
        let temp_dir = std::env::temp_dir().join(format!(
            "baco-patch-test-{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();

        // Create a sample Cargo.toml
        fs::write(
            temp_dir.join("Cargo.toml"),
            r#"[package]
name = "test-repo"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();

        // Create src/main.rs with valid Rust code
        let src_dir = temp_dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(
            src_dir.join("main.rs"),
            r#"fn main() {
    let x = 42;
    println!("Value: {}", x);
}
"#,
        )
        .unwrap();

        temp_dir
    }

    #[test]
    fn test_patch_candidate_creation() {
        let diff = r#"--- a/src/main.rs
+++ b/src/main.rs
@@ -1,4 +1,4 @@
 fn main() {
-    let x = 42;
+    let x = 100;
     println!("Value: {}", x);
 }
"#;

        let candidate = PatchCandidate::new(diff, "src/main.rs");
        assert_eq!(candidate.file_path, "src/main.rs");
        assert!(!candidate.applied);
        assert!(!candidate.diff.is_empty());
    }

    #[test]
    fn test_apply_patch_to_file() {
        let temp_dir = create_temp_dir_with_project();
        let main_rs = temp_dir.join("src/main.rs");

        let original = fs::read_to_string(&main_rs).unwrap();
        assert!(original.contains("let x = 42;"));

        // Simulate patch application
        let patched = original.replace("let x = 42;", "let x = 100;");
        fs::write(&main_rs, &patched).unwrap();

        let new_content = fs::read_to_string(&main_rs).unwrap();
        assert!(new_content.contains("let x = 100;"));

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_invalid_patch_fails() {
        let temp_dir = create_temp_dir_with_project();
        let main_rs = temp_dir.join("src/main.rs");

        // Write invalid Rust syntax
        fs::write(
            &main_rs,
            r#"fn main() {
    let x = ; // Invalid
}
"#,
        )
        .unwrap();

        // cargo check should fail
        let check_output = Command::new("cargo")
            .current_dir(&temp_dir)
            .args(["check"])
            .output()
            .unwrap();

        assert!(!check_output.status.success());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_autopatcher_new() {
        let temp_dir = create_temp_dir_with_project();
        let autopatcher = AutoPatcher::new(temp_dir.clone());

        assert_eq!(autopatcher.repo_path, temp_dir);
    }

    #[test]
    fn test_generate_placeholder_patch() {
        let temp_dir = create_temp_dir_with_project();
        let autopatcher = AutoPatcher::new(temp_dir);

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
    }

    #[test]
    fn test_format_patch_report_validated() {
        let temp_dir = create_temp_dir_with_project();
        let autopatcher = AutoPatcher::new(temp_dir);

        let candidate = PatchCandidate::new("diff content", "src/main.rs");
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
        assert!(report.contains("diff content"));
    }

    #[test]
    fn test_format_patch_report_compiles_but_tests_fail() {
        let temp_dir = create_temp_dir_with_project();
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
        let temp_dir = create_temp_dir_with_project();
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
        let temp_dir = create_temp_dir_with_project();
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
    fn test_patch_validation_result_creation() {
        // Test success case
        let success = PatchValidationResult::success();
        assert!(success.compiles);
        assert!(success.tests_pass);
        assert_eq!(success.warnings, 0);
        assert!(success.error_message.is_none());

        // Test failure case
        let failure = PatchValidationResult::failure("Patch application failed");
        assert!(!failure.compiles);
        assert!(!failure.tests_pass);
        assert_eq!(failure.warnings, 0);
        assert_eq!(failure.error_message, Some("Patch application failed".to_string()));
    }

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
            max_auto_patches: 10,
            staging_prefix: Some("custom-prefix-".to_string()),
        };

        assert!(config.dry_run);
        assert!(config.allow_network_access);
        assert_eq!(config.max_auto_patches, 10);
        assert_eq!(config.staging_prefix, Some("custom-prefix-".to_string()));
    }

    #[test]
    fn test_autopatch_error_enum() {
        // Test error display
        let gen_err = AutoPatchError::Generation("IO error".to_string());
        assert!(gen_err.to_string().contains("Failed to generate patch"));

        let apply_err = AutoPatchError::Apply("Patch rejected".to_string());
        assert!(apply_err.to_string().contains("Failed to apply patch"));

        let val_err = AutoPatchError::Validation("Type mismatch".to_string());
        assert!(val_err.to_string().contains("Validation failed"));

        let staging_err = AutoPatchError::Staging("Worktree create failed".to_string());
        assert!(staging_err.to_string().contains("Staging error"));

        let llm_err = AutoPatchError::NoLlmClient;
        assert!(llm_err.to_string().contains("No LLM client configured"));
    }

    #[test]
    fn test_patch_candidate_default() {
        let candidate = PatchCandidate::default();

        assert!(candidate.diff.is_empty());
        assert!(candidate.file_path.is_empty());
        assert!(!candidate.applied);
        assert!(candidate.validation_result.is_none());
    }

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
}
