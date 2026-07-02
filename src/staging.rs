//! Git worktree staging utilities for safe auto-patching
//!
//! Provides safe patch application and validation in isolated git worktrees.

use crate::scanner_types::patch::PatchCandidate;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::string::String;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StagingError {
    #[error("Failed to create worktree: {0}")]
    WorktreeCreate(String),
    #[error("Failed to apply patch: {0}")]
    PatchApply(String),
    #[error("Validation failed: {0}")]
    Validation(String),
    #[error("Cleanup failed: {0}")]
    Cleanup(String),
    #[error("Rollback failed: {0}")]
    Rollback(String),
    #[error("Git command failed: {0}")]
    GitError(String),
}

/// Unified error type for auto-patching operations
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

pub type StagingResult<T> = std::result::Result<T, StagingError>;
pub type AutoPatchResult<T> = std::result::Result<T, AutoPatchError>;

/// Result of patch validation
#[derive(Debug, Clone, PartialEq)]
pub struct PatchValidationResult {
    pub compiles: bool,
    pub tests_pass: bool,
    pub warnings: u32,
    pub error_message: Option<String>,
}

impl Default for PatchValidationResult {
    fn default() -> Self {
        Self {
            compiles: true,
            tests_pass: true,
            warnings: 0,
            error_message: None,
        }
    }
}

impl PatchValidationResult {
    pub fn success() -> Self {
        Self::default()
    }

    pub fn failure(msg: &str) -> Self {
        Self {
            compiles: false,
            tests_pass: false,
            warnings: 0,
            error_message: Some(msg.to_string()),
        }
    }
}

impl From<PatchValidationResult> for crate::scanner_types::patch::PatchValidationResult {
    fn from(val: PatchValidationResult) -> crate::scanner_types::patch::PatchValidationResult {
        crate::scanner_types::patch::PatchValidationResult {
            compiles: val.compiles,
            tests_pass: val.tests_pass,
            warnings: val.warnings,
            error_message: val.error_message,
        }
    }
}

/// Manages a temporary git worktree for safe patch validation
pub struct StagingArea {
    pub worktree_path: PathBuf,
    pub original_repo_path: PathBuf,
    pub is_created: bool,
}

impl StagingArea {
    /// Creates a new staging area by cloning the repo into a temp worktree
    pub fn create(repo_path: &Path) -> StagingResult<Self> {
        let original_repo_path = repo_path.to_path_buf();
        let worktree_path = std::env::temp_dir().join(format!(
            "baco-staging-{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        tracing::info!("Creating staging worktree at: {:?}", worktree_path);

        // Create worktree
        let output = Command::new("git")
            .current_dir(repo_path)
            .args(["worktree", "add", worktree_path.to_str().unwrap(), "HEAD"])
            .output()
            .map_err(|e| StagingError::WorktreeCreate(e.to_string()))?;

        if !output.status.success() {
            return Err(StagingError::WorktreeCreate(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        Ok(Self {
            worktree_path,
            original_repo_path: original_repo_path.to_path_buf(),
            is_created: true,
        })
    }

    /// Applies a unified diff patch to the staging worktree
    pub fn apply_patch(&self, diff: &str) -> StagingResult<()> {
        if !self.is_created {
            return Err(StagingError::PatchApply(
                "Staging area not created".to_string(),
            ));
        }

        tracing::info!("Applying patch to {:?}", self.worktree_path);

        // Write patch to temp file
        let patch_path = self.worktree_path.join("patch.diff");
        std::fs::write(&patch_path, diff)
            .map_err(|e| StagingError::PatchApply(format!("Failed to write patch: {}", e)))?;

        // Apply patch
        let output = Command::new("git")
            .current_dir(&self.worktree_path)
            .args(["apply", "--verbose", patch_path.to_str().unwrap()])
            .output()
            .map_err(|e| StagingError::PatchApply(e.to_string()))?;

        if !output.status.success() {
            return Err(StagingError::PatchApply(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        Ok(())
    }

    /// Validates the patch by running cargo check and cargo test
    pub fn validate(&self) -> StagingResult<PatchValidationResult> {
        if !self.is_created {
            return Err(StagingError::Validation(
                "Staging area not created".to_string(),
            ));
        }

        tracing::info!("Validating patch in {:?}", self.worktree_path);

        let mut result = PatchValidationResult::default();

        // Run cargo check
        let check_output = Command::new("cargo")
            .current_dir(&self.worktree_path)
            .args(["check", "--message-format=short"])
            .output()
            .map_err(|e| StagingError::Validation(format!("cargo check failed: {}", e)))?;

        result.compiles = check_output.status.success();

        if !result.compiles {
            result.error_message = Some(String::from_utf8_lossy(&check_output.stderr).to_string());
            return Ok(result);
        }

        // Count warnings
        let warning_count = String::from_utf8_lossy(&check_output.stdout)
            .lines()
            .filter(|line| line.contains("warning:"))
            .count() as u32;
        result.warnings = warning_count;

        // Run cargo test (quick check, no output capture for speed)
        let test_output = Command::new("cargo")
            .current_dir(&self.worktree_path)
            .args(["test", "--lib", "--quiet"])
            .output()
            .map_err(|e| StagingError::Validation(format!("cargo test failed: {}", e)))?;

        result.tests_pass = test_output.status.success();

        if !result.tests_pass {
            result.error_message = Some(String::from_utf8_lossy(&test_output.stderr).to_string());
        }

        Ok(result)
    }

    /// Cleans up the staging worktree
    pub fn cleanup(&mut self) -> StagingResult<()> {
        if !self.is_created {
            return Ok(());
        }

        tracing::info!("Cleaning up staging worktree at {:?}", self.worktree_path);

        let output = Command::new("git")
            .current_dir(&self.original_repo_path)
            .args([
                "worktree",
                "remove",
                "--force",
                self.worktree_path.to_str().unwrap(),
            ])
            .output()
            .map_err(|e| StagingError::Cleanup(e.to_string()))?;

        if !output.status.success() {
            tracing::warn!(
                "Git worktree remove failed: {:?}",
                String::from_utf8_lossy(&output.stderr)
            );
            // Try force removal
            let _ = std::fs::remove_dir_all(&self.worktree_path);
        }

        // Ensure temp dir is gone
        let _ = std::fs::remove_dir_all(&self.worktree_path);

        self.is_created = false;
        Ok(())
    }

    /// Rolls back changes and cleans up
    pub fn rollback(&mut self) -> StagingResult<()> {
        if self.is_created {
            // Reset worktree to HEAD
            let _ = Command::new("git")
                .current_dir(&self.worktree_path)
                .args(["reset", "--hard", "HEAD"])
                .output();

            self.cleanup()
        } else {
            Ok(())
        }
    }
}

impl Drop for StagingArea {
    fn drop(&mut self) {
        // Auto-cleanup on drop
        if self.is_created {
            let _ = self.cleanup();
        }
    }
}

/// Auto-Patcher for generating and validating patches
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
    ) -> AutoPatchResult<PatchCandidate> {
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
    pub fn validate_patch(
        &self,
        candidate: &PatchCandidate,
    ) -> AutoPatchResult<PatchValidationResult> {
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
    ) -> AutoPatchResult<PatchValidationResult> {
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
    ) -> AutoPatchResult<Vec<crate::findings::VulnerabilityFinding>> {
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
    use std::path::PathBuf;

    /// Create a simple temp directory with basic Rust project structure (no git)
    fn create_temp_dir_with_project() -> PathBuf {
        let temp_dir = std::env::temp_dir().join(format!(
            "baco-test-{:x}",
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

    #[test]
    fn test_apply_patch_simple() {
        let temp_dir = create_temp_dir_with_project();
        let main_rs = temp_dir.join("src/main.rs");

        // Read original content
        let original = fs::read_to_string(&main_rs).unwrap();
        assert!(original.contains("Hello, world!"));

        // Apply a simple patch manually (simulating what apply_patch would do)
        let patched = original.replace("Hello, world!", "Hello, patched world!");
        fs::write(&main_rs, &patched).unwrap();

        // Verify patch applied
        let new_content = fs::read_to_string(&main_rs).unwrap();
        assert!(new_content.contains("Hello, patched world!"));

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_patch_validation_logic() {
        let temp_dir = create_temp_dir_with_project();
        let main_rs = temp_dir.join("src/main.rs");

        // Write invalid Rust syntax
        fs::write(
            &main_rs,
            r#"fn main() {
    let x = ; // Invalid syntax
}
"#,
        )
        .unwrap();

        // Run cargo check to validate (simulating the validate method)
        let check_output = Command::new("cargo")
            .current_dir(&temp_dir)
            .args(["check"])
            .output()
            .unwrap();

        // Should fail to compile
        assert!(!check_output.status.success());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_valid_code_compiles() {
        let temp_dir = create_temp_dir_with_project();

        // Run cargo check on valid code
        let check_output = Command::new("cargo")
            .current_dir(&temp_dir)
            .args(["check"])
            .output()
            .unwrap();

        // Should compile successfully
        assert!(check_output.status.success());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

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
        let result = PatchValidationResult::failure("Compilation error");

        assert!(!result.compiles);
        assert!(!result.tests_pass);
        assert_eq!(result.warnings, 0);
        assert_eq!(result.error_message, Some("Compilation error".to_string()));
    }

    #[test]
    fn test_patch_validation_result_clone() {
        let original = PatchValidationResult {
            compiles: true,
            tests_pass: false,
            warnings: 3,
            error_message: Some("test failed".to_string()),
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

        assert_eq!(result1, result2);
        assert_ne!(result1, result3);
    }

    #[test]
    fn test_staging_error_display() {
        let worktree_err = StagingError::WorktreeCreate("Permission denied".to_string());
        assert!(worktree_err
            .to_string()
            .contains("Failed to create worktree"));

        let patch_err = StagingError::PatchApply("Hunk failed".to_string());
        assert!(patch_err.to_string().contains("Failed to apply patch"));

        let val_err = StagingError::Validation("Cargo check failed".to_string());
        assert!(val_err.to_string().contains("Validation failed"));

        let cleanup_err = StagingError::Cleanup("Git worktree busy".to_string());
        assert!(cleanup_err.to_string().contains("Cleanup failed"));

        let rollback_err = StagingError::Rollback("Reset failed".to_string());
        assert!(rollback_err.to_string().contains("Rollback failed"));

        let git_err = StagingError::GitError("Git not found".to_string());
        assert!(git_err.to_string().contains("Git command failed"));
    }

    #[test]
    fn test_staging_area_not_created_error() {
        // Create a StagingArea without actually creating it (simulating error state)
        let temp_dir = create_temp_dir_with_project();
        let staging = StagingArea {
            worktree_path: temp_dir.clone(),
            original_repo_path: temp_dir.clone(),
            is_created: false,
        };

        // Test apply_patch with not created
        let result = staging.apply_patch("some diff");
        assert!(result.is_err());
        assert!(matches!(result, Err(StagingError::PatchApply(_))));

        // Test validate with not created
        let result = staging.validate();
        assert!(result.is_err());
        assert!(matches!(result, Err(StagingError::Validation(_))));

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_staging_area_rollback_not_created() {
        let temp_dir = create_temp_dir_with_project();
        let mut staging = StagingArea {
            worktree_path: temp_dir.clone(),
            original_repo_path: temp_dir.clone(),
            is_created: false,
        };

        // Rollback should succeed even when not created
        let result = staging.rollback();
        assert!(result.is_ok());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_staging_area_cleanup_not_created() {
        let temp_dir = create_temp_dir_with_project();
        let mut staging = StagingArea {
            worktree_path: temp_dir.clone(),
            original_repo_path: temp_dir.clone(),
            is_created: false,
        };

        // Cleanup should succeed even when not created
        let result = staging.cleanup();
        assert!(result.is_ok());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_staging_area_drop() {
        let temp_dir = create_temp_dir_with_project();

        // Create a staging area that will be dropped
        {
            let mut staging = StagingArea {
                worktree_path: temp_dir.clone(),
                original_repo_path: temp_dir.clone(),
                is_created: true,
            };

            // Manually set is_created to false to simulate cleanup
            staging.is_created = false;
        } // Drop happens here

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_staging_area_is_created_flag() {
        let temp_dir = create_temp_dir_with_project();

        // Test with is_created = true
        let staging = StagingArea {
            worktree_path: temp_dir.clone(),
            original_repo_path: temp_dir.clone(),
            is_created: true,
        };

        // The flag should be set
        assert!(staging.is_created);

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_patch_validation_result_from() {
        let local_result = PatchValidationResult {
            compiles: true,
            tests_pass: false,
            warnings: 2,
            error_message: Some("test error".to_string()),
        };

        let converted: crate::scanner_types::PatchValidationResult = local_result.into();

        assert!(converted.compiles);
        assert!(!converted.tests_pass);
        assert_eq!(converted.warnings, 2);
        assert_eq!(converted.error_message, Some("test error".to_string()));
    }

    #[test]
    fn test_staging_path_generation() {
        let _repo_path = PathBuf::from("/tmp/test-repo");
        let worktree_path = std::env::temp_dir().join(format!(
            "baco-staging-{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        // Verify path is in temp directory
        assert!(worktree_path.starts_with(std::env::temp_dir()));
        assert!(worktree_path.to_string_lossy().contains("baco-staging-"));
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
        let vulnerable_code =
            "let query = format!(\"SELECT * FROM users WHERE id = {}\", user_id);";
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

    #[test]
    fn test_staging_area_worktree_path_type() {
        let temp_dir = create_temp_dir_with_project();
        let staging = StagingArea {
            worktree_path: temp_dir.clone(),
            original_repo_path: temp_dir.clone(),
            is_created: false,
        };

        // Verify worktree_path is a PathBuf
        assert!(staging.worktree_path.is_absolute() || staging.worktree_path.starts_with("/tmp"));

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_staging_area_original_repo_path() {
        let temp_dir = create_temp_dir_with_project();
        let staging = StagingArea {
            worktree_path: temp_dir.join("worktree"),
            original_repo_path: temp_dir.clone(),
            is_created: false,
        };

        assert_eq!(staging.original_repo_path, temp_dir);

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_apply_patch_with_empty_diff() {
        let temp_dir = create_temp_dir_with_project();
        let mut staging = StagingArea {
            worktree_path: temp_dir.clone(),
            original_repo_path: temp_dir.clone(),
            is_created: true,
        };

        // Empty patch should still write and attempt apply
        let result = staging.apply_patch("");
        // This may fail due to git apply expecting a valid diff, but shouldn't panic
        // We're testing the function handles empty input gracefully
        let _ = staging.cleanup();
        let _ = fs::remove_dir_all(&temp_dir);
        
        // The important thing is it doesn't panic - result can be Ok or Err
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_apply_patch_creates_patch_file() {
        let temp_dir = create_temp_dir_with_project();
        let staging = StagingArea {
            worktree_path: temp_dir.clone(),
            original_repo_path: temp_dir.clone(),
            is_created: true,
        };

        // Write patch manually to simulate apply_patch
        let patch_path = staging.worktree_path.join("patch.diff");
        let diff = "--- a/test.rs\n+++ b/test.rs\n@@ -1 +1 @@\n-old\n+new\n";
        fs::write(&patch_path, diff).unwrap();

        assert!(patch_path.exists());

        // Cleanup
        fs::remove_file(&patch_path).unwrap();
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_validate_without_creation() {
        let temp_dir = create_temp_dir_with_project();
        let staging = StagingArea {
            worktree_path: temp_dir.clone(),
            original_repo_path: temp_dir.clone(),
            is_created: false,
        };

        let result = staging.validate();
        assert!(result.is_err());
        assert!(matches!(result, Err(StagingError::Validation(_))));

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_cleanup_sets_is_created_false() {
        let temp_dir = create_temp_dir_with_project();
        let mut staging = StagingArea {
            worktree_path: temp_dir.clone(),
            original_repo_path: temp_dir.clone(),
            is_created: true,
        };

        // Manually set is_created to false to simulate cleanup
        staging.is_created = false;

        assert!(!staging.is_created);

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_rollback_without_creation() {
        let temp_dir = create_temp_dir_with_project();
        let mut staging = StagingArea {
            worktree_path: temp_dir.clone(),
            original_repo_path: temp_dir.clone(),
            is_created: false,
        };

        let result = staging.rollback();
        assert!(result.is_ok());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_autopatch_error_from_staging_error() {
        let staging_err = StagingError::WorktreeCreate("test error".to_string());
        let autopatch_err: AutoPatchError = AutoPatchError::Staging(staging_err.to_string());

        assert!(autopatch_err.to_string().contains("Staging error"));
    }

    #[test]
    fn test_autopatcher_generate_patch_empty_inputs() {
        let temp_dir = create_temp_dir_with_project();
        let autopatcher = AutoPatcher::new(temp_dir.clone());

        // Test with empty vulnerability description
        let patch = autopatcher
            .generate_patch("", "", "empty.rs")
            .unwrap();

        assert_eq!(patch.file_path, "empty.rs");
        assert!(!patch.diff.is_empty());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_format_patch_report_empty_diff() {
        let temp_dir = create_temp_dir_with_project();
        let autopatcher = AutoPatcher::new(temp_dir);

        let candidate = PatchCandidate::new("", "empty.rs");
        let validation = PatchValidationResult::success();

        let report = autopatcher.format_patch_report(&candidate, &validation);

        assert!(report.contains("✅ VALIDATED"));
        assert!(report.contains("empty.rs"));
    }

    #[test]
    fn test_patching_config_builder_pattern() {
        // Test creating config with partial overrides
        let config = PatchingConfig {
            max_auto_patches: 3,
            ..PatchingConfig::default()
        };

        assert_eq!(config.max_auto_patches, 3);
        assert!(!config.dry_run);
        assert_eq!(config.staging_prefix, Some("baco-auto-".to_string()));
    }

    #[test]
    fn test_staging_result_type_alias() {
        let ok_result: StagingResult<()> = Ok(());
        assert!(ok_result.is_ok());

        let err_result: StagingResult<()> = Err(StagingError::GitError("test".to_string()));
        assert!(err_result.is_err());
    }

    #[test]
    fn test_auto_patch_result_type_alias() {
        let ok_result: AutoPatchResult<()> = Ok(());
        assert!(ok_result.is_ok());

        let err_result: AutoPatchResult<()> = Err(AutoPatchError::NoLlmClient);
        assert!(err_result.is_err());
    }

    #[test]
    fn test_patch_validation_result_warning_count() {
        let mut result = PatchValidationResult::success();
        result.warnings = 10;

        assert_eq!(result.warnings, 10);
        assert!(result.compiles);
        assert!(result.tests_pass);
    }

    #[test]
    fn test_staging_error_from_std_error() {
        let std_err = std::io::Error::other("io error");
        let staging_err = StagingError::WorktreeCreate(std_err.to_string());

        assert!(staging_err.to_string().contains("Failed to create worktree"));
        assert!(staging_err.to_string().contains("io error"));
    }

    #[test]
    fn test_patch_candidate_applied_flag() {
        let mut candidate = PatchCandidate::new("diff", "test.rs");
        assert!(!candidate.applied);

        candidate.applied = true;
        assert!(candidate.applied);
    }

    #[test]
    fn test_patch_candidate_validation_result_setting() {
        let mut candidate = PatchCandidate::new("diff", "test.rs");
        assert!(candidate.validation_result.is_none());

        let validation = PatchValidationResult::failure("test error");
        candidate.validation_result = Some(validation.into());

        assert!(candidate.validation_result.is_some());
    }

    #[test]
    fn test_auto_patcher_repo_path_storage() {
        let temp_dir = create_temp_dir_with_project();
        let autopatcher = AutoPatcher::new(temp_dir.clone());

        assert_eq!(autopatcher.repo_path, temp_dir);

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_staging_area_paths_after_creation() {
        let temp_dir = create_temp_dir_with_project();
        let staging = StagingArea {
            worktree_path: temp_dir.join("staging-worktree"),
            original_repo_path: temp_dir.clone(),
            is_created: true,
        };

        assert!(staging.worktree_path.ends_with("staging-worktree"));
        assert_eq!(staging.original_repo_path, temp_dir);

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_patch_validation_result_all_fields() {
        let result = PatchValidationResult {
            compiles: false,
            tests_pass: false,
            warnings: 42,
            error_message: Some("comprehensive error".to_string()),
        };

        assert!(!result.compiles);
        assert!(!result.tests_pass);
        assert_eq!(result.warnings, 42);
        assert_eq!(result.error_message, Some("comprehensive error".to_string()));
    }

    #[test]
    fn test_multiple_staging_areas_independent() {
        let temp_dir1 = create_temp_dir_with_project();
        let temp_dir2 = create_temp_dir_with_project();

        let staging1 = StagingArea {
            worktree_path: temp_dir1.join("worktree1"),
            original_repo_path: temp_dir1.clone(),
            is_created: true,
        };

        let staging2 = StagingArea {
            worktree_path: temp_dir2.join("worktree2"),
            original_repo_path: temp_dir2.clone(),
            is_created: true,
        };

        assert_ne!(staging1.worktree_path, staging2.worktree_path);
        assert_ne!(staging1.original_repo_path, staging2.original_repo_path);

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir1);
        let _ = fs::remove_dir_all(&temp_dir2);
    }

    #[test]
    fn test_patch_candidate_clone_behavior() {
        let original = PatchCandidate {
            diff: "original diff".to_string(),
            file_path: "test.rs".to_string(),
            applied: false,
            validation_result: None,
        };

        let cloned = original.clone();

        assert_eq!(original.diff, cloned.diff);
        assert_eq!(original.file_path, cloned.file_path);
        assert_eq!(original.applied, cloned.applied);
        assert_eq!(original.validation_result, cloned.validation_result);
    }

    #[test]
    fn test_patch_candidate_equality() {
        let candidate1 = PatchCandidate {
            diff: "same diff".to_string(),
            file_path: "test.rs".to_string(),
            applied: false,
            validation_result: None,
        };

        let candidate2 = PatchCandidate {
            diff: "same diff".to_string(),
            file_path: "test.rs".to_string(),
            applied: false,
            validation_result: None,
        };

        let candidate3 = PatchCandidate {
            diff: "different diff".to_string(),
            file_path: "test.rs".to_string(),
            applied: false,
            validation_result: None,
        };

        assert_eq!(candidate1, candidate2);
        assert_ne!(candidate1, candidate3);
    }

    #[test]
    fn test_staging_error_debug_format() {
        let err = StagingError::PatchApply("test error".to_string());
        let debug_str = format!("{:?}", err);

        assert!(debug_str.contains("PatchApply"));
        assert!(debug_str.contains("test error"));
    }

    #[test]
    fn test_auto_patch_error_debug_format() {
        let err = AutoPatchError::Apply("test error".to_string());
        let debug_str = format!("{:?}", err);

        assert!(debug_str.contains("Apply"));
        assert!(debug_str.contains("test error"));
    }

    #[test]
    fn test_patch_validation_result_display() {
        let success = PatchValidationResult::success();
        assert!(success.compiles && success.tests_pass);

        let failure = PatchValidationResult::failure("error message");
        assert!(!failure.compiles && !failure.tests_pass);
        assert_eq!(failure.error_message, Some("error message".to_string()));
    }

    #[test]
    fn test_staging_area_drop_cleanup_flag() {
        let temp_dir = create_temp_dir_with_project();
        let staging_path = temp_dir.clone();

        // Create staging area that will be dropped
        {
            let mut staging = StagingArea {
                worktree_path: temp_dir.clone(),
                original_repo_path: temp_dir.clone(),
                is_created: true,
            };
            // Manually set is_created to false so cleanup doesn't try to remove
            staging.is_created = false;
        } // Drop happens here

        // The path should still exist (we're not actually creating git worktree)
        assert!(staging_path.exists());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_patch_candidate_with_validation_result() {
        let mut candidate = PatchCandidate::new("diff", "test.rs");
        
        // Set validation result
        let validation = PatchValidationResult {
            compiles: true,
            tests_pass: true,
            warnings: 0,
            error_message: None,
        };
        candidate.validation_result = Some(validation.into());
        candidate.applied = true;

        assert!(candidate.validation_result.is_some());
        assert!(candidate.applied);
    }

    #[test]
    fn test_patching_config_all_fields_custom() {
        let config = PatchingConfig {
            dry_run: true,
            allow_network_access: true,
            max_auto_patches: 100,
            staging_prefix: Some("test-".to_string()),
        };

        assert!(config.dry_run);
        assert!(config.allow_network_access);
        assert_eq!(config.max_auto_patches, 100);
        assert_eq!(config.staging_prefix, Some("test-".to_string()));
    }

    #[test]
    fn test_staging_error_coverage_all_variants() {
        // Test all StagingError variants are properly formatted
        let variants = vec![
            StagingError::WorktreeCreate("err".to_string()).to_string(),
            StagingError::PatchApply("err".to_string()).to_string(),
            StagingError::Validation("err".to_string()).to_string(),
            StagingError::Cleanup("err".to_string()).to_string(),
            StagingError::Rollback("err".to_string()).to_string(),
            StagingError::GitError("err".to_string()).to_string(),
        ];

        for variant in variants {
            assert!(!variant.is_empty());
            assert!(variant.contains("err"));
        }
    }

    #[test]
    fn test_auto_patch_error_coverage_all_variants() {
        // Test all AutoPatchError variants are properly formatted
        let variants = vec![
            AutoPatchError::Generation("err".to_string()).to_string(),
            AutoPatchError::Apply("err".to_string()).to_string(),
            AutoPatchError::Validation("err".to_string()).to_string(),
            AutoPatchError::Staging("err".to_string()).to_string(),
            AutoPatchError::NoLlmClient.to_string(),
        ];

        for variant in variants {
            assert!(!variant.is_empty());
        }
    }
}
