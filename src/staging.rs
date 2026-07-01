//! Git worktree staging utilities for safe auto-patching
//!
//! Provides safe patch application and validation in isolated git worktrees.

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

pub type Result<T> = std::result::Result<T, StagingError>;

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

impl From<PatchValidationResult> for crate::scanner_types::PatchValidationResult {
    fn from(val: PatchValidationResult) -> crate::scanner_types::PatchValidationResult {
        crate::scanner_types::PatchValidationResult {
            compiles: val.compiles,
            tests_pass: val.tests_pass,
            warnings: val.warnings,
            error_message: val.error_message,
        }
    }
}

/// Manages a temporary git worktree for safe patch validation
pub struct StagingArea {
    worktree_path: PathBuf,
    original_repo_path: PathBuf,
    is_created: bool,
}

impl StagingArea {
    /// Creates a new staging area by cloning the repo into a temp worktree
    pub fn create(repo_path: &Path) -> Result<Self> {
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
    pub fn apply_patch(&self, diff: &str) -> Result<()> {
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
    pub fn validate(&self) -> Result<PatchValidationResult> {
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
    pub fn cleanup(&mut self) -> Result<()> {
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
    pub fn rollback(&mut self) -> Result<()> {
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
}
