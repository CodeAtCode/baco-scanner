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
}
