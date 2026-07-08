//! Core staging area and worktree management

use crate::staging::error::{StagingError, StagingResult};
use std::path::{Path, PathBuf};
use std::process::Command;

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
    pub fn validate(&self) -> StagingResult<crate::staging::error::PatchValidationResult> {
        if !self.is_created {
            return Err(StagingError::Validation(
                "Staging area not created".to_string(),
            ));
        }

        tracing::info!("Validating patch in {:?}", self.worktree_path);

        let mut result = crate::staging::error::PatchValidationResult::default();

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
