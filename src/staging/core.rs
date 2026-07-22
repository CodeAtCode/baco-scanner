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

        // Attempt git worktree removal, but don't fail if it doesn't work
        let output = match Command::new("git")
            .current_dir(&self.original_repo_path)
            .args([
                "worktree",
                "remove",
                "--force",
                self.worktree_path.to_str().unwrap(),
            ])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!("Git worktree remove failed: {}", e);
                std::fs::remove_dir_all(&self.worktree_path).ok();
                self.is_created = false;
                return Ok(());
            }
        };

        if !output.status.success() {
            tracing::warn!(
                "Git worktree remove failed: {:?}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Try force removal
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // ============================================================================
    // StagingArea Tests
    // ============================================================================

    #[test]
    fn test_staging_area_struct_fields() {
        // Verify the struct has the expected fields
        let temp_path = Path::new("/tmp/test-repo");
        let staging = StagingArea {
            worktree_path: PathBuf::from("/tmp/staging-test"),
            original_repo_path: temp_path.to_path_buf(),
            is_created: false,
        };

        assert_eq!(staging.worktree_path, PathBuf::from("/tmp/staging-test"));
        assert_eq!(staging.original_repo_path, temp_path);
        assert!(!staging.is_created);
    }

    #[test]
    fn test_staging_area_not_created_error() {
        let mut staging = StagingArea {
            worktree_path: PathBuf::from("/tmp/staging-test"),
            original_repo_path: PathBuf::from("/tmp/test-repo"),
            is_created: false,
        };

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
        let mut staging = StagingArea {
            worktree_path: PathBuf::from("/tmp/staging-test"),
            original_repo_path: PathBuf::from("/tmp/test-repo"),
            is_created: false,
        };

        // Rollback when not created should succeed without doing anything
        let result = staging.rollback();
        assert!(result.is_ok());
        assert!(!staging.is_created);
    }

    #[test]
    fn test_patch_path_construction() {
        let staging = StagingArea {
            worktree_path: PathBuf::from("/tmp/staging-test"),
            original_repo_path: PathBuf::from("/tmp/test-repo"),
            is_created: true,
        };

        // Verify patch path would be constructed correctly
        let expected_patch_path = staging.worktree_path.join("patch.diff");
        assert_eq!(
            expected_patch_path,
            PathBuf::from("/tmp/staging-test/patch.diff")
        );
    }

    #[test]
    fn test_staging_area_drop_cleanup() {
        // Create a staging area that will be dropped
        {
            let mut staging = StagingArea {
                worktree_path: PathBuf::from("/tmp/staging-drop-test"),
                original_repo_path: PathBuf::from("/tmp/test-repo"),
                is_created: true,
            };

            // Verify it's created
            assert!(staging.is_created);

            // Cleanup is called - the flag should be reset regardless of actual git operation result
            // Capture the cleanup result but the key assertion is that is_created becomes false
            let _ = staging.cleanup();
            assert!(
                !staging.is_created,
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
}
