//! Git Worktree Staging Utilities
//!
//! Provides utilities for creating isolated git worktrees to stage and validate
//! patch candidates before applying them to the main codebase.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use thiserror::Error;
use tracing::{info, warn};

/// Errors that can occur during git worktree operations
#[derive(Debug, Error)]
pub enum WorktreeError {
    #[error("Git command failed: {0}")]
    GitCommandFailed(String),

    #[error("Worktree path already exists: {0}")]
    WorktreeExists(String),

    #[error("Failed to create worktree: {0}")]
    WorktreeCreationFailed(String),

    #[error("Failed to checkout branch: {0}")]
    CheckoutFailed(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Result type for worktree operations
pub type WorktreeResult<T> = Result<T, WorktreeError>;

/// Manages git worktree operations for patch staging
pub struct WorktreeManager {
    /// Base repository path
    repo_path: PathBuf,
    /// Temporary worktrees directory
    temp_dir: PathBuf,
}

impl WorktreeManager {
    /// Create a new worktree manager
    pub fn new(repo_path: PathBuf) -> Self {
        let temp_dir = repo_path.join(".baco-temp").join("worktrees");
        Self { repo_path, temp_dir }
    }

    /// Create a new isolated worktree for patch staging
    ///
    /// # Arguments
    /// * `patch_id` - Unique identifier for the patch (used in worktree name)
    /// * `base_branch` - Branch to base the worktree on
    pub fn create_staging_worktree(
        &self,
        patch_id: &str,
        base_branch: &str,
    ) -> WorktreeResult<PathBuf> {
        let worktree_name = format!("baco-staging-{}", patch_id);
        let worktree_path = self.temp_dir.join(&worktree_name);

        // Ensure temp directory exists
        std::fs::create_dir_all(&self.temp_dir)?;

        // Check if worktree already exists
        if worktree_path.exists() {
            warn!("Worktree already exists at {:?}, removing first", worktree_path);
            self.remove_worktree(&worktree_name)?;
        }

        info!("Creating staging worktree '{}' from '{}'", worktree_name, base_branch);

        let output = Command::new("git")
            .current_dir(&self.repo_path)
            .args([
                "worktree",
                "add",
                worktree_path.to_str().ok_or_else(|| {
                    WorktreeError::GitCommandFailed("Invalid path".to_string())
                })?,
                "-b",
                &worktree_name,
                base_branch,
            ])
            .output()
            .map_err(|e| WorktreeError::GitCommandFailed(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WorktreeError::WorktreeCreationFailed(stderr.to_string()));
        }

        info!("Worktree created at {:?}", worktree_path);
        Ok(worktree_path)
    }

    /// Apply a patch to a worktree
    ///
    /// # Arguments
    /// * `worktree_path` - Path to the worktree
    /// * `patch_content` - Git diff content to apply
    pub fn apply_patch(
        &self,
        worktree_path: &Path,
        patch_content: &str,
    ) -> WorktreeResult<()> {
        info!("Applying patch to worktree at {:?}", worktree_path);

        let mut output = Command::new("git")
            .current_dir(worktree_path)
            .args(["apply", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| WorktreeError::GitCommandFailed(e.to_string()))?;

        // Write patch to stdin
        use std::io::Write;
        if let Some(ref mut stdin) = output.stdin {
            stdin
                .write_all(patch_content.as_bytes())
                .map_err(|e| WorktreeError::GitCommandFailed(e.to_string()))?;
        }

        let result = output
            .wait_with_output()
            .map_err(|e| WorktreeError::GitCommandFailed(e.to_string()))?;

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            return Err(WorktreeError::CheckoutFailed(format!(
                "Patch apply failed: {}",
                stderr
            )));
        }

        info!("Patch applied successfully");
        Ok(())
    }

    /// Run validation commands in the worktree
    ///
    /// # Arguments
    /// * `worktree_path` - Path to the worktree
    /// * `commands` - List of commands to run (e.g., ["cargo", "build"])
    pub fn run_validation(
        &self,
        worktree_path: &Path,
        commands: &[&[&str]],
    ) -> WorktreeResult<Vec<(String, bool)>> {
        let mut results = Vec::new();

        for cmd in commands {
            let cmd_name = cmd.join(" ");
            info!("Running validation: {}", cmd_name);

            let output = Command::new(cmd[0])
                .current_dir(worktree_path)
                .args(&cmd[1..])
                .output()
                .map_err(|e| WorktreeError::GitCommandFailed(e.to_string()))?;

            let success = output.status.success();
            results.push((cmd_name.clone(), success));

            if !success {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("Validation '{}' failed: {}", cmd_name, stderr);
            } else {
                info!("Validation '{}' passed", cmd_name);
            }
        }

        Ok(results)
    }

    /// Remove a staging worktree
    pub fn remove_worktree(&self, worktree_name: &str) -> WorktreeResult<()> {
        info!("Removing worktree '{}'", worktree_name);

        let output = Command::new("git")
            .current_dir(&self.repo_path)
            .args(["worktree", "remove", "--force", worktree_name])
            .output()
            .map_err(|e| WorktreeError::GitCommandFailed(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Worktree might not exist, which is OK
            if !stderr.contains("not a worktree") {
                return Err(WorktreeError::GitCommandFailed(stderr.to_string()));
            }
        }

        info!("Worktree '{}' removed", worktree_name);
        Ok(())
    }

    /// Clean up all stale worktrees older than specified duration
    pub fn cleanup_stale_worktrees(&self, max_age: Duration) -> WorktreeResult<usize> {
        let mut cleaned = 0;

        if !self.temp_dir.exists() {
            return Ok(cleaned);
        }

        for entry in std::fs::read_dir(&self.temp_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                if let Ok(metadata) = std::fs::metadata(&path) {
                    if let Ok(modified) = metadata.modified() {
                        if modified.elapsed().unwrap_or(Duration::ZERO) > max_age {
                            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                info!("Removing stale worktree '{}'", name);
                                if std::fs::remove_dir_all(&path).is_ok() {
                                    cleaned += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Instant;

    #[test]
    fn test_worktree_manager_creation() {
        let timestamp = Instant::now().elapsed().as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("baco-test-worktree-{}", timestamp));
        let manager = WorktreeManager::new(temp_dir.clone());

        assert!(manager.temp_dir.ends_with(".baco-temp/worktrees"));
    }

    #[test]
    fn test_cleanup_nonexistent_directory() {
        let timestamp = Instant::now().elapsed().as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("baco-test-cleanup-{}", timestamp));
        let manager = WorktreeManager::new(temp_dir.clone());

        let cleaned = manager.cleanup_stale_worktrees(Duration::from_secs(0)).unwrap();
        assert_eq!(cleaned, 0);
    }

    #[test]
    fn test_patch_validation_result_format() {
        let results = vec![
            ("cargo build".to_string(), true),
            ("cargo test".to_string(), false),
        ];

        assert_eq!(results.len(), 2);
        assert!(results[0].1);
        assert!(!results[1].1);
    }
}
