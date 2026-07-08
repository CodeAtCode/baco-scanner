//! Error types for staging operations

use thiserror::Error;

/// Errors for git worktree staging operations
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

/// Result type for staging operations
pub type StagingResult<T> = std::result::Result<T, StagingError>;

/// Result type for auto-patching operations
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
