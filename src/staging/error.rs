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

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // StagingError Tests
    // ============================================================================

    #[test]
    fn test_staging_error_worktree_create_display() {
        let err = StagingError::WorktreeCreate("test error".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Failed to create worktree"));
        assert!(display.contains("test error"));
    }

    #[test]
    fn test_staging_error_patch_apply_display() {
        let err = StagingError::PatchApply("patch failed".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Failed to apply patch"));
        assert!(display.contains("patch failed"));
    }

    #[test]
    fn test_staging_error_validation_display() {
        let err = StagingError::Validation("validation failed".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Validation failed"));
        assert!(display.contains("validation failed"));
    }

    #[test]
    fn test_staging_error_cleanup_display() {
        let err = StagingError::Cleanup("cleanup failed".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Cleanup failed"));
        assert!(display.contains("cleanup failed"));
    }

    #[test]
    fn test_staging_error_rollback_display() {
        let err = StagingError::Rollback("rollback failed".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Rollback failed"));
        assert!(display.contains("rollback failed"));
    }

    #[test]
    fn test_staging_error_git_error_display() {
        let err = StagingError::GitError("git error".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Git command failed"));
        assert!(display.contains("git error"));
    }

    // ============================================================================
    // AutoPatchError Tests
    // ============================================================================

    #[test]
    fn test_auto_patch_error_generation_display() {
        let err = AutoPatchError::Generation("generation failed".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Failed to generate patch"));
        assert!(display.contains("generation failed"));
    }

    #[test]
    fn test_auto_patch_error_apply_display() {
        let err = AutoPatchError::Apply("apply failed".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Failed to apply patch"));
        assert!(display.contains("apply failed"));
    }

    #[test]
    fn test_auto_patch_error_validation_display() {
        let err = AutoPatchError::Validation("validation failed".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Validation failed"));
        assert!(display.contains("validation failed"));
    }

    #[test]
    fn test_auto_patch_error_staging_display() {
        let err = AutoPatchError::Staging("staging error".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Staging error"));
        assert!(display.contains("staging error"));
    }

    #[test]
    fn test_auto_patch_error_no_llm_client_display() {
        let err = AutoPatchError::NoLlmClient;
        let display = format!("{}", err);
        assert!(display.contains("No LLM client configured"));
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
        let result = PatchValidationResult::failure("test error");
        assert!(!result.compiles);
        assert!(!result.tests_pass);
        assert_eq!(result.warnings, 0);
        assert_eq!(result.error_message, Some("test error".to_string()));
    }

    #[test]
    fn test_patch_validation_result_clone() {
        let result1 = PatchValidationResult {
            compiles: true,
            tests_pass: false,
            warnings: 5,
            error_message: Some("error".to_string()),
        };
        let result2 = result1.clone();
        assert_eq!(result1, result2);
    }

    // ============================================================================
    // Conversion Tests
    // ============================================================================

    #[test]
    fn test_patch_validation_result_conversion() {
        let result = PatchValidationResult {
            compiles: true,
            tests_pass: false,
            warnings: 3,
            error_message: Some("conversion test".to_string()),
        };

        let converted: crate::scanner_types::patch::PatchValidationResult = result.into();
        assert!(converted.compiles);
        assert!(!converted.tests_pass);
        assert_eq!(converted.warnings, 3);
        assert_eq!(converted.error_message, Some("conversion test".to_string()));
    }
}
