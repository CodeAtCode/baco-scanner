//! Patch-related types

use serde::{Deserialize, Serialize};

/// Candidate patch for auto-patching
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PatchCandidate {
    pub diff: String,
    pub file_path: String,
    pub applied: bool,
    pub validation_result: Option<PatchValidationResult>,
}

impl PatchCandidate {
    pub fn new(diff: &str, file_path: &str) -> Self {
        Self {
            diff: diff.to_string(),
            file_path: file_path.to_string(),
            applied: false,
            validation_result: None,
        }
    }
}

/// Result of patch validation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PatchValidationResult {
    pub compiles: bool,
    pub tests_pass: bool,
    pub warnings: u32,
    pub error_message: Option<String>,
}

impl PatchValidationResult {
    pub fn success() -> Self {
        Self {
            compiles: true,
            tests_pass: true,
            warnings: 0,
            error_message: None,
        }
    }

    pub fn failure(error_message: &str) -> Self {
        Self {
            compiles: false,
            tests_pass: false,
            warnings: 0,
            error_message: Some(error_message.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patch_validation_result() {
        let success = PatchValidationResult::success();
        assert!(success.compiles);
        assert!(success.tests_pass);
        assert!(success.error_message.is_none());

        let failure = PatchValidationResult::failure("Syntax error");
        assert!(!failure.compiles);
        assert!(!failure.tests_pass);
        assert_eq!(failure.error_message, Some("Syntax error".to_string()));
    }
}
