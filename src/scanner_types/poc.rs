//! PoC (Proof of Concept) related types

use serde::{Deserialize, Serialize};

/// Verifier verdict in multi-verifier voting
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub enum VerifierVerdict {
    Confirmed,
    Rejected,
    #[default]
    Inconclusive,
}

/// PoC compilation result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PoCCompileResult {
    pub language: String,
    pub compiles: bool,
    pub errors: Vec<String>,
}

impl PoCCompileResult {
    pub fn success(language: &str) -> Self {
        Self {
            language: language.to_string(),
            compiles: true,
            errors: Vec::new(),
        }
    }

    pub fn failure(language: &str, errors: Vec<String>) -> Self {
        Self {
            language: language.to_string(),
            compiles: false,
            errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poc_compile_result() {
        let success = PoCCompileResult::success("rust");
        assert!(success.compiles);
        assert!(success.errors.is_empty());

        let failure =
            PoCCompileResult::failure("python", vec!["SyntaxError: invalid syntax".to_string()]);
        assert!(!failure.compiles);
        assert_eq!(failure.errors.len(), 1);
    }
}
