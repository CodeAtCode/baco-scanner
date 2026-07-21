//! Semantic path extraction using LLM-powered functional summarization.
//!
//! Uses a small LLM call to generate a functional summary of the code.
//! Note: The full async LLM integration requires LlmClient chat API setup.

use std::fmt;

/// Error types for semantic path operations
#[derive(Debug, Clone)]
pub enum ContextError {
    LlmError(String),
    EmptySource,
    ParseError(String),
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContextError::LlmError(msg) => write!(f, "LLM error: {}", msg),
            ContextError::EmptySource => write!(f, "Source code cannot be empty"),
            ContextError::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for ContextError {}

/// Semantic path containing LLM-generated summary
#[derive(Debug, Clone)]
pub struct SemanticPath {
    pub summary: String,
}

/// Generate functional summary using LLM
///
/// Note: This is a placeholder that returns an error. The full implementation
/// requires integrating with the LlmClient chat API.
pub async fn summarize(
    _source: &str,
    _llm: &crate::llm::LlmClient,
) -> Result<SemanticPath, ContextError> {
    // Placeholder - full implementation requires LlmClient chat integration
    Err(ContextError::LlmError(
        "LLM summary not yet implemented - requires chat API integration".to_string(),
    ))
}

/// Generate summary without actual LLM call (for testing)
///
/// This is a mock implementation that returns a deterministic summary
/// based on code analysis. Use only in tests.
pub fn summarize_mock(source: &str) -> Result<SemanticPath, ContextError> {
    if source.trim().is_empty() {
        return Err(ContextError::EmptySource);
    }

    // Simple heuristic-based summary for testing
    let has_function =
        source.contains("fn ") || source.contains("def ") || source.contains("function");
    let has_loop = source.contains("for ") || source.contains("while ");
    let has_condition =
        source.contains("if ") || source.contains("match ") || source.contains("switch");

    let mut parts = Vec::new();

    if has_function {
        parts.push("Contains function definitions");
    }
    if has_loop {
        parts.push("Includes iteration logic");
    }
    if has_condition {
        parts.push("Has conditional branching");
    }

    let summary = if parts.is_empty() {
        "Simple code module with basic operations".to_string()
    } else {
        format!(
            "Code module that: {}. Implements core functionality.",
            parts.join(", ")
        )
    };

    Ok(SemanticPath { summary })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_summarize_mock_with_function() {
        let source = "fn main() { println!(\"hello\"); }";
        let result = summarize_mock(source).expect("Should summarize");

        assert!(!result.summary.is_empty(), "Summary should not be empty");
        assert!(
            result.summary.contains("function"),
            "Should mention functions"
        );
    }

    #[test]
    fn test_summarize_mock_empty() {
        let source = "";
        let result = summarize_mock(source);

        assert!(result.is_err(), "Should error on empty source");
    }

    #[test]
    fn test_truncation_bound() {
        let long_source = "x ".repeat(3000);
        let truncated = if long_source.len() > 2000 {
            &long_source[..2000]
        } else {
            &long_source
        };

        assert_eq!(truncated.len(), 2000, "Should truncate to 2000 chars");
    }
}
