//! Semantic path extraction using LLM-powered functional summarization.
//!
//! Uses a small LLM call to generate a functional summary of the code.

use std::fmt;

/// Error types for semantic path operations
#[derive(Debug)]
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
pub async fn summarize(
    source: &str,
    llm: &crate::llm::LlmClient,
) -> Result<SemanticPath, ContextError> {
    if source.trim().is_empty() {
        return Err(ContextError::EmptySource);
    }

    let truncated = if source.len() > 2000 {
        &source[..2000]
    } else {
        source
    };

    let messages = vec![
        crate::llm::ChatMessage::system(
            "You are a code analysis assistant. Summarize the following code's functionality in 2-3 sentences. Focus on: what it does, key inputs/outputs, and any security-relevant behavior.",
        ),
        crate::llm::ChatMessage::user(truncated),
    ];

    let response = llm
        .chat(&messages)
        .await
        .map_err(|e| ContextError::LlmError(e.to_string()))?;

    Ok(SemanticPath {
        summary: response.content,
    })
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
