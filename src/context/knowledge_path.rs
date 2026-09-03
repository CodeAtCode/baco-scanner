//! Knowledge path retrieval using BM25 search over CWE rules.
//!
//! Wraps the existing retrieval module to fetch related vulnerability rules
//! based on code content.

use crate::retrieval::CweKnowledgeBase;
use std::fmt;

/// Error types for knowledge path operations
#[derive(Debug, Clone)]
pub enum ContextError {
    RetrievalError(String),
    EmptyQuery,
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContextError::RetrievalError(msg) => write!(f, "Retrieval error: {}", msg),
            ContextError::EmptyQuery => write!(f, "Query cannot be empty"),
        }
    }
}

impl std::error::Error for ContextError {}

/// A retrieved rule with relevance score and code snippet
#[derive(Debug, Clone)]
pub struct RetrievedRule {
    pub rule_id: String,
    pub score: f64,
    pub snippet: String,
}

/// Knowledge path containing retrieved CWE rules
#[derive(Debug, Clone)]
pub struct KnowledgePath {
    pub retrieved_rules: Vec<RetrievedRule>,
}

/// Retrieve related CWE rules based on code content
pub fn retrieve(
    code: &str,
    cwe_kb: &CweKnowledgeBase,
    top_k: usize,
) -> Result<KnowledgePath, ContextError> {
    if code.trim().is_empty() {
        return Err(ContextError::EmptyQuery);
    }

    // Extract keywords from code for search
    let query = extract_keywords(code);

    if query.trim().is_empty() {
        return Err(ContextError::EmptyQuery);
    }

    let results = cwe_kb.search(&query, top_k);

    let retrieved_rules: Vec<RetrievedRule> = results
        .iter()
        .map(|doc| RetrievedRule {
            rule_id: doc.cwe_id.clone(),
            score: 1.0, // BM25 doesn't expose scores directly, use placeholder
            snippet: truncate_text(&doc.description, 200),
        })
        .collect();

    Ok(KnowledgePath { retrieved_rules })
}

/// Extract searchable keywords from code
pub fn extract_keywords(code: &str) -> String {
    // Simple keyword extraction: keep alphanumeric words, filter common terms
    let common_terms = [
        "the", "and", "for", "with", "this", "that", "from", "have", "has", "int", "void", "char",
        "struct", "return", "if", "else", "while", "for", "do", "switch", "case", "break",
        "continue", "goto",
    ];

    code.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| {
            !word.is_empty()
                && word.len() > 2
                && !common_terms.contains(word)
                && !word.chars().all(|c| c.is_numeric())
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Truncate text to max length with ellipsis
pub fn truncate_text(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        text.to_string()
    } else {
        // Use char-based truncation for unicode safety
        let trunc_len = (max_len.saturating_sub(3)).min(text.chars().count());
        format!("{}...", text.chars().take(trunc_len).collect::<String>())
    }
}
