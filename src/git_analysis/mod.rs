//! Git history analysis for vulnerability detection and security pattern tracking.
//!
//! This module provides `GitHistoryAnalyzer` which analyzes git history to:
//! - Detect vulnerability patterns in commit messages and code changes
//! - Track security fixes and their evolution over time
//! - Identify risky commit patterns (e.g., large changes, hotfixes)
//! - Generate git-based confidence scores for findings
//! - Integrate with AnalysisContext for state persistence

mod analyzer;
mod helpers;
mod models;
mod patterns;

#[cfg(test)]
mod tests;

// Re-export public API
pub use analyzer::{GitAnalyzer, GitHistoryAnalyzer};
pub use models::{
    CommitReference, GitAnalysisResult, GitConfidenceModifier, RiskyCommitPattern,
    RiskyPatternType, VulnerabilityPattern, VulnerabilityPatternType,
};
