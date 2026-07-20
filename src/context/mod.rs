//! Hierarchical context extraction for LLM analysis.
//!
//! Extracts function/module/project-level summaries to provide
//! structured context to LLM prompts.

mod summary;

pub use summary::{ContextExtractor, ContextSummary, FunctionSummary};
