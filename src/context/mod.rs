//! Hierarchical context extraction for LLM analysis.
//!
//! Extracts function/module/project-level summaries to provide
//! structured context to LLM prompts.

mod summary;

// Triple path context modules (T2.2 - VulTriage)
pub mod control_path;
pub mod knowledge_path;
pub mod semantic_path;
pub mod triple_path;

pub use control_path::{
    extract as extract_control_path, ContextError as ControlPathError, ControlPath, Language,
};
pub use knowledge_path::{retrieve as retrieve_knowledge, KnowledgePath, RetrievedRule};
pub use semantic_path::{summarize as summarize_semantic, SemanticPath};
pub use summary::{ContextExtractor, ContextSummary, FunctionSummary};
pub use triple_path::TriplePathContext;
