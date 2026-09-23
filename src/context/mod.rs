//! Hierarchical context extraction for LLM analysis.
//!
//! Extracts function/module/project-level summaries to provide
//! structured context to LLM prompts.

// Triple path context modules (T2.2 - VulTriage)
pub mod control_path;
pub mod knowledge_path;

pub mod semantic_path;
pub mod triple_path;

// PacVD primitive-API abstraction (P4.2-P4.5)
pub mod callee_walker;
pub mod pacvd_extractor;

pub use callee_walker::{CallSite, extract_call_sites};
pub use control_path::{
    ContextError as ControlPathError, ControlPath, Language, extract as extract_control_path,
};
pub use knowledge_path::{
    KnowledgePath, RetrievedRule, retrieve as retrieve_knowledge, truncate_text,
};
pub use pacvd_extractor::{
    AbstractionLevel, AbstractionVector, auto_level, categorize, extract as extract_pacvd, tag_cwe,
};
pub use semantic_path::{SemanticPath, summarize as summarize_semantic};
pub use triple_path::TriplePathContext;
