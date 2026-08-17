//! Hierarchical context extraction for LLM analysis.
//!
//! Extracts function/module/project-level summaries to provide
//! structured context to LLM prompts.

pub mod summary;

// Triple path context modules (T2.2 - VulTriage)
pub mod control_path;
pub mod knowledge_path;
pub mod primitive_api;
pub mod semantic_path;
pub mod triple_path;

// PacVD primitive-API abstraction (P4.2-P4.5)
pub mod callee_walker;
pub mod pacvd_extractor;

pub use callee_walker::{extract_call_sites, CallSite};
pub use control_path::{
    extract as extract_control_path, ContextError as ControlPathError, ControlPath, Language,
};
pub use knowledge_path::{
    retrieve as retrieve_knowledge, truncate_text, KnowledgePath, RetrievedRule,
};
pub use pacvd_extractor::{
    auto_level, categorize, extract as extract_pacvd, tag_cwe, AbstractionLevel, AbstractionVector,
};
pub use primitive_api::{lookup as lookup_primitive_api, PrimitiveApiEntry, PrimitiveApiVulnType};
pub use semantic_path::{summarize as summarize_semantic, SemanticPath};
pub use summary::{ContextExtractor, ContextSummary, FunctionSummary};
pub use triple_path::TriplePathContext;
