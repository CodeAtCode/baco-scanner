//! Triple path context combiner for LLM prompts.
//!
//! Combines control path (AST/CFG/DFG), knowledge path (CWE rules),
//! and semantic path (LLM summary) into a unified context block.

use super::control_path::{extract, ContextError as ControlError, ControlPath, Language};
use super::knowledge_path::{retrieve, ContextError as KnowledgeError, KnowledgePath};
use crate::retrieval::CweKnowledgeBase;

/// Error types for triple path operations
#[derive(Debug)]
pub enum ContextError {
    Control(ControlError),
    Knowledge(KnowledgeError),
    NoSemantic,
}

impl std::fmt::Display for ContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContextError::Control(e) => write!(f, "Control path error: {}", e),
            ContextError::Knowledge(e) => write!(f, "Knowledge path error: {}", e),
            ContextError::NoSemantic => write!(f, "Semantic path not available"),
        }
    }
}

impl std::error::Error for ContextError {}

impl From<ControlError> for ContextError {
    fn from(e: ControlError) -> Self {
        ContextError::Control(e)
    }
}

impl From<KnowledgeError> for ContextError {
    fn from(e: KnowledgeError) -> Self {
        ContextError::Knowledge(e)
    }
}

/// Triple path context containing all three context paths
#[derive(Debug, Clone)]
pub struct TriplePathContext {
    pub control: ControlPath,
    pub knowledge: KnowledgePath,
    pub semantic_summary: Option<String>,
}

impl TriplePathContext {
    /// Build triple path context from source code
    ///
    /// This is a synchronous builder that creates control and knowledge paths.
    /// Semantic path requires async LLM call and should be added separately.
    pub fn build(
        source: &str,
        language: Language,
        cwe_kb: &CweKnowledgeBase,
        kb_top_k: usize,
    ) -> Result<Self, ContextError> {
        let control = extract(source, language)?;
        let knowledge = retrieve(source, cwe_kb, kb_top_k)?;

        Ok(TriplePathContext {
            control,
            knowledge,
            semantic_summary: None,
        })
    }

    /// Add semantic summary to the context
    pub fn with_semantic(mut self, summary: String) -> Self {
        self.semantic_summary = Some(summary);
        self
    }

    /// Format as a prompt section for LLM input
    pub fn to_prompt_section(&self) -> String {
        let mut result = String::new();

        result.push_str("%%TRIPLE_PATH_CONTEXT%%\n\n");

        // Control Path section
        result.push_str("### Control Path\n\n");
        result.push_str("AST Structure:\n");
        result.push_str(&self.control.ast_text);
        result.push_str("\nControl Flow Graph:\n");
        result.push_str(&self.control.cfg_text);
        result.push_str("\nData Flow Graph:\n");
        result.push_str(&self.control.dfg_text);
        result.push('\n');

        // Knowledge Path section
        result.push_str("\n### Knowledge Path\n\n");
        if self.knowledge.retrieved_rules.is_empty() {
            result.push_str("(no related CWE rules found)\n");
        } else {
            for (i, rule) in self.knowledge.retrieved_rules.iter().enumerate() {
                result.push_str(&format!(
                    "{}. **{}** (score: {:.2})\n   {}\n\n",
                    i + 1,
                    rule.rule_id,
                    rule.score,
                    rule.snippet
                ));
            }
        }

        // Semantic Path section
        result.push_str("\n### Semantic Path\n\n");
        match &self.semantic_summary {
            Some(summary) => result.push_str(summary),
            None => result.push_str("(semantic summary not available)\n"),
        }
        result.push('\n');

        result
    }
}
