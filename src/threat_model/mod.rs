//! Threat Modeling Phase
//!
//! Implements STRIDE-based threat modeling that:
//! - Consumes architecture summary from static analysis (generated on clean scan)
//! - Identifies trust boundaries, data flows, attack surfaces
//! - Generates comprehensive threat models
//! - Persists to AnalysisContext

pub mod fs;
pub mod generation;
pub mod model;

pub use generation::{
    generate_threat_model_static, generate_threat_model_with_llm, load_or_generate_architecture,
    save_to_context,
};
pub use model::{ThreatModelFile, ThreatModelFrontmatter};

use crate::analysis_context::AnalysisContext;
use crate::llm::LlmClient;
use std::path::Path;

/// Threat modeling phase that analyzes codebase architecture and generates STRIDE threat models.
#[derive(Debug)]
pub struct ThreatModelingPhase;

impl ThreatModelingPhase {
    /// Run threat modeling phase on the target codebase.
    ///
    /// Uses architecture summary from static analysis to:
    /// - Identify trust boundaries (external APIs, DB connections, file system access)
    /// - Map data flows (request/response cycles, persistence points)
    /// - Locate attack surfaces (entry points, deserialization, privilege escalation)
    /// - Generate STRIDE threats (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
    ///
    /// # Arguments
    /// * `target_path` - Path to the codebase
    /// * `context` - AnalysisContext containing architecture summary
    /// * `llm_client` - Optional LLM client for deep analysis (fallback to static if unavailable)
    ///
    /// # Returns
    /// `Ok(analysis_output)` with generated threat model string, or `Err` if analysis fails
    pub async fn run(
        target_path: &Path,
        context: &AnalysisContext,
        llm_client: Option<&LlmClient>,
    ) -> Result<String, String> {
        // Load or generate architecture summary via static analysis
        let architecture = load_or_generate_architecture(target_path, context);

        let prompt = if let Some(client) = llm_client {
            generate_threat_model_with_llm(target_path, &architecture, client).await?
        } else {
            generate_threat_model_static(&architecture)
        };

        // Persist threat model to context
        save_to_context(target_path, &prompt);

        tracing::info!("Threat modeling complete");
        Ok(prompt)
    }
}
