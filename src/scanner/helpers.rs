//! Shared helpers for scanner operations.

use crate::findings::VulnerabilityFinding;

/// Type alias for phase result
pub(crate) type PhaseResult = Result<(Vec<VulnerabilityFinding>, Vec<String>), String>;

/// Log and aggregate LLM static analysis results.
/// This helper consolidates the common pattern for handling LLM phase results.
pub(crate) fn log_and_aggregate_llm_results(
    llm_static_result: &Option<PhaseResult>,
    findings: &mut Vec<VulnerabilityFinding>,
    analyzed_files: &mut Vec<String>,
) {
    if let Some(Ok((llm_findings, new_files))) = llm_static_result {
        tracing::info!("[SCANNER] Added {} LLM findings", llm_findings.len());
        if !llm_findings.is_empty() {
            tracing::debug!(
                "[SCANNER] First finding description length: {}",
                llm_findings[0].description.len()
            );
        }
        findings.extend(llm_findings.clone());
        *analyzed_files = new_files.to_vec();
    } else if let Some(Err(e)) = llm_static_result {
        tracing::warn!("[SCANNER] LLM static analysis failed: {}", e);
    }
}
