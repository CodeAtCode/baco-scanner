//! Shared helpers for scanner operations.

use crate::findings::VulnerabilityFinding;

/// Type alias for phase result
pub type PhaseResult = Result<
    (
        Vec<VulnerabilityFinding>,
        Vec<String>,
        Vec<crate::scanner::phases::llm_phases::RejectedFinding>,
    ),
    String,
>;

/// Log and aggregate LLM static analysis results.
///
/// Returns the failure reason when the phase died so the caller can record it
/// against the phase. Logging alone is not enough: the scan health is built from
/// the phase plan, so an error that is only logged leaves a dead phase reading
/// as a clean one.
pub fn log_and_aggregate_llm_results(
    llm_static_result: &Option<PhaseResult>,
    findings: &mut Vec<VulnerabilityFinding>,
    analyzed_files: &mut Vec<String>,
) -> Option<String> {
    match llm_static_result {
        Some(Ok((llm_findings, new_files, _))) => {
            tracing::info!("[SCANNER] Added {} LLM findings", llm_findings.len());
            if !llm_findings.is_empty() {
                tracing::debug!(
                    "[SCANNER] First finding description length: {}",
                    llm_findings[0].description.len()
                );
            }
            findings.extend(llm_findings.clone());
            *analyzed_files = new_files.to_vec();
            None
        }
        Some(Err(e)) => {
            tracing::warn!("[SCANNER] LLM static analysis failed: {}", e);
            Some(e.to_string())
        }
        None => None,
    }
}
