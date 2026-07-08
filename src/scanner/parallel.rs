//! Parallel phase execution utilities

use crate::checkpoint::ScanPhase;
use crate::findings::VulnerabilityFinding;

use indicatif::ProgressBar;

/// Type alias for phase result
type PhaseResult = Result<(Vec<VulnerabilityFinding>, Vec<String>), String>;

/// Configuration for parallel phase execution
#[allow(dead_code)]
pub struct ParallelPhaseConfig<'a> {
    pub indexing_enabled: bool,
    pub semgrep_enabled: bool,
    pub llm_static_enabled: bool,
    pub completed_phases: &'a [ScanPhase],
    pub progress_bar: &'a ProgressBar,
}

/// Result from parallel phase execution
#[allow(dead_code)]
pub struct ParallelPhaseResult {
    pub indexing_findings: Vec<VulnerabilityFinding>,
    pub semgrep_findings: Vec<VulnerabilityFinding>,
    pub llm_static_findings: Vec<VulnerabilityFinding>,
    pub analyzed_files: Vec<String>,
    pub duration: std::time::Duration,
}

/// Execute indexing phase in parallel
#[allow(dead_code)]
pub async fn run_indexing_phase(
    scanner: &super::Scanner,
    pb: &ProgressBar,
    initial_findings: Vec<VulnerabilityFinding>,
) -> Result<(Vec<VulnerabilityFinding>, Vec<String>), String> {
    tracing::info!("Running Indexing phase");

    let result = scanner
        .run_phase(&ScanPhase::Indexing, initial_findings, pb, &[])
        .await;

    result
}

/// Execute Semgrep phase in parallel
#[allow(dead_code)]
pub async fn run_semgrep_phase(
    scanner: &super::Scanner,
    pb: &ProgressBar,
    initial_findings: Vec<VulnerabilityFinding>,
) -> Result<(Vec<VulnerabilityFinding>, Vec<String>), String> {
    tracing::info!("Running Semgrep phase");

    let result = scanner
        .run_phase(&ScanPhase::Semgrep, initial_findings, pb, &[])
        .await;

    result
}

/// Execute LLM static analysis phase in parallel
#[allow(dead_code)]
pub async fn run_llm_static_phase(
    scanner: &super::Scanner,
    pb: &ProgressBar,
    initial_findings: Vec<VulnerabilityFinding>,
    analyzed_files: &[String],
) -> Result<(Vec<VulnerabilityFinding>, Vec<String>), String> {
    tracing::info!("Running LLM Static Analysis phase");

    let result = scanner
        .run_phase(
            &ScanPhase::LlmStaticAnalysis,
            initial_findings,
            pb,
            analyzed_files,
        )
        .await;

    result
}

/// Check if a phase has valid findings in checkpoint
#[allow(dead_code)]
pub async fn has_valid_checkpoint_findings(
    checkpoint_path: &std::path::Path,
    phase: &ScanPhase,
) -> bool {
    use crate::scanner::checkpoint::load_checkpoint_findings;

    let checkpoint_findings = load_checkpoint_findings(checkpoint_path, phase).await;

    !checkpoint_findings.is_empty()
        && checkpoint_findings
            .iter()
            .any(|f| !f.description.is_empty())
}

/// Combine results from multiple parallel phases
#[allow(dead_code)]
pub fn combine_parallel_results(
    mut findings: Vec<VulnerabilityFinding>,
    indexing_result: Option<PhaseResult>,
    semgrep_result: Option<PhaseResult>,
    llm_static_result: Option<PhaseResult>,
) -> (Vec<VulnerabilityFinding>, Vec<String>) {
    let mut analyzed_files = Vec::new();

    if let Some(Ok((mut index_findings, _))) = indexing_result {
        findings.append(&mut index_findings);
    }

    if let Some(Ok((mut semgrep_findings, _))) = semgrep_result {
        findings.append(&mut semgrep_findings);
    }

    if let Some(Ok((mut llm_findings, new_files))) = llm_static_result {
        tracing::info!("[SCANNER] Added {} LLM findings", llm_findings.len());
        if !llm_findings.is_empty() {
            tracing::debug!(
                "[SCANNER] First finding description length: {}",
                llm_findings[0].description.len()
            );
        }
        findings.append(&mut llm_findings);
        analyzed_files = new_files;
    } else {
        tracing::warn!("[SCANNER] LLM static analysis result was None or Err");
    }

    (findings, analyzed_files)
}
