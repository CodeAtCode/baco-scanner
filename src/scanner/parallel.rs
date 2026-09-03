//! Parallel phase execution utilities

use crate::checkpoint::ScanPhase;
use crate::findings::VulnerabilityFinding;
use crate::scanner::helpers::log_and_aggregate_llm_results;

use indicatif::ProgressBar;

/// Type alias for phase result (legacy 2-tuple for parallel phases that don't produce rejected findings)
type PhaseResult = Result<(Vec<VulnerabilityFinding>, Vec<String>), String>;

/// Type alias for full phase result with rejected findings (3-tuple)
type FullPhaseResult = Result<
    (
        Vec<VulnerabilityFinding>,
        Vec<String>,
        Vec<crate::scanner::phases::llm_phases::RejectedFinding>,
    ),
    String,
>;

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

/// Combine results from multiple parallel phases
#[allow(dead_code)]
pub fn combine_parallel_results(
    mut findings: Vec<VulnerabilityFinding>,
    indexing_result: Option<PhaseResult>,
    semgrep_result: Option<PhaseResult>,
    llm_static_result: Option<FullPhaseResult>,
) -> (Vec<VulnerabilityFinding>, Vec<String>) {
    let mut analyzed_files = Vec::new();

    if let Some(Ok((mut index_findings, _))) = indexing_result {
        findings.append(&mut index_findings);
    }

    if let Some(Ok((mut semgrep_findings, _))) = semgrep_result {
        findings.append(&mut semgrep_findings);
    }

    log_and_aggregate_llm_results(&llm_static_result, &mut findings, &mut analyzed_files);

    (findings, analyzed_files)
}
