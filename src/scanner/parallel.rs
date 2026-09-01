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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;
    use crate::phase::helpers::create_test_finding_simple;

    #[tokio::test]
    async fn test_combine_parallel_results_with_all_success() {
        let findings = vec![create_test_finding_simple("Initial", Severity::Low)];

        let indexing_result = Ok((
            vec![create_test_finding_simple("Indexing", Severity::Medium)],
            vec!["file1.rs".to_string()],
        ));

        let semgrep_result = Ok((
            vec![create_test_finding_simple("Semgrep", Severity::High)],
            vec!["file2.rs".to_string()],
        ));

        let llm_static_result = Ok((
            vec![create_test_finding_simple("LLM", Severity::Critical)],
            vec!["file3.rs".to_string()],
            Vec::new(),
        ));

        let (combined_findings, analyzed_files) = combine_parallel_results(
            findings,
            Some(indexing_result),
            Some(semgrep_result),
            Some(llm_static_result),
        );

        // Should have initial + indexing + semgrep + llm findings
        assert_eq!(combined_findings.len(), 4);

        // LLM results provide analyzed files
        assert_eq!(analyzed_files.len(), 1);
        assert_eq!(analyzed_files[0], "file3.rs");
    }

    #[tokio::test]
    async fn test_combine_parallel_results_with_none_results() {
        let findings = vec![create_test_finding_simple("Initial", Severity::Low)];

        let (combined_findings, analyzed_files) =
            combine_parallel_results(findings.clone(), None, None, None);

        // Should only have initial findings
        assert_eq!(combined_findings.len(), 1);
        assert_eq!(combined_findings[0].title, "Initial");

        // No analyzed files when all results are None
        assert!(analyzed_files.is_empty());
    }

    #[tokio::test]
    async fn test_combine_parallel_results_with_error_results() {
        let findings = vec![create_test_finding_simple("Initial", Severity::Low)];

        let indexing_result = Err("Indexing failed".to_string());
        let semgrep_result = Err("Semgrep failed".to_string());
        let llm_static_result = Err("LLM failed".to_string());

        let (combined_findings, analyzed_files) = combine_parallel_results(
            findings,
            Some(indexing_result),
            Some(semgrep_result),
            Some(llm_static_result),
        );

        // Errors are silently ignored, only initial findings remain
        assert_eq!(combined_findings.len(), 1);

        // No analyzed files from error results
        assert!(analyzed_files.is_empty());
    }

    #[tokio::test]
    async fn test_combine_parallel_results_partial_success() {
        let findings = vec![create_test_finding_simple("Initial", Severity::Low)];

        let indexing_result = Ok((
            vec![create_test_finding_simple("Indexing", Severity::Medium)],
            vec!["file1.rs".to_string()],
        ));

        let semgrep_result = Err("Semgrep failed".to_string());
        let llm_static_result = Ok((
            vec![create_test_finding_simple("LLM", Severity::Critical)],
            vec!["file3.rs".to_string()],
            Vec::new(),
        ));

        let (combined_findings, analyzed_files) = combine_parallel_results(
            findings,
            Some(indexing_result),
            Some(semgrep_result),
            Some(llm_static_result),
        );

        // Should have initial + indexing + llm (semgrep error ignored)
        assert_eq!(combined_findings.len(), 3);

        // LLM provides analyzed files
        assert_eq!(analyzed_files.len(), 1);
        assert_eq!(analyzed_files[0], "file3.rs");
    }

    #[tokio::test]
    async fn test_parallel_phase_config_creation() {
        let pb = ProgressBar::hidden();
        let completed_phases: [ScanPhase; 2] = [ScanPhase::Indexing, ScanPhase::Semgrep];

        let config = ParallelPhaseConfig {
            indexing_enabled: true,
            semgrep_enabled: true,
            llm_static_enabled: false,
            completed_phases: &completed_phases,
            progress_bar: &pb,
        };

        assert!(config.indexing_enabled);
        assert!(config.semgrep_enabled);
        assert!(!config.llm_static_enabled);
        assert_eq!(config.completed_phases.len(), 2);
    }

    #[tokio::test]
    async fn test_parallel_phase_result_creation() {
        let findings = vec![create_test_finding_simple("Test", Severity::High)];
        let duration = std::time::Duration::from_secs(42);

        let result = ParallelPhaseResult {
            indexing_findings: findings.clone(),
            semgrep_findings: findings.clone(),
            llm_static_findings: findings,
            analyzed_files: vec!["test.rs".to_string()],
            duration,
        };

        assert_eq!(result.indexing_findings.len(), 1);
        assert_eq!(result.semgrep_findings.len(), 1);
        assert_eq!(result.llm_static_findings.len(), 1);
        assert_eq!(result.analyzed_files.len(), 1);
        assert_eq!(result.duration.as_secs(), 42);
    }
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
