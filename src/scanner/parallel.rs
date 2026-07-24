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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;

    fn create_test_finding(title: &str, severity: Severity) -> VulnerabilityFinding {
        VulnerabilityFinding {
            id: format!("test-{}", title.to_lowercase().replace(' ', "-")),
            title: title.to_string(),
            severity,
            confidence_score: 0.8,
            file_path: "src/test.rs".to_string(),
            line_number: Some(42),
            code_snippet: Some("let x = 5;".to_string()),
            description: format!("Test vulnerability: {}", title),
            cwe_id: Some("CWE-79".to_string()),
            verification_status: None,
            sources: vec!["test".to_string()],
            cross_file_references: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
            statement_range: None,
            triage_verdict: None,
        }
    }

    #[tokio::test]
    async fn test_combine_parallel_results_with_all_success() {
        let findings = vec![create_test_finding("Initial", Severity::Low)];

        let indexing_result = Ok((
            vec![create_test_finding("Indexing", Severity::Medium)],
            vec!["file1.rs".to_string()],
        ));

        let semgrep_result = Ok((
            vec![create_test_finding("Semgrep", Severity::High)],
            vec!["file2.rs".to_string()],
        ));

        let llm_static_result = Ok((
            vec![create_test_finding("LLM", Severity::Critical)],
            vec!["file3.rs".to_string()],
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
        let findings = vec![create_test_finding("Initial", Severity::Low)];

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
        let findings = vec![create_test_finding("Initial", Severity::Low)];

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
        let findings = vec![create_test_finding("Initial", Severity::Low)];

        let indexing_result = Ok((
            vec![create_test_finding("Indexing", Severity::Medium)],
            vec!["file1.rs".to_string()],
        ));

        let semgrep_result = Err("Semgrep failed".to_string());
        let llm_static_result = Ok((
            vec![create_test_finding("LLM", Severity::Critical)],
            vec!["file3.rs".to_string()],
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
    async fn test_has_valid_checkpoint_findings_empty() {
        // Test with a non-existent path - should return false
        let temp_path = std::path::PathBuf::from("/tmp/nonexistent_checkpoint");

        let result = has_valid_checkpoint_findings(&temp_path, &ScanPhase::Indexing).await;
        assert!(!result);
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
        let findings = vec![create_test_finding("Test", Severity::High)];
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
    } else if let Some(Err(e)) = &llm_static_result {
        tracing::warn!("[SCANNER] LLM static analysis failed: {}", e);
    }

    (findings, analyzed_files)
}
