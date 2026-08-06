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
#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_finding(title: &str) -> VulnerabilityFinding {
        VulnerabilityFinding {
            id: format!("test-{}", title),
            title: title.to_string(),
            description: format!("Test finding: {}", title),
            severity: crate::findings::Severity::Medium,
            confidence_score: 0.8,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: Some(1),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
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

    #[test]
    fn test_log_and_aggregate_some_ok() {
        let llm_result = Some(Ok((
            vec![create_test_finding("finding1")],
            vec!["file1.rs".to_string()],
        )));

        let mut findings = vec![create_test_finding("existing")];
        let mut analyzed_files = vec!["old.rs".to_string()];

        log_and_aggregate_llm_results(&llm_result, &mut findings, &mut analyzed_files);

        assert_eq!(findings.len(), 2);
        assert_eq!(analyzed_files, vec!["file1.rs".to_string()]);
    }

    #[test]
    fn test_log_and_aggregate_some_ok_empty_findings() {
        let llm_result = Some(Ok((vec![], vec!["file1.rs".to_string()])));

        let mut findings = vec![create_test_finding("existing")];
        let mut analyzed_files = vec!["old.rs".to_string()];

        log_and_aggregate_llm_results(&llm_result, &mut findings, &mut analyzed_files);

        assert_eq!(findings.len(), 1);
        assert_eq!(analyzed_files, vec!["file1.rs".to_string()]);
    }

    #[test]
    fn test_log_and_aggregate_some_err() {
        let llm_result = Some(Err("test error".to_string()));

        let mut findings = vec![create_test_finding("existing")];
        let mut analyzed_files = vec!["old.rs".to_string()];

        log_and_aggregate_llm_results(&llm_result, &mut findings, &mut analyzed_files);

        assert_eq!(findings.len(), 1);
        assert_eq!(analyzed_files, vec!["old.rs".to_string()]);
    }

    #[test]
    fn test_log_and_aggregate_none() {
        let llm_result: Option<PhaseResult> = None;

        let mut findings = vec![create_test_finding("existing")];
        let mut analyzed_files = vec!["old.rs".to_string()];

        log_and_aggregate_llm_results(&llm_result, &mut findings, &mut analyzed_files);

        assert_eq!(findings.len(), 1);
        assert_eq!(analyzed_files, vec!["old.rs".to_string()]);
    }

    #[test]
    fn test_log_and_aggregate_multiple_findings() {
        let llm_result = Some(Ok((
            vec![
                create_test_finding("finding1"),
                create_test_finding("finding2"),
                create_test_finding("finding3"),
            ],
            vec!["file1.rs".to_string()],
        )));

        let mut findings = vec![create_test_finding("existing")];
        let mut analyzed_files = vec!["old.rs".to_string()];

        log_and_aggregate_llm_results(&llm_result, &mut findings, &mut analyzed_files);

        assert_eq!(findings.len(), 4);
        assert_eq!(analyzed_files, vec!["file1.rs".to_string()]);
    }
}
