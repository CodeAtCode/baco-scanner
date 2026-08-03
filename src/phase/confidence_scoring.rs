use super::{PhaseContext, PhaseError, ScanPhase};
use crate::confidence::ConfidenceCalculator;
use crate::findings::VulnerabilityFinding;
use async_trait::async_trait;

pub struct ConfidenceScoringPhase;

#[async_trait]
impl ScanPhase for ConfidenceScoringPhase {
    fn name(&self) -> &'static str {
        "ConfidenceScoring"
    }

    fn order(&self) -> u8 {
        9
    }

    async fn execute(
        &self,
        ctx: &mut PhaseContext,
    ) -> Result<Vec<VulnerabilityFinding>, PhaseError> {
        tracing::info!("Running Confidence Scoring phase...");

        let mut findings = ctx.scanner.findings();

        if findings.is_empty() {
            tracing::debug!("No findings to calculate confidence scores for");
            return Ok(Vec::new());
        }

        for finding in &mut findings {
            // Calculate composite confidence and set it on the finding
            finding.confidence_score = ConfidenceCalculator::calculate_composite(finding) * 100.0;
            ConfidenceCalculator::recalculate_priority(finding);
        }

        let avg_confidence: f64 = findings
            .iter()
            .map(|f| f.confidence_score as f64)
            .sum::<f64>()
            / findings.len() as f64;

        let avg_priority: f64 = findings
            .iter()
            .filter_map(|f| f.priority_score.map(|p| p as f64))
            .sum::<f64>()
            / findings.len() as f64;

        tracing::info!(
            "Confidence Scoring complete - {} findings processed, avg confidence: {:.2}, avg priority: {:.2}",
            findings.len(),
            avg_confidence,
            avg_priority
        );

        Ok(findings)
    }

    fn is_enabled(&self, _ctx: &PhaseContext) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Severity, VerificationStatus, VulnerabilityFinding};
    use crate::phase::helpers::setup_test_phase_context;

    #[test]
    fn test_confidence_scoring_phase_creation() {
        let phase = ConfidenceScoringPhase;
        assert_eq!(phase.name(), "ConfidenceScoring");
        assert_eq!(phase.order(), 9);
    }

    #[test]
    fn test_is_enabled_always_true() {
        let (_, ctx) = setup_test_phase_context();
        let phase = ConfidenceScoringPhase;
        assert!(phase.is_enabled(&ctx));
    }

    #[tokio::test]
    async fn test_execute_with_empty_findings() {
        let (_temp, mut ctx) = setup_test_phase_context();
        let phase = ConfidenceScoringPhase;
        let result = phase.execute(&mut ctx).await;
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_execute_calculates_confidence_scores() {
        use crate::phase::helpers::create_test_scanner;
        let (scanner, _temp) = create_test_scanner();
        scanner.state.send_modify(|s| {
            s.findings.push(VulnerabilityFinding {
                id: "test-1".to_string(),
                title: "Test vulnerability".to_string(),
                description: "Test description".to_string(),
                severity: Severity::High,
                confidence_score: 0.0,
                cwe_id: Some("CWE-79".to_string()),
                file_path: "test.c".to_string(),
                line_number: Some(10),
                code_snippet: None,
                diff_hunk: None,
                recommendation: None,
                code_location: None,
                already_reported: false,
                sources: vec!["test".to_string()],
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
            });
        });
        let analyzed_files = Vec::new();
        let mut ctx = PhaseContext {
            scanner: Box::leak(Box::new(scanner)),
            analyzed_files: Box::leak(Box::new(analyzed_files)),
        };
        let phase = ConfidenceScoringPhase;
        let result = phase.execute(&mut ctx).await;
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].confidence_score > 0.0);
        assert!(findings[0].priority_score.is_some());
    }

    #[tokio::test]
    async fn test_execute_with_confirmed_finding() {
        use crate::phase::helpers::create_test_scanner;
        let (scanner, _temp) = create_test_scanner();
        scanner.state.send_modify(|s| {
            s.findings.push(VulnerabilityFinding {
                id: "test-1".to_string(),
                title: "Test vulnerability".to_string(),
                description: "Test description".to_string(),
                severity: Severity::Critical,
                confidence_score: 0.0,
                cwe_id: Some("CWE-79".to_string()),
                file_path: "test.c".to_string(),
                line_number: Some(10),
                code_snippet: None,
                diff_hunk: None,
                recommendation: None,
                code_location: None,
                already_reported: false,
                sources: vec!["test1".to_string(), "test2".to_string()],
                commit_reference: Some("abc123".to_string()),
                ticket_reference: Some("SEC-123".to_string()),
                priority_score: None,
                cross_file_references: None,
                verification_status: Some(VerificationStatus::Confirmed),
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
            });
        });
        let analyzed_files = Vec::new();
        let mut ctx = PhaseContext {
            scanner: Box::leak(Box::new(scanner)),
            analyzed_files: Box::leak(Box::new(analyzed_files)),
        };
        let phase = ConfidenceScoringPhase;
        let result = phase.execute(&mut ctx).await;
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].confidence_score >= 100.0);
    }
}
