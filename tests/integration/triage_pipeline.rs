//! Integration tests for triage pipeline

use baco::analysis_context::AnalysisContext;
use baco::confidence_refinement::{ConfidenceFactor, ConfidenceRefinementPhase};
use baco::findings::{
    IssueCategory, SecurityIssue, Severity, VerificationStatus, VulnerabilityFinding,
};
use baco::llm::{ChatMessage, ChatResponseWithModel};
use baco::llm_verification::{AsyncLlmClient, TriageFilter, TriageVerdict};

/// Simple mock client for testing
struct SimpleMockClient {
    response: String,
}

impl SimpleMockClient {
    fn new(response: String) -> Self {
        Self { response }
    }
}

#[async_trait::async_trait]
impl AsyncLlmClient for SimpleMockClient {
    async fn chat(&self, _messages: &[ChatMessage]) -> Result<ChatResponseWithModel, String> {
        Ok(ChatResponseWithModel::new(
            self.response.clone(),
            "mock-integration-model".to_string(),
        ))
    }
}

fn create_finding(title: &str, code: Option<&str>) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: format!("integration-{}", title.to_lowercase().replace(' ', "-")),
        title: title.to_string(),
        description: format!("Integration test finding: {}", title),
        severity: Severity::High,
        confidence_score: 0.75,
        cwe_id: Some("CWE-89".to_string()),
        file_path: "src/app.rs".to_string(),
        line_number: Some(100),
        code_snippet: code.map(|s| s.to_string()),
        diff_hunk: None,
        recommendation: None,
        code_location: Some("src/app.rs:100".to_string()),
        already_reported: false,
        sources: vec!["semgrep".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status: None,
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: Some(SecurityIssue {
            category: IssueCategory::Injection,
            cwe_id: Some("CWE-89".to_string()),
            owasp_category: Some("SQL Injection".to_string()),
            mitre_attack: None,
            custom_tags: vec![],
        }),
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
async fn test_triage_fp_down_ranks_confidence() {
    let mock = SimpleMockClient::new(
        r#"{"verdict": "false_positive", "confidence": 0.95, "reasoning": "Input is properly sanitized"}"#.to_string(),
    );
    let filter = TriageFilter::new(None);
    let finding = create_finding("SQL Injection FP", Some("sanitize(input); query(input)"));

    let triage_result = filter.triage_finding(&finding, &mock).await.unwrap();

    assert_eq!(triage_result.verdict, TriageVerdict::FalsePositive);
    assert!((triage_result.confidence - 0.95).abs() < 0.01);

    // Simulate applying triage result to verification notes
    let mut finding_with_triage = finding.clone();
    finding_with_triage.verification_notes = Some(format!(
        "Triage verdict: {} with reasoning: {}",
        triage_result.verdict, triage_result.reasoning
    ));
    finding_with_triage.verification_status = Some(VerificationStatus::FalsePositive);

    // Apply confidence refinement
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();
    let refinements = phase.run(vec![finding_with_triage], &context);

    let refined = refinements.get("integration-sql-injection-fp").unwrap();

    // FP should drop below 0.5 confidence
    assert!(
        refined.refined_score < 0.5,
        "FP finding confidence {} should be below 0.5",
        refined.refined_score
    );

    assert!(
        refined
            .factors
            .contains(&ConfidenceFactor::TriageFalsePositive),
        "Should have TriageFalsePositive factor"
    );
}

#[tokio::test]
async fn test_triage_tp_boosts_confidence() {
    let mock = SimpleMockClient::new(
        r#"{"verdict": "true_positive", "confidence": 0.88, "reasoning": "Clear injection vulnerability detected"}"#.to_string(),
    );
    let filter = TriageFilter::new(None);
    let finding = create_finding("SQL Injection TP", Some("query(user_input)"));

    let triage_result = filter.triage_finding(&finding, &mock).await.unwrap();

    assert_eq!(triage_result.verdict, TriageVerdict::TruePositive);
    assert!((triage_result.confidence - 0.88).abs() < 0.01);

    // Simulate applying triage result to verification notes
    let mut finding_with_triage = finding.clone();
    finding_with_triage.verification_notes = Some(format!(
        "Triage verdict: {} with reasoning: {}",
        triage_result.verdict, triage_result.reasoning
    ));
    finding_with_triage.verification_status = Some(VerificationStatus::Confirmed);

    // Apply confidence refinement
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();
    let refinements = phase.run(vec![finding_with_triage], &context);

    let refined = refinements.get("integration-sql-injection-tp").unwrap();

    // TP should get +0.10 boost
    let expected_boost = 0.75 + 0.10; // base + triage boost
    assert!(
        (refined.refined_score - expected_boost).abs() < 0.01
            || refined.refined_score >= expected_boost,
        "TP finding confidence {} should be at least {}",
        refined.refined_score,
        expected_boost
    );

    assert!(
        refined
            .factors
            .contains(&ConfidenceFactor::TriageTruePositive),
        "Should have TriageTruePositive factor"
    );
}

#[tokio::test]
async fn test_triage_pipeline_end_to_end() {
    // Create multiple findings with different triage outcomes
    let findings = vec![
        create_finding("Vuln1FP", Some("sanitize(x); use(x)")),
        create_finding("Vuln2TP", Some("dangerous_op(input)")),
        create_finding("Vuln3FP", Some("escape(html)")),
    ];

    let mock_client_fp = SimpleMockClient::new(
        r#"{"verdict": "false_positive", "confidence": 0.9, "reasoning": "Sanitization present"}"#
            .to_string(),
    );
    let mock_client_tp = SimpleMockClient::new(
        r#"{"verdict": "true_positive", "confidence": 0.85, "reasoning": "No sanitization"}"#
            .to_string(),
    );

    let filter = TriageFilter::new(None);
    let mut processed_findings = Vec::new();

    // Process each finding through triage
    for (i, mut finding) in findings.into_iter().enumerate() {
        let client = if i % 2 == 0 {
            &mock_client_fp
        } else {
            &mock_client_tp
        };

        if let Ok(triage_result) = filter.triage_finding(&finding, client).await {
            finding.verification_notes = Some(format!(
                "Triage: {} - {}",
                triage_result.verdict, triage_result.reasoning
            ));
            finding.verification_status = Some(match triage_result.verdict {
                TriageVerdict::TruePositive => VerificationStatus::Confirmed,
                TriageVerdict::FalsePositive => VerificationStatus::FalsePositive,
            });
        }
        processed_findings.push(finding);
    }

    // Apply confidence refinement
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();
    let refinements = phase.run(processed_findings, &context);

    // Verify FP findings are down-ranked
    let fp_refinement = refinements.get("integration-vuln1fp").unwrap();
    assert!(
        fp_refinement.refined_score < 0.7,
        "FP finding should be down-ranked, got {}",
        fp_refinement.refined_score
    );

    // Verify TP findings are boosted
    let tp_refinement = refinements.get("integration-vuln2tp").unwrap();
    assert!(
        tp_refinement.refined_score > 0.75,
        "TP finding should be boosted, got {}",
        tp_refinement.refined_score
    );
}
