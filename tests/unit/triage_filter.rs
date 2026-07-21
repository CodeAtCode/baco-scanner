//! Unit tests for TriageFilter

use baco::findings::{IssueCategory, SecurityIssue, Severity, VulnerabilityFinding};
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
            "mock-model".to_string(),
        ))
    }
}

fn create_test_finding(title: &str, code: Option<&str>) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: format!("test-{}", title.to_lowercase().replace(' ', "-")),
        title: title.to_string(),
        description: format!("Test finding: {}", title),
        severity: Severity::Medium,
        confidence_score: 0.7,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "src/vuln.rs".to_string(),
        line_number: Some(42),
        code_snippet: code.map(|s| s.to_string()),
        diff_hunk: None,
        recommendation: None,
        code_location: Some("src/vuln.rs:42".to_string()),
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
            cwe_id: Some("CWE-79".to_string()),
            owasp_category: None,
            mitre_attack: None,
            custom_tags: vec![],
        }),
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
        statement_range: None,
    }
}

#[tokio::test]
async fn test_triage_true_positive() {
    let mock = SimpleMockClient::new(
        r#"{"verdict": "true_positive", "confidence": 0.85, "reasoning": "Code shows clear vulnerability pattern"}"#.to_string(),
    );
    let filter = TriageFilter::new(None);
    let finding = create_test_finding("SQL Injection", Some("query(user_input)"));

    let result = filter.triage_finding(&finding, &mock).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.verdict, TriageVerdict::TruePositive);
    assert!((result.confidence - 0.85).abs() < 0.01);
    assert!(result.reasoning.contains("vulnerability"));
}

#[tokio::test]
async fn test_triage_false_positive() {
    let mock = SimpleMockClient::new(
        r#"{"verdict": "false_positive", "confidence": 0.92, "reasoning": "Input is sanitized before use"}"#.to_string(),
    );
    let filter = TriageFilter::new(None);
    let finding = create_test_finding("XSS", Some("escape_html(user_input)"));

    let result = filter.triage_finding(&finding, &mock).await.unwrap();

    assert_eq!(result.verdict, TriageVerdict::FalsePositive);
    assert!((result.confidence - 0.92).abs() < 0.01);
    assert!(result.reasoning.contains("sanitized"));
}

#[tokio::test]
async fn test_triage_malformed_json_fallback() {
    let mock = SimpleMockClient::new(r#"This is not valid JSON at all"#.to_string());
    let filter = TriageFilter::new(None);
    let finding = create_test_finding("Test Issue", Some("some_code"));

    let result = filter.triage_finding(&finding, &mock).await;

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("JSON parse error"));
}

#[tokio::test]
async fn test_triage_confidence_clamped() {
    // Test confidence > 1.0 gets clamped
    let mock = SimpleMockClient::new(
        r#"{"verdict": "true_positive", "confidence": 1.5, "reasoning": "test"}"#.to_string(),
    );
    let filter = TriageFilter::new(None);
    let finding = create_test_finding("Test", Some("code"));

    let result = filter.triage_finding(&finding, &mock).await.unwrap();
    assert!((result.confidence - 1.0).abs() < 0.01);

    // Test confidence < 0.0 gets clamped
    let mock2 = SimpleMockClient::new(
        r#"{"verdict": "false_positive", "confidence": -0.3, "reasoning": "test"}"#.to_string(),
    );
    let filter2 = TriageFilter::new(None);
    let result2 = filter2.triage_finding(&finding, &mock2).await.unwrap();
    assert!((result2.confidence - 0.0).abs() < 0.01);
}

#[tokio::test]
async fn test_triage_invalid_verdict() {
    let mock = SimpleMockClient::new(
        r#"{"verdict": "unknown", "confidence": 0.5, "reasoning": "test"}"#.to_string(),
    );
    let filter = TriageFilter::new(None);
    let finding = create_test_finding("Test", Some("code"));

    let result = filter.triage_finding(&finding, &mock).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Invalid verdict"));
}

#[tokio::test]
async fn test_triage_with_code_snippet() {
    let mock = SimpleMockClient::new(
        r#"{"verdict": "false_positive", "confidence": 0.8, "reasoning": "Parameterized query prevents SQL injection"}"#.to_string(),
    );
    let filter = TriageFilter::new(None);
    let finding = create_test_finding("SQL Injection", Some("SELECT * FROM users WHERE id = ?"));

    let result = filter.triage_finding(&finding, &mock).await.unwrap();

    assert_eq!(result.verdict, TriageVerdict::FalsePositive);
    assert!(result.reasoning.to_lowercase().contains("parameterized"));
}
