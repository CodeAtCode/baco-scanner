//! Tests for batch verification with index field handling
//!
//! Verifies:
//! 1. Well-formed responses WITH index field → correct mapping
//! 2. Responses WITHOUT index field → positional fallback with warning
//! 3. Malformed responses → salvage path without mass-degradation

use baco::error::ScanError;
use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::llm::{ChatMessage, ChatResponseWithModel, LlmChatClient};
use baco::scanner::phases::llm_phases::verification::{
    parse_batch_verification_verdict, verify_findings_batched,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Mock LLM client for testing
struct MockLlmClient {
    responses: Vec<String>,
    call_count: Arc<Mutex<usize>>,
}

impl MockLlmClient {
    fn new(responses: Vec<String>) -> Self {
        Self {
            responses,
            call_count: Arc::new(Mutex::new(0)),
        }
    }
}

impl LlmChatClient for MockLlmClient {
    async fn chat(&self, _messages: &[ChatMessage]) -> Result<ChatResponseWithModel, ScanError> {
        let mut count = self.call_count.lock().unwrap();
        let idx = *count;
        *count += 1;

        let response = self.responses.get(idx).ok_or(ScanError::Parse {
            message: "No more responses available".to_string(),
            source: None,
        })?;

        Ok(ChatResponseWithModel {
            content: response.clone(),
            model_used: "mock".to_string(),
        })
    }
}

fn create_test_finding(id: &str, line: u32) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: "Test finding".to_string(),
        description: "Test finding".to_string(),
        severity: Severity::Medium,
        confidence_score: 0.5,
        cwe_id: None,
        file_path: "test.rs".to_string(),
        line_number: Some(line),
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
        evidence: vec![],
        verification_tier: None,
    }
}

#[tokio::test]
async fn test_batch_verdict_with_index_field() {
    // Well-formed response WITH index field
    let json_response = r#"[
        {"index": 0, "verification_status": "confirmed", "verification_notes": "Real vulnerability"},
        {"index": 1, "verification_status": "false_positive", "verification_notes": "Safe context"},
        {"index": 2, "verification_status": "needs_review", "verification_notes": "Unclear evidence"}
    ]"#;

    let results = parse_batch_verification_verdict(json_response, 3);

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].0, VerificationStatus::Confirmed);
    assert_eq!(results[0].1, "Real vulnerability");
    assert_eq!(results[1].0, VerificationStatus::FalsePositive);
    assert_eq!(results[1].1, "Safe context");
    assert_eq!(results[2].0, VerificationStatus::NeedsReview);
    assert_eq!(results[2].1, "Unclear evidence");
}

#[tokio::test]
async fn test_batch_verdict_without_index_field_positional_fallback() {
    // Response WITHOUT index field - should use positional fallback
    let json_response = r#"[
        {"verification_status": "confirmed", "verification_notes": "First item"},
        {"verification_status": "false_positive", "verification_notes": "Second item"},
        {"verification_status": "confirmed", "verification_notes": "Third item"}
    ]"#;

    let results = parse_batch_verification_verdict(json_response, 3);

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].0, VerificationStatus::Confirmed);
    assert_eq!(results[0].1, "First item");
    assert_eq!(results[1].0, VerificationStatus::FalsePositive);
    assert_eq!(results[1].1, "Second item");
    assert_eq!(results[2].0, VerificationStatus::Confirmed);
    assert_eq!(results[2].1, "Third item");
}

#[tokio::test]
async fn test_batch_verdict_malformed_object_salvage() {
    // Malformed response - invalid JSON
    let malformed = r#"[{"verification_status": "confirmed", "invalid json"#;

    let results = parse_batch_verification_verdict(malformed, 3);

    // Entire batch fails - all become NeedsReview with raw content
    assert_eq!(results.len(), 3);
    assert!(results
        .iter()
        .all(|(status, _)| *status == VerificationStatus::NeedsReview));
    assert!(results[0].1.contains("invalid json"));
}

#[tokio::test]
async fn test_batch_verdict_invalid_status_defaults_to_needs_review() {
    // Invalid verification_status should default to NeedsReview
    let json_response = r#"[
        {"index": 0, "verification_status": "invalid_status", "verification_notes": "Bad status"}
    ]"#;

    let results = parse_batch_verification_verdict(json_response, 1);

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, VerificationStatus::NeedsReview);
    assert_eq!(results[0].1, "Bad status");
}

#[tokio::test]
async fn test_batch_verdict_fewer_items_than_expected() {
    // Response has fewer items than expected
    let json_response = r#"[
        {"index": 0, "verification_status": "confirmed", "verification_notes": "First"}
    ]"#;

    let results = parse_batch_verification_verdict(json_response, 3);

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].0, VerificationStatus::Confirmed);
    // Missing items should be NeedsReview with placeholder message
    assert_eq!(results[1].0, VerificationStatus::NeedsReview);
    assert!(results[1].1.contains("missing"));
    assert_eq!(results[2].0, VerificationStatus::NeedsReview);
    assert!(results[2].1.contains("missing"));
}

#[tokio::test]
async fn test_verify_findings_batched_with_index() {
    // Test full batch verification flow with index field
    let responses = vec![
        r#"[
            {"index": 0, "verification_status": "confirmed", "verification_notes": "Real vuln"},
            {"index": 1, "verification_status": "false_positive", "verification_notes": "Safe code"},
            {"index": 2, "verification_status": "confirmed", "verification_notes": "Another vuln"},
            {"index": 3, "verification_status": "false_positive", "verification_notes": "Not a vuln"}
        ]"#.to_string(),
    ];

    let client = MockLlmClient::new(responses);
    let findings = vec![
        create_test_finding("f1", 10),
        create_test_finding("f2", 20),
        create_test_finding("f3", 30),
        create_test_finding("f4", 40),
    ];

    let (results, fallback_count) =
        verify_findings_batched(&client, &findings, 8, &HashMap::new(), &HashMap::new()).await;

    assert_eq!(results.len(), 4);
    assert_eq!(fallback_count, 0); // No fallbacks used
    assert_eq!(results[0].0, VerificationStatus::Confirmed);
    assert_eq!(results[1].0, VerificationStatus::FalsePositive);
    assert_eq!(results[2].0, VerificationStatus::Confirmed);
    assert_eq!(results[3].0, VerificationStatus::FalsePositive);
}

#[tokio::test]
async fn test_verify_findings_batched_without_index_fallback() {
    // Test full batch verification flow without index field
    let responses = vec![r#"[
            {"verification_status": "confirmed", "verification_notes": "First"},
            {"verification_status": "false_positive", "verification_notes": "Second"},
            {"verification_status": "needs_review", "verification_notes": "Third"},
            {"verification_status": "confirmed", "verification_notes": "Fourth"}
        ]"#
    .to_string()];

    let client = MockLlmClient::new(responses);
    let findings = vec![
        create_test_finding("f1", 10),
        create_test_finding("f2", 20),
        create_test_finding("f3", 30),
        create_test_finding("f4", 40),
    ];

    let (results, fallback_count) =
        verify_findings_batched(&client, &findings, 8, &HashMap::new(), &HashMap::new()).await;

    assert_eq!(results.len(), 4);
    assert_eq!(fallback_count, 4); // All 4 items used positional fallback
    assert_eq!(results[0].0, VerificationStatus::Confirmed);
    assert_eq!(results[1].0, VerificationStatus::FalsePositive);
    assert_eq!(results[2].0, VerificationStatus::NeedsReview);
    assert_eq!(results[3].0, VerificationStatus::Confirmed);
}
