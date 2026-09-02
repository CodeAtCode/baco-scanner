//! LLM request-count tests for batching functionality
//!
//! Verifies that verify_findings_batched and enrich_findings_batched
//! make the expected number of LLM chat calls.

use baco::error::ScanError;
use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::llm::{ChatMessage, ChatResponseWithModel, LlmChatClient};
use baco::report::ai_aggregation::enrichment::enrich_findings_batched;
use baco::scanner::phases::llm_phases::verification::verify_findings_batched;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Counting LLM client that tracks the number of chat calls
struct CountingLlmClient {
    responses: Vec<String>,
    call_count: Arc<Mutex<usize>>,
}

impl CountingLlmClient {
    fn new(responses: Vec<String>) -> Self {
        Self {
            responses,
            call_count: Arc::new(Mutex::new(0)),
        }
    }

    fn get_call_count(&self) -> usize {
        *self.call_count.lock().unwrap()
    }
}

impl LlmChatClient for CountingLlmClient {
    async fn chat(&self, _messages: &[ChatMessage]) -> Result<ChatResponseWithModel, ScanError> {
        let mut count = self.call_count.lock().unwrap();
        *count += 1;

        let idx = (*count - 1).min(self.responses.len() - 1);
        let content = self.responses[idx].clone();

        Ok(ChatResponseWithModel {
            content,
            model_used: "test-model".to_string(),
        })
    }
}

/// Helper to create a minimal test VulnerabilityFinding
fn create_finding(id: usize) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: format!("TEST-{}", id),
        title: format!("Test Finding {}", id),
        description: format!("This is a test vulnerability finding number {}", id),
        severity: Severity::Medium,
        confidence_score: 0.8,
        cwe_id: None,
        file_path: "test.rs".to_string(),
        line_number: Some(100 + id as u32),
        code_snippet: Some(format!("let x = {};", id)),
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
        evidence: vec![],
        verification_tier: None,
    }
}

// ============================================================================
// Verification Batching Tests
// ============================================================================

#[tokio::test]
async fn test_verification_n_findings_leq_batch_size() {
    // Test 1: N findings ≤ batch_size → exactly 1 chat call
    let findings: Vec<VulnerabilityFinding> = (0..5).map(create_finding).collect();
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let responses = vec![serde_json::to_string(&vec![
        json!({"index": 0, "verification_status": "confirmed", "verification_notes": "OK"});
        5
    ])
    .unwrap()];

    let client = CountingLlmClient::new(responses);
    let results = verify_findings_batched(&client, &findings, 8, &hunt_prompts).await;

    assert_eq!(
        client.get_call_count(),
        1,
        "Expected exactly 1 LLM call for 5 findings with batch_size 8"
    );
    assert_eq!(results.len(), 5, "Expected results for all 5 findings");
}

#[tokio::test]
async fn test_verification_n_findings_spanning_k_batches() {
    // Test 2: N findings spanning k batches → exactly k calls
    // 20 findings with batch_size 8 = ceil(20/8) = 3 batches
    let findings: Vec<VulnerabilityFinding> = (0..20).map(create_finding).collect();
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let responses = vec![
        serde_json::to_string(&vec![
            json!({"index": 0, "verification_status": "confirmed", "verification_notes": "OK"});
            8
        ])
        .unwrap(),
        serde_json::to_string(&vec![
            json!({"index": 0, "verification_status": "confirmed", "verification_notes": "OK"});
            8
        ])
        .unwrap(),
        serde_json::to_string(&vec![
            json!({"index": 0, "verification_status": "confirmed", "verification_notes": "OK"});
            4
        ])
        .unwrap(),
    ];

    let client = CountingLlmClient::new(responses);
    let results = verify_findings_batched(&client, &findings, 8, &hunt_prompts).await;

    assert_eq!(
        client.get_call_count(),
        3,
        "Expected exactly 3 LLM calls for 20 findings with batch_size 8"
    );
    assert_eq!(results.len(), 20, "Expected results for all 20 findings");
}

#[tokio::test]
async fn test_enrichment_n_findings_ceil_n_batch() {
    // Test 3: Enrichment batching: N findings → ceil(N/batch) calls
    // 17 findings with batch_size 8 = ceil(17/8) = 3 calls
    let findings: Vec<VulnerabilityFinding> = (0..17).map(create_finding).collect();

    let responses = vec![
        serde_json::to_string(&vec![
            json!({"index": 0, "description": "Desc", "recommendation": "Rec"});
            8
        ])
        .unwrap(),
        serde_json::to_string(&vec![
            json!({"index": 0, "description": "Desc", "recommendation": "Rec"});
            8
        ])
        .unwrap(),
        serde_json::to_string(&vec![
            json!({"index": 0, "description": "Desc", "recommendation": "Rec"});
            1
        ])
        .unwrap(),
    ];

    let client = CountingLlmClient::new(responses);
    let results = enrich_findings_batched(&client, &findings, 8).await;

    assert_eq!(
        client.get_call_count(),
        3,
        "Expected exactly 3 LLM calls for 17 findings with batch_size 8 (ceil(17/8))"
    );
    assert_eq!(results.len(), 17, "Expected 17 enriched findings");
}

#[tokio::test]
async fn test_empty_findings_zero_calls() {
    // Test 4: Empty findings → 0 calls
    let findings: Vec<VulnerabilityFinding> = vec![];
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let client = CountingLlmClient::new(vec![]);
    let results = verify_findings_batched(&client, &findings, 8, &hunt_prompts).await;

    assert_eq!(
        client.get_call_count(),
        0,
        "Expected 0 LLM calls for empty findings"
    );
    assert_eq!(results.len(), 0, "Expected empty results");
}

#[tokio::test]
async fn test_parse_failure_batch_counts_as_one_call() {
    // Test 5: A parse-failure batch still counts as 1 call and marks findings NeedsReview
    let findings: Vec<VulnerabilityFinding> = (0..5).map(create_finding).collect();
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    // Garbage response that fails JSON parsing
    let responses = vec!["This is not valid JSON".to_string()];

    let client = CountingLlmClient::new(responses);
    let results = verify_findings_batched(&client, &findings, 8, &hunt_prompts).await;

    assert_eq!(
        client.get_call_count(),
        1,
        "Expected 1 LLM call even when parse fails"
    );
    assert_eq!(results.len(), 5, "Expected 5 results");

    // All should be NeedsReview since the batch parse failed
    for (i, (status, notes)) in results.iter().enumerate() {
        assert_eq!(
            *status,
            VerificationStatus::NeedsReview,
            "Item {} should be NeedsReview after parse failure",
            i
        );
        assert!(
            !notes.is_empty(),
            "Item {} notes should contain error info",
            i
        );
    }
}
