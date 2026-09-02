//! Tests for batched LLM processing in verification and enrichment
//!
//! This module tests the batching functionality that reduces LLM API calls
//! by processing multiple findings in a single request.

use baco::error::ScanError;
use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::llm::{ChatMessage, ChatResponseWithModel, LlmChatClient};
use baco::report::ai_aggregation::enrichment::enrich_findings_batched;
use baco::scanner::phases::llm_phases::verification::verify_findings_batched;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Counting LLM client that tracks the number of chat calls and implements LlmChatClient
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
async fn test_verification_batching_call_count() {
    // 20 findings with batch_size 8 should result in exactly 3 calls
    let findings: Vec<VulnerabilityFinding> = (0..20).map(create_finding).collect();
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    // Create responses for 3 batches
    let responses = vec![
        // Batch 1: findings 0-7
        serde_json::to_string(&[
            json!({"index": 0, "verification_status": "confirmed", "verification_notes": "Code matches pattern"}),
            json!({"index": 1, "verification_status": "confirmed", "verification_notes": "Code matches pattern"}),
            json!({"index": 2, "verification_status": "false_positive", "verification_notes": "Safe context"}),
            json!({"index": 3, "verification_status": "confirmed", "verification_notes": "Code matches pattern"}),
            json!({"index": 4, "verification_status": "confirmed", "verification_notes": "Code matches pattern"}),
            json!({"index": 5, "verification_status": "needs_review", "verification_notes": "Unclear context"}),
            json!({"index": 6, "verification_status": "confirmed", "verification_notes": "Code matches pattern"}),
            json!({"index": 7, "verification_status": "confirmed", "verification_notes": "Code matches pattern"}),
        ]).unwrap(),
        // Batch 2: findings 8-15
        serde_json::to_string(&[
            json!({"index": 0, "verification_status": "confirmed", "verification_notes": "Code matches pattern"}),
            json!({"index": 1, "verification_status": "false_positive", "verification_notes": "Safe context"}),
            json!({"index": 2, "verification_status": "confirmed", "verification_notes": "Code matches pattern"}),
            json!({"index": 3, "verification_status": "confirmed", "verification_notes": "Code matches pattern"}),
            json!({"index": 4, "verification_status": "needs_review", "verification_notes": "Unclear context"}),
            json!({"index": 5, "verification_status": "confirmed", "verification_notes": "Code matches pattern"}),
            json!({"index": 6, "verification_status": "confirmed", "verification_notes": "Code matches pattern"}),
            json!({"index": 7, "verification_status": "false_positive", "verification_notes": "Safe context"}),
        ]).unwrap(),
        // Batch 3: findings 16-19
        serde_json::to_string(&[
            json!({"index": 0, "verification_status": "confirmed", "verification_notes": "Code matches pattern"}),
            json!({"index": 1, "verification_status": "confirmed", "verification_notes": "Code matches pattern"}),
            json!({"index": 2, "verification_status": "false_positive", "verification_notes": "Safe context"}),
            json!({"index": 3, "verification_status": "confirmed", "verification_notes": "Code matches pattern"}),
        ]).unwrap(),
    ];

    let client = CountingLlmClient::new(responses);
    let results = verify_findings_batched(&client, &findings, 8, &hunt_prompts).await;

    // Assert exactly 3 calls were made
    assert_eq!(
        client.get_call_count(),
        3,
        "Expected exactly 3 LLM calls for 20 findings with batch_size 8"
    );

    // Assert all 20 findings got results
    assert_eq!(results.len(), 20, "Expected results for all 20 findings");
}

#[tokio::test]
async fn test_verification_batch_single_bad_item() {
    // Test that a single bad item in a batch results in NeedsReview for that item only
    let findings: Vec<VulnerabilityFinding> = (0..5).map(create_finding).collect();
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    let responses = vec![
        // One batch with one malformed item
        serde_json::to_string(&[
            json!({"index": 0, "verification_status": "confirmed", "verification_notes": "Good"}),
            json!({"index": 1, "verification_status": "confirmed", "verification_notes": "Good"}),
            // Malformed - missing required field
            json!({"index": 2, "verification_notes": "Missing status"}),
            json!({"index": 3, "verification_status": "confirmed", "verification_notes": "Good"}),
            json!({"index": 4, "verification_status": "false_positive", "verification_notes": "Good"}),
        ]).unwrap(),
    ];

    let client = CountingLlmClient::new(responses);
    let results = verify_findings_batched(&client, &findings, 8, &hunt_prompts).await;

    assert_eq!(client.get_call_count(), 1, "Expected 1 LLM call");
    assert_eq!(results.len(), 5, "Expected 5 results");

    // Items 0, 1, 3, 4 should be confirmed/false_positive
    assert_eq!(results[0].0, VerificationStatus::Confirmed);
    assert_eq!(results[1].0, VerificationStatus::Confirmed);

    // Item 2 should be NeedsReview due to parse failure
    assert_eq!(results[2].0, VerificationStatus::NeedsReview);

    // Item 3, 4 should be confirmed/false_positive
    assert_eq!(results[3].0, VerificationStatus::Confirmed);
    assert_eq!(results[4].0, VerificationStatus::FalsePositive);
}

#[tokio::test]
async fn test_verification_batch_whole_batch_garbage_fallback() {
    // Test that when the entire batch fails to parse, it returns NeedsReview for all
    let findings: Vec<VulnerabilityFinding> = (0..5).map(create_finding).collect();
    let hunt_prompts: HashMap<String, String> = HashMap::new();

    // Garbage response that fails JSON parsing
    let responses = vec!["This is not valid JSON at all".to_string()];

    let client = CountingLlmClient::new(responses);
    let results = verify_findings_batched(&client, &findings, 8, &hunt_prompts).await;

    // Should have made 1 batch call
    assert_eq!(client.get_call_count(), 1, "Expected 1 LLM call for batch");
    assert_eq!(results.len(), 5, "Expected 5 results");

    // All should be NeedsReview since the batch parse failed
    for (i, (status, notes)) in results.iter().enumerate() {
        assert_eq!(
            *status,
            VerificationStatus::NeedsReview,
            "Item {} should be NeedsReview after batch failure",
            i
        );
        assert!(!notes.is_empty(), "Notes should contain error info");
    }
}

// ============================================================================
// Enrichment Batching Tests
// ============================================================================

#[tokio::test]
async fn test_enrichment_batching_call_count() {
    // 20 findings with batch_size 8 should result in exactly 3 calls
    let findings: Vec<VulnerabilityFinding> = (0..20).map(create_finding).collect();

    let responses = vec![
        // Batch 1: findings 0-7
        serde_json::to_string(&[
            json!({"index": 0, "description": "Desc 0", "recommendation": "Rec 0"}),
            json!({"index": 1, "description": "Desc 1", "recommendation": "Rec 1"}),
            json!({"index": 2, "description": "Desc 2", "recommendation": "Rec 2"}),
            json!({"index": 3, "description": "Desc 3", "recommendation": "Rec 3"}),
            json!({"index": 4, "description": "Desc 4", "recommendation": "Rec 4"}),
            json!({"index": 5, "description": "Desc 5", "recommendation": "Rec 5"}),
            json!({"index": 6, "description": "Desc 6", "recommendation": "Rec 6"}),
            json!({"index": 7, "description": "Desc 7", "recommendation": "Rec 7"}),
        ])
        .unwrap(),
        // Batch 2: findings 8-15
        serde_json::to_string(&[
            json!({"index": 0, "description": "Desc 8", "recommendation": "Rec 8"}),
            json!({"index": 1, "description": "Desc 9", "recommendation": "Rec 9"}),
            json!({"index": 2, "description": "Desc 10", "recommendation": "Rec 10"}),
            json!({"index": 3, "description": "Desc 11", "recommendation": "Rec 11"}),
            json!({"index": 4, "description": "Desc 12", "recommendation": "Rec 12"}),
            json!({"index": 5, "description": "Desc 13", "recommendation": "Rec 13"}),
            json!({"index": 6, "description": "Desc 14", "recommendation": "Rec 14"}),
            json!({"index": 7, "description": "Desc 15", "recommendation": "Rec 15"}),
        ])
        .unwrap(),
        // Batch 3: findings 16-19
        serde_json::to_string(&[
            json!({"index": 0, "description": "Desc 16", "recommendation": "Rec 16"}),
            json!({"index": 1, "description": "Desc 17", "recommendation": "Rec 17"}),
            json!({"index": 2, "description": "Desc 18", "recommendation": "Rec 18"}),
            json!({"index": 3, "description": "Desc 19", "recommendation": "Rec 19"}),
        ])
        .unwrap(),
    ];

    let client = CountingLlmClient::new(responses);
    let results = enrich_findings_batched(&client, &findings, 8).await;

    // Assert exactly 3 calls were made
    assert_eq!(
        client.get_call_count(),
        3,
        "Expected exactly 3 LLM calls for 20 findings with batch_size 8"
    );

    // Assert all 20 findings got enriched
    assert_eq!(results.len(), 20, "Expected 20 enriched findings");

    // Verify enrichment was applied (description and recommendation fields are modified)
    for (i, finding) in results.iter().enumerate() {
        assert!(
            finding.description.contains(&format!("Desc {}", i))
                || finding.description.contains(&format!("Finding {}", i))
        );
        assert!(finding
            .recommendation
            .as_ref()
            .is_some_and(|r| r.contains(&format!("Rec {}", i))));
    }
}

#[tokio::test]
async fn test_enrichment_batch_single_bad_item() {
    // Test that a single bad item in a batch keeps empty fields while others are enriched
    let findings: Vec<VulnerabilityFinding> = (0..5).map(create_finding).collect();

    let responses = vec![serde_json::to_string(&[
        json!({"index": 0, "description": "Desc 0", "recommendation": "Rec 0"}),
        json!({"index": 1, "description": "Desc 1", "recommendation": "Rec 1"}),
        // Malformed - missing fields
        json!({"index": 2}),
        json!({"index": 3, "description": "Desc 3", "recommendation": "Rec 3"}),
        json!({"index": 4, "description": "Desc 4", "recommendation": "Rec 4"}),
    ])
    .unwrap()];

    let client = CountingLlmClient::new(responses);
    let results = enrich_findings_batched(&client, &findings, 8).await;

    assert_eq!(client.get_call_count(), 1, "Expected 1 LLM call");
    assert_eq!(results.len(), 5, "Expected 5 results");

    // Items 0, 1, 3, 4 should be enriched
    assert!(results[0].description.contains("Desc 0"));
    assert!(results[1].description.contains("Desc 1"));

    // Item 2 should have default enrichment due to parse failure
    assert!(!results[2].description.contains("Desc 2"));
    assert!(results[2]
        .recommendation
        .as_ref()
        .is_some_and(|r| r == "Review and fix the identified security issue."));

    // Items 3, 4 should be enriched
    assert!(results[3].description.contains("Desc 3"));
    assert!(results[4].description.contains("Desc 4"));
}

// ============================================================================
// Boundary Tests
// ============================================================================

#[tokio::test]
async fn test_verification_batch_exact_boundary() {
    // Test exact batch boundary: 16 findings with batch_size 8 = exactly 2 calls
    let findings: Vec<VulnerabilityFinding> = (0..16).map(create_finding).collect();
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
    ];

    let client = CountingLlmClient::new(responses);
    let results = verify_findings_batched(&client, &findings, 8, &hunt_prompts).await;

    assert_eq!(
        client.get_call_count(),
        2,
        "Expected exactly 2 LLM calls for 16 findings with batch_size 8"
    );
    assert_eq!(results.len(), 16, "Expected 16 results");
}

#[tokio::test]
async fn test_enrichment_batch_exact_boundary() {
    // Test exact batch boundary: 16 findings with batch_size 8 = exactly 2 calls
    let findings: Vec<VulnerabilityFinding> = (0..16).map(create_finding).collect();

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
    ];

    let client = CountingLlmClient::new(responses);
    let results = enrich_findings_batched(&client, &findings, 8).await;

    assert_eq!(
        client.get_call_count(),
        2,
        "Expected exactly 2 LLM calls for 16 findings with batch_size 8"
    );
    assert_eq!(results.len(), 16, "Expected 16 enriched findings");
}
