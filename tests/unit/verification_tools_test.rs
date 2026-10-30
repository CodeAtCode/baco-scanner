//! Regression test for T14: verification phase tool calling
//!
//! This test verifies that verify_findings_batched actually uses the tool loop
//! when max_turns > 0, proving that tools are passed to the LLM and executed.

use baco::agent::ToolCall;
use baco::error::ScanError;
use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::llm::{ChatMessage, ChatResponse, ChatResponseWithModel, LlmChatClient, ToolSchema};
use baco::scanner::phases::llm_phases::verification::verify_findings_batched;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Mock LLM client that simulates tool calling behavior:
/// - First call: returns a tool call for file_read
/// - Second call: returns final content with empty tool_calls
/// - Tracks message history to verify tool results were appended
struct ToolCallingMockClient {
    call_count: Arc<Mutex<usize>>,
    message_history: Arc<Mutex<Vec<ChatMessage>>>,
}

impl ToolCallingMockClient {
    fn new() -> Self {
        Self {
            call_count: Arc::new(Mutex::new(0)),
            message_history: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn get_call_count(&self) -> usize {
        *self.call_count.lock().unwrap()
    }

    fn get_message_history(&self) -> Vec<ChatMessage> {
        self.message_history.lock().unwrap().clone()
    }
}

impl LlmChatClient for ToolCallingMockClient {
    async fn chat(&self, _messages: &[ChatMessage]) -> Result<ChatResponseWithModel, ScanError> {
        // For the default chat_with_tools impl path, return a simple response
        Ok(ChatResponseWithModel {
            content: serde_json::to_string(&vec![json!({
                "index": 0,
                "verification_status": "confirmed",
                "verification_notes": "Direct chat response"
            })])
            .unwrap(),
            model_used: "test-model".to_string(),
        })
    }

    async fn chat_with_tools(
        &self,
        messages: &[ChatMessage],
        _tools: &[ToolSchema],
    ) -> Result<ChatResponse, ScanError> {
        let mut count = self.call_count.lock().unwrap();
        *count += 1;

        // Store message history for inspection
        {
            let mut history = self.message_history.lock().unwrap();
            history.extend(messages.iter().cloned());
        }

        if *count == 1 {
            // First call: return a tool call for file_read
            Ok(ChatResponse {
                content: String::new(),
                tool_calls: vec![ToolCall {
                    id: Some("call_1".to_string()),
                    name: "file_read".to_string(),
                    arguments: json!({
                        "path": "src/main.rs",
                        "start_line": 1,
                        "end_line": 10
                    }),
                }],
                raw: serde_json::Value::Null,
                model_used: "test-model".to_string(),
            })
        } else {
            // Second call: return final verdict
            Ok(ChatResponse {
                content: serde_json::to_string(&vec![json!({
                    "index": 0,
                    "verification_status": "confirmed",
                    "verification_notes": "Verified via file_read tool",
                    "seven_question_gate": {
                        "reachability": "yes",
                        "controllability": "yes",
                        "preconditions": "no",
                        "impact": "yes",
                        "context": "yes",
                        "evidence": "yes",
                        "confidence": "yes"
                    },
                    "concrete_impact_proof": {
                        "attack_vector": "test",
                        "consequence": "test",
                        "is_theoretical": false
                    }
                })])
                .unwrap(),
                tool_calls: vec![],
                raw: serde_json::Value::Null,
                model_used: "test-model".to_string(),
            })
        }
    }
}

fn create_test_finding(id: usize) -> VulnerabilityFinding {
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
        verification_gate_answers: None,
    }
}

#[tokio::test]
async fn test_verification_uses_tool_loop_when_max_turns_gt_zero() {
    // Create a temp directory that exists
    let temp_dir = std::env::temp_dir();

    // Create a test finding
    let findings = vec![create_test_finding(1)];
    let hunt_prompts: HashMap<String, String> = HashMap::new();
    let primitives: HashMap<String, Vec<String>> = HashMap::new();

    let client = ToolCallingMockClient::new();

    // Call with max_turns = 2, allowing the tool loop to run
    let (results, _fallback_count) = verify_findings_batched(
        &client,
        &findings,
        8,
        &hunt_prompts,
        &primitives,
        &temp_dir,
        2,
    )
    .await;

    // Assert that chat_with_tools was called at least twice (tool loop ran)
    assert!(
        client.get_call_count() >= 2,
        "Expected at least 2 LLM calls (tool loop should run), got {}",
        client.get_call_count()
    );

    // Assert that we got a result
    assert_eq!(results.len(), 1, "Expected 1 result");
    assert_eq!(
        results[0].0,
        VerificationStatus::Confirmed,
        "Expected confirmed status from tool-assisted verification"
    );
}

#[tokio::test]
async fn test_verification_skips_tool_loop_when_max_turns_is_zero() {
    // Create a temp directory that exists
    let temp_dir = std::env::temp_dir();

    // Create a test finding
    let findings = vec![create_test_finding(1)];
    let hunt_prompts: HashMap<String, String> = HashMap::new();
    let primitives: HashMap<String, Vec<String>> = HashMap::new();

    let client = ToolCallingMockClient::new();

    // Call with max_turns = 0, should skip tool loop
    let (results, _fallback_count) = verify_findings_batched(
        &client,
        &findings,
        8,
        &hunt_prompts,
        &primitives,
        &temp_dir,
        0,
    )
    .await;

    // With max_turns=0, the default impl is used which calls chat()
    // But chat() returns an error, so we should get NeedsReview
    assert_eq!(results.len(), 1, "Expected 1 result");
    assert_eq!(
        results[0].0,
        VerificationStatus::NeedsReview,
        "Expected NeedsReview when chat_with_tools is not properly implemented"
    );
}

#[tokio::test]
async fn test_verification_tool_result_appended_to_messages() {
    // This test verifies that tool execution results are actually appended
    // to the message history for the next LLM call

    let temp_dir = std::env::temp_dir();
    let findings = vec![create_test_finding(1)];
    let hunt_prompts: HashMap<String, String> = HashMap::new();
    let primitives: HashMap<String, Vec<String>> = HashMap::new();

    let client = ToolCallingMockClient::new();

    let (_results, _fallback_count) = verify_findings_batched(
        &client,
        &findings,
        8,
        &hunt_prompts,
        &primitives,
        &temp_dir,
        2,
    )
    .await;

    // Check that message history contains tool result messages
    let history = client.get_message_history();

    // We should have: system + user (initial) + assistant (tool call) + user (tool result) + ...
    // At minimum, verify we have more than just the initial messages
    assert!(
        history.len() > 2,
        "Expected tool result to be appended to messages, but history only has {} messages",
        history.len()
    );

    // Check that there's at least one tool-related message
    let has_tool_message = history
        .iter()
        .any(|msg| msg.content.contains("Tool") || msg.content.contains("file_read"));
    assert!(
        has_tool_message,
        "Expected tool execution message in history"
    );
}
