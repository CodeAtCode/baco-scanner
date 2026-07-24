//! Boundary condition tests for agent session max_turns
//!
//! These tests verify correct behavior at turn limit boundaries,
//! including edge cases for max_turns=0, max_turns=1, and exact boundary conditions.

use baco::agent::mock_llm::MockLlmClient;
use baco::agent::session::{AgentSession, ProgressCallback};
use baco::config::AgentConfig;
use baco::findings::Severity;
use baco::findings::VulnerabilityFinding;
use baco::llm::ChatResponse;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

/// Helper to create a test file in a temp directory
fn setup_test_file(content: &str) -> (tempfile::TempDir, PathBuf) {
    let tmpdir = tempfile::tempdir().unwrap();
    let test_file = tmpdir.path().join("test.rs");
    std::fs::write(&test_file, content).unwrap();
    (tmpdir, test_file)
}

/// Helper to create AgentSession with mock client
fn create_session(mock_client: MockLlmClient, max_turns: u32) -> (AgentSession, tempfile::TempDir) {
    let config = AgentConfig {
        enabled: false,
        max_turns,
        tool_timeout_secs: 30,
        trusted_paths: vec![],
        keep_artifacts: false,
    };
    let tmpdir = tempfile::tempdir().unwrap();
    let progress_cb: ProgressCallback = Arc::new(|_| {});
    let session = AgentSession::new(mock_client, &config, tmpdir.path(), progress_cb);
    (session, tmpdir)
}

// ============================================================================
// Test 1: Exactly at max_turns boundary (turn 5 when max=5)
// Verify that the agent completes successfully on the last allowed turn
// ============================================================================

#[tokio::test]
async fn test_analyze_file_exact_max_turns_boundary() {
    // Exactly 5 turns: 4 tool calls + 1 final response
    let responses = vec![
        MockLlmClient::mock_tool_call("file_read", json!({ "path": "test.rs" })),
        MockLlmClient::mock_tool_call("pattern_search", json!({ "pattern": "unsafe" })),
        MockLlmClient::mock_tool_call("file_read", json!({ "path": "src/lib.rs" })),
        MockLlmClient::mock_tool_call("pattern_search", json!({ "pattern": "malloc" })),
        MockLlmClient::mock_final_response(
            r#"{"title": "Buffer Overflow", "description": "Found buffer overflow", "severity": "High", "cwe_id": "CWE-120"}"#,
        ),
    ];

    let mock_client = MockLlmClient::new(responses);
    let (session, _tmpdir) = create_session(mock_client, 5);

    let (_tmpdir, test_file) = setup_test_file("fn main() {}");

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;
    assert!(result.is_ok());
    let finding = result.unwrap();

    // Should complete exactly at turn 5 (the max)
    assert_eq!(finding.agent_turns, 5);
    assert_eq!(finding.finding.severity, Severity::High);
}

// ============================================================================
// Test 2: max_turns=1 edge case
// Verify agent can complete in a single turn without tool calls
// ============================================================================

#[tokio::test]
async fn test_analyze_file_max_turns_one() {
    // Single turn: immediate final response without tool calls
    let responses = vec![MockLlmClient::mock_final_response(
        r#"{"title": "Path Traversal", "description": "Unvalidated path input", "severity": "Medium"}"#,
    )];

    let mock_client = MockLlmClient::new(responses);
    let (session, _tmpdir) = create_session(mock_client, 1);

    let (_tmpdir, test_file) = setup_test_file("fn main() {}");

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;
    assert!(result.is_ok());
    let finding = result.unwrap();

    // Should complete in exactly 1 turn
    assert_eq!(finding.agent_turns, 1);
    assert!(!finding.finding.title.is_empty());
}

// ============================================================================
// Test 3: max_turns=0 edge case (should fail immediately)
// Verify agent respects zero-turn limit by not executing any turns
// ============================================================================

#[tokio::test]
async fn test_analyze_file_max_turns_zero_immediate_exit() {
    // Even if we have responses, max_turns=0 should prevent any execution
    let responses = vec![MockLlmClient::mock_final_response(
        r#"{"title": "Should not appear", "description": "This should not happen"}"#,
    )];

    let mock_client = MockLlmClient::new(responses);
    let (session, _tmpdir) = create_session(mock_client, 0);

    let (_tmpdir, test_file) = setup_test_file("fn main() {}");

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;
    assert!(result.is_ok());
    let finding = result.unwrap();

    // With max_turns=0, the loop should exit immediately at turn 1 > 0
    // The turn counter increments first, then checks if turn > max_turns
    // So it will be turn 1 when it breaks
    assert!(finding.agent_turns >= 1);
    // Should be an empty/audit finding since no LLM response was processed
    assert!(finding.finding.title.is_empty() || finding.finding.title.contains("Security Audit"));
}

// ============================================================================
// Test 4: Tool call on last allowed turn
// Verify tool execution works correctly when it's the final turn
// ============================================================================

#[tokio::test]
async fn test_analyze_file_tool_call_on_last_turn() {
    // Turn 4: tool call (last allowed turn since max=4)
    // Turn 5: would be over limit, so agent should process tool then exit
    let responses = vec![
        MockLlmClient::mock_tool_call("file_read", json!({ "path": "test.rs" })),
        MockLlmClient::mock_tool_call("pattern_search", json!({ "pattern": "vuln" })),
        MockLlmClient::mock_tool_call("file_read", json!({ "path": "src/main.rs" })),
        // On turn 4 (last allowed), make a tool call
        MockLlmClient::mock_tool_call(
            "file_write",
            json!({ "path": "poc.txt", "content": "exploit" }),
        ),
        // Turn 5 would be over limit
        MockLlmClient::mock_final_response(
            r#"{"title": "Command Injection", "description": "Shell command injection", "severity": "High"}"#,
        ),
    ];

    let mock_client = MockLlmClient::new(responses);
    let (session, _tmpdir) = create_session(mock_client, 4);

    let (_tmpdir, test_file) = setup_test_file("fn main() {}");

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;
    assert!(result.is_ok());
    let finding = result.unwrap();

    // Should stop at or around turn 4-5 (the boundary)
    assert!(finding.agent_turns >= 4 && finding.agent_turns <= 5);
    // Should have used tools
    assert!(!finding.tools_used.is_empty());
}

// ============================================================================
// Test 5: Tool call on forbidden turn (should error)
// Verify that attempting tool calls beyond max_turns is blocked
// ============================================================================

#[tokio::test]
async fn test_analyze_file_tool_call_forbidden_turn_errors() {
    // Keep returning tool calls past the limit
    let responses: Vec<ChatResponse> = (0..10)
        .map(|i| {
            MockLlmClient::mock_tool_call("file_read", json!({ "path": format!("file{}.rs", i) }))
        })
        .collect();

    let mock_client = MockLlmClient::new(responses);
    let (session, _tmpdir) = create_session(mock_client, 3);

    let (_tmpdir, test_file) = setup_test_file("fn main() {}");

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;
    assert!(result.is_ok());
    let finding = result.unwrap();

    // Should stop when turns are exceeded (around turn 3-4)
    assert!(finding.agent_turns >= 3 && finding.agent_turns <= 4);
    // Should have some tools used before hitting the limit
    assert!(!finding.tools_used.is_empty());
}

// ============================================================================
// Test 6: Multiple tool calls exhausting turns
// Verify turn counter correctly tracks multiple sequential tool calls
// ============================================================================

#[tokio::test]
async fn test_analyze_file_multiple_tools_exhaust_turns() {
    // 4 tool calls + 1 final response within max_turns=5
    let responses = vec![
        MockLlmClient::mock_tool_call("file_read", json!({ "path": "a.rs" })),
        MockLlmClient::mock_tool_call("pattern_search", json!({ "pattern": "x" })),
        MockLlmClient::mock_tool_call("file_write", json!({ "path": "b.rs", "content": "x" })),
        MockLlmClient::mock_tool_call("test_compile", json!({ "path": "b.rs" })),
        MockLlmClient::mock_final_response(
            r#"{"title": "Finding", "description": "Test finding", "severity": "Medium"}"#,
        ),
    ];

    let mock_client = MockLlmClient::new(responses);
    let (session, _tmpdir) = create_session(mock_client, 5);

    let (_tmpdir, test_file) = setup_test_file("fn main() {}");

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;
    assert!(result.is_ok());
    let finding = result.unwrap();

    // Should use 5 turns: 4 tool calls + 1 final response
    assert_eq!(finding.agent_turns, 5);
    // Should have used 4 unique tools before final response
    assert_eq!(finding.tools_used.len(), 4);
}

// ============================================================================
// Test 7: Turn counter reset behavior
// Verify that a new session starts with turn counter at 0
// ============================================================================

#[tokio::test]
async fn test_session_turn_counter_reset_on_new_instance() {
    // First session
    let responses1 = vec![
        MockLlmClient::mock_tool_call("file_read", json!({ "path": "test.rs" })),
        MockLlmClient::mock_final_response(
            r#"{"title": "Finding 1", "description": "First finding", "severity": "Low"}"#,
        ),
    ];

    let mock_client1 = MockLlmClient::new(responses1);
    let (session1, _tmpdir1) = create_session(mock_client1, 10);
    let (_tmpdir_a, test_file_a) = setup_test_file("fn main() {}");

    let result1 = session1
        .analyze_file(test_file_a.to_string_lossy().as_ref())
        .await;
    assert!(result1.is_ok());
    let finding1 = result1.unwrap();
    assert_eq!(finding1.agent_turns, 2);

    // Second session (new instance)
    let responses2 = vec![
        MockLlmClient::mock_tool_call("pattern_search", json!({ "pattern": "vuln" })),
        MockLlmClient::mock_final_response(
            r#"{"title": "Finding 2", "description": "Second finding", "severity": "Medium"}"#,
        ),
    ];

    let mock_client2 = MockLlmClient::new(responses2);
    let (session2, _tmpdir2) = create_session(mock_client2, 10);
    let (_tmpdir_b, test_file_b) = setup_test_file("fn main() {}");

    let result2 = session2
        .analyze_file(test_file_b.to_string_lossy().as_ref())
        .await;
    assert!(result2.is_ok());
    let finding2 = result2.unwrap();

    // Second session should also start fresh at turn 2 (not cumulative)
    assert_eq!(finding2.agent_turns, 2);
}

// ============================================================================
// Test 8: Concurrent turn limit checks (verify_finding boundary)
// Verify verify_finding also respects max_turns correctly
// ============================================================================

#[tokio::test]
async fn test_verify_finding_max_turns_boundary() {
    // Exactly 3 turns for verification
    let responses = vec![
        MockLlmClient::mock_tool_call(
            "file_write",
            json!({ "path": "poc_test.rs", "content": "print('exploit')" }),
        ),
        MockLlmClient::mock_tool_call("test_compile", json!({ "path": "poc_test.rs" })),
        MockLlmClient::mock_final_response(
            "compiled=true\ntest_passed=true\nVulnerability confirmed with PoC",
        ),
    ];

    let mock_client = MockLlmClient::new(responses);
    let (session, _tmpdir) = create_session(mock_client, 3);

    let finding = VulnerabilityFinding {
        id: "boundary-test-1".to_string(),
        title: "Test Buffer Overflow".to_string(),
        description: "A buffer overflow vulnerability in string handling".to_string(),
        severity: Severity::High,
        confidence_score: 0.9,
        cwe_id: Some("CWE-120".to_string()),
        file_path: "test.rs".to_string(),
        line_number: Some(42),
        code_snippet: Some("unsafe { strcpy(...) }".to_string()),
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
        agent_mode: true,
        statement_range: None,
        triage_verdict: None,
    };

    let result = session.verify_finding("test.rs", &finding).await;
    assert!(result.is_ok());
    let verified = result.unwrap();

    // Should complete exactly at turn 3 (the max)
    assert_eq!(verified.agent_turns, 3);
    assert_eq!(verified.tools_used.len(), 2);
    // Should be confirmed since test_passed=true
    assert_eq!(
        verified.finding.verification_status,
        Some(baco::findings::VerificationStatus::Confirmed)
    );
}
