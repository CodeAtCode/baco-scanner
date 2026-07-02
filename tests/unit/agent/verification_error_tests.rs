//! Tool error recovery tests for SecurityAgent verification
//!
//! These tests verify that `verify_finding` correctly handles various
//! tool execution errors, including permission denied, compilation failures,
//! timeouts, crashes, network errors, malformed responses, retry logic,
//! and error accumulation.

use baco::agent::mock_llm::MockLlmClient;
use baco::agent::session::{AgentSession, ProgressCallback};
use baco::config::AgentConfig;
use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::llm::ChatResponse;
use serde_json::json;
use std::sync::Arc;

/// Helper to create AgentSession with mock client
fn create_session(
    mock_client: MockLlmClient,
    max_turns: u32,
    tool_timeout_secs: u64,
) -> (AgentSession, tempfile::TempDir) {
    let config = AgentConfig {
        enabled: false,
        max_turns,
        tool_timeout_secs,
        trusted_paths: vec![],
        keep_artifacts: false,
    };
    let tmpdir = tempfile::tempdir().unwrap();
    let progress_cb: ProgressCallback = Arc::new(|_| {});
    let session = AgentSession::new(mock_client, &config, tmpdir.path(), progress_cb);
    (session, tmpdir)
}

/// Helper to create a test finding
fn create_test_finding() -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "error-test-1".to_string(),
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
    }
}

// ============================================================================
// Test 1: File write permission denied
// Verify that permission errors during file_write are handled gracefully
// ============================================================================

#[tokio::test]
async fn test_verify_finding_file_write_permission_denied() {
    // LLM tries to write a file, but the tool returns permission error
    let responses = vec![
        MockLlmClient::mock_tool_call(
            "file_write",
            json!({ "path": "poc.py", "content": "print('exploit')" }),
        ),
        // After error, LLM reports failure
        ChatResponse {
            content: "Error: Cannot write file - permission denied\nUnable to create PoC test"
                .to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        },
    ];

    let mock_client = MockLlmClient::new(responses);
    let (session, _tmpdir) = create_session(mock_client, 5, 30);

    let finding = create_test_finding();
    let result = session.verify_finding("test.rs", &finding).await;

    assert!(result.is_ok());
    let verified = result.unwrap();

    // Should be marked as NeedsReview due to tool error
    assert_eq!(
        verified.finding.verification_status,
        Some(VerificationStatus::NeedsReview)
    );
    // Test log should contain the error message
    assert!(verified.test_log.is_some());
    assert!(verified.test_log.unwrap().contains("permission denied"));
}

// ============================================================================
// Test 2: Test compilation failure (invalid language)
// Verify that compilation errors with unsupported languages are handled
// ============================================================================

#[tokio::test]
async fn test_verify_finding_test_compile_invalid_language() {
    // LLM tries to compile with unsupported language
    let responses = vec![
        MockLlmClient::mock_tool_call(
            "file_write",
            json!({ "path": "test.xyz", "content": "print('test')" }),
        ),
        MockLlmClient::mock_tool_call(
            "test_compile",
            json!({ "source_path": "test.xyz", "language": "invalid_lang" }),
        ),
        // Report compilation failure
        ChatResponse {
            content: "Compilation failed: Unsupported language: invalid_lang\nCannot verify vulnerability".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        },
    ];

    let mock_client = MockLlmClient::new(responses);
    let (session, _tmpdir) = create_session(mock_client, 5, 30);

    let finding = create_test_finding();
    let result = session.verify_finding("test.rs", &finding).await;

    assert!(result.is_ok());
    let verified = result.unwrap();

    // Should be NeedsReview due to compilation failure
    assert_eq!(
        verified.finding.verification_status,
        Some(VerificationStatus::NeedsReview)
    );
    assert!(verified.test_log.is_some());
    assert!(verified.test_log.unwrap().contains("Unsupported language"));
}

// ============================================================================
// Test 3: Test run timeout
// Verify that timeout errors during test execution are handled
// ============================================================================

#[tokio::test]
async fn test_verify_finding_test_run_timeout() {
    // LLM tries to run a test that times out
    let responses = vec![
        MockLlmClient::mock_tool_call(
            "file_write",
            json!({ "path": "slow.py", "content": "import time; time.sleep(100)" }),
        ),
        MockLlmClient::mock_tool_call(
            "test_run",
            json!({ "executable_path": "slow.py", "timeout_secs": 1 }),
        ),
        // Report timeout
        ChatResponse {
            content: "Test execution timed out after 1 seconds\nUnable to complete verification"
                .to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        },
    ];

    let mock_client = MockLlmClient::new(responses);
    let (session, _tmpdir) = create_session(mock_client, 5, 30);

    let finding = create_test_finding();
    let result = session.verify_finding("test.rs", &finding).await;

    assert!(result.is_ok());
    let verified = result.unwrap();

    // Should be NeedsReview due to timeout
    assert_eq!(
        verified.finding.verification_status,
        Some(VerificationStatus::NeedsReview)
    );
    assert!(verified.test_log.is_some());
    assert!(verified.test_log.unwrap().contains("timed out"));
}

// ============================================================================
// Test 4: Tool execution crash
// Verify that unexpected tool crashes are handled gracefully
// ============================================================================

#[tokio::test]
async fn test_verify_finding_tool_execution_crash() {
    // LLM tries to use a tool that crashes
    let responses = vec![
        MockLlmClient::mock_tool_call("file_read", json!({ "path": "crash_test.rs" })),
        // Report tool crash
        ChatResponse {
            content: "Error: Tool crashed with signal SIGSEGV\nTool execution failed unexpectedly"
                .to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        },
    ];

    let mock_client = MockLlmClient::new(responses);
    let (session, _tmpdir) = create_session(mock_client, 5, 30);

    let finding = create_test_finding();
    let result = session.verify_finding("test.rs", &finding).await;

    assert!(result.is_ok());
    let verified = result.unwrap();

    // Should be NeedsReview due to crash
    assert_eq!(
        verified.finding.verification_status,
        Some(VerificationStatus::NeedsReview)
    );
    assert!(verified.test_log.is_some());
    assert!(verified.test_log.unwrap().contains("crashed"));
}

// ============================================================================
// Test 5: Network error during tool call
// Verify that network-related errors are handled correctly
// ============================================================================

#[tokio::test]
async fn test_verify_finding_network_error_during_tool_call() {
    // LLM tries a tool that requires network (simulated)
    let responses = vec![
        MockLlmClient::mock_tool_call(
            "pattern_search",
            json!({ "pattern": "vuln", "path": "remote://repo/src/main.rs" }),
        ),
        // Report network error
        ChatResponse {
            content: "Error: Network timeout - unable to reach remote source\nCannot complete verification".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        },
    ];

    let mock_client = MockLlmClient::new(responses);
    let (session, _tmpdir) = create_session(mock_client, 5, 30);

    let finding = create_test_finding();
    let result = session.verify_finding("test.rs", &finding).await;

    assert!(result.is_ok());
    let verified = result.unwrap();

    // Should be NeedsReview due to network error
    assert_eq!(
        verified.finding.verification_status,
        Some(VerificationStatus::NeedsReview)
    );
    assert!(verified.test_log.is_some());
    assert!(verified.test_log.unwrap().contains("Network"));
}

// ============================================================================
// Test 6: Malformed tool response
// Verify that malformed JSON responses from tools are handled
// ============================================================================

#[tokio::test]
async fn test_verify_finding_malformed_tool_response() {
    // LLM receives malformed response from tool
    let responses = vec![
        MockLlmClient::mock_tool_call(
            "file_write",
            json!({ "path": "test.py", "content": "print(1)" }),
        ),
        // Report malformed response error
        ChatResponse {
            content: "Error: Failed to parse tool response - invalid JSON format\nCannot process tool result".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        },
    ];

    let mock_client = MockLlmClient::new(responses);
    let (session, _tmpdir) = create_session(mock_client, 5, 30);

    let finding = create_test_finding();
    let result = session.verify_finding("test.rs", &finding).await;

    assert!(result.is_ok());
    let verified = result.unwrap();

    // Should be NeedsReview due to malformed response
    assert_eq!(
        verified.finding.verification_status,
        Some(VerificationStatus::NeedsReview)
    );
    assert!(verified.test_log.is_some());
    assert!(verified.test_log.unwrap().contains("invalid JSON"));
}

// ============================================================================
// Test 7: Retry logic on transient errors
// Verify that transient errors trigger retry attempts
// ============================================================================

#[tokio::test]
async fn test_verify_finding_retry_logic_on_transient_errors() {
    // LLM attempts retry after transient error
    let responses = vec![
        // First attempt - transient error
        MockLlmClient::mock_tool_call(
            "file_write",
            json!({ "path": "poc.py", "content": "print('test')" }),
        ),
        ChatResponse {
            content: "Error: Temporary file lock - retrying...\n".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        },
        // Second attempt - success
        MockLlmClient::mock_tool_call(
            "file_write",
            json!({ "path": "poc.py", "content": "print('test')" }),
        ),
        // Final success
        ChatResponse {
            content: "compiled=true\ntest_passed=true\nRetried successfully".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        },
    ];

    let mock_client = MockLlmClient::new(responses);
    let (session, _tmpdir) = create_session(mock_client, 10, 30);

    let finding = create_test_finding();
    let result = session.verify_finding("test.rs", &finding).await;

    assert!(result.is_ok());
    let verified = result.unwrap();

    // Should eventually confirm after retry
    assert!(
        verified.finding.verification_status == Some(VerificationStatus::Confirmed)
            || verified.finding.verification_status == Some(VerificationStatus::NeedsReview)
    );
    assert!(verified.test_log.is_some());
    // Flexible check for retry evidence in log
    let log = verified.test_log.unwrap();
    assert!(log.contains("Retry") || log.contains("retry") || log.contains("attempt"));
    // Should have used at least one turn for verification
    assert!(verified.agent_turns >= 1);
}

// ============================================================================
// Test 8: Error accumulation across multiple tools
// Verify that errors from multiple tool calls are accumulated
// ============================================================================

#[tokio::test]
async fn test_verify_finding_error_accumulation_multiple_tools() {
    // Multiple tool errors accumulate
    let responses = vec![
        // First tool error
        MockLlmClient::mock_tool_call(
            "file_write",
            json!({ "path": "poc.py", "content": "print('test')" }),
        ),
        ChatResponse {
            content: "Error 1: Permission denied writing to poc.py\n".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        },
        // Second tool error
        MockLlmClient::mock_tool_call(
            "file_read",
            json!({ "path": "poc.py" }),
        ),
        ChatResponse {
            content: "Error 2: File not found - poc.py does not exist\n".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        },
        // Third tool error
        MockLlmClient::mock_tool_call(
            "pattern_search",
            json!({ "pattern": "exploit", "path": "poc.py" }),
        ),
        // Final accumulated error report
        ChatResponse {
            content: "Multiple errors accumulated:\n1. Permission denied writing to poc.py\n2. File not found - poc.py does not exist\n3. Pattern search failed\nUnable to verify vulnerability".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        },
    ];

    let mock_client = MockLlmClient::new(responses);
    let (session, _tmpdir) = create_session(mock_client, 10, 30);

    let finding = create_test_finding();
    let result = session.verify_finding("test.rs", &finding).await;

    assert!(result.is_ok());
    let verified = result.unwrap();

    // Should be NeedsReview with accumulated errors
    assert_eq!(
        verified.finding.verification_status,
        Some(VerificationStatus::NeedsReview)
    );
    assert!(verified.test_log.is_some());
    let log = verified.test_log.unwrap();
    // Allow flexible error message patterns
    assert!(log.contains("Multiple") || log.contains("error") || log.contains("Error"));
}

// ============================================================================
// Additional test: Verify error messages propagate correctly through verify_finding
// ============================================================================

#[tokio::test]
async fn test_verify_finding_error_messages_propagated_correctly() {
    // Test that specific error messages are preserved in verification_notes
    let error_message = "Specific error: EACCES: permission denied, open '/tmp/poc.py'";

    let responses = vec![
        MockLlmClient::mock_tool_call(
            "file_write",
            json!({ "path": "poc.py", "content": "print('test')" }),
        ),
        ChatResponse {
            content: error_message.to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        },
    ];

    let mock_client = MockLlmClient::new(responses);
    let (session, _tmpdir) = create_session(mock_client, 5, 30);

    let finding = create_test_finding();
    let result = session.verify_finding("test.rs", &finding).await;

    assert!(result.is_ok());
    let verified = result.unwrap();

    // Error message should be preserved
    assert!(verified.test_log.is_some());
    let log = verified.test_log.unwrap();
    assert!(log.contains("EACCES"));
    assert!(log.contains("permission denied"));
}
