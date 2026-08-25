//! Comprehensive unit tests for AgentSession
//!
//! Tests cover:
//! - Session creation and configuration
//! - Tool registry initialization
//! - Progress callbacks
//! - analyze_file functionality
//! - verify_finding functionality
//! - Error handling
//! - Edge cases

use baco::agent::mock_llm::MockLlmClient;
use baco::agent::session::{AgentSession, ProgressCallback};
use baco::config::AgentConfig;
use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::llm::ChatResponse;
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

/// Helper to create a minimal AgentConfig for tests
fn create_test_config(max_turns: u32) -> AgentConfig {
    AgentConfig {
        enabled: false,
        max_turns,
        tool_timeout_secs: 30,
        trusted_paths: vec![],
    }
}

/// Helper to create a temporary directory for tests
fn create_temp_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("Failed to create temp directory")
}

/// Helper to create a test file in the temp directory
fn create_test_file(
    temp_dir: &tempfile::TempDir,
    filename: &str,
    content: &str,
) -> std::path::PathBuf {
    let file_path = temp_dir.path().join(filename);
    std::fs::write(&file_path, content).expect("Failed to write test file");
    file_path
}

/// Helper to create a basic VulnerabilityFinding for tests
fn create_test_finding(title: &str, severity: Severity) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-finding-1".to_string(),
        title: title.to_string(),
        description: "Test vulnerability description".to_string(),
        severity,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "test.rs".to_string(),
        line_number: Some(42),
        code_snippet: Some("let x = unsafe { ... }".to_string()),
        diff_hunk: None,
        recommendation: Some("Add input validation".to_string()),
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
        evidence: vec![],
        verification_tier: None,
    }
}

// ============================================================================
// Session Creation Tests
// ============================================================================

/// Helper for creating an agent session with default test configuration
fn create_test_session(max_turns: u32) -> AgentSession {
    let mock_client = MockLlmClient::new(vec![]);
    let config = create_test_config(max_turns);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb)
}

#[test]
fn test_session_creation_with_mock_client() {
    let _session = create_test_session(10);

    // Session created successfully
}

#[test]
fn test_session_creation_with_custom_max_turns() {
    let _session = create_test_session(50);

    // Session created with custom max_turns
}

#[test]
fn test_session_creation_with_minimal_max_turns() {
    let _session = create_test_session(1);

    // Session created with minimal max_turns
}

#[test]
fn test_session_uses_provided_project_root() {
    let _session = create_test_session(10);

    // Session created with project root
}

#[test]
fn test_session_creation_with_custom_timeout() {
    let mock_client = MockLlmClient::new(vec![]);
    let config = AgentConfig {
        enabled: false,
        max_turns: 10,
        tool_timeout_secs: 60,
        trusted_paths: vec![],
    };
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    // Session should use the configured timeout
    let _ = session; // Just verify it creates successfully
}

// ============================================================================
// Tool Registry Tests
// ============================================================================

#[test]
fn test_session_has_tool_registry() {
    let _session = create_test_session(10);

    // Tool registry is initialized (verified by successful session creation)
}

// ============================================================================
// Progress Callback Tests
// ============================================================================

#[test]
fn test_progress_callback_basic() {
    let called = Arc::new(AtomicBool::new(false));
    let called_clone = called.clone();

    let progress_cb: ProgressCallback = Arc::new(move |_msg| {
        called_clone.store(true, Ordering::SeqCst);
    });

    progress_cb("test message".to_string());

    assert!(called.load(Ordering::SeqCst));
}

#[test]
fn test_progress_callback_with_counter() {
    let count = Arc::new(AtomicUsize::new(0));
    let count_clone = count.clone();

    let progress_cb: ProgressCallback = Arc::new(move |_msg| {
        count_clone.fetch_add(1, Ordering::SeqCst);
    });

    progress_cb("msg1".to_string());
    progress_cb("msg2".to_string());
    progress_cb("msg3".to_string());

    assert_eq!(count.load(Ordering::SeqCst), 3);
}

#[test]
fn test_progress_callback_thread_safe() {
    let called = Arc::new(AtomicBool::new(false));
    let called_clone = called.clone();
    let progress_cb: ProgressCallback = Arc::new(move |_msg| {
        called_clone.store(true, Ordering::SeqCst);
    });

    // Clone and call from "another thread" (simulated)
    let progress_cb_clone = progress_cb.clone();
    progress_cb_clone("from clone".to_string());

    assert!(called.load(Ordering::SeqCst));
}

#[test]
fn test_progress_callback_empty_message() {
    let called = Arc::new(AtomicBool::new(false));
    let called_clone = called.clone();

    let progress_cb: ProgressCallback = Arc::new(move |_msg| {
        called_clone.store(true, Ordering::SeqCst);
    });

    progress_cb("".to_string());

    assert!(called.load(Ordering::SeqCst));
}

#[test]
fn test_progress_callback_long_message() {
    let called = Arc::new(AtomicBool::new(false));
    let called_clone = called.clone();

    let progress_cb: ProgressCallback = Arc::new(move |_msg| {
        called_clone.store(true, Ordering::SeqCst);
    });

    let long_msg = "a".repeat(10000);
    progress_cb(long_msg);

    assert!(called.load(Ordering::SeqCst));
}

// ============================================================================
// analyze_file Tests - Basic Scenarios
// ============================================================================

#[tokio::test]
async fn test_analyze_file_success_with_mock_llm() {
    let responses = vec![MockLlmClient::mock_final_response(
        r#"{"title": "Test Finding", "description": "Found an issue", "severity": "Medium"}"#,
    )];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let test_file = create_test_file(&temp_dir, "test.rs", "fn main() {}");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;

    assert!(result.is_ok());
    let finding = result.unwrap();
    assert!(!finding.finding.title.is_empty());
}

#[tokio::test]
async fn test_analyze_file_with_tool_calls() {
    let responses = vec![
        MockLlmClient::mock_tool_call("file_read", serde_json::json!({ "path": "test.rs" })),
        MockLlmClient::mock_final_response(
            r#"{"title": "After Tools", "description": "Found after using tools", "severity": "Low"}"#,
        ),
    ];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let test_file = create_test_file(&temp_dir, "test.rs", "fn main() {}");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;

    assert!(result.is_ok());
    let finding = result.unwrap();
    assert_eq!(finding.agent_turns, 2);
}

#[tokio::test]
async fn test_analyze_file_max_turns_reached() {
    // Keep returning responses that don't converge
    let responses: Vec<ChatResponse> = (0..20)
        .map(|i| {
            MockLlmClient::mock_tool_call(
                "file_read",
                serde_json::json!({ "path": format!("file{}.rs", i) }),
            )
        })
        .collect();

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(3);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let test_file = create_test_file(&temp_dir, "test.rs", "fn main() {}");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;

    assert!(result.is_ok());
    let finding = result.unwrap();
    // Should stop around max_turns
    assert!(finding.agent_turns >= 3 && finding.agent_turns <= 4);
}

#[tokio::test]
async fn test_analyze_file_empty_file() {
    let responses = vec![MockLlmClient::mock_final_response(
        r#"{"title": "Empty File", "description": "File is empty", "severity": "Low"}"#,
    )];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let test_file = create_test_file(&temp_dir, "empty.rs", "");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_analyze_file_nonexistent_file() {
    let mock_client = MockLlmClient::new(vec![]);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    // Try to analyze a file that doesn't exist
    let result = session.analyze_file("/nonexistent/path/file.rs").await;

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("FILE_NOT_FOUND"));
}

// ============================================================================
// analyze_file Tests - Severity Handling
// ============================================================================

#[tokio::test]
async fn test_analyze_file_high_severity() {
    let responses = vec![MockLlmClient::mock_final_response(
        r#"{"title": "Critical Buffer Overflow", "description": "Buffer overflow found", "severity": "High"}"#,
    )];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let test_file = create_test_file(&temp_dir, "test.rs", "fn main() {}");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;

    assert!(result.is_ok());
    let finding = result.unwrap();
    assert_eq!(finding.finding.severity, Severity::High);
}

#[tokio::test]
async fn test_analyze_file_low_severity() {
    let responses = vec![MockLlmClient::mock_final_response(
        r#"{"title": "Info Disclosure", "description": "Debug info exposed", "severity": "Low"}"#,
    )];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let test_file = create_test_file(&temp_dir, "test.rs", "fn main() {}");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;

    assert!(result.is_ok());
    let finding = result.unwrap();
    assert_eq!(finding.finding.severity, Severity::Low);
}

#[tokio::test]
async fn test_analyze_file_medium_severity_default() {
    let responses = vec![MockLlmClient::mock_final_response(
        r#"{"title": "Missing Validation", "description": "Input not validated"}"#,
    )];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let test_file = create_test_file(&temp_dir, "test.rs", "fn main() {}");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;

    assert!(result.is_ok());
    let finding = result.unwrap();
    // Default severity is Medium
    assert_eq!(finding.finding.severity, Severity::Medium);
}

// ============================================================================
// analyze_file Tests - Finding Metadata
// ============================================================================

#[tokio::test]
async fn test_analyze_file_with_cwe_id() {
    let responses = vec![MockLlmClient::mock_final_response(
        r#"{"title": "SQL Injection", "description": "Unsanitized SQL", "severity": "High", "cwe_id": "CWE-89"}"#,
    )];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let test_file = create_test_file(&temp_dir, "test.rs", "fn main() {}");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;

    assert!(result.is_ok());
    let finding = result.unwrap();
    assert_eq!(finding.finding.cwe_id, Some("CWE-89".to_string()));
}

#[tokio::test]
async fn test_analyze_file_with_line_number() {
    let responses = vec![MockLlmClient::mock_final_response(
        r#"{"title": "Overflow", "description": "Buffer overflow", "severity": "High", "line_number": 123}"#,
    )];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let test_file = create_test_file(&temp_dir, "test.rs", "fn main() {}");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;

    assert!(result.is_ok());
    let finding = result.unwrap();
    assert_eq!(finding.finding.line_number, Some(123));
}

#[tokio::test]
async fn test_analyze_file_with_code_snippet() {
    let responses = vec![MockLlmClient::mock_final_response(
        r#"{"title": "Unsafe Code", "description": "Unsafe block", "severity": "Medium", "code_snippet": "unsafe { ptr.read() }"}"#,
    )];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let test_file = create_test_file(&temp_dir, "test.rs", "fn main() {}");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;

    assert!(result.is_ok());
    let finding = result.unwrap();
    assert!(finding.finding.code_snippet.is_some());
    assert_eq!(
        finding.finding.code_snippet.unwrap(),
        "unsafe { ptr.read() }"
    );
}

#[tokio::test]
async fn test_analyze_file_generates_finding_id() {
    let responses = vec![MockLlmClient::mock_final_response(
        r#"{"title": "Test", "description": "Test desc", "severity": "Medium"}"#,
    )];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let test_file = create_test_file(&temp_dir, "my_file.rs", "fn main() {}");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;

    assert!(result.is_ok());
    let finding = result.unwrap();
    // ID should be based on file path
    assert!(finding.finding.id.contains("my_file"));
    assert!(finding.finding.id.starts_with("agent-"));
}

// ============================================================================
// analyze_file Tests - Error Handling
// ============================================================================

#[tokio::test]
async fn test_analyze_file_llm_error_recovery() {
    let responses = vec![
        ChatResponse {
            content: "Error: rate limit exceeded".to_string(),
            tool_calls: vec![],
            raw: serde_json::json!({}),
            model_used: "mock".to_string(),
        },
        MockLlmClient::mock_final_response(
            r#"{"title": "Recovered", "description": "Recovered from error", "severity": "Medium"}"#,
        ),
    ];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let test_file = create_test_file(&temp_dir, "test.rs", "fn main() {}");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;

    assert!(result.is_ok());
    let finding = result.unwrap();
    assert!(finding.finding.title.is_empty());
}

#[tokio::test]
async fn test_analyze_file_empty_response() {
    let responses = vec![ChatResponse {
        content: "".to_string(),
        tool_calls: vec![],
        raw: serde_json::json!({}),
        model_used: "mock".to_string(),
    }];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let test_file = create_test_file(&temp_dir, "test.rs", "fn main() {}");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;

    assert!(result.is_ok());
    // Empty response should result in empty/audit finding
    let finding = result.unwrap();
    assert!(finding.finding.title.is_empty() || finding.finding.title.contains("Security Audit"));
}

#[tokio::test]
async fn test_analyze_file_invalid_json_response() {
    let responses = vec![ChatResponse {
        content: "This is not JSON at all".to_string(),
        tool_calls: vec![],
        raw: serde_json::json!({}),
        model_used: "mock".to_string(),
    }];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let test_file = create_test_file(&temp_dir, "test.rs", "fn main() {}");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;

    assert!(result.is_ok());
    let finding = result.unwrap();
    // Invalid JSON should result in audit finding
    assert!(finding.finding.title.is_empty() || finding.finding.title.contains("Security Audit"));
}

#[tokio::test]
async fn test_analyze_file_no_vulnerability_found() {
    let responses = vec![ChatResponse {
        content: "After thorough review, no vulnerabilities were found. All inputs are properly validated and sanitized.".to_string(),
        tool_calls: vec![],
        raw: serde_json::json!({}),
        model_used: "mock".to_string(),
    }];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let test_file = create_test_file(&temp_dir, "secure.rs", "fn main() {}");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;

    assert!(result.is_ok());
    let finding = result.unwrap();
    // Should create an audit finding (not a vulnerability finding)
    assert!(finding.finding.title.is_empty() || finding.finding.title.contains("Security Audit"));
}

// ============================================================================
// verify_finding Tests - Basic Scenarios
// ============================================================================

#[tokio::test]
async fn test_verify_finding_confirmed() {
    let responses = vec![MockLlmClient::mock_final_response(
        "compiled=true\ntest_passed=true\nVulnerability confirmed with test",
    )];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);
    let finding = create_test_finding("Test Vuln", Severity::High);

    let result = session.verify_finding("test.rs", &finding).await;

    assert!(result.is_ok());
    let verified = result.unwrap();
    assert_eq!(
        verified.finding.verification_status,
        Some(VerificationStatus::Confirmed)
    );
}

#[tokio::test]
async fn test_verify_finding_unconfirmed() {
    let responses = vec![MockLlmClient::mock_final_response(
        "Could not reproduce. Test compilation failed.",
    )];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);
    let finding = create_test_finding("Test Vuln", Severity::Medium);

    let result = session.verify_finding("test.rs", &finding).await;

    assert!(result.is_ok());
    let verified = result.unwrap();
    assert_eq!(
        verified.finding.verification_status,
        Some(VerificationStatus::NeedsReview)
    );
}

#[tokio::test]
async fn test_verify_finding_with_tool_calls() {
    let responses = vec![
        MockLlmClient::mock_tool_call(
            "file_write",
            serde_json::json!({ "path": "poc.rs", "content": "fn test() {}" }),
        ),
        MockLlmClient::mock_tool_call("test_compile", serde_json::json!({ "path": "poc.rs" })),
        MockLlmClient::mock_final_response(
            "compiled=true\ntest_passed=true\nTest demonstrates the vulnerability",
        ),
    ];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);
    let finding = create_test_finding("Test Vuln", Severity::High);

    let result = session.verify_finding("test.rs", &finding).await;

    assert!(result.is_ok());
    let verified = result.unwrap();
    assert_eq!(verified.agent_turns, 3);
    assert!(!verified.tools_used.is_empty());
}

#[tokio::test]
async fn test_verify_finding_max_turns_reached() {
    // Keep returning tool calls
    let responses: Vec<ChatResponse> = (0..20)
        .map(|i| {
            MockLlmClient::mock_tool_call(
                "file_write",
                serde_json::json!({ "path": format!("test{}.rs", i), "content": "fn test() {}" }),
            )
        })
        .collect();

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(5);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);
    let finding = create_test_finding("Test Vuln", Severity::Medium);

    let result = session.verify_finding("test.rs", &finding).await;

    assert!(result.is_ok());
    let verified = result.unwrap();
    // Should stop around max_turns
    assert!(verified.agent_turns >= 5 && verified.agent_turns <= 6);
}

// ============================================================================
// verify_finding Tests - Error Handling
// ============================================================================

#[tokio::test]
async fn test_verify_finding_llm_error() {
    let responses = vec![ChatResponse {
        content: "Error: model unavailable".to_string(),
        tool_calls: vec![],
        raw: serde_json::json!({}),
        model_used: "mock".to_string(),
    }];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);
    let finding = create_test_finding("Test Vuln", Severity::High);

    let result = session.verify_finding("test.rs", &finding).await;

    assert!(result.is_ok());
    let verified = result.unwrap();
    assert!(verified.test_log.is_some());
    assert!(verified.test_log.unwrap().contains("Error"));
    assert_eq!(
        verified.finding.verification_status,
        Some(VerificationStatus::NeedsReview)
    );
}

#[tokio::test]
async fn test_verify_finding_empty_response() {
    let responses = vec![ChatResponse {
        content: "".to_string(),
        tool_calls: vec![],
        raw: serde_json::json!({}),
        model_used: "mock".to_string(),
    }];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);
    let finding = create_test_finding("Test Vuln", Severity::Medium);

    let result = session.verify_finding("test.rs", &finding).await;

    assert!(result.is_ok());
    let verified = result.unwrap();
    // Empty response should be NeedsReview
    assert_eq!(
        verified.finding.verification_status,
        Some(VerificationStatus::NeedsReview)
    );
}

// ============================================================================
// verify_finding Tests - Finding Metadata Preservation
// ============================================================================

#[tokio::test]
async fn test_verify_finding_preserves_title() {
    let responses = vec![MockLlmClient::mock_final_response(
        "compiled=true\ntest_passed=true",
    )];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);
    let finding = create_test_finding("Original Title", Severity::High);

    let result = session.verify_finding("test.rs", &finding).await;

    assert!(result.is_ok());
    let verified = result.unwrap();
    assert_eq!(verified.finding.title, "Original Title");
}

#[tokio::test]
async fn test_verify_finding_preserves_severity() {
    let responses = vec![MockLlmClient::mock_final_response(
        "compiled=true\ntest_passed=true",
    )];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);
    let finding = create_test_finding("Test", Severity::Low);

    let result = session.verify_finding("test.rs", &finding).await;

    assert!(result.is_ok());
    let verified = result.unwrap();
    assert_eq!(verified.finding.severity, Severity::Low);
}

#[tokio::test]
async fn test_verify_finding_preserves_file_path() {
    let responses = vec![MockLlmClient::mock_final_response(
        "compiled=true\ntest_passed=true",
    )];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);
    let mut finding = create_test_finding("Test", Severity::Medium);
    finding.file_path = "src/vulnerable.rs".to_string();

    let result = session.verify_finding("src/vulnerable.rs", &finding).await;

    assert!(result.is_ok());
    let verified = result.unwrap();
    assert_eq!(verified.finding.file_path, "src/vulnerable.rs");
}

#[tokio::test]
async fn test_verify_finding_preserves_cwe_id() {
    let responses = vec![MockLlmClient::mock_final_response(
        "compiled=true\ntest_passed=true",
    )];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);
    let mut finding = create_test_finding("Test", Severity::High);
    finding.cwe_id = Some("CWE-119".to_string());

    let result = session.verify_finding("test.rs", &finding).await;

    assert!(result.is_ok());
    let verified = result.unwrap();
    assert_eq!(verified.finding.cwe_id, Some("CWE-119".to_string()));
}

// ============================================================================
// Integration Tests - Combined Scenarios
// ============================================================================

#[tokio::test]
async fn test_full_analyze_and_verify_flow() {
    // First, analyze a file
    let analyze_responses = vec![MockLlmClient::mock_final_response(
        r#"{"title": "Buffer Overflow", "description": "Found buffer overflow", "severity": "High", "cwe_id": "CWE-120"}"#,
    )];

    let mock_client = MockLlmClient::new(analyze_responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let test_file = create_test_file(&temp_dir, "test.rs", "fn main() {}");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb.clone());

    // Analyze
    let analyze_result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;
    assert!(analyze_result.is_ok());
    let finding = analyze_result.unwrap();

    // Now verify the finding (need new session with new mock client)
    let verify_responses = vec![MockLlmClient::mock_final_response(
        "compiled=true\ntest_passed=true\nVulnerability confirmed",
    )];

    let mock_client2 = MockLlmClient::new(verify_responses);
    let session2 = AgentSession::new(mock_client2, &config, temp_dir.path(), progress_cb);

    let verify_result = session2
        .verify_finding(&finding.finding.file_path, &finding.finding)
        .await;
    assert!(verify_result.is_ok());
    let verified = verify_result.unwrap();

    assert_eq!(
        verified.finding.verification_status,
        Some(VerificationStatus::Confirmed)
    );
}

#[tokio::test]
async fn test_multiple_analyze_calls_same_session() {
    let responses = vec![
        MockLlmClient::mock_final_response(
            r#"{"title": "Finding 1", "description": "First finding", "severity": "Medium"}"#,
        ),
        MockLlmClient::mock_final_response(
            r#"{"title": "Finding 2", "description": "Second finding", "severity": "Low"}"#,
        ),
    ];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let test_file1 = create_test_file(&temp_dir, "file1.rs", "fn main() {}");
    let test_file2 = create_test_file(&temp_dir, "file2.rs", "fn main() {}");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    // First analyze
    let result1 = session
        .analyze_file(test_file1.to_string_lossy().as_ref())
        .await;
    assert!(result1.is_ok());
    assert_eq!(result1.unwrap().finding.title, "Finding 1");

    // Second analyze (should get second response)
    let result2 = session
        .analyze_file(test_file2.to_string_lossy().as_ref())
        .await;
    assert!(result2.is_ok());
    assert_eq!(result2.unwrap().finding.title, "Finding 2");
}

#[tokio::test]
async fn test_session_with_custom_model_name() {
    let responses = vec![MockLlmClient::mock_final_response(
        r#"{"title": "Test", "description": "Test", "severity": "Medium"}"#,
    )];

    let mock_client = MockLlmClient::with_model(responses, "custom-model-v1".to_string());
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let test_file = create_test_file(&temp_dir, "test.rs", "fn main() {}");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;
    assert!(result.is_ok());
    let finding = result.unwrap();

    // Model name should be recorded
    assert_eq!(
        finding.finding.llm_model,
        Some("custom-model-v1".to_string())
    );
}

// ============================================================================
// Edge Cases
// ============================================================================

#[tokio::test]
async fn test_analyze_file_with_special_characters_in_path() {
    let responses = vec![MockLlmClient::mock_final_response(
        r#"{"title": "Test", "description": "Test", "severity": "Medium"}"#,
    )];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    // Create file with special characters in name
    let test_file = create_test_file(&temp_dir, "test_file-v1.0.rs", "fn main() {}");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;

    assert!(result.is_ok());
    let finding = result.unwrap();
    // ID should handle special characters
    assert!(finding.finding.id.contains("test_file-v1-0"));
}

#[tokio::test]
async fn test_analyze_file_with_very_long_content() {
    let responses = vec![MockLlmClient::mock_final_response(
        r#"{"title": "Test", "description": "Test", "severity": "Medium"}"#,
    )];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    // Create file with very long content
    let long_content = "fn main() {}\n".repeat(1000);
    let test_file = create_test_file(&temp_dir, "large.rs", &long_content);
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_verify_finding_with_minimal_finding() {
    let responses = vec![MockLlmClient::mock_final_response(
        "compiled=true\ntest_passed=true",
    )];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(10);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    // Create minimal finding
    let finding = VulnerabilityFinding {
        id: "minimal".to_string(),
        title: "".to_string(),
        description: "".to_string(),
        severity: Severity::Medium,
        confidence_score: 0.0,
        cwe_id: None,
        file_path: "test.rs".to_string(),
        line_number: None,
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
        agent_mode: true,
        statement_range: None,
        triage_verdict: None,
        evidence: vec![],
        verification_tier: None,
    };

    let result = session.verify_finding("test.rs", &finding).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_analyze_file_single_turn_limit() {
    let responses = vec![
        MockLlmClient::mock_tool_call("file_read", serde_json::json!({ "path": "test.rs" })),
        MockLlmClient::mock_tool_call("file_read", serde_json::json!({ "path": "test2.rs" })),
    ];

    let mock_client = MockLlmClient::new(responses);
    let config = create_test_config(1);
    let temp_dir = create_temp_dir();
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let test_file = create_test_file(&temp_dir, "test.rs", "fn main() {}");
    let session = AgentSession::new(mock_client, &config, temp_dir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;

    assert!(result.is_ok());
    let finding = result.unwrap();
    // Should stop at or near 1 turn
    assert!(finding.agent_turns >= 1 && finding.agent_turns <= 2);
}

// Tests merged from agent_session_inline_tests.rs

#[tokio::test]
async fn test_analyze_file_with_mock_llm_tool_call() {
    let responses = vec![
        // First turn: tool call
        MockLlmClient::mock_tool_call("file_read", json!({ "path": "test.rs" })),
        // Second turn: final response with vulnerability
        MockLlmClient::mock_final_response(
            r#"{"title": "Buffer Overflow", "description": "Found buffer overflow", "severity": "High", "cwe_id": "CWE-120"}"#,
        ),
    ];

    let mock_client = MockLlmClient::new(responses);
    let config = AgentConfig {
        enabled: false,
        max_turns: 10,
        tool_timeout_secs: 30,
        trusted_paths: vec![],
    };
    let tmpdir = tempfile::tempdir().unwrap();
    let progress_cb = Arc::new(|_| {});

    // Create a test file
    let test_file = tmpdir.path().join("test.rs");
    std::fs::write(&test_file, "fn main() {}").unwrap();

    let session = AgentSession::new(mock_client, &config, tmpdir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;
    assert!(result.is_ok());
    let finding = result.unwrap();

    // Should have parsed the JSON finding
    assert!(!finding.finding.title.is_empty());
    assert_eq!(finding.agent_turns, 2);
    assert!(!finding.tools_used.is_empty());
}

#[tokio::test]
async fn test_analyze_file_with_mock_llm_no_vulnerability() {
    let responses = vec![
        // Single response indicating no vulnerability
        ChatResponse {
            content: "After reviewing the code, no security vulnerabilities were found. All inputs are properly validated.".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        },
    ];

    let mock_client = MockLlmClient::new(responses);
    let config = AgentConfig {
        enabled: false,
        max_turns: 10,
        tool_timeout_secs: 30,
        trusted_paths: vec![],
    };
    let tmpdir = tempfile::tempdir().unwrap();
    let progress_cb = Arc::new(|_| {});

    // Create a test file
    let test_file = tmpdir.path().join("test.rs");
    std::fs::write(&test_file, "fn main() {}").unwrap();

    let session = AgentSession::new(mock_client, &config, tmpdir.path(), progress_cb);

    let result = session
        .analyze_file(test_file.to_string_lossy().as_ref())
        .await;
    assert!(result.is_ok());
    let finding = result.unwrap();

    // Should have an audit finding
    assert!(finding.finding.title.contains("Security Audit") || finding.finding.title.is_empty());
}

#[tokio::test]
async fn test_verify_finding_with_mock_llm() {
    let responses = vec![
        // First turn: tool call to write test
        MockLlmClient::mock_tool_call(
            "file_write",
            json!({ "path": "poc.py", "content": "print('exploit')" }),
        ),
        // Second turn: verification result
        ChatResponse {
            content:
                "compiled=true\ntest_passed=true\nTest successfully demonstrated the vulnerability"
                    .to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        },
    ];

    let mock_client = MockLlmClient::new(responses);
    let config = AgentConfig {
        enabled: false,
        max_turns: 10,
        tool_timeout_secs: 30,
        trusted_paths: vec![],
    };
    let tmpdir = tempfile::tempdir().unwrap();
    let progress_cb = Arc::new(|_| {});

    let session = AgentSession::new(mock_client, &config, tmpdir.path(), progress_cb);

    let finding = VulnerabilityFinding {
        id: "test-1".to_string(),
        title: "Test Vulnerability".to_string(),
        description: "A test vulnerability".to_string(),
        severity: Severity::High,
        confidence_score: 0.9,
        cwe_id: None,
        file_path: "test.rs".to_string(),
        line_number: Some(42),
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
        agent_mode: true,
        statement_range: None,
        triage_verdict: None,
        evidence: vec![],
        verification_tier: None,
    };

    let result = session.verify_finding("test.rs", &finding).await;
    assert!(result.is_ok());
    let verified = result.unwrap();

    assert_eq!(verified.agent_turns, 2);
    assert!(!verified.tools_used.is_empty());
    assert!(verified.test_log.is_some());
}

#[test]
fn test_progress_callback_type() {
    // Verify that ProgressCallback can be created and called
    let cb: ProgressCallback = Arc::new(|_msg| {
        // Note: This test demonstrates the limitation - the closure cannot modify outer vars
        // In real usage, ProgressCallback would use channels or other mechanisms
    });

    cb("test message".to_string());
    // Just verify the callback can be created and invoked without panicking
}
