//! Comprehensive unit tests for agent executor module
//!
//! Migrated from src/agent/executor.rs inline tests
//!
//! Tests cover:
//! - Agent finding creation (empty and audit findings)
//! - Tool execution flow and state transitions
//! - Error handling and edge cases
//! - Path capture for test/compile artifacts
//! - Message flow validation
//! - Progress callback behavior

use baco::agent::executor::{
    create_audit_finding, create_empty_finding, execute_tool_calls, ProgressCallback,
};
use baco::agent::sandbox::ToolSandbox;
use baco::agent::tool_schema::ToolRegistry;
use baco::agent::ToolCall;
use baco::llm::{ChatMessage, ChatResponse};
use std::sync::Arc;

#[allow(dead_code)]
fn create_progress_callback() -> ProgressCallback {
    Arc::new(|_| {})
}

#[allow(dead_code)]
fn setup_sandbox() -> (ToolSandbox, tempfile::TempDir) {
    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
    (sandbox, tmpdir)
}

#[test]
fn test_create_empty_finding() {
    let finding = create_empty_finding(
        "test.rs",
        1,
        vec!["tool1".to_string()],
        Some("test-model".to_string()),
    );

    assert!(finding.finding.id.is_empty());
    assert!(finding.finding.title.is_empty());
    assert!(finding.finding.description.is_empty());
    assert_eq!(finding.finding.severity, baco::findings::Severity::Low);
    assert_eq!(finding.finding.confidence_score, 0.0);
    assert_eq!(finding.finding.file_path, "test.rs");
    assert!(finding.finding.line_number.is_none());
    assert_eq!(finding.agent_turns, 1);
    assert_eq!(finding.tools_used, vec!["tool1".to_string()]);
    assert_eq!(finding.finding.llm_model, Some("test-model".to_string()));
    assert!(finding.finding.agent_mode);
}

#[test]
fn test_create_empty_finding_no_model() {
    let finding = create_empty_finding("test.rs", 1, vec![], None);

    assert!(finding.finding.llm_model.is_none());
    assert_eq!(finding.agent_turns, 1);
}

#[test]
fn test_create_audit_finding() {
    let reasoning = "No vulnerabilities found after thorough analysis";
    let finding = create_audit_finding(
        "test.rs",
        2,
        vec!["file_read".to_string()],
        reasoning.to_string(),
        Some("model".to_string()),
    );

    assert!(finding.finding.id.starts_with("agent-"));
    assert_eq!(
        finding.finding.title,
        "Security Audit - No Critical Vulnerabilities Detected"
    );
    assert_eq!(finding.finding.description, reasoning);
    assert_eq!(finding.finding.severity, baco::findings::Severity::Medium);
    assert_eq!(finding.finding.confidence_score, 0.7);
    assert_eq!(finding.finding.file_path, "test.rs");
    assert_eq!(finding.agent_turns, 2);
    assert_eq!(finding.tools_used, vec!["file_read".to_string()]);
}

#[test]
fn test_create_audit_finding_no_model() {
    let finding = create_audit_finding("test.rs", 1, vec![], "reasoning".to_string(), None);

    assert!(finding.finding.llm_model.is_none());
}

#[tokio::test]
async fn test_execute_tool_calls_single_tool() {
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(baco::agent::tools::FileReadTool));

    let tmpdir = tempfile::tempdir().unwrap();
    let path = tmpdir.path().join("test.txt");
    std::fs::write(&path, "hello").unwrap();

    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![ToolCall {
            id: Some("call_1".to_string()),
            name: "file_read".to_string(),
            arguments: serde_json::json!({ "path": "test.txt" }),
        }],
        raw: serde_json::json!({}),
        model_used: "test".to_string(),
    };

    let messages = vec![ChatMessage::user("test")];

    let (tools_used, test_path, compile_path, messages) = execute_tool_calls(
        &registry,
        &sandbox,
        &response,
        messages,
        &progress_cb,
        tmpdir.path(),
        1,
        10,
        "Turn",
    )
    .await;

    assert_eq!(tools_used, vec!["file_read".to_string()]);
    assert!(test_path.is_none());
    assert!(compile_path.is_none());
    assert_eq!(messages.len(), 3); // original + assistant call + user result
}

#[tokio::test]
async fn test_execute_tool_calls_file_write_path_capture() {
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(baco::agent::tools::FileWriteTool));

    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![ToolCall {
            id: Some("call_1".to_string()),
            name: "file_write".to_string(),
            arguments: serde_json::json!({ "path": "test.rs", "content": "fn main() {}" }),
        }],
        raw: serde_json::json!({}),
        model_used: "test".to_string(),
    };

    let messages = vec![ChatMessage::user("test")];

    let (tools_used, test_path, compile_path, _) = execute_tool_calls(
        &registry,
        &sandbox,
        &response,
        messages,
        &progress_cb,
        tmpdir.path(),
        1,
        10,
        "Turn",
    )
    .await;

    assert_eq!(tools_used, vec!["file_write".to_string()]);
    assert!(test_path.is_some());
    assert!(compile_path.is_none());
}

#[tokio::test]
async fn test_execute_tool_calls_test_compile_path_capture() {
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(baco::agent::tools::TestCompileTool));

    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![ToolCall {
            id: Some("call_1".to_string()),
            name: "test_compile".to_string(),
            arguments: serde_json::json!({ "source_path": "test.rs", "language": "rust" }),
        }],
        raw: serde_json::json!({}),
        model_used: "test".to_string(),
    };

    let messages = vec![ChatMessage::user("test")];

    let (tools_used, test_path, compile_path, _) = execute_tool_calls(
        &registry,
        &sandbox,
        &response,
        messages,
        &progress_cb,
        tmpdir.path(),
        1,
        10,
        "Turn",
    )
    .await;

    assert_eq!(tools_used, vec!["test_compile".to_string()]);
    assert!(test_path.is_none());
    assert!(compile_path.is_some());
}

#[tokio::test]
async fn test_execute_tool_calls_unknown_tool() {
    let registry = ToolRegistry::new();
    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![ToolCall {
            id: Some("call_1".to_string()),
            name: "unknown_tool".to_string(),
            arguments: serde_json::json!({}),
        }],
        raw: serde_json::json!({}),
        model_used: "test".to_string(),
    };

    let messages = vec![ChatMessage::user("test")];

    let (tools_used, _, _, messages) = execute_tool_calls(
        &registry,
        &sandbox,
        &response,
        messages,
        &progress_cb,
        tmpdir.path(),
        1,
        10,
        "Turn",
    )
    .await;

    assert!(tools_used.is_empty());
    assert_eq!(messages.len(), 1); // No new messages since tool not found
}

#[tokio::test]
async fn test_execute_tool_calls_tool_error() {
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(baco::agent::tools::FileReadTool));

    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![ToolCall {
            id: Some("call_1".to_string()),
            name: "file_read".to_string(),
            arguments: serde_json::json!({ "path": "nonexistent.txt" }),
        }],
        raw: serde_json::json!({}),
        model_used: "test".to_string(),
    };

    let messages = vec![ChatMessage::user("test")];

    let (_, _, _, messages) = execute_tool_calls(
        &registry,
        &sandbox,
        &response,
        messages,
        &progress_cb,
        tmpdir.path(),
        1,
        10,
        "Turn",
    )
    .await;

    // Should have assistant call + user error message
    assert_eq!(messages.len(), 3);
    assert!(messages[2].content.contains("error"));
}

#[tokio::test]
async fn test_execute_tool_calls_multiple_tools() {
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(baco::agent::tools::FileReadTool));
    registry.register(Box::new(baco::agent::tools::FileWriteTool));

    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![
            ToolCall {
                id: Some("call_1".to_string()),
                name: "file_read".to_string(),
                arguments: serde_json::json!({ "path": "test.txt" }),
            },
            ToolCall {
                id: Some("call_2".to_string()),
                name: "file_write".to_string(),
                arguments: serde_json::json!({ "path": "out.txt", "content": "test" }),
            },
        ],
        raw: serde_json::json!({}),
        model_used: "test".to_string(),
    };

    let messages = vec![ChatMessage::user("test")];

    let (tools_used, test_path, _, _) = execute_tool_calls(
        &registry,
        &sandbox,
        &response,
        messages,
        &progress_cb,
        tmpdir.path(),
        1,
        10,
        "Turn",
    )
    .await;

    assert_eq!(tools_used.len(), 2);
    assert!(tools_used.contains(&"file_read".to_string()));
    assert!(tools_used.contains(&"file_write".to_string()));
    assert!(test_path.is_some());
}

#[tokio::test]
async fn test_execute_tool_calls_duplicate_tool_calls() {
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(baco::agent::tools::FileReadTool));

    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    // Same tool called twice
    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![
            ToolCall {
                id: Some("call_1".to_string()),
                name: "file_read".to_string(),
                arguments: serde_json::json!({ "path": "test1.txt" }),
            },
            ToolCall {
                id: Some("call_2".to_string()),
                name: "file_read".to_string(),
                arguments: serde_json::json!({ "path": "test2.txt" }),
            },
        ],
        raw: serde_json::json!({}),
        model_used: "test".to_string(),
    };

    let messages = vec![ChatMessage::user("test")];

    let (tools_used, _, _, _) = execute_tool_calls(
        &registry,
        &sandbox,
        &response,
        messages,
        &progress_cb,
        tmpdir.path(),
        1,
        10,
        "Turn",
    )
    .await;

    // Should only track tool once even if called multiple times
    assert_eq!(tools_used.len(), 1);
    assert_eq!(tools_used[0], "file_read");
}

#[tokio::test]
async fn test_execute_tool_calls_empty_tool_calls() {
    let registry = ToolRegistry::new();
    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
    let progress_cb: ProgressCallback = Arc::new(|_| {});

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![],
        raw: serde_json::json!({}),
        model_used: "test".to_string(),
    };

    let messages = vec![ChatMessage::user("test")];

    let (tools_used, test_path, compile_path, messages) = execute_tool_calls(
        &registry,
        &sandbox,
        &response,
        messages,
        &progress_cb,
        tmpdir.path(),
        1,
        10,
        "Turn",
    )
    .await;

    assert!(tools_used.is_empty());
    assert!(test_path.is_none());
    assert!(compile_path.is_none());
    assert_eq!(messages.len(), 1); // No changes
}

#[test]
fn test_create_empty_finding_all_defaults() {
    let finding = create_empty_finding("test.rs", 0, vec![], None);

    assert!(finding.finding.id.is_empty());
    assert!(finding.finding.title.is_empty());
    assert!(finding.finding.description.is_empty());
    assert_eq!(finding.finding.severity, baco::findings::Severity::Low);
    assert_eq!(finding.finding.confidence_score, 0.0);
    assert_eq!(finding.agent_turns, 0);
    assert!(finding.tools_used.is_empty());
    assert!(finding.finding.llm_model.is_none());
    assert!(finding.finding.agent_mode);
}

#[test]
fn test_create_audit_finding_all_defaults() {
    let finding = create_audit_finding("test.rs", 0, vec![], "No issues".to_string(), None);

    assert!(finding.finding.id.starts_with("agent-"));
    assert!(finding.finding.title.contains("Security Audit"));
    assert_eq!(finding.finding.description, "No issues");
    assert_eq!(finding.finding.severity, baco::findings::Severity::Medium);
    assert_eq!(finding.finding.confidence_score, 0.7);
    assert_eq!(finding.agent_turns, 0);
    assert!(finding.finding.llm_model.is_none());
}
