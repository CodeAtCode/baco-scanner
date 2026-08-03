//! Comprehensive unit tests for agent executor module
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
use baco::findings::Severity;
use baco::llm::{ChatMessage, ChatResponse};
use std::sync::Arc;

// ============================================================================
// Fixture Helpers
// ============================================================================

fn create_progress_callback() -> ProgressCallback {
    Arc::new(|_| {})
}

fn create_tool_registry_with_all_tools() -> ToolRegistry {
    use baco::agent::tools::{
        FileReadTool, FileWriteTool, PatternSearchTool, TestCompileTool, TestRunTool,
    };
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(FileReadTool));
    registry.register(Box::new(PatternSearchTool));
    registry.register(Box::new(FileWriteTool));
    registry.register(Box::new(TestCompileTool));
    registry.register(Box::new(TestRunTool));
    registry
}

fn make_test_response(tool_name: &str, args: serde_json::Value) -> ChatResponse {
    ChatResponse {
        content: "".to_string(),
        tool_calls: vec![ToolCall {
            id: Some("call_1".to_string()),
            name: tool_name.to_string(),
            arguments: args,
        }],
        raw: serde_json::json!({}),
        model_used: "test-model".to_string(),
    }
}

fn setup_sandbox() -> (ToolSandbox, tempfile::TempDir) {
    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
    (sandbox, tmpdir)
}

// ============================================================================
// Finding Creation Tests
// ============================================================================

#[test]
fn test_create_empty_finding_basic() {
    let finding = create_empty_finding("test.rs", 1, vec!["tool1".to_string()], None);

    assert!(finding.finding.id.is_empty());
    assert_eq!(finding.finding.file_path, "test.rs");
    assert_eq!(finding.agent_turns, 1);
    assert_eq!(finding.finding.severity, Severity::Low);
    assert_eq!(finding.finding.confidence_score, 0.0);
}

#[test]
fn test_create_empty_finding_with_model() {
    let finding = create_empty_finding(
        "src/main.rs",
        5,
        vec!["file_read".to_string()],
        Some("gpt-4".to_string()),
    );

    assert_eq!(finding.finding.llm_model, Some("gpt-4".to_string()));
    assert!(finding.finding.agent_mode);
}

#[test]
fn test_create_empty_finding_empty_tools() {
    let finding = create_empty_finding("test.rs", 0, vec![], None);

    assert!(finding.tools_used.is_empty());
    assert_eq!(finding.agent_turns, 0);
}

#[test]
fn test_create_audit_finding_basic() {
    let finding = create_audit_finding(
        "test.rs",
        1,
        vec![],
        "No vulnerabilities found".to_string(),
        None,
    );

    assert!(finding.finding.id.starts_with("agent-"));
    assert!(finding.finding.title.contains("Security Audit"));
    assert_eq!(finding.finding.severity, Severity::Medium);
    assert_eq!(finding.finding.confidence_score, 0.7);
}

#[test]
fn test_create_audit_finding_with_model() {
    let finding = create_audit_finding(
        "test.rs",
        2,
        vec!["file_read".to_string()],
        "Clean code".to_string(),
        Some("claude-3".to_string()),
    );

    assert_eq!(finding.finding.llm_model, Some("claude-3".to_string()));
    assert_eq!(finding.tools_used, vec!["file_read".to_string()]);
}

#[test]
fn test_create_audit_finding_id_format() {
    let finding = create_audit_finding("test.rs", 42, vec![], "Reasoning".to_string(), None);

    assert_eq!(finding.finding.id, "agent-42");
}

// ============================================================================
// Single Tool Execution Tests
// ============================================================================

#[tokio::test]
async fn test_execute_single_file_read() {
    let (sandbox, tmpdir) = setup_sandbox();
    std::fs::write(tmpdir.path().join("test.txt"), "hello world").unwrap();

    let registry = create_tool_registry_with_all_tools();
    let progress_cb = create_progress_callback();

    let response = make_test_response("file_read", serde_json::json!({ "path": "test.txt" }));
    let messages = vec![ChatMessage::user("initial message")];

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
    assert_eq!(messages.len(), 3);
}

#[tokio::test]
async fn test_execute_single_file_write() {
    let (sandbox, tmpdir) = setup_sandbox();
    let registry = create_tool_registry_with_all_tools();
    let progress_cb = create_progress_callback();

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![ToolCall {
            id: Some("call_1".to_string()),
            name: "file_write".to_string(),
            arguments: serde_json::json!({ "path": "output.rs", "content": "fn main() {}" }),
        }],
        raw: serde_json::json!({}),
        model_used: "test-model".to_string(),
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
    assert_eq!(test_path.unwrap().file_name().unwrap(), "output.rs");
    assert!(compile_path.is_none());
}

#[tokio::test]
async fn test_execute_single_test_compile() {
    let (sandbox, tmpdir) = setup_sandbox();
    let registry = create_tool_registry_with_all_tools();
    let progress_cb = create_progress_callback();

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![ToolCall {
            id: Some("call_1".to_string()),
            name: "test_compile".to_string(),
            arguments: serde_json::json!({ "source_path": "test.rs", "language": "rust" }),
        }],
        raw: serde_json::json!({}),
        model_used: "test-model".to_string(),
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
    assert!(compile_path.is_some());
    assert!(test_path.is_none());
}

// ============================================================================
// Multiple Tool Execution Tests
// ============================================================================

#[tokio::test]
async fn test_execute_multiple_tools_sequential() {
    let (sandbox, tmpdir) = setup_sandbox();
    std::fs::write(tmpdir.path().join("input.txt"), "data").unwrap();

    let registry = create_tool_registry_with_all_tools();
    let progress_cb = create_progress_callback();

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![
            ToolCall {
                id: Some("call_1".to_string()),
                name: "file_read".to_string(),
                arguments: serde_json::json!({ "path": "input.txt" }),
            },
            ToolCall {
                id: Some("call_2".to_string()),
                name: "file_write".to_string(),
                arguments: serde_json::json!({ "path": "output.txt", "content": "result" }),
            },
        ],
        raw: serde_json::json!({}),
        model_used: "test-model".to_string(),
    };

    let messages = vec![ChatMessage::user("test")];

    let (tools_used, _test_path, _, messages) = execute_tool_calls(
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
    assert_eq!(messages.len(), 5); // original + 2*(call+result)
}

#[tokio::test]
async fn test_execute_tools_unique_tracking() {
    let (sandbox, tmpdir) = setup_sandbox();
    std::fs::write(tmpdir.path().join("a.txt"), "a").unwrap();
    std::fs::write(tmpdir.path().join("b.txt"), "b").unwrap();

    let registry = create_tool_registry_with_all_tools();
    let progress_cb = create_progress_callback();

    // Same tool called multiple times
    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![
            ToolCall {
                id: Some("call_1".to_string()),
                name: "file_read".to_string(),
                arguments: serde_json::json!({ "path": "a.txt" }),
            },
            ToolCall {
                id: Some("call_2".to_string()),
                name: "file_read".to_string(),
                arguments: serde_json::json!({ "path": "b.txt" }),
            },
        ],
        raw: serde_json::json!({}),
        model_used: "test-model".to_string(),
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

    // Should track unique tools only
    assert_eq!(tools_used.len(), 1);
    assert_eq!(tools_used[0], "file_read");
}

#[tokio::test]
async fn test_execute_all_five_tools() {
    let (sandbox, tmpdir) = setup_sandbox();
    std::fs::write(tmpdir.path().join("test.txt"), "pattern").unwrap();

    let registry = create_tool_registry_with_all_tools();
    let progress_cb = create_progress_callback();

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
                name: "pattern_search".to_string(),
                arguments: serde_json::json!({ "pattern": ".*", "path": "." }),
            },
            ToolCall {
                id: Some("call_3".to_string()),
                name: "file_write".to_string(),
                arguments: serde_json::json!({ "path": "out.txt", "content": "x" }),
            },
            ToolCall {
                id: Some("call_4".to_string()),
                name: "test_compile".to_string(),
                arguments: serde_json::json!({ "source_path": "test.rs", "language": "rust" }),
            },
            ToolCall {
                id: Some("call_5".to_string()),
                name: "test_run".to_string(),
                arguments: serde_json::json!({ "source_path": "test.rs", "language": "rust" }),
            },
        ],
        raw: serde_json::json!({}),
        model_used: "test-model".to_string(),
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

    assert_eq!(tools_used.len(), 5);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_execute_tool_unknown_tool_name() {
    let (sandbox, tmpdir) = setup_sandbox();
    let registry = ToolRegistry::new(); // Empty registry
    let progress_cb = create_progress_callback();

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![ToolCall {
            id: Some("call_1".to_string()),
            name: "nonexistent_tool".to_string(),
            arguments: serde_json::json!({}),
        }],
        raw: serde_json::json!({}),
        model_used: "test-model".to_string(),
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
    assert_eq!(messages.len(), 1); // No messages added for unknown tool
}

#[tokio::test]
async fn test_execute_tool_file_read_missing_file() {
    let (sandbox, tmpdir) = setup_sandbox();
    let registry = create_tool_registry_with_all_tools();
    let progress_cb = create_progress_callback();

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![ToolCall {
            id: Some("call_1".to_string()),
            name: "file_read".to_string(),
            arguments: serde_json::json!({ "path": "nonexistent.txt" }),
        }],
        raw: serde_json::json!({}),
        model_used: "test-model".to_string(),
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

    assert_eq!(tools_used, vec!["file_read".to_string()]);
    assert_eq!(messages.len(), 3);
    // Error should be in the result message
    assert!(messages[2].content.contains("error"));
}

#[tokio::test]
async fn test_execute_tool_mixed_success_failure() {
    let (sandbox, tmpdir) = setup_sandbox();
    std::fs::write(tmpdir.path().join("exists.txt"), "data").unwrap();

    let registry = create_tool_registry_with_all_tools();
    let progress_cb = create_progress_callback();

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![
            ToolCall {
                id: Some("call_1".to_string()),
                name: "file_read".to_string(),
                arguments: serde_json::json!({ "path": "exists.txt" }),
            },
            ToolCall {
                id: Some("call_2".to_string()),
                name: "file_read".to_string(),
                arguments: serde_json::json!({ "path": "missing.txt" }),
            },
        ],
        raw: serde_json::json!({}),
        model_used: "test-model".to_string(),
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

    assert_eq!(tools_used, vec!["file_read".to_string()]);
    assert_eq!(messages.len(), 5); // Both tools still generate messages
}

// ============================================================================
// Edge Cases
// ============================================================================

#[tokio::test]
async fn test_execute_empty_tool_calls() {
    let (sandbox, tmpdir) = setup_sandbox();
    let registry = create_tool_registry_with_all_tools();
    let progress_cb = create_progress_callback();

    let response = ChatResponse {
        content: "Just text, no tools".to_string(),
        tool_calls: vec![],
        raw: serde_json::json!({}),
        model_used: "test-model".to_string(),
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
    assert_eq!(messages.len(), 1);
}

#[tokio::test]
async fn test_execute_tool_with_null_id() {
    let (sandbox, tmpdir) = setup_sandbox();
    std::fs::write(tmpdir.path().join("test.txt"), "data").unwrap();

    let registry = create_tool_registry_with_all_tools();
    let progress_cb = create_progress_callback();

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![ToolCall {
            id: None, // No ID
            name: "file_read".to_string(),
            arguments: serde_json::json!({ "path": "test.txt" }),
        }],
        raw: serde_json::json!({}),
        model_used: "test-model".to_string(),
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

    assert_eq!(tools_used, vec!["file_read".to_string()]);
}

#[tokio::test]
async fn test_execute_tool_with_empty_arguments() {
    let (sandbox, tmpdir) = setup_sandbox();
    let registry = create_tool_registry_with_all_tools();
    let progress_cb = create_progress_callback();

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![ToolCall {
            id: Some("call_1".to_string()),
            name: "file_read".to_string(),
            arguments: serde_json::json!({}), // Missing required path
        }],
        raw: serde_json::json!({}),
        model_used: "test-model".to_string(),
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

    // Tool is still tracked, but execution will fail
    assert_eq!(tools_used, vec!["file_read".to_string()]);
    assert_eq!(messages.len(), 3);
}

#[tokio::test]
async fn test_execute_with_many_turns_parameters() {
    let (sandbox, tmpdir) = setup_sandbox();
    std::fs::write(tmpdir.path().join("test.txt"), "data").unwrap();

    let registry = create_tool_registry_with_all_tools();
    let progress_cb = create_progress_callback();

    let response = make_test_response("file_read", serde_json::json!({ "path": "test.txt" }));
    let messages = vec![ChatMessage::user("test")];

    let (tools_used, _, _, messages) = execute_tool_calls(
        &registry,
        &sandbox,
        &response,
        messages,
        &progress_cb,
        tmpdir.path(),
        15,
        50,
        "Agent Turn",
    )
    .await;

    assert_eq!(tools_used, vec!["file_read".to_string()]);
    assert_eq!(messages.len(), 3);
}

// ============================================================================
// Path Capture Edge Cases
// ============================================================================

#[tokio::test]
async fn test_file_write_path_capture_with_subdir() {
    let (sandbox, tmpdir) = setup_sandbox();
    let registry = create_tool_registry_with_all_tools();
    let progress_cb = create_progress_callback();

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![ToolCall {
            id: Some("call_1".to_string()),
            name: "file_write".to_string(),
            arguments: serde_json::json!({ "path": "tests/test_main.rs", "content": "fn main() {}" }),
        }],
        raw: serde_json::json!({}),
        model_used: "test-model".to_string(),
    };

    let messages = vec![ChatMessage::user("test")];

    let (_, test_path, _, _) = execute_tool_calls(
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

    assert!(test_path.is_some());
    let path = test_path.unwrap();
    assert!(path.to_string_lossy().contains("tests/test_main.rs"));
}

#[tokio::test]
async fn test_test_compile_path_capture_with_subdir() {
    let (sandbox, tmpdir) = setup_sandbox();
    let registry = create_tool_registry_with_all_tools();
    let progress_cb = create_progress_callback();

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![ToolCall {
            id: Some("call_1".to_string()),
            name: "test_compile".to_string(),
            arguments: serde_json::json!({ "source_path": "integration/test.rs", "language": "rust" }),
        }],
        raw: serde_json::json!({}),
        model_used: "test-model".to_string(),
    };

    let messages = vec![ChatMessage::user("test")];

    let (_, _, compile_path, _) = execute_tool_calls(
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

    assert!(compile_path.is_some());
    let path = compile_path.unwrap();
    assert!(path.to_string_lossy().contains("integration/test.rs"));
}

#[tokio::test]
async fn test_file_write_missing_path_argument() {
    let (sandbox, tmpdir) = setup_sandbox();
    let registry = create_tool_registry_with_all_tools();
    let progress_cb = create_progress_callback();

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![ToolCall {
            id: Some("call_1".to_string()),
            name: "file_write".to_string(),
            arguments: serde_json::json!({ "content": "no path here" }),
        }],
        raw: serde_json::json!({}),
        model_used: "test-model".to_string(),
    };

    let messages = vec![ChatMessage::user("test")];

    let (_, test_path, _, _) = execute_tool_calls(
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

    // Path capture should be None when path argument is missing
    assert!(test_path.is_none());
}

#[tokio::test]
async fn test_test_compile_missing_source_path_argument() {
    let (sandbox, tmpdir) = setup_sandbox();
    let registry = create_tool_registry_with_all_tools();
    let progress_cb = create_progress_callback();

    let response = ChatResponse {
        content: "".to_string(),
        tool_calls: vec![ToolCall {
            id: Some("call_1".to_string()),
            name: "test_compile".to_string(),
            arguments: serde_json::json!({ "language": "rust" }),
        }],
        raw: serde_json::json!({}),
        model_used: "test-model".to_string(),
    };

    let messages = vec![ChatMessage::user("test")];

    let (_, _, compile_path, _) = execute_tool_calls(
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

    assert!(compile_path.is_none());
}

// ============================================================================
// Message Flow Tests
// ============================================================================

#[tokio::test]
async fn test_message_flow_preserves_initial_messages() {
    let (sandbox, tmpdir) = setup_sandbox();
    std::fs::write(tmpdir.path().join("test.txt"), "data").unwrap();

    let registry = create_tool_registry_with_all_tools();
    let progress_cb = create_progress_callback();

    let response = make_test_response("file_read", serde_json::json!({ "path": "test.txt" }));
    let messages = vec![
        ChatMessage::user("system prompt"),
        ChatMessage::assistant("assistant response"),
        ChatMessage::user("user question"),
    ];

    let (_, _, _, result_messages) = execute_tool_calls(
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

    assert_eq!(result_messages.len(), 5);
    assert_eq!(result_messages[0].content, "system prompt");
}

#[tokio::test]
async fn test_message_content_formatting() {
    let (sandbox, tmpdir) = setup_sandbox();
    std::fs::write(tmpdir.path().join("test.txt"), "data").unwrap();

    let registry = create_tool_registry_with_all_tools();
    let progress_cb = create_progress_callback();

    let response = make_test_response("file_read", serde_json::json!({ "path": "test.txt" }));
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

    assert!(messages[1].content.contains("Calling:"));
    assert!(messages[1].content.contains("file_read"));
    assert!(messages[1].content.contains("Args:"));
}

// ============================================================================
// Progress Callback Tests
// ============================================================================

#[test]
fn test_progress_callback_type_compatibility() {
    // Verify the progress callback type works with Arc
    let cb: ProgressCallback = Arc::new(|msg| {
        let _ = msg; // Use the parameter
    });

    cb("test message".to_string());
}

#[test]
fn test_progress_callback_with_closure() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let called = Arc::new(AtomicBool::new(false));
    let called_clone = called.clone();
    let cb: ProgressCallback = Arc::new(move |msg| {
        assert_eq!(msg, "progress update");
        called_clone.store(true, Ordering::SeqCst);
    });

    cb("progress update".to_string());
    assert!(called.load(Ordering::SeqCst));
}

// ============================================================================
// Finding Structure Tests
// ============================================================================

#[test]
fn test_agent_finding_severity_levels() {
    let empty = create_empty_finding("test.rs", 0, vec![], None);
    let audit = create_audit_finding("test.rs", 0, vec![], "reasoning".to_string(), None);

    assert_eq!(empty.finding.severity, Severity::Low);
    assert_eq!(audit.finding.severity, Severity::Medium);
}

#[test]
fn test_agent_finding_confidence_scores() {
    let empty = create_empty_finding("test.rs", 0, vec![], None);
    let audit = create_audit_finding("test.rs", 0, vec![], "reasoning".to_string(), None);

    assert_eq!(empty.finding.confidence_score, 0.0);
    assert_eq!(audit.finding.confidence_score, 0.7);
}

#[test]
fn test_agent_finding_agent_mode_flag() {
    let empty = create_empty_finding("test.rs", 0, vec![], None);
    let audit = create_audit_finding("test.rs", 0, vec![], "reasoning".to_string(), None);

    assert!(empty.finding.agent_mode);
    assert!(audit.finding.agent_mode);
}

// ============================================================================
// Tool Registry Integration Tests
// ============================================================================

#[test]
fn test_tool_registry_creation() {
    let registry = create_tool_registry_with_all_tools();

    // Verify tools are registered (can't directly access internal state,
    // but we can verify the registry is usable)
    assert!(registry.get("file_read").is_some());
    assert!(registry.get("file_write").is_some());
    assert!(registry.get("pattern_search").is_some());
    assert!(registry.get("test_compile").is_some());
    assert!(registry.get("test_run").is_some());
    assert!(registry.get("nonexistent").is_none());
}

#[tokio::test]
async fn test_executor_with_minimal_registry() {
    let (sandbox, tmpdir) = setup_sandbox();
    std::fs::write(tmpdir.path().join("test.txt"), "data").unwrap();

    // Create registry with only one tool
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(baco::agent::tools::FileReadTool));

    let progress_cb = create_progress_callback();

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
                name: "file_write".to_string(), // Not registered
                arguments: serde_json::json!({ "path": "out.txt", "content": "x" }),
            },
        ],
        raw: serde_json::json!({}),
        model_used: "test-model".to_string(),
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

    // Only file_read should be executed
    assert_eq!(tools_used, vec!["file_read".to_string()]);
    // Only 2 messages added (call + result for file_read)
    assert_eq!(messages.len(), 3);
}
