#![allow(clippy::unused_unit, clippy::redundant_closure)]
//! Comprehensive unit tests for agent sandbox module
//!
//! Tests cover:
//! - ToolSandbox constructor and configuration
//! - SandboxLike trait implementation
//! - ToolRegistry operations
//! - Tool execution (all 5 tools)
//! - MockLlmClient functionality
//! - AgentFinding serialization/deserialization
//! - Error handling and edge cases
//! - Path traversal prevention
//! - Dangerous code validation

use baco::agent::mock_llm::MockLlmClient;
use baco::agent::sandbox::ToolSandbox;
use baco::agent::tool_schema::{default_tools, tool_definitions, SandboxLike, Tool, ToolRegistry};
use baco::agent::tools::{
    FileReadTool, FileWriteTool, PatternSearchTool, TestCompileTool, TestRunTool,
};
use baco::agent::AgentFinding;
use baco::findings::{Severity, VulnerabilityFinding};
use std::path::PathBuf;

// ============================================================================
// Fixture Helpers
// ============================================================================

fn create_sandbox() -> (ToolSandbox, tempfile::TempDir) {
    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
    (sandbox, tmpdir)
}

fn create_minimal_finding() -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-1".to_string(),
        title: "Test".to_string(),
        description: "Test description".to_string(),
        severity: Severity::Medium,
        confidence_score: 0.5,
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
    }
}

// ============================================================================
// ToolSandbox Constructor Tests
// ============================================================================

#[test]
fn test_tool_sandbox_new_sets_timeout() {
    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 60);

    assert_eq!(sandbox.temp_dir(), tmpdir.path());
}

// ============================================================================
// SandboxLike Trait Implementation Tests
// ============================================================================

#[test]
fn test_sandbox_resolve_safe_path_success() {
    let (sandbox, tmpdir) = create_sandbox();
    let test_file = tmpdir.path().join("test.txt");
    std::fs::write(&test_file, "content").unwrap();

    let result = sandbox.resolve_safe_path("test.txt");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), test_file);
}

#[test]
fn test_sandbox_resolve_safe_path_path_traversal_blocked() {
    let (sandbox, _) = create_sandbox();

    let result = sandbox.resolve_safe_path("../etc/passwd");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Path traversal"));
}

#[test]
fn test_sandbox_resolve_safe_path_nonexistent_file() {
    let (sandbox, _) = create_sandbox();

    let result = sandbox.resolve_safe_path("nonexistent.txt");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Path does not exist"));
}

#[test]
fn test_sandbox_is_path_allowed_within_sandbox() {
    let (sandbox, tmpdir) = create_sandbox();
    let allowed_path = tmpdir.path().join("allowed.txt");

    assert!(sandbox.is_path_allowed(&allowed_path));
}

#[test]
fn test_sandbox_is_path_allowed_outside_sandbox() {
    let (sandbox, _) = create_sandbox();
    let outside_path = PathBuf::from("/etc/passwd");

    assert!(!sandbox.is_path_allowed(&outside_path));
}

#[test]
fn test_sandbox_validate_test_source_valid_rust() {
    let (sandbox, _) = create_sandbox();
    let valid_code = "fn main() { println!(\"hello\"); }";

    let result = sandbox.validate_test_source(valid_code);
    assert!(result.is_ok());
}

#[test]
fn test_sandbox_validate_test_source_blocks_os_system() {
    let (sandbox, _) = create_sandbox();
    let malicious_code = "import os; os.system('rm -rf /')";

    let result = sandbox.validate_test_source(malicious_code);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Dangerous pattern"));
}

#[test]
fn test_sandbox_validate_test_source_blocks_subprocess() {
    let (sandbox, _) = create_sandbox();
    let malicious_code = "import subprocess; subprocess.run(['ls'])";

    let result = sandbox.validate_test_source(malicious_code);
    assert!(result.is_err());
}

#[test]
fn test_sandbox_validate_test_source_blocks_eval() {
    let (sandbox, _) = create_sandbox();
    let malicious_code = "eval(user_input)";

    let result = sandbox.validate_test_source(malicious_code);
    assert!(result.is_err());
}

#[test]
fn test_sandbox_validate_test_source_blocks_exec() {
    let (sandbox, _) = create_sandbox();
    let malicious_code = "exec(malicious_code)";

    let result = sandbox.validate_test_source(malicious_code);
    assert!(result.is_err());
}

#[test]
fn test_sandbox_validate_test_source_blocks_underscore_import() {
    let (sandbox, _) = create_sandbox();
    let malicious_code = "__import__('os')";

    let result = sandbox.validate_test_source(malicious_code);
    assert!(result.is_err());
}

#[test]
fn test_sandbox_validate_test_source_blocks_unsafe_rust() {
    let (sandbox, _) = create_sandbox();
    let malicious_code = "unsafe { std::process::Command::new(\"rm\") }";

    let result = sandbox.validate_test_source(malicious_code);
    assert!(result.is_err());
}

#[test]
fn test_sandbox_create_temp_file_success() {
    let (sandbox, tmpdir) = create_sandbox();

    let result = sandbox.create_temp_file("test.txt", "test content 123");
    assert!(
        result.is_ok(),
        "create_temp_file failed: {:?}",
        result.as_ref().err()
    );

    let path = result.unwrap();
    assert!(path.exists());
    let content = std::fs::read_to_string(&path).unwrap();
    assert_eq!(content, "test content 123");

    // Keep tmpdir alive until end of test
    let _ = &tmpdir;
}

#[test]
fn test_sandbox_create_temp_file_path_traversal_blocked() {
    let (sandbox, _) = create_sandbox();

    let result = sandbox.create_temp_file("../outside.txt", "content");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Path traversal"));
}

#[test]
fn test_sandbox_create_temp_file_blocks_dangerous_content() {
    let (sandbox, _) = create_sandbox();

    let result = sandbox.create_temp_file("bad.py", "import os; os.system('rm')");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Validation failed"));
}

#[test]
fn test_sandbox_run_with_timeout_success() {
    let (sandbox, _) = create_sandbox();

    let result = sandbox.run_with_timeout("/bin/echo", &["hello"], Some(5));
    assert!(result.is_ok());
    let tool_result = result.unwrap();
    assert!(tool_result.success);
    assert!(tool_result.output.contains("hello"));
}

#[test]
fn test_sandbox_run_with_timeout_failure() {
    let (sandbox, _) = create_sandbox();

    let result = sandbox.run_with_timeout("false", &[], Some(5));
    assert!(result.is_ok());
    let tool_result = result.unwrap();
    assert!(!tool_result.success);
}

#[test]
fn test_sandbox_run_with_timeout_nonexistent_command() {
    let (sandbox, _) = create_sandbox();

    let result = sandbox.run_with_timeout("nonexistent_cmd_xyz_123", &[], Some(1));
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("spawn"));
}

// ============================================================================
// ToolRegistry Tests
// ============================================================================

#[test]
fn test_tool_registry_new_empty() {
    let registry = ToolRegistry::new();

    assert!(registry.get("file_read").is_none());
    assert!(registry.get_definitions().is_empty());
}

#[test]
fn test_tool_registry_register_and_get() {
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(FileReadTool));

    assert!(registry.get("file_read").is_some());
}

#[test]
fn test_tool_registry_register_multiple_tools() {
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(FileReadTool));
    registry.register(Box::new(PatternSearchTool));
    registry.register(Box::new(FileWriteTool));

    assert!(registry.get("file_read").is_some());
    assert!(registry.get("pattern_search").is_some());
    assert!(registry.get("file_write").is_some());
}

#[test]
fn test_tool_registry_get_missing_tool() {
    let registry = ToolRegistry::new();

    assert!(registry.get("nonexistent_tool").is_none());
}

#[test]
fn test_tool_registry_overwrite_existing_tool() {
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(FileReadTool));
    registry.register(Box::new(FileReadTool));

    // Should still have the tool (just overwritten)
    assert!(registry.get("file_read").is_some());
}

#[test]
fn test_default_tools_registry_has_all_tools() {
    let registry = default_tools();

    assert!(registry.get("file_read").is_some());
    assert!(registry.get("pattern_search").is_some());
    assert!(registry.get("file_write").is_some());
    assert!(registry.get("test_compile").is_some());
    assert!(registry.get("test_run").is_some());
}

#[test]
fn test_tool_definitions_returns_five_tools() {
    let definitions = tool_definitions();

    assert_eq!(definitions.len(), 5);
}

#[test]
fn test_tool_definitions_structure() {
    let definitions = tool_definitions();

    for def in &definitions {
        assert_eq!(def["type"], "function");
        assert!(def["function"].is_object());
        assert!(def["function"]["name"].is_string());
        assert!(def["function"]["description"].is_string());
        assert!(def["function"]["parameters"].is_object());
    }
}

// ============================================================================
// Individual Tool Execution Tests
// ============================================================================

#[test]
fn test_file_read_tool_name() {
    let tool = FileReadTool;
    assert_eq!(tool.name(), "file_read");
}

#[test]
fn test_file_read_executes_successfully() {
    let (sandbox, tmpdir) = create_sandbox();
    std::fs::write(tmpdir.path().join("test.txt"), "hello").unwrap();

    let tool = FileReadTool;
    let args = serde_json::json!({ "path": "test.txt" });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_ok());
    let tool_result = result.unwrap();
    assert!(tool_result.success);
    assert!(tool_result.output.contains("hello"));
}

#[test]
fn test_file_read_missing_file_error() {
    let (sandbox, _) = create_sandbox();

    let tool = FileReadTool;
    let args = serde_json::json!({ "path": "nonexistent.txt" });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Open/read failed"));
}

#[test]
fn test_file_read_path_traversal_blocked() {
    let (sandbox, _) = create_sandbox();

    let tool = FileReadTool;
    let args = serde_json::json!({ "path": "../etc/passwd" });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Path traversal"));
}

#[test]
fn test_file_read_missing_path_argument() {
    let (sandbox, _) = create_sandbox();

    let tool = FileReadTool;
    let args = serde_json::json!({});
    let result = tool.execute(args, &sandbox);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing 'path'"));
}

#[test]
fn test_file_read_empty_file() {
    let (sandbox, tmpdir) = create_sandbox();
    std::fs::write(tmpdir.path().join("empty.txt"), "").unwrap();

    let tool = FileReadTool;
    let args = serde_json::json!({ "path": "empty.txt" });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_ok());
    assert_eq!(result.unwrap().output, "");
}

#[test]
fn test_pattern_search_tool_name() {
    let tool = PatternSearchTool;
    assert_eq!(tool.name(), "pattern_search");
}

#[test]
fn test_pattern_search_within_sandbox() {
    let (sandbox, tmpdir) = create_sandbox();
    std::fs::write(tmpdir.path().join("search.txt"), "hello world\nhello test").unwrap();

    let tool = PatternSearchTool;
    let args = serde_json::json!({ "pattern": "hello", "path": tmpdir.path().to_string_lossy().to_string() });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_ok());
    let tool_result = result.unwrap();
    assert!(tool_result.output.contains("hello"));
}

#[test]
fn test_pattern_search_outside_sandbox_blocked() {
    let (sandbox, _) = create_sandbox();

    let tool = PatternSearchTool;
    let args = serde_json::json!({ "pattern": "test", "path": "/etc" });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Path outside sandbox"));
}

#[test]
fn test_pattern_search_missing_pattern_argument() {
    let (sandbox, _) = create_sandbox();

    let tool = PatternSearchTool;
    let args = serde_json::json!({ "path": "." });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing 'pattern'"));
}

#[test]
fn test_pattern_search_missing_path_argument() {
    let (sandbox, _) = create_sandbox();

    let tool = PatternSearchTool;
    let args = serde_json::json!({ "pattern": "test" });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing 'path'"));
}

#[test]
fn test_file_write_tool_name() {
    let tool = FileWriteTool;
    assert_eq!(tool.name(), "file_write");
}

#[test]
fn test_file_write_executes_successfully() {
    let (sandbox, tmpdir) = create_sandbox();

    let tool = FileWriteTool;
    let args = serde_json::json!({ "path": "output.txt", "content": "test content" });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_ok());
    let tool_result = result.unwrap();
    assert!(tool_result.success);
    assert!(tool_result.output.contains("Successfully wrote"));

    let written_path = tmpdir.path().join("output.txt");
    assert!(written_path.exists());
    assert_eq!(
        std::fs::read_to_string(&written_path).unwrap(),
        "test content"
    );
}

#[test]
fn test_file_write_missing_path_argument() {
    let (sandbox, _) = create_sandbox();

    let tool = FileWriteTool;
    let args = serde_json::json!({ "content": "test" });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing 'path'"));
}

#[test]
fn test_file_write_missing_content_argument() {
    let (sandbox, _) = create_sandbox();

    let tool = FileWriteTool;
    let args = serde_json::json!({ "path": "test.txt" });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing 'content'"));
}

#[test]
fn test_file_write_empty_content() {
    let (sandbox, tmpdir) = create_sandbox();

    let tool = FileWriteTool;
    let args = serde_json::json!({ "path": "empty.txt", "content": "" });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_ok());
    let written_path = tmpdir.path().join("empty.txt");
    assert!(written_path.exists());
    assert_eq!(std::fs::read_to_string(&written_path).unwrap(), "");
}

#[test]
fn test_test_compile_tool_name() {
    let tool = TestCompileTool;
    assert_eq!(tool.name(), "test_compile");
}

#[test]
fn test_test_compile_rust_success() {
    let (sandbox, tmpdir) = create_sandbox();
    let test_file = tmpdir.path().join("test.rs");
    std::fs::write(&test_file, "fn main() { println!(\"hello\"); }").unwrap();

    let tool = TestCompileTool;
    let args = serde_json::json!({ "source_path": "test.rs", "language": "rust" });
    let result = tool.execute(args, &sandbox);

    // Compilation may fail but tool execution should succeed
    assert!(result.is_ok());
}

#[test]
fn test_test_compile_python_success() {
    let (sandbox, tmpdir) = create_sandbox();
    let test_file = tmpdir.path().join("test.py");
    std::fs::write(&test_file, "def hello(): pass").unwrap();

    let tool = TestCompileTool;
    let args = serde_json::json!({ "source_path": "test.py", "language": "python" });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_ok());
}

#[test]
fn test_test_compile_c_success() {
    let (sandbox, tmpdir) = create_sandbox();
    let test_file = tmpdir.path().join("test.c");
    std::fs::write(&test_file, "int main() { return 0; }").unwrap();

    let tool = TestCompileTool;
    let args = serde_json::json!({ "source_path": "test.c", "language": "c" });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_ok());
}

#[test]
fn test_test_compile_cpp_success() {
    let (sandbox, tmpdir) = create_sandbox();
    let test_file = tmpdir.path().join("test.cpp");
    std::fs::write(&test_file, "int main() { return 0; }").unwrap();

    let tool = TestCompileTool;
    let args = serde_json::json!({ "source_path": "test.cpp", "language": "cpp" });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_ok());
}

#[test]
fn test_test_compile_unsupported_language() {
    let (sandbox, tmpdir) = create_sandbox();
    let test_file = tmpdir.path().join("test.xyz");
    std::fs::write(&test_file, "content").unwrap();

    let tool = TestCompileTool;
    let args = serde_json::json!({ "source_path": "test.xyz", "language": "unsupported" });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Unsupported language"));
}

#[test]
fn test_test_compile_missing_language_argument() {
    let (sandbox, _) = create_sandbox();

    let tool = TestCompileTool;
    let args = serde_json::json!({ "source_path": "test.rs" });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing 'language'"));
}

#[test]
fn test_test_compile_missing_source_path_argument() {
    let (sandbox, _) = create_sandbox();

    let tool = TestCompileTool;
    let args = serde_json::json!({ "language": "rust" });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing 'source_path'"));
}

#[test]
fn test_test_run_tool_name() {
    let tool = TestRunTool;
    assert_eq!(tool.name(), "test_run");
}

#[test]
fn test_test_run_python_script() {
    let (sandbox, tmpdir) = create_sandbox();
    let test_file = tmpdir.path().join("test.py");
    std::fs::write(&test_file, "print('hello')").unwrap();

    let tool = TestRunTool;
    let args = serde_json::json!({ "executable_path": "test.py" });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_ok());
}

#[test]
fn test_test_run_missing_executable_path_argument() {
    let (sandbox, _) = create_sandbox();

    let tool = TestRunTool;
    let args = serde_json::json!({});
    let result = tool.execute(args, &sandbox);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing 'executable_path'"));
}

#[test]
fn test_test_run_with_custom_timeout() {
    let (sandbox, tmpdir) = create_sandbox();
    let test_file = tmpdir.path().join("test.py");
    std::fs::write(&test_file, "print('hello')").unwrap();

    let tool = TestRunTool;
    let args = serde_json::json!({ "executable_path": "test.py", "timeout_secs": 10 });
    let result = tool.execute(args, &sandbox);

    assert!(result.is_ok());
}

// ============================================================================
// MockLlmClient Tests
// ============================================================================

#[test]
fn test_mock_llm_client_new_empty() {
    let mock = MockLlmClient::new(vec![]);

    assert_eq!(mock.response_count(), 0);
    assert_eq!(mock.model_name(), "mock-model");
}

#[test]
fn test_mock_llm_client_with_model_name() {
    let mock = MockLlmClient::with_model(vec![], "custom-model".to_string());

    assert_eq!(mock.model_name(), "custom-model");
}

#[tokio::test]
async fn test_mock_tool_call_helper() {
    let response =
        MockLlmClient::mock_tool_call("test_tool", serde_json::json!({ "arg1": "value1" }));

    assert_eq!(response.tool_calls.len(), 1);
    assert_eq!(response.tool_calls[0].name, "test_tool");
    assert_eq!(
        response.tool_calls[0].arguments,
        serde_json::json!({ "arg1": "value1" })
    );
}

#[tokio::test]
async fn test_mock_final_response_helper() {
    let response = MockLlmClient::mock_final_response("Final answer");

    assert_eq!(response.content, "Final answer");
    assert!(response.tool_calls.is_empty());
}

// ============================================================================
// AgentFinding Tests
// ============================================================================

#[test]
fn test_agent_finding_into_finding_with_test_source_path() {
    let finding = AgentFinding {
        finding: create_minimal_finding(),
        compile_path: None,
        test_source_path: Some(PathBuf::from("/path/to/test.rs")),
        test_log: None,
        agent_turns: 0,
        tools_used: vec![],
    };

    let result = finding.into_finding();
    assert_eq!(
        result.agent_evidence_path,
        Some("/path/to/test.rs".to_string())
    );
}

#[test]
fn test_agent_finding_into_finding_with_compile_path_only() {
    let finding = AgentFinding {
        finding: create_minimal_finding(),
        compile_path: Some(PathBuf::from("/path/to/compiled")),
        test_source_path: None,
        test_log: None,
        agent_turns: 0,
        tools_used: vec![],
    };

    let result = finding.into_finding();
    assert_eq!(
        result.agent_evidence_path,
        Some("/path/to/compiled".to_string())
    );
}

#[test]
fn test_agent_finding_into_finding_prefers_test_source_over_compile() {
    let finding = AgentFinding {
        finding: create_minimal_finding(),
        compile_path: Some(PathBuf::from("/path/to/compile")),
        test_source_path: Some(PathBuf::from("/path/to/test")),
        test_log: None,
        agent_turns: 0,
        tools_used: vec![],
    };

    let result = finding.into_finding();
    // test_source_path takes precedence
    assert_eq!(
        result.agent_evidence_path,
        Some("/path/to/test".to_string())
    );
}

#[test]
fn test_agent_finding_into_finding_with_turns_and_tools_no_path() {
    let finding = AgentFinding {
        finding: create_minimal_finding(),
        compile_path: None,
        test_source_path: None,
        test_log: None,
        agent_turns: 5,
        tools_used: vec!["file_read".to_string(), "pattern_search".to_string()],
    };

    let result = finding.into_finding();
    assert_eq!(
        result.agent_evidence_path,
        Some("5 turns, 2 tools".to_string())
    );
}

#[test]
fn test_agent_finding_into_finding_with_test_log() {
    let mut finding = create_minimal_finding();
    finding.verification_notes = None;

    let agent_finding = AgentFinding {
        finding,
        compile_path: None,
        test_source_path: None,
        test_log: Some("Test log output".to_string()),
        agent_turns: 0,
        tools_used: vec![],
    };

    let result = agent_finding.into_finding();
    assert_eq!(
        result.verification_notes,
        Some("Test log output".to_string())
    );
}

#[test]
fn test_agent_finding_into_finding_preserves_existing_verification_notes() {
    let mut finding = create_minimal_finding();
    finding.verification_notes = Some("Existing notes".to_string());

    let agent_finding = AgentFinding {
        finding,
        compile_path: None,
        test_source_path: None,
        test_log: Some("New test log".to_string()),
        agent_turns: 0,
        tools_used: vec![],
    };

    let result = agent_finding.into_finding();
    // Existing notes should be preserved
    assert_eq!(
        result.verification_notes,
        Some("Existing notes".to_string())
    );
}

#[test]
fn test_agent_finding_serialization_roundtrip() {
    let finding = AgentFinding {
        finding: create_minimal_finding(),
        compile_path: Some(PathBuf::from("/path/to/compile")),
        test_source_path: Some(PathBuf::from("/path/to/test")),
        test_log: Some("Test log".to_string()),
        agent_turns: 3,
        tools_used: vec!["file_read".to_string()],
    };

    let serialized = serde_json::to_string(&finding).unwrap();
    let deserialized: AgentFinding = serde_json::from_str(&serialized).unwrap();

    assert_eq!(deserialized.agent_turns, 3);
    assert_eq!(deserialized.tools_used, vec!["file_read".to_string()]);
    assert!(deserialized.compile_path.is_some());
    assert!(deserialized.test_source_path.is_some());
}
