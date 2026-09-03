//! Comprehensive unit tests for tool implementations
//!
//! Migrated from src/agent/tools.rs inline tests

use baco::agent::sandbox::ToolSandbox;
use baco::agent::tool_schema::Tool;
use baco::agent::tools::{
    FileReadTool, FileWriteTool, PatternSearchTool, TestCompileTool, TestRunTool,
};

#[test]
fn test_file_read_existing_file() {
    let tmpdir = tempfile::tempdir().unwrap();
    let path = tmpdir.path().join("test.txt");
    std::fs::write(&path, "hello world").unwrap();

    let tool = FileReadTool;
    let args = serde_json::json!({ "path": "test.txt" });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_ok());
    let output = result.unwrap().output;
    assert!(output.contains("hello world"));
}

#[test]
fn test_pattern_search_rejects_outside_sandbox() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tool = PatternSearchTool;
    let args = serde_json::json!({ "pattern": "test", "path": "/etc" });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_err());
}

#[test]
fn test_file_write_valid_content() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tool = FileWriteTool;
    let args = serde_json::json!({
        "path": "test.txt",
        "content": "valid content here"
    });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_ok());

    let written_path = tmpdir.path().join("test.txt");
    assert!(written_path.exists());
    let content = std::fs::read_to_string(&written_path).unwrap();
    assert!(content.contains("valid content here"));
}

#[test]
fn test_file_write_rejects_malicious_rust() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tool = FileWriteTool;
    let args = serde_json::json!({
        "path": "malicious.rs",
        "content": "unsafe { std::process::Command::new(\"rm\") }"
    });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_err());
}

#[test]
fn test_file_write_rejects_malicious_python() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tool = FileWriteTool;
    let args = serde_json::json!({
        "path": "malicious.py",
        "content": "import os; os.system(\"rm -rf /\")"
    });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_err());
}

#[test]
fn test_test_compile_valid_rust() {
    let tmpdir = tempfile::tempdir().unwrap();
    let path = tmpdir.path().join("test.rs");
    std::fs::write(&path, "fn main() { println!(\"hello\"); }").unwrap();

    let tool = TestCompileTool;
    let args = serde_json::json!({ "source_path": "test.rs", "language": "rust" });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_ok());
}

#[test]
fn test_test_compile_python() {
    let tmpdir = tempfile::tempdir().unwrap();
    let path = tmpdir.path().join("test.py");
    std::fs::write(&path, "def hello(): pass").unwrap();

    let tool = TestCompileTool;
    let args = serde_json::json!({ "source_path": "test.py", "language": "python" });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_ok());
}

#[test]
fn test_test_run_passing() {
    let tmpdir = tempfile::tempdir().unwrap();
    let path = tmpdir.path().join("pass.py");
    std::fs::write(&path, "import sys; sys.exit(0)").unwrap();

    let tool = TestRunTool;
    let args = serde_json::json!({ "executable_path": "pass.py" });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_ok());
}

#[test]
fn test_test_run_failing() {
    let tmpdir = tempfile::tempdir().unwrap();
    let path = tmpdir.path().join("fail.py");
    std::fs::write(&path, "import sys; sys.exit(1)").unwrap();

    let tool = TestRunTool;
    let args = serde_json::json!({ "executable_path": "fail.py" });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_ok());
    let output = result.unwrap().output;
    assert!(!output.contains("0"));
}

#[test]
fn test_file_read_missing_file() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tool = FileReadTool;
    let args = serde_json::json!({ "path": "nonexistent.txt" });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Open/read failed"));
}

#[test]
fn test_file_read_missing_path_argument() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tool = FileReadTool;
    let args = serde_json::json!({});
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing 'path'"));
}

#[test]
fn test_pattern_search_with_context_lines() {
    let tmpdir = tempfile::tempdir().unwrap();
    let path = tmpdir.path().join("search.txt");
    std::fs::write(&path, "line1\nline2\ntarget\nline4\nline5").unwrap();

    let tool = PatternSearchTool;
    let args = serde_json::json!({
        "pattern": "target",
        "path": tmpdir.path().to_string_lossy().to_string(),
        "context_lines": 1
    });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_ok());
    let output = result.unwrap().output;
    assert!(output.contains("target"));
}

#[test]
fn test_pattern_search_missing_pattern() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tool = PatternSearchTool;
    let args = serde_json::json!({ "path": "test.txt" });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing 'pattern'"));
}

#[test]
fn test_file_write_missing_content() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tool = FileWriteTool;
    let args = serde_json::json!({ "path": "test.txt" });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing 'content'"));
}

#[test]
fn test_file_write_missing_path() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tool = FileWriteTool;
    let args = serde_json::json!({ "content": "test" });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing 'path'"));
}

#[test]
fn test_test_compile_unsupported_language() {
    let tmpdir = tempfile::tempdir().unwrap();
    let path = tmpdir.path().join("test.xyz");
    std::fs::write(&path, "content").unwrap();

    let tool = TestCompileTool;
    let args = serde_json::json!({ "source_path": "test.xyz", "language": "unsupported" });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Unsupported language"));
}

#[test]
fn test_test_compile_missing_language() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tool = TestCompileTool;
    let args = serde_json::json!({ "source_path": "test.rs" });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing 'language'"));
}

#[test]
fn test_test_compile_cpp() {
    let tmpdir = tempfile::tempdir().unwrap();
    let path = tmpdir.path().join("test.cpp");
    std::fs::write(&path, "int main() { return 0; }").unwrap();

    let tool = TestCompileTool;
    let args = serde_json::json!({ "source_path": "test.cpp", "language": "cpp" });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_ok());
}

#[test]
fn test_test_compile_c() {
    let tmpdir = tempfile::tempdir().unwrap();
    let path = tmpdir.path().join("test.c");
    std::fs::write(&path, "int main() { return 0; }").unwrap();

    let tool = TestCompileTool;
    let args = serde_json::json!({ "source_path": "test.c", "language": "c" });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_ok());
}

#[test]
fn test_test_run_missing_executable_path() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tool = TestRunTool;
    let args = serde_json::json!({});
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing 'executable_path'"));
}

#[test]
fn test_test_run_with_custom_timeout() {
    let tmpdir = tempfile::tempdir().unwrap();
    let path = tmpdir.path().join("sleep.py");
    std::fs::write(&path, "import time; time.sleep(0.1)").unwrap();

    let tool = TestRunTool;
    let args = serde_json::json!({
        "executable_path": "sleep.py",
        "timeout_secs": 5
    });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_ok());
}

#[test]
fn test_file_read_path_traversal() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tool = FileReadTool;
    let args = serde_json::json!({ "path": "../etc/passwd" });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Path traversal"));
}

#[test]
fn test_pattern_search_missing_path() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tool = PatternSearchTool;
    let args = serde_json::json!({ "pattern": "test" });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing 'path'"));
}

#[test]
fn test_file_write_path_traversal() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tool = FileWriteTool;
    let args = serde_json::json!({
        "path": "../outside.txt",
        "content": "test"
    });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(err_msg.contains("Path traversal") || err_msg.contains("Validation"));
}

#[test]
fn test_test_compile_missing_source_path() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tool = TestCompileTool;
    let args = serde_json::json!({ "language": "rust" });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing 'source_path'"));
}

#[test]
fn test_test_run_with_timeout_secs() {
    let tmpdir = tempfile::tempdir().unwrap();
    let path = tmpdir.path().join("quick.py");
    std::fs::write(&path, "print('hello')").unwrap();

    let tool = TestRunTool;
    let args = serde_json::json!({
        "executable_path": "quick.py",
        "timeout_secs": 10
    });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_ok());
}

#[test]
fn test_file_read_empty_file() {
    let tmpdir = tempfile::tempdir().unwrap();
    let path = tmpdir.path().join("empty.txt");
    std::fs::write(&path, "").unwrap();

    let tool = FileReadTool;
    let args = serde_json::json!({ "path": "empty.txt" });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().output, "");
}

#[test]
fn test_pattern_search_empty_result() {
    let tmpdir = tempfile::tempdir().unwrap();
    let path = tmpdir.path().join("search.txt");
    std::fs::write(&path, "line1\nline2\nline3").unwrap();

    let tool = PatternSearchTool;
    let args = serde_json::json!({
        "pattern": "nonexistent",
        "path": tmpdir.path().to_string_lossy().to_string()
    });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_ok());
    // grep returns non-success when no match found
    let tool_result = result.unwrap();
    assert!(!tool_result.success);
    assert!(tool_result.output.is_empty());
}

#[test]
fn test_file_write_empty_content() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tool = FileWriteTool;
    let args = serde_json::json!({
        "path": "empty.txt",
        "content": ""
    });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    assert!(result.is_ok());

    let written_path = tmpdir.path().join("empty.txt");
    assert!(written_path.exists());
    let content = std::fs::read_to_string(&written_path).unwrap();
    assert_eq!(content, "");
}

#[test]
fn test_test_compile_with_whitespace_content() {
    let tmpdir = tempfile::tempdir().unwrap();
    let path = tmpdir.path().join("whitespace.rs");
    std::fs::write(&path, "   \n\n   ").unwrap();

    let tool = TestCompileTool;
    let args = serde_json::json!({ "source_path": "whitespace.rs", "language": "rust" });
    let sandbox = Box::new(ToolSandbox::new(tmpdir.path().to_path_buf(), 30));

    let result = tool.execute(args, &*sandbox);
    // Should fail to compile but tool execution should succeed
    assert!(result.is_ok());
}

#[test]
fn test_file_read_tool_name() {
    let tool = FileReadTool;
    assert_eq!(tool.name(), "file_read");
}

#[test]
fn test_pattern_search_tool_name() {
    let tool = PatternSearchTool;
    assert_eq!(tool.name(), "pattern_search");
}

#[test]
fn test_file_write_tool_name() {
    let tool = FileWriteTool;
    assert_eq!(tool.name(), "file_write");
}

#[test]
fn test_test_compile_tool_name() {
    let tool = TestCompileTool;
    assert_eq!(tool.name(), "test_compile");
}

#[test]
fn test_test_run_tool_name() {
    let tool = TestRunTool;
    assert_eq!(tool.name(), "test_run");
}
