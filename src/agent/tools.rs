use crate::agent::tool_schema::{SandboxLike, Tool};
use crate::agent::ToolResult;
use std::io::Read;

pub struct FileReadTool;
impl Tool for FileReadTool {
    fn name(&self) -> &str {
        "file_read"
    }
    fn execute(
        &self,
        args: serde_json::Value,
        sandbox: &dyn SandboxLike,
    ) -> Result<ToolResult, String> {
        let path = args["path"].as_str().ok_or("Missing 'path' argument")?;
        let full_path = sandbox
            .resolve_safe_path(path)
            .map_err(|e| format!("Path error: {}", e))?;
        let mut content = String::new();
        std::fs::File::open(&full_path)
            .and_then(|mut f| f.read_to_string(&mut content))
            .map_err(|e| format!("Open/read failed: {}", e))?;
        Ok(ToolResult {
            tool_call_id: "file_read".to_string(),
            success: true,
            output: content,
        })
    }
}

pub struct PatternSearchTool;
impl Tool for PatternSearchTool {
    fn name(&self) -> &str {
        "pattern_search"
    }
    fn execute(
        &self,
        args: serde_json::Value,
        sandbox: &dyn SandboxLike,
    ) -> Result<ToolResult, String> {
        let pattern = args["pattern"]
            .as_str()
            .ok_or("Missing 'pattern' argument")?;
        let path = args["path"].as_str().ok_or("Missing 'path' argument")?;

        // Validate path is within sandbox
        let search_path = std::path::PathBuf::from(path);
        if !sandbox.is_path_allowed(&search_path) {
            return Err("Path outside sandbox".to_string());
        }

        let ctx = args
            .get("context_lines")
            .and_then(|v| v.as_i64())
            .unwrap_or(2) as usize;
        let output = std::process::Command::new("grep")
            .arg("-rn")
            .arg(format!("-C{}", ctx))
            .arg(pattern)
            .arg(path)
            .output()
            .map_err(|e| format!("grep failed: {}", e))?;
        Ok(ToolResult {
            tool_call_id: "pattern_search".to_string(),
            success: output.status.success(),
            output: String::from_utf8_lossy(&output.stdout).to_string(),
        })
    }
}

pub struct FileWriteTool;
impl Tool for FileWriteTool {
    fn name(&self) -> &str {
        "file_write"
    }
    fn execute(
        &self,
        args: serde_json::Value,
        sandbox: &dyn SandboxLike,
    ) -> Result<ToolResult, String> {
        let path = args["path"].as_str().ok_or("Missing 'path' argument")?;
        let content = args["content"]
            .as_str()
            .ok_or("Missing 'content' argument")?;
        sandbox
            .validate_test_source(content)
            .map_err(|e| format!("Validation failed: {}", e))?;
        let _ = sandbox
            .create_temp_file(path, content)
            .map_err(|e| format!("Write failed: {}", e))?;
        Ok(ToolResult {
            tool_call_id: "file_write".to_string(),
            success: true,
            output: format!("Successfully wrote to {}", path),
        })
    }
}

pub struct TestCompileTool;
impl Tool for TestCompileTool {
    fn name(&self) -> &str {
        "test_compile"
    }
    fn execute(
        &self,
        args: serde_json::Value,
        sandbox: &dyn SandboxLike,
    ) -> Result<ToolResult, String> {
        let source_path = args["source_path"]
            .as_str()
            .ok_or("Missing 'source_path' argument")?;
        let language = args["language"]
            .as_str()
            .ok_or("Missing 'language' argument")?
            .to_lowercase();
        sandbox
            .resolve_safe_path(source_path)
            .map_err(|e| format!("Path error: {}", e))?;
        let (cmd, args) = match language.as_str() {
            "rust" => ("rustc", vec!["--crate-type=lib", source_path]),
            "python" => ("python3", vec!["-m", "py_compile", source_path]),
            "c" => ("gcc", vec!["-c", source_path]),
            "cpp" => ("g++", vec!["-c", source_path]),
            _ => return Err(format!("Unsupported language: {}", language)),
        };
        let result = sandbox.run_with_timeout(cmd, &args.to_vec(), None)?;
        Ok(ToolResult {
            tool_call_id: "test_compile".to_string(),
            success: result.success,
            output: result.output,
        })
    }
}

pub struct TestRunTool;
impl Tool for TestRunTool {
    fn name(&self) -> &str {
        "test_run"
    }
    fn execute(
        &self,
        args: serde_json::Value,
        sandbox: &dyn SandboxLike,
    ) -> Result<ToolResult, String> {
        let path = args["executable_path"]
            .as_str()
            .ok_or("Missing 'executable_path' argument")?;
        let timeout: u64 = args
            .get("timeout_secs")
            .and_then(|v| v.as_i64())
            .unwrap_or(30)
            .try_into()
            .unwrap();
        let full = sandbox
            .resolve_safe_path(path)
            .map_err(|e| format!("Path error: {}", e))?;

        // Determine interpreter based on file extension
        let full_str = full.to_string_lossy().to_string();
        let (cmd, cmd_args) = if path.ends_with(".py") {
            ("python", vec![full_str.as_str()])
        } else if path.ends_with(".rs") {
            (
                "rustc",
                vec!["-o", "tmp_out", full_str.as_str(), "&&", "tmp_out"],
            )
        } else {
            // Try to execute directly
            (full_str.as_str(), vec![])
        };

        let result = sandbox.run_with_timeout(cmd, &cmd_args.to_vec(), Some(timeout))?;
        // Always return Ok() for test_run, even when test fails (non-zero exit)
        // The success field indicates if the process ran, not if it passed
        Ok(ToolResult {
            tool_call_id: "test_run".to_string(),
            success: true,
            output: result.output,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::sandbox::ToolSandbox;

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
}
