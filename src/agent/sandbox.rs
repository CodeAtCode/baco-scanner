use crate::agent::tool_schema::SandboxLike;
use crate::agent::ToolResult;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

pub struct ToolSandbox {
    temp_dir: PathBuf,
    timeout_secs: u64,
}

impl SandboxLike for ToolSandbox {
    fn temp_dir(&self) -> &Path {
        &self.temp_dir
    }
    fn resolve_safe_path(&self, path: &str) -> Result<PathBuf, String> {
        // Check for path traversal before joining
        if path.contains("..") {
            return Err(format!("Path traversal: {}", path));
        }
        let full = self.temp_dir.join(path);
        if !full.exists() {
            return Err(format!("Path does not exist: {}", path));
        }
        Ok(full)
    }
    fn run_with_timeout(
        &self,
        cmd: &str,
        args: &[&str],
        timeout_secs: Option<u64>,
    ) -> Result<ToolResult, String> {
        let dur = Duration::from_secs(timeout_secs.unwrap_or(self.timeout_secs));
        let child = Command::new(cmd)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn {}: {}", cmd, e))?;
        let dur = child
            .wait_with_timeout(dur)
            .map_err(|e| format!("timeout/err: {}", e))?;
        let ec = dur.status.code().unwrap_or(-1);
        let out = format!(
            "{}{}",
            String::from_utf8_lossy(&dur.stdout),
            String::from_utf8_lossy(&dur.stderr)
        );
        // Trim whitespace from output for reliable matching
        Ok(ToolResult {
            tool_call_id: "sandbox".to_string(),
            success: ec == 0,
            output: out.trim().to_string(),
        })
    }
    fn validate_test_source(&self, content: &str) -> Result<(), String> {
        let dangerous_patterns = [
            "os.system",
            "subprocess.",
            "eval(",
            "exec(",
            "__import__",
            "| sh",
            "|bash",
            "unsafe",
            "process::Command",
        ];
        for pat in &dangerous_patterns {
            if content.contains(pat) {
                return Err(format!("Dangerous pattern: {}", pat));
            }
        }
        Ok(())
    }
    fn create_temp_file(&self, path: &str, content: &str) -> Result<PathBuf, String> {
        self.validate_test_source(content)
            .map_err(|e| format!("Validation failed: {}", e))?;
        // Check path traversal by looking for ".." in the input path
        if path.contains("..") {
            return Err(format!("Path traversal: {}", path));
        }
        let full = self.temp_dir.join(path);
        std::fs::File::create(&full)
            .and_then(|mut f| f.write_all(content.as_bytes()))
            .map_err(|e| format!("Write failed: {}", e))?;
        Ok(full)
    }
    fn is_path_allowed(&self, path: &Path) -> bool {
        let canonical = match path.canonicalize() {
            Ok(p) => p,
            Err(_) => {
                return match path.parent() {
                    Some(parent) => parent.starts_with(&self.temp_dir),
                    None => false,
                };
            }
        };
        canonical.starts_with(&self.temp_dir)
    }
}

trait WaitWithTimeout {
    fn wait_with_timeout(self, dur: Duration) -> Result<Output, String>;
}
impl WaitWithTimeout for std::process::Child {
    fn wait_with_timeout(mut self, dur: Duration) -> Result<Output, String> {
        if !dur.is_zero() {
            let deadline = Instant::now() + dur;
            while self.try_wait().map(|r| r.is_none()).unwrap_or(false) && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        // Use wait_with_output to capture stdout/stderr
        let output = self.wait_with_output().map_err(|e| format!("wait_with_output: {}", e))?;
        if output.status.code() == Some(-15) {
            return Err("timeout".to_string());
        }
        Ok(output)
    }
}

impl ToolSandbox {
    pub fn new(temp_dir: PathBuf, timeout_secs: u64) -> Self {
        Self {
            temp_dir,
            timeout_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_path_allowed_within_trusted() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
        let allowed_path = tmpdir.path().join("test.txt");
        let allowed = sandbox.is_path_allowed(&allowed_path);
        assert!(allowed);
    }

    #[test]
    fn test_is_path_allowed_blocks_traversal() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
        let outside_path = PathBuf::from("/etc/passwd");
        let allowed = sandbox.is_path_allowed(&outside_path);
        assert!(!allowed);
    }

    #[test]
    fn test_validate_test_source_valid_rust() {
        let sandbox = ToolSandbox::new(PathBuf::new(), 30);
        let valid_code = "fn main() { println!(\"hello\"); }";
        let result = sandbox.validate_test_source(valid_code);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_test_source_blocks_unsafe() {
        let sandbox = ToolSandbox::new(PathBuf::new(), 30);
        let malicious_code = "unsafe { std::process::Command::new(\"rm\") }";
        let result = sandbox.validate_test_source(malicious_code);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_test_source_valid_python() {
        let sandbox = ToolSandbox::new(PathBuf::new(), 30);
        let valid_code = "def hello(): pass";
        let result = sandbox.validate_test_source(valid_code);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_test_source_blocks_system() {
        let sandbox = ToolSandbox::new(PathBuf::new(), 30);
        let malicious_code = "import os; os.system(\"rm -rf /\")";
        let result = sandbox.validate_test_source(malicious_code);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_safe_path_success() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
        
        // Create a file first
        let test_file = tmpdir.path().join("test.txt");
        std::fs::write(&test_file, "content").unwrap();
        
        let result = sandbox.resolve_safe_path("test.txt");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_file);
    }

    #[test]
    fn test_resolve_safe_path_path_traversal() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
        
        let result = sandbox.resolve_safe_path("../etc/passwd");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Path traversal"));
    }

    #[test]
    fn test_resolve_safe_path_nonexistent() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
        
        let result = sandbox.resolve_safe_path("nonexistent.txt");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Path does not exist"));
    }

    #[test]
    fn test_create_temp_file_success() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
        
        let result = sandbox.create_temp_file("newfile.txt", "hello world");
        assert!(result.is_ok());
        
        let created_path = result.unwrap();
        assert!(created_path.exists());
        let content = std::fs::read_to_string(&created_path).unwrap();
        assert_eq!(content, "hello world");
    }

    #[test]
    fn test_create_temp_file_path_traversal() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
        
        let result = sandbox.create_temp_file("../outside.txt", "content");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Path traversal"));
    }

    #[test]
    fn test_create_temp_file_blocks_dangerous_content() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
        
        let result = sandbox.create_temp_file("bad.py", "import os; os.system('rm -rf /')");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Validation failed"));
    }

    #[test]
    fn test_run_with_timeout_success() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
        
        let result = sandbox.run_with_timeout("/bin/echo", &["hello"], Some(5));
        assert!(result.is_ok());
        let tool_result = result.unwrap();
        assert!(tool_result.success);
        assert!(tool_result.output.contains("hello"));
    }

    #[test]
    fn test_run_with_timeout_failure() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
        
        let result = sandbox.run_with_timeout("false", &[], Some(5));
        assert!(result.is_ok());
        let tool_result = result.unwrap();
        assert!(!tool_result.success);
    }

    #[test]
    fn test_is_path_allowed_nonexistent_path() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);
        
        // Path that doesn't exist but parent is within tempdir
        let non_existent = tmpdir.path().join("subdir").join("file.txt");
        let allowed = sandbox.is_path_allowed(&non_existent);
        assert!(allowed);
    }
}
