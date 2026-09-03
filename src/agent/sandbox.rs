use crate::agent::tool_schema::SandboxLike;
use crate::agent::ToolResult;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Error type for sandbox operations
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("Docker unavailable: {0}")]
    DockerUnavailable(String),
    #[error("Runtime error: {0}")]
    RuntimeError(String),
    #[error("Timeout after {0}s")]
    Timeout(u64),
}

pub struct ToolSandbox {
    pub(super) temp_dir: PathBuf,
    pub(super) timeout_secs: u64,
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
        let output = self
            .wait_with_output()
            .map_err(|e| format!("wait_with_output: {}", e))?;
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

    pub fn temp_dir(&self) -> &Path {
        &self.temp_dir
    }

    pub fn timeout_secs(&self) -> u64 {
        self.timeout_secs
    }

    pub fn resolve_safe_path(&self, path: &str) -> Result<PathBuf, String> {
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

    pub fn run_with_timeout(
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

    pub fn validate_test_source(&self, content: &str) -> Result<(), String> {
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

    pub fn create_temp_file(&self, path: &str, content: &str) -> Result<PathBuf, String> {
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

    pub fn is_path_allowed(&self, path: &Path) -> bool {
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
