use crate::agent::ToolResult;
use crate::agent::tool_schema::SandboxLike;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Reject source that shells out, scoped to the target language.
///
/// The real containment controls are path checks, the enforced process timeout and
/// core-dump suppression; this text filter is a secondary guard. Rust is exempt because
/// a harness for code that legitimately uses `unsafe` or `process::Command` must be
/// writable, and this tool exists to analyse exactly that kind of code.
fn validate_test_source_content(path: &str, content: &str) -> Result<(), String> {
    let dangerous_patterns: &[&str] = match Path::new(path).extension().and_then(|e| e.to_str()) {
        Some("py") => &["os.system", "subprocess.", "eval(", "exec(", "__import__"],
        Some("sh") => &["| sh", "| bash", "|sh", "|bash"],
        Some("rs") => &[],
        _ => &[
            "os.system",
            "subprocess.",
            "eval(",
            "exec(",
            "__import__",
            "| sh",
            "| bash",
            "|sh",
            "|bash",
        ],
    };
    for pat in dangerous_patterns {
        if content.contains(pat) {
            return Err(format!("Dangerous pattern: {}", pat));
        }
    }
    Ok(())
}

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

/// Validate that a resolved path is contained within the sandbox root.
///
/// Checks:
/// - Path is not absolute
/// - No `..` components in the path
/// - Final resolved path starts with canonicalized sandbox root
/// - Parent directory exists (does not create directories)
fn validate_path_containment(sandbox_root: &Path, user_path: &str) -> Result<PathBuf, String> {
    let path = Path::new(user_path);

    // Reject absolute paths
    if path.is_absolute() {
        return Err(format!("Absolute path not allowed: {}", user_path));
    }

    // Reject dot sequences before component analysis: encoded, spaced, and
    // separator-mixed variants are never legitimate sandbox paths.
    if user_path.contains("..") {
        return Err(format!("Path traversal: {}", user_path));
    }

    // Reject any path with `..` components
    if path
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(format!("Path traversal not allowed: {}", user_path));
    }

    // Join with sandbox root
    let full = sandbox_root.join(path);

    // Canonicalize the sandbox root for comparison
    let canonical_root = sandbox_root
        .canonicalize()
        .map_err(|e| format!("Cannot canonicalize sandbox root {:?}: {}", sandbox_root, e))?;

    // Check containment by canonicalizing the target if it exists,
    // or verifying the parent path structure is within bounds
    let final_check = if full.exists() {
        full.canonicalize()
            .map_err(|e| format!("Cannot canonicalize target {:?}: {}", full, e))?
    } else {
        // If the file doesn't exist, verify parent is within bounds
        if let Some(parent) = full.parent() {
            if parent.exists() {
                parent
                    .canonicalize()
                    .map_err(|e| format!("Cannot canonicalize parent {:?}: {}", parent, e))?
            } else {
                // Parent doesn't exist - check path components are safe
                // We already rejected .. and absolute, so join is safe
                canonical_root.join(parent.strip_prefix(&canonical_root).unwrap_or(parent))
            }
        } else {
            canonical_root.clone()
        }
    };

    if !final_check.starts_with(&canonical_root) {
        return Err(format!("Path escapes sandbox: {}", user_path));
    }

    Ok(full)
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
        let full = validate_path_containment(&self.temp_dir, path)?;
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
        let child = unsafe {
            Command::new(cmd)
                .args(args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .pre_exec(disable_core_dumps)
                .spawn()
        }
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
    fn validate_test_source(&self, path: &str, content: &str) -> Result<(), String> {
        validate_test_source_content(path, content)
    }
    fn create_temp_file(&self, path: &str, content: &str) -> Result<PathBuf, String> {
        self.validate_test_source(path, content)
            .map_err(|e| format!("Validation failed: {}", e))?;

        // Pre-condition: validate path containment before write
        let full = validate_path_containment(&self.temp_dir, path)?;

        // Write the file
        std::fs::File::create(&full)
            .and_then(|mut f| f.write_all(content.as_bytes()))
            .map_err(|e| format!("Write failed: {}", e))?;

        // Post-condition: verify containment after write (catches symlink swaps)
        let canonical_after = full
            .canonicalize()
            .map_err(|e| format!("Cannot canonicalize after write {:?}: {}", full, e))?;
        let canonical_root = self
            .temp_dir
            .canonicalize()
            .map_err(|e| format!("Cannot canonicalize sandbox root: {}", e))?;
        if !canonical_after.starts_with(&canonical_root) {
            // File was created via symlink outside sandbox - delete and error
            let _ = std::fs::remove_file(&full);
            return Err(format!("Path escapes sandbox after write: {}", path));
        }

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

/// Zero `RLIMIT_CORE` in the child, so a crashing fixture cannot write a multi-megabyte
/// core file into the directory the scanner was run from.
use crate::core_limit::disable_core_dumps;

impl WaitWithTimeout for std::process::Child {
    fn wait_with_timeout(mut self, dur: Duration) -> Result<Output, String> {
        // Zero timeout means "no timeout" — fall through to wait_with_output
        if dur.is_zero() {
            return self
                .wait_with_output()
                .map_err(|e| format!("wait_with_output: {}", e));
        }

        let deadline = Instant::now() + dur;

        // Take ownership of the pipes
        let mut stdout = self.stdout.take().expect("stdout should be piped");
        let mut stderr = self.stderr.take().expect("stderr should be piped");

        // Spawn threads to drain output while we poll (prevents pipe deadlock)
        let stdout_handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = std::io::Read::read_to_end(&mut stdout, &mut buf);
            buf
        });
        let stderr_handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = std::io::Read::read_to_end(&mut stderr, &mut buf);
            buf
        });

        // Poll for completion until deadline
        loop {
            if let Some(status) = self.try_wait().map_err(|e| format!("try_wait: {}", e))? {
                // Child exited normally or by signal before timeout
                let stdout_buf = stdout_handle.join().unwrap_or_default();
                let stderr_buf = stderr_handle.join().unwrap_or_default();
                return Ok(Output {
                    status,
                    stdout: stdout_buf,
                    stderr: stderr_buf,
                });
            }

            if Instant::now() >= deadline {
                // Timeout: kill the child
                let _ = self.kill();
                let _ = self.wait();

                let stdout_buf = stdout_handle.join().unwrap_or_default();
                let stderr_buf = stderr_handle.join().unwrap_or_default();

                return Err(format!(
                    "timeout after {}s (killed, stdout={} bytes, stderr={} bytes)",
                    dur.as_secs(),
                    stdout_buf.len(),
                    stderr_buf.len()
                ));
            }

            std::thread::sleep(Duration::from_millis(50));
        }
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
        let full = validate_path_containment(&self.temp_dir, path)?;
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
        let child = unsafe {
            Command::new(cmd)
                .args(args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .pre_exec(disable_core_dumps)
                .spawn()
        }
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

    pub fn validate_test_source(&self, path: &str, content: &str) -> Result<(), String> {
        validate_test_source_content(path, content)
    }

    pub fn create_temp_file(&self, path: &str, content: &str) -> Result<PathBuf, String> {
        self.validate_test_source(path, content)
            .map_err(|e| format!("Validation failed: {}", e))?;

        // Pre-condition: validate path containment before write
        let full = validate_path_containment(&self.temp_dir, path)?;

        // Write the file
        std::fs::File::create(&full)
            .and_then(|mut f| f.write_all(content.as_bytes()))
            .map_err(|e| format!("Write failed: {}", e))?;

        // Post-condition: verify containment after write (catches symlink swaps)
        let canonical_after = full
            .canonicalize()
            .map_err(|e| format!("Cannot canonicalize after write {:?}: {}", full, e))?;
        let canonical_root = self
            .temp_dir
            .canonicalize()
            .map_err(|e| format!("Cannot canonicalize sandbox root: {}", e))?;
        if !canonical_after.starts_with(&canonical_root) {
            // File was created via symlink outside sandbox - delete and error
            let _ = std::fs::remove_file(&full);
            return Err(format!("Path escapes sandbox after write: {}", path));
        }

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
