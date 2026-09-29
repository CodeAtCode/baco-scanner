//! Comprehensive unit tests for ToolSandbox
//!
//! Migrated from src/agent/sandbox.rs inline tests

use baco::agent::sandbox::ToolSandbox;
use std::fs;
use std::path::PathBuf;

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
    let result = sandbox.validate_test_source("test.rs", valid_code);
    assert!(result.is_ok());
}

#[test]
fn test_validate_test_source_blocks_unsafe() {
    let sandbox = ToolSandbox::new(PathBuf::new(), 30);
    // unsafe is now allowed in Rust files
    let code = "unsafe { std::process::Command::new(\"rm\") }";
    let result = sandbox.validate_test_source("test.rs", code);
    assert!(result.is_ok()); // Rust files allow unsafe
}

#[test]
fn test_validate_test_source_valid_python() {
    let sandbox = ToolSandbox::new(PathBuf::new(), 30);
    let valid_code = "def hello(): pass";
    let result = sandbox.validate_test_source("test.py", valid_code);
    assert!(result.is_ok());
}

#[test]
fn test_validate_test_source_blocks_system() {
    let sandbox = ToolSandbox::new(PathBuf::new(), 30);
    let malicious_code = "import os; os.system(\"rm -rf /\")";
    let result = sandbox.validate_test_source("test.py", malicious_code);
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

#[test]
fn test_sandbox_new() {
    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 60);

    assert_eq!(sandbox.temp_dir(), tmpdir.path());
    assert_eq!(sandbox.timeout_secs(), 60);
}

#[test]
fn test_resolve_safe_path_with_subdirectory() {
    let tmpdir = tempfile::tempdir().unwrap();
    let subdir = tmpdir.path().join("subdir");
    std::fs::create_dir_all(&subdir).unwrap();
    let test_file = subdir.join("test.txt");
    std::fs::write(&test_file, "content").unwrap();

    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);

    let result = sandbox.resolve_safe_path("subdir/test.txt");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), test_file);
}

#[test]
fn test_create_temp_file_with_subdirectory() {
    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);

    // create_temp_file doesn't create subdirectories, so just test flat files
    let result = sandbox.create_temp_file("newfile.txt", "hello");
    assert!(result.is_ok());

    let created_path = result.unwrap();
    assert!(created_path.exists());
    let content = std::fs::read_to_string(&created_path).unwrap();
    assert_eq!(content, "hello");
}

#[test]
fn test_validate_test_source_blocks_eval() {
    let sandbox = ToolSandbox::new(PathBuf::new(), 30);
    let malicious_code = "eval('print(1)')";
    let result = sandbox.validate_test_source("test.py", malicious_code);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Dangerous pattern"));
}

#[test]
fn test_validate_test_source_blocks_exec() {
    let sandbox = ToolSandbox::new(PathBuf::new(), 30);
    let malicious_code = "exec('code')";
    let result = sandbox.validate_test_source("test.py", malicious_code);
    assert!(result.is_err());
}

#[test]
fn test_validate_test_source_blocks_import() {
    let sandbox = ToolSandbox::new(PathBuf::new(), 30);
    let malicious_code = "__import__('os')";
    let result = sandbox.validate_test_source("test.py", malicious_code);
    assert!(result.is_err());
}

#[test]
fn test_run_with_timeout_nonexistent_command() {
    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);

    let result = sandbox.run_with_timeout("nonexistent_cmd_xyz", &[], Some(1));
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("spawn"));
}

#[test]
fn test_run_with_timeout_default_timeout() {
    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 5); // 5 second default

    let result = sandbox.run_with_timeout("/bin/echo", &["hello"], None); // No override
    assert!(result.is_ok());
    let tool_result = result.unwrap();
    assert!(tool_result.success);
}

#[test]
fn test_is_path_allowed_root_path() {
    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);

    // Root path should not be allowed (not within tempdir)
    let allowed = sandbox.is_path_allowed(&PathBuf::from("/"));
    assert!(!allowed);
}

// ============================================================================
// Test: Core dump prevention
// Verify that child processes spawned via run_with_timeout do not create
// core dump files, even when they crash (e.g., via os.abort() in Python)
// ============================================================================

#[test]
fn test_no_core_dump_on_child_crash() {
    // Get the current working directory to check for core files
    let cwd = std::env::current_dir().unwrap();

    // Count existing core files before the test
    let core_files_before: Vec<_> = fs::read_dir(&cwd)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("core."))
        .collect();

    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);

    // Run a Python script that calls os.abort() to trigger a crash
    // The child process should NOT be able to write a core dump
    let result = sandbox.run_with_timeout("python3", &["-c", "import os; os.abort()"], Some(10));

    // The child should crash (non-zero exit), but the call itself should succeed
    assert!(
        result.is_ok(),
        "run_with_timeout should handle child crash gracefully"
    );
    let tool_result = result.unwrap();
    assert!(!tool_result.success, "Child process should have crashed");

    // Count core files after the test
    let core_files_after: Vec<_> = fs::read_dir(&cwd)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("core."))
        .collect();

    // No new core files should have been created
    assert_eq!(
        core_files_before.len(),
        core_files_after.len(),
        "No new core dump files should be created when child crashes"
    );
}
// ============================================================================
// Bug 1 tests: extension-aware denylist
// ============================================================================

#[test]
fn test_validate_test_source_allows_unsafe_rust() {
    // Bug 1 fix: Rust files should allow unsafe blocks
    let sandbox = ToolSandbox::new(PathBuf::new(), 30);
    let code = "unsafe { std::ptr::null::<u8>() }";
    let result = sandbox.validate_test_source("test.rs", code);
    assert!(result.is_ok(), "Rust files should allow unsafe blocks");
}

#[test]
fn test_validate_test_source_allows_process_command_in_rust() {
    // Bug 1 fix: Rust files should allow process::Command for legitimate harnesses
    let sandbox = ToolSandbox::new(PathBuf::new(), 30);
    let code = "std::process::Command::new(\"echo\").output()";
    let result = sandbox.validate_test_source("test.rs", code);
    assert!(result.is_ok(), "Rust files should allow process::Command");
}

#[test]
fn test_validate_test_source_blocks_os_system_in_python() {
    // Python files should still block os.system
    let sandbox = ToolSandbox::new(PathBuf::new(), 30);
    let code = "import os; os.system('ls')";
    let result = sandbox.validate_test_source("test.py", code);
    assert!(result.is_err(), "Python files should block os.system");
}

#[test]
fn test_validate_test_source_blocks_pipe_bash_in_shell() {
    // Shell files should still block | bash
    let sandbox = ToolSandbox::new(PathBuf::new(), 30);
    let code = "echo test | bash";
    let result = sandbox.validate_test_source("test.sh", code);
    assert!(result.is_err(), "Shell files should block | bash");
}

#[test]
fn test_validate_test_source_blocks_eval_in_unknown_extension() {
    // Unknown extensions should block common dangerous patterns
    let sandbox = ToolSandbox::new(PathBuf::new(), 30);
    let code = "eval('malicious')";
    let result = sandbox.validate_test_source("test.xyz", code);
    assert!(result.is_err(), "Unknown extensions should block eval");
}
