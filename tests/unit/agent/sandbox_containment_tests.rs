//! Security regression tests for sandbox containment bugs
//!
//! These tests verify fixes for three verified escape vectors:
//! - Bug A: TOCTOU in create_temp_file (symlink swap)
//! - Bug B: is_path_allowed .. bypass
//! - Bug C: FileReadTool bypasses resolve_safe_path

use baco::agent::sandbox::ToolSandbox;
use baco::agent::tool_schema::Tool;
use baco::agent::tools::FileReadTool;
use std::fs;
use std::os::unix::fs::symlink;
use tempfile::TempDir;

/// Create a fresh sandbox with a dedicated temp directory
fn setup_sandbox() -> (ToolSandbox, TempDir) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let sandbox = ToolSandbox::new(temp_dir.path().to_path_buf(), 30);
    (sandbox, temp_dir)
}

/// Bug A regression: TOCTOU in create_temp_file
///
/// After the fix: create_temp_file uses File::create_new which is atomic
/// and fails if the file already exists. Without create_new + O_NOFOLLOW,
/// an attacker could pre-create a file and have it clobbered.
///
/// Test strategy: pre-create a legitimate file in the sandbox, then attempt
/// to overwrite it via create_temp_file. With File::create (vulnerable), the
/// existing file gets clobbered (attack succeeds). With create_new (fixed),
/// the operation fails with an error (attack blocked).
#[test]
fn test_create_temp_file_rejects_symlink_swap() {
    let (sandbox, temp_dir) = setup_sandbox();
    let temp_path = temp_dir.path();

    // Pre-create a legitimate file inside the sandbox
    let target_path = temp_path.join("protected.txt");
    let original_content = "LEGITIMATE_SANDBOX_DATA";
    fs::write(&target_path, original_content).expect("Failed to create protected file");

    // Verify the file exists with original content
    let before_content = fs::read_to_string(&target_path).expect("Failed to read protected file");
    assert_eq!(before_content, original_content);

    // Attempt to create a file at the same path via create_temp_file
    // With File::create (vulnerable): clobbers existing file (attack succeeds)
    // With create_new (fixed): errors because file already exists (attack blocked)
    let result = sandbox.create_temp_file("protected.txt", "ATTACKER_CONTENT");

    // Should fail - create_new requires non-existent path
    assert!(
        result.is_err(),
        "create_temp_file should fail when target file already exists"
    );

    let err_msg = result.unwrap_err();
    // Error should mention file existence
    assert!(
        err_msg.contains("exists") || err_msg.contains("already"),
        "Error should mention file existence, got: {}",
        err_msg
    );

    // Verify the original file was NOT clobbered
    let after_content = fs::read_to_string(&target_path).expect("Failed to read protected file");
    assert_eq!(
        after_content, original_content,
        "Original file content must not be clobbered"
    );
}

/// Bug B regression: is_path_allowed .. bypass
///
/// After the fix: is_path_allowed rejects any path with .. components
/// and canonicalizes before containment check.
#[test]
fn test_path_validation_rejects_dotdot_traversal() {
    let (sandbox, temp_dir) = setup_sandbox();
    let temp_path = temp_dir.path();

    // Create a subdirectory inside the sandbox so that paths using .. through
    // it have an existing parent — without the explicit .. rejection, the
    // parent-exists check would pass and allow the traversal.
    let subdir = temp_path.join("subdir");
    fs::create_dir(&subdir).expect("Failed to create subdir");

    // Paths with .. that resolve through the existing subdir should be
    // rejected by the explicit .. check, not by the parent-doesn't-exist
    // fallback.
    let dangerous_paths = vec![
        "subdir/../escape.txt",
        "subdir/../../etc/passwd",
        "../etc/passwd",
        "subdir/./../other.txt",
    ];

    for dangerous_path in dangerous_paths {
        let path = std::path::Path::new(dangerous_path);
        let result = sandbox.is_path_allowed(path);
        assert!(
            !result,
            "Path with .. traversal should be rejected: {}",
            dangerous_path
        );
    }

    // Verify legitimate paths still work
    let legitimate_path = temp_path.join("legitimate.txt");
    assert!(
        sandbox.is_path_allowed(&legitimate_path),
        "Legitimate file should be allowed"
    );

    // Verify the subdir itself is allowed
    assert!(
        sandbox.is_path_allowed(&subdir),
        "Existing subdir should be allowed"
    );
}

/// Bug B teeth test: verify .. rejection has real teeth
///
/// This test creates a scenario where removing the .. check would allow
/// path traversal that escapes the sandbox. The test MUST fail if the
/// .. component check is removed from is_path_allowed.
#[test]
fn test_dotdot_rejection_has_teeth() {
    let (sandbox, _temp_dir) = setup_sandbox();
    let temp_path = sandbox.temp_dir();

    // Create a path that uses .. to escape the sandbox
    // This path: subdir/../../outside.txt
    // - subdir exists inside sandbox
    // - .. goes to sandbox root
    // - .. goes OUTSIDE sandbox
    // - outside.txt is the target
    //
    // Without the .. check, is_path_allowed would:
    // 1. Try to canonicalize the path
    // 2. Fail because the path doesn't exist
    // 3. Fall back to checking if parent starts with temp_dir
    // 4. The parent (sandbox root) DOES start with temp_dir
    // 5. So it would return TRUE (allowing the escape!)
    //
    // With the .. check, it returns FALSE immediately

    // First, create a subdirectory so the path has a valid starting point
    let subdir = temp_path.join("subdir");
    fs::create_dir(&subdir).expect("Failed to create subdir");

    // This path uses .. to escape: subdir/../.. escapes to parent of sandbox
    let escape_path = std::path::Path::new("subdir/../../outside.txt");

    // The path should be rejected because it contains ..
    let result = sandbox.is_path_allowed(escape_path);
    assert!(
        !result,
        "Path with .. that escapes sandbox must be rejected: {:?}",
        escape_path
    );

    // Additional verification: a path that stays within sandbox after .. resolution
    // should also be rejected (the .. check is unconditional)
    let intra_sandbox_path = std::path::Path::new("subdir/../legitimate.txt");
    let result2 = sandbox.is_path_allowed(intra_sandbox_path);
    assert!(
        !result2,
        "Path with .. should be rejected even if it stays in sandbox: {:?}",
        intra_sandbox_path
    );
}

/// Bug C regression: FileReadTool bypasses resolve_safe_path
///
/// After the fix: FileReadTool uses resolve_safe_path which validates
/// the canonical path is inside the sandbox and rejects symlinks.
#[test]
fn test_file_read_tool_rejects_symlink_escape() {
    let (sandbox, temp_dir) = setup_sandbox();
    let temp_path = temp_dir.path();

    // Create a file outside the sandbox with sensitive content
    let outside_file = temp_path.parent().unwrap().join("secret_data.txt");
    fs::write(&outside_file, "SENSITIVE_DATA_OUTSIDE_SANDBOX")
        .expect("Failed to create outside file");

    // Create a symlink inside temp_dir pointing to the outside file
    let symlink_path = temp_path.join("escape_link.txt");
    symlink(outside_file.as_path(), &symlink_path).expect("Failed to create symlink");

    // Verify the symlink exists and points outside
    assert!(symlink_path.is_symlink());
    let canonical = fs::canonicalize(&symlink_path).expect("Failed to canonicalize symlink");
    assert!(
        !canonical.starts_with(temp_path),
        "Symlink must point outside sandbox"
    );

    // Attempt to read through FileReadTool
    let tool = FileReadTool;
    let args = serde_json::json!({ "path": "escape_link.txt" });
    let result = tool.execute(args, &sandbox);

    // The operation must fail - we should NOT get the outside file's contents
    match result {
        Ok(tool_result) => {
            // If it succeeded, verify we didn't leak the outside content
            assert!(
                !tool_result
                    .output
                    .contains("SENSITIVE_DATA_OUTSIDE_SANDBOX"),
                "FileReadTool leaked content from outside sandbox via symlink!"
            );
        }
        Err(_) => {
            // Good - it rejected the symlink
        }
    }

    // Verify the outside file still exists
    assert!(outside_file.exists(), "Outside file should still exist");
}
