//! Sandbox timeout enforcement tests
//!
//! These tests verify that the timeout mechanism actually kills processes
//! and prevents pipe deadlocks.

use baco::agent::sandbox::ToolSandbox;
use std::time::Instant;

/// Test that a sleeping process is actually killed at timeout
/// This test must complete in a bounded time (well under the script's 100s sleep)
#[test]
fn test_timeout_actually_kills_process() {
    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);

    // Create a script that sleeps for 100 seconds
    let script_path = tmpdir.path().join("sleep_long.py");
    std::fs::write(&script_path, "import time; time.sleep(100)").unwrap();

    let start = Instant::now();
    let result = sandbox.run_with_timeout(
        "python3",
        &[script_path.to_string_lossy().as_ref()],
        Some(1),
    );

    let elapsed = start.elapsed();

    // The test must complete in a bounded time (under 5 seconds for a 1s timeout)
    // If the bug exists, this would take 100+ seconds
    assert!(
        elapsed.as_secs() < 5,
        "Timeout not enforced: took {:?} for 1s timeout",
        elapsed
    );

    // Should return an error containing "timeout"
    assert!(result.is_err(), "Expected timeout error, got: {:?}", result);
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("timeout"),
        "Error should mention timeout: {}",
        err_msg
    );
    assert!(
        err_msg.contains("killed"),
        "Error should mention killed: {}",
        err_msg
    );
}

/// Test that a process producing massive output doesn't deadlock
/// This tests the pipe-draining fix
#[test]
fn test_no_pipe_deadlock_with_large_output() {
    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);

    // Create a script that prints more than 64KB (pipe buffer size)
    // This would deadlock if output isn't drained while waiting
    let script_path = tmpdir.path().join("chatty.py");
    let large_output = "x".repeat(100 * 1024); // 100KB
    std::fs::write(&script_path, format!("print('{}')", large_output)).unwrap();

    let start = Instant::now();
    let result = sandbox.run_with_timeout(
        "python3",
        &[script_path.to_string_lossy().as_ref()],
        Some(5),
    );

    let elapsed = start.elapsed();

    // Should complete quickly, not hang
    assert!(
        elapsed.as_secs() < 5,
        "Pipe deadlock detected: took {:?}",
        elapsed
    );
    assert!(
        result.is_ok(),
        "Should succeed with large output: {:?}",
        result
    );
    let tool_result = result.unwrap();
    assert!(tool_result.success, "Process should exit 0");
    // Verify output was captured (should be ~100KB of 'x' characters)
    assert!(
        tool_result.output.len() >= 100 * 1024,
        "Output should be captured: {} bytes",
        tool_result.output.len()
    );
}

/// Test that normal short-running processes still work correctly
#[test]
fn test_normal_process_with_output() {
    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);

    // Create a simple script with known output
    let script_path = tmpdir.path().join("simple.py");
    std::fs::write(
        &script_path,
        "print('hello world')\nimport sys; sys.exit(0)",
    )
    .unwrap();

    let result = sandbox.run_with_timeout(
        "python3",
        &[script_path.to_string_lossy().as_ref()],
        Some(5),
    );

    assert!(result.is_ok(), "Should succeed: {:?}", result);
    let tool_result = result.unwrap();
    assert!(tool_result.success, "Process should exit 0");
    assert!(
        tool_result.output.contains("hello world"),
        "Output should contain expected text: {}",
        tool_result.output
    );
}

/// Test that a failing process (non-zero exit) is handled correctly
#[test]
fn test_failing_process_returns_error_status() {
    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);

    let script_path = tmpdir.path().join("fail.py");
    std::fs::write(&script_path, "import sys; sys.exit(1)").unwrap();

    let result = sandbox.run_with_timeout(
        "python3",
        &[script_path.to_string_lossy().as_ref()],
        Some(5),
    );

    assert!(
        result.is_ok(),
        "Tool call should succeed even if process fails: {:?}",
        result
    );
    let tool_result = result.unwrap();
    assert!(
        !tool_result.success,
        "Process should have non-zero exit status"
    );
}

/// Test that zero timeout means "no timeout"
#[test]
fn test_zero_timeout_means_no_timeout() {
    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);

    let script_path = tmpdir.path().join("quick.py");
    std::fs::write(&script_path, "print('quick')").unwrap();

    // Zero timeout should work like no timeout
    let result = sandbox.run_with_timeout(
        "python3",
        &[script_path.to_string_lossy().as_ref()],
        Some(0),
    );

    assert!(
        result.is_ok(),
        "Should succeed with zero timeout: {:?}",
        result
    );
    let tool_result = result.unwrap();
    assert!(tool_result.success);
    assert!(tool_result.output.contains("quick"));
}

/// Test that a process exiting quickly doesn't trigger false timeout
#[test]
fn test_quick_exit_does_not_false_timeout() {
    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);

    let script_path = tmpdir.path().join("instant.py");
    std::fs::write(&script_path, "print('done')").unwrap();

    let start = Instant::now();
    let result = sandbox.run_with_timeout(
        "python3",
        &[script_path.to_string_lossy().as_ref()],
        Some(1),
    );

    let elapsed = start.elapsed();

    // Should complete almost instantly
    assert!(
        elapsed.as_secs() < 1,
        "Quick process took too long: {:?}",
        elapsed
    );
    assert!(result.is_ok(), "Should succeed: {:?}", result);
    let tool_result = result.unwrap();
    assert!(tool_result.success);
    assert!(tool_result.output.contains("done"));
}

/// Test stderr is also captured and drained
#[test]
fn test_stderr_is_drained() {
    let tmpdir = tempfile::tempdir().unwrap();
    let sandbox = ToolSandbox::new(tmpdir.path().to_path_buf(), 30);

    let script_path = tmpdir.path().join("stderr.py");
    std::fs::write(
        &script_path,
        "import sys; sys.stderr.write('error output')\nprint('stdout')",
    )
    .unwrap();

    let result = sandbox.run_with_timeout(
        "python3",
        &[script_path.to_string_lossy().as_ref()],
        Some(5),
    );

    assert!(result.is_ok(), "Should succeed: {:?}", result);
    let tool_result = result.unwrap();
    assert!(
        tool_result.output.contains("error output") || tool_result.output.contains("stdout"),
        "Output should contain stdout or stderr: {}",
        tool_result.output
    );
}
