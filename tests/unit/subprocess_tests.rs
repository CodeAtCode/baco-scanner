//! `subprocess::run_with_timeout` bounds every child it spawns.

use baco::subprocess::run_with_timeout;
use std::time::{Duration, Instant};

#[test]
fn test_a_fast_command_returns_its_output() {
    let out = run_with_timeout("sh", ["-c", "echo hello"], Duration::from_secs(10))
        .expect("sh should run");
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello");
}

#[test]
fn test_a_hung_command_is_killed_and_reported_as_a_timeout() {
    let start = Instant::now();
    let err = run_with_timeout("sleep", ["30"], Duration::from_millis(300))
        .expect_err("a child that outlives its timeout must not be reported as success");

    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "the call must return when the timeout expires, not when the child exits"
    );
}

#[test]
fn test_output_larger_than_a_pipe_buffer_is_not_mistaken_for_a_hang() {
    // 256 KiB exceeds the 64 KiB pipe buffer, so a child writing to a pipe
    // would block until someone drained it.
    let out = run_with_timeout(
        "sh",
        ["-c", "head -c 262144 /dev/zero | tr '\\0' 'x'"],
        Duration::from_secs(10),
    )
    .expect("large output must still complete");

    assert_eq!(out.stdout.len(), 262144);
}

#[test]
fn test_a_missing_program_reports_not_found() {
    let err = run_with_timeout(
        "baco-definitely-not-a-real-binary",
        ["--version"],
        Duration::from_secs(5),
    )
    .expect_err("a missing program is an error, not empty output");

    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}
