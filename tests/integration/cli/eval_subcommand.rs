//! Integration tests for the `baco eval` subcommand
//!
//! These tests verify the CLI parsing and basic functionality of the eval subcommand.

use std::path::PathBuf;

/// Get the path to an eval fixture file
fn eval_fixture_path(subpath: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("eval/fixtures")
        .join(subpath)
}

/// Get the path to an oracle JSON file
fn oracle_path(target: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("eval/oracles")
        .join(format!("{}.json", target))
}

/// Get the path to a bundled findings file (if available)
fn bundled_findings_path(target: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("eval/findings")
        .join(format!("{}.json", target))
}

// ============================================================================
// CLI Argument Parsing Tests
// ============================================================================

#[test]
fn test_eval_missing_target_exits_nonzero() {
    // Running eval without --target should fail
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "eval", "--ground-truth", "test.json"])
        .output()
        .expect("Failed to run cargo");

    assert!(
        !output.status.success(),
        "Should exit non-zero without --target"
    );
}

#[test]
fn test_eval_missing_ground_truth_exits_nonzero() {
    // Running eval without --ground-truth should fail
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "eval", "--target", "test"])
        .output()
        .expect("Failed to run cargo");

    assert!(
        !output.status.success(),
        "Should exit non-zero without --ground-truth"
    );
}

#[test]
fn test_eval_requires_both_target_and_ground_truth() {
    // Both --target and --ground-truth are required
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "eval"])
        .output()
        .expect("Failed to run cargo");

    assert!(
        !output.status.success(),
        "Should exit non-zero with missing required args"
    );
}

// ============================================================================
// Scoring Tests with Bundled Findings
// ============================================================================

#[test]
fn test_eval_py_sqli_scoring_with_bundled_findings() {
    // Test scoring against py-sqli oracle with pre-computed findings
    let target_path = eval_fixture_path("py-sqli");
    let ground_truth = oracle_path("py-sqli");

    // Check if bundled findings exist
    let findings_path = bundled_findings_path("py-sqli");
    if !findings_path.exists() {
        // If no bundled findings, create a synthetic one for testing
        // This test verifies the scoring logic works with the oracle
        println!(
            "Skipping bundled findings test - no findings at {}",
            findings_path.display()
        );
        return;
    }

    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "--",
            "eval",
            "--target",
            target_path.to_str().unwrap(),
            "--ground-truth",
            ground_truth.to_str().unwrap(),
            "--findings",
            findings_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run eval");

    assert!(
        output.status.success(),
        "Eval should succeed with valid inputs"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("EVALUATION REPORT"),
        "Should print evaluation report"
    );
    assert!(stdout.contains("Recall"), "Should show recall metric");
    assert!(stdout.contains("Precision"), "Should show precision metric");
}

#[test]
fn test_eval_c_overflow_scoring_with_bundled_findings() {
    // Test scoring against c-overflow oracle
    let target_path = eval_fixture_path("c-overflow");
    let ground_truth = oracle_path("c-overflow");

    let findings_path = bundled_findings_path("c-overflow");
    if !findings_path.exists() {
        println!(
            "Skipping bundled findings test - no findings at {}",
            findings_path.display()
        );
        return;
    }

    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "--",
            "eval",
            "--target",
            target_path.to_str().unwrap(),
            "--ground-truth",
            ground_truth.to_str().unwrap(),
            "--findings",
            findings_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run eval");

    assert!(
        output.status.success(),
        "Eval should succeed with valid inputs"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("EVALUATION REPORT"),
        "Should print evaluation report"
    );
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_eval_nonexistent_ground_truth_fails() {
    // Running eval with non-existent ground truth should fail
    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "--",
            "eval",
            "--target",
            "test",
            "--ground-truth",
            "/nonexistent/oracle.json",
        ])
        .output()
        .expect("Failed to run cargo");

    assert!(
        !output.status.success(),
        "Should exit non-zero with non-existent ground truth"
    );

    // Check both stdout and stderr for error message
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{} {}", stdout, stderr);

    assert!(
        combined.contains("not found") || combined.contains("Failed"),
        "Should report file not found error, got: {}",
        combined
    );
}

#[test]
fn test_eval_nonexistent_findings_fails() {
    // Running eval with non-existent findings file should fail
    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "--",
            "eval",
            "--target",
            "test",
            "--ground-truth",
            "/nonexistent/oracle.json",
            "--findings",
            "/nonexistent/findings.json",
        ])
        .output()
        .expect("Failed to run cargo");

    assert!(
        !output.status.success(),
        "Should exit non-zero with non-existent files"
    );
}
