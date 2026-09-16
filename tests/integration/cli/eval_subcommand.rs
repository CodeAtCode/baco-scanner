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
fn test_eval_partial_args_still_rejected() {
    // Supplying only one of --target/--ground-truth remains an error;
    // suite mode requires NO arguments at all (or --all)
    for args in [
        vec!["eval", "--target", "test"],
        vec!["eval", "--ground-truth", "test.json"],
        vec!["eval", "--findings", "findings.json"],
    ] {
        let output = std::process::Command::new("cargo")
            .args(["run", "--"])
            .args(&args)
            .output()
            .expect("Failed to run cargo");

        assert!(
            !output.status.success(),
            "Should exit non-zero with partial eval args: {:?}",
            args
        );
    }
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
// Suite Mode Tests (offline regression gate)
// ============================================================================

/// Run `cargo run --bin baco -- eval ...` with a controlled BACO_EVAL_FLOOR
fn run_baco_eval(args: &[&str], env_floor: Option<&str>) -> std::process::Output {
    let mut cmd = std::process::Command::new("cargo");
    cmd.args(["run", "--bin", "baco", "--", "eval"]).args(args);
    match env_floor {
        Some(value) => {
            cmd.env("BACO_EVAL_FLOOR", value);
        }
        None => {
            cmd.env_remove("BACO_EVAL_FLOOR");
        }
    }
    cmd.output().expect("Failed to run baco eval")
}

#[test]
fn test_eval_suite_no_args_runs_all_targets_offline() {
    let output = run_baco_eval(&[], None);

    assert!(
        output.status.success(),
        "Bare `baco eval` should run the suite and pass, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("EVAL SUITE (10 targets)"),
        "Should list 10 targets, got: {}",
        stdout
    );
    assert!(stdout.contains("php-sqli"), "Should include php-sqli row");
    assert!(stdout.contains("c-uaf"), "Should include c-uaf row");
    assert!(
        stdout.contains("Aggregate pass-rate: 100.00%"),
        "Should print a numeric aggregate of 100.00%, got: {}",
        stdout
    );
    assert!(stdout.contains("SUITE PASS"), "Should report suite pass");
}

#[test]
fn test_eval_suite_all_flag_matches_no_args() {
    let output = run_baco_eval(&["--all"], None);

    assert!(
        output.status.success(),
        "`baco eval --all` should behave like bare suite mode, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("EVAL SUITE (10 targets)"),
        "--all should run all 10 targets"
    );
    assert!(stdout.contains("Aggregate pass-rate: 100.00%"));
}

#[test]
fn test_eval_suite_raised_floor_fails() {
    // Floor 1.0 requires the aggregate to EXCEED 1.0, which is impossible:
    // the floor semantics are strictly-greater, so this must fail.
    let output = run_baco_eval(&[], Some("1.0"));

    assert!(
        !output.status.success(),
        "BACO_EVAL_FLOOR=1.0 must make the suite exit non-zero"
    );

    let combined = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("does not exceed floor"),
        "Should explain the floor failure, got: {}",
        combined
    );
}

#[test]
fn test_eval_suite_lowered_floor_passes() {
    let output = run_baco_eval(&[], Some("0.5"));

    assert!(
        output.status.success(),
        "BACO_EVAL_FLOOR=0.5 with a 100% aggregate should pass, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_eval_suite_invalid_floor_value_fails() {
    let output = run_baco_eval(&[], Some("not-a-number"));

    assert!(
        !output.status.success(),
        "An unparseable BACO_EVAL_FLOOR must fail loudly, not silently default"
    );
}

/// Write a temp config file containing the given `[eval]` floor and return its path.
fn write_eval_config(floor: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "baco-eval-cfg-{}-{}.toml",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, format!("[eval]\nfloor = {}\n", floor)).expect("write temp config");
    path
}

/// Like `run_baco_eval` but with an explicit `--config` argument.
fn run_baco_eval_with_config(
    args: &[&str],
    env_floor: Option<&str>,
    config: &std::path::Path,
) -> std::process::Output {
    let mut cmd = std::process::Command::new("cargo");
    cmd.args(["run", "--bin", "baco", "--", "eval"])
        .arg("--config")
        .arg(config)
        .args(args);
    match env_floor {
        Some(value) => {
            cmd.env("BACO_EVAL_FLOOR", value);
        }
        None => {
            cmd.env_remove("BACO_EVAL_FLOOR");
        }
    }
    cmd.output().expect("Failed to run baco eval")
}

#[test]
fn test_eval_suite_config_floor_used() {
    let config = write_eval_config("0.5");
    let output = run_baco_eval_with_config(&[], None, &config);

    assert!(
        output.status.success(),
        "config floor 0.5 with a 100% aggregate should pass, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Floor: 0.50 (eval.floor)"),
        "Should name eval.floor as the active source, got: {}",
        stdout
    );
}

#[test]
fn test_eval_suite_config_floor_one_fails() {
    // Strictly-greater semantics make floor 1.0 impossible to exceed
    let config = write_eval_config("1.0");
    let output = run_baco_eval_with_config(&[], None, &config);

    assert!(
        !output.status.success(),
        "config floor 1.0 must make the suite exit non-zero"
    );
}

#[test]
fn test_eval_suite_config_floor_invalid_rejected() {
    let config = write_eval_config("1.5");
    let output = run_baco_eval_with_config(&[], None, &config);

    assert!(
        !output.status.success(),
        "An out-of-range config floor must fail loudly"
    );

    let combined = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("between 0.0 and 1.0"),
        "Should explain the invalid floor, got: {}",
        combined
    );
}

#[test]
fn test_eval_suite_env_overrides_config_floor() {
    // env 0.5 must win over a config floor (1.0) that would fail the suite
    let config = write_eval_config("1.0");
    let output = run_baco_eval_with_config(&[], Some("0.5"), &config);

    assert!(
        output.status.success(),
        "BACO_EVAL_FLOOR=0.5 must override config floor 1.0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Floor: 0.50 (BACO_EVAL_FLOOR)"),
        "Should name BACO_EVAL_FLOOR as the active source, got: {}",
        stdout
    );
}

#[test]
fn test_eval_all_flag_rejects_combined_args() {
    let output = run_baco_eval(&["--all", "--target", "somewhere"], None);

    assert!(
        !output.status.success(),
        "--all combined with --target must be rejected"
    );
}

// ============================================================================
// Oracle / Fixture Consistency Tests (new targets)
// ============================================================================

#[test]
fn test_new_target_oracles_consistent_with_findings() {
    let new_targets = [
        "php-sqli",
        "php-xss",
        "js-eval",
        "js-path-traversal",
        "py-weak-hash",
        "py-cmdi",
        "c-sprintf",
        "c-uaf",
    ];

    for name in new_targets {
        let oracle_json = std::fs::read_to_string(oracle_path(name))
            .unwrap_or_else(|e| panic!("target {name}: oracle unreadable: {e}"));
        let oracle = baco::eval::parse_oracle(&oracle_json)
            .unwrap_or_else(|e| panic!("target {name}: oracle invalid: {e}"));
        assert_eq!(
            oracle.target, name,
            "oracle target field must match file stem"
        );

        let findings = baco::validation::validate_findings(&bundled_findings_path(name))
            .unwrap_or_else(|e| panic!("target {name}: findings fixture invalid: {e}"));

        let report = baco::eval::score_findings(&oracle, &findings);
        assert_eq!(
            report.matched,
            oracle.expected_findings.len(),
            "target {name}: every oracle finding must be matched by the findings fixture"
        );
        assert_eq!(
            report.false_flags, 0,
            "target {name}: findings fixture must not flag suppressed files"
        );
    }
}

#[test]
fn test_new_target_fixture_files_exist() {
    let new_targets: &[(&str, &str)] = &[
        ("php-sqli", "php"),
        ("php-xss", "php"),
        ("js-eval", "js"),
        ("js-path-traversal", "js"),
        ("py-weak-hash", "py"),
        ("py-cmdi", "py"),
        ("c-sprintf", "c"),
        ("c-uaf", "c"),
    ];

    for (name, ext) in new_targets {
        for role in ["vulnerable", "safe_twin", "innocent"] {
            let path = eval_fixture_path(&format!("{name}/{role}.{ext}"));
            assert!(
                path.is_file(),
                "target {name}: missing fixture file {}",
                path.display()
            );
        }
    }
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
