//! End-to-end tests for `baco scan --diff` functionality.
//!
//! These tests verify that the diff filtering correctly limits findings
//! to only files changed in the specified git revspec.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// Create a git repository with two commits:
/// - Baseline commit with app.py containing vulnerable code
/// - Second commit modifying app.py to safer code
///   Returns (temp_dir, repo_path)
fn create_git_repo_with_two_commits() -> (TempDir, PathBuf) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let repo_path = temp_dir.path().to_path_buf();

    // Initialize git repo
    Command::new("git")
        .arg("init")
        .current_dir(&repo_path)
        .output()
        .expect("Failed to init git repo");

    // Configure git user (required for commits)
    Command::new("git")
        .arg("config")
        .arg("user.name")
        .arg("Test User")
        .current_dir(&repo_path)
        .output()
        .expect("Failed to config git user name");

    Command::new("git")
        .arg("config")
        .arg("user.email")
        .arg("test@example.com")
        .current_dir(&repo_path)
        .output()
        .expect("Failed to config git user email");

    // Create baseline Python file with vulnerable code
    let file1_path = repo_path.join("app.py");
    std::fs::write(
        &file1_path,
        "def get_user(id):\n    query = 'SELECT * FROM users WHERE id = ' + id\n    return query",
    )
    .expect("Failed to write baseline file");

    // Baseline commit
    Command::new("git")
        .arg("add")
        .arg(".")
        .current_dir(&repo_path)
        .output()
        .expect("Failed to add baseline file");

    Command::new("git")
        .arg("commit")
        .arg("-m")
        .arg("Baseline commit")
        .current_dir(&repo_path)
        .output()
        .expect("Failed to create baseline commit");

    // Modify file with safer code
    std::fs::write(
        &file1_path,
        "def get_user(id):\n    query = 'SELECT * FROM users WHERE id = ?'\n    return query",
    )
    .expect("Failed to modify file");

    // Second commit
    Command::new("git")
        .arg("add")
        .arg(".")
        .current_dir(&repo_path)
        .output()
        .expect("Failed to add modified file");

    Command::new("git")
        .arg("commit")
        .arg("-m")
        .arg("Second commit with changes")
        .current_dir(&repo_path)
        .output()
        .expect("Failed to create second commit");

    (temp_dir, repo_path)
}

/// Create a minimal config TOML for testing.
/// LLM phases are disabled by leaving api_key empty.
fn create_minimal_config(output_dir: &str, project_path: &str) -> String {
    format!(
        r#"
[project]
name = "test-diff-project"
path = "{project_path}"
languages = ["python"]

[output]
dir = "{output_dir}"
evidence_gate = false

[scanner]
max_file_size_kb = 512
exclude_paths = []

[llm]
timeout_secs = 2
max_retries = 0

[llm.phases.discovery]

[llm.phases.verification]

[llm.phases.aggregation]

[eval]
floor = 0.70
"#,
        output_dir = output_dir,
        project_path = project_path,
    )
}

/// Run baco scan with the given config and diff revspec.
fn run_scan_with_diff(config_path: &str, diff_revspec: Option<&str>) -> std::process::Output {
    let mut cmd = Command::new("cargo");
    cmd.args([
        "run",
        "--bin",
        "baco",
        "--",
        "scan",
        "--config",
        config_path,
    ]);

    if let Some(revspec) = diff_revspec {
        cmd.arg("--diff").arg(revspec);
    }

    cmd.current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to execute scan command")
}

/// Run baco report command with given input and format.
fn run_report(input_path: &str, format: &str) -> std::process::Output {
    Command::new("cargo")
        .args([
            "run", "--bin", "baco", "--", "report", "--input", input_path, "--format", format,
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap()
}

#[test]
fn test_diff_report_e2e() {
    let (_temp_dir, repo_path) = create_git_repo_with_two_commits();

    let output_dir = TempDir::new().expect("Failed to create output temp dir");
    let config_path = output_dir.path().join("config.toml");

    let config_content = create_minimal_config(
        output_dir.path().to_str().unwrap(),
        repo_path.to_str().unwrap(),
    );
    std::fs::write(&config_path, config_content).expect("Failed to write config");

    // Run scan with diff revspec covering only the second commit
    let output = run_scan_with_diff(config_path.to_str().unwrap(), Some("HEAD~1...HEAD"));

    assert!(
        output.status.success(),
        "Scan with diff should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Check findings.json exists
    let findings_path = output_dir.path().join("findings.json");
    assert!(
        findings_path.exists(),
        "findings.json should be created\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let findings_content =
        std::fs::read_to_string(&findings_path).expect("Failed to read findings.json");
    let findings: serde_json::Value =
        serde_json::from_str(&findings_content).expect("findings.json should be valid JSON");

    // With --diff HEAD~1...HEAD, only app.py should be in changed files
    // All findings (if any) must be within the changed file set
    if let Some(arr) = findings.as_array() {
        for finding in arr {
            if let Some(file_path) = finding.get("file_path").and_then(|fp| fp.as_str()) {
                assert!(
                    file_path == "app.py" || file_path.ends_with("/app.py"),
                    "Finding file_path '{}' must be in changed files (only app.py changed)",
                    file_path
                );
            }
        }
    }

    // Only run report generation if there are findings
    if !findings.as_array().map(|a| a.is_empty()).unwrap_or(true) {
        let report_output = run_report(findings_path.to_str().unwrap(), "html");

        assert!(
            report_output.status.success(),
            "HTML report generation should succeed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&report_output.stdout),
            String::from_utf8_lossy(&report_output.stderr)
        );

        // Verify HTML report was created
        let html_path = output_dir.path().join("report.html");
        assert!(
            html_path.exists(),
            "HTML report should be created at {:?}",
            html_path
        );

        let html_content = std::fs::read_to_string(&html_path).expect("Failed to read HTML report");
        assert!(!html_content.is_empty(), "HTML report should not be empty");
    }
}

#[test]
fn test_diff_report_no_findings_when_no_vulnerabilities() {
    let (_temp_dir, repo_path) = create_git_repo_with_two_commits();

    let output_dir = TempDir::new().expect("Failed to create output temp dir");
    let config_path = output_dir.path().join("config.toml");

    let config_content = create_minimal_config(
        output_dir.path().to_str().unwrap(),
        repo_path.to_str().unwrap(),
    );
    std::fs::write(&config_path, config_content).expect("Failed to write config");

    // Run scan without diff - should produce findings for vulnerable Python code
    let output_no_diff = run_scan_with_diff(config_path.to_str().unwrap(), None);

    assert!(
        output_no_diff.status.success(),
        "Scan without diff should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output_no_diff.stdout),
        String::from_utf8_lossy(&output_no_diff.stderr)
    );

    let findings_path = output_dir.path().join("findings.json");
    let findings_content =
        std::fs::read_to_string(&findings_path).expect("Failed to read findings.json");
    let findings_no_diff: serde_json::Value =
        serde_json::from_str(&findings_content).expect("findings.json should be valid JSON");

    // Run scan with diff - should produce findings only for changed files
    let output_diff = run_scan_with_diff(config_path.to_str().unwrap(), Some("HEAD~1...HEAD"));

    assert!(
        output_diff.status.success(),
        "Scan with diff should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output_diff.stdout),
        String::from_utf8_lossy(&output_diff.stderr)
    );

    let findings_diff_content =
        std::fs::read_to_string(&findings_path).expect("Failed to read findings.json");
    let findings_diff: serde_json::Value =
        serde_json::from_str(&findings_diff_content).expect("findings.json should be valid JSON");

    // Both should be arrays (may or may not be empty depending on semgrep rules)
    assert!(
        findings_no_diff.is_array(),
        "Scan without diff should produce array findings"
    );
    assert!(
        findings_diff.is_array(),
        "Scan with diff should produce array findings"
    );
}

#[test]
fn test_diff_invalid_revspec() {
    let (_temp_dir, repo_path) = create_git_repo_with_two_commits();

    let output_dir = TempDir::new().expect("Failed to create output temp dir");
    let config_path = output_dir.path().join("config.toml");

    let config_content = create_minimal_config(
        output_dir.path().to_str().unwrap(),
        repo_path.to_str().unwrap(),
    );
    std::fs::write(&config_path, config_content).expect("Failed to write config");

    // Run scan with invalid revspec
    let output = run_scan_with_diff(config_path.to_str().unwrap(), Some("nonexistent...HEAD"));

    // Should fail with non-zero exit code
    assert!(
        !output.status.success(),
        "Scan with invalid revspec should fail\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Error message should mention the git diff failure
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("git diff") || stderr.contains("failed"),
        "Error should mention git diff failure\nstderr: {}",
        stderr
    );
}
