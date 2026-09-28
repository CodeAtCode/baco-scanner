//! End-to-end tests for scan output generation.
//!
//! These tests verify that the `baco scan` command produces the expected output files
//! (findings.json, findings.md) and respects configuration flags like evidence_gate and quiet mode.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// Create a minimal config TOML for testing.
/// LLM phases are disabled by leaving api_key empty (they will skip gracefully).
fn create_minimal_config(
    _temp_dir: &TempDir,
    output_dir: &str,
    project_path: &str,
    evidence_gate: bool,
) -> String {
    format!(
        r#"
[project]
name = "test-vulnerable-project"
path = "{project_path}"
languages = ["python"]

[output]
dir = "{output_dir}"
evidence_gate = {evidence_gate}

[scanner]
max_file_size_kb = 512
exclude_paths = []

[llm]
timeout_secs = 2
max_retries = 0

# LLM phases disabled (no API key) - they will skip gracefully
[llm.phases.discovery]

[llm.phases.verification]

[llm.phases.aggregation]

[eval]
floor = 0.70
"#,
        output_dir = output_dir,
        project_path = project_path,
        evidence_gate = evidence_gate,
    )
}

/// Run baco scan with the given config and return the output.
fn run_scan(config_path: &str, extra_args: &[&str]) -> std::process::Output {
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

    for arg in extra_args {
        cmd.arg(arg);
    }

    cmd.current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to execute scan command")
}

#[test]
fn test_scan_output_evidence_gate_off() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let output_dir = temp_dir.path().to_str().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let config_content = create_minimal_config(
        &temp_dir,
        output_dir,
        "tests/fixtures/vulnerable-project",
        false,
    );
    std::fs::write(&config_path, config_content).expect("Failed to write config");

    let output = run_scan(config_path.to_str().unwrap(), &[]);

    // Should succeed (exit code 0) - semgrep runs, LLM phases skip due to no API key
    assert!(
        output.status.success(),
        "Scan should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Check that findings.json exists and is valid JSON
    let findings_path = PathBuf::from(output_dir).join("findings.json");
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
    assert!(findings.is_array(), "findings.json should contain an array");

    // Check that findings.md exists and is non-empty
    let md_path = PathBuf::from(output_dir).join("findings.md");
    assert!(md_path.exists(), "findings.md should be created");
    let md_content = std::fs::read_to_string(&md_path).expect("Failed to read findings.md");
    assert!(!md_content.is_empty(), "findings.md should not be empty");

    // Evidence gate line should NOT appear (it's off)
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        !combined.contains("Evidence gate:"),
        "Evidence gate line should not appear when disabled\nOutput: {}",
        combined
    );
}

#[test]
fn test_scan_output_evidence_gate_on() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let output_dir = temp_dir.path().to_str().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    // Enable evidence_gate in config
    let config_content = create_minimal_config(
        &temp_dir,
        output_dir,
        "tests/fixtures/vulnerable-project",
        true,
    );
    std::fs::write(&config_path, config_content).expect("Failed to write config");

    let output = run_scan(config_path.to_str().unwrap(), &[]);

    // Should succeed
    assert!(
        output.status.success(),
        "Scan should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Check findings.json exists
    let findings_path = PathBuf::from(output_dir).join("findings.json");
    assert!(findings_path.exists(), "findings.json should be created");

    let findings_content =
        std::fs::read_to_string(&findings_path).expect("Failed to read findings.json");
    let findings: serde_json::Value =
        serde_json::from_str(&findings_content).expect("findings.json should be valid JSON");
    assert!(findings.is_array(), "findings.json should contain an array");

    // Evidence gate summary line SHOULD appear in output
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        combined.contains("Evidence gate:"),
        "Evidence gate line should appear when enabled\nOutput: {}",
        combined
    );

    // Verify the format: "Evidence gate: N verified, N supported, N unverified"
    assert!(
        combined.contains("verified")
            && combined.contains("supported")
            && combined.contains("unverified"),
        "Evidence gate line should mention all three tiers\nOutput: {}",
        combined
    );
}

#[test]
fn test_scan_output_quiet() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let output_dir = temp_dir.path().to_str().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let config_content = create_minimal_config(
        &temp_dir,
        output_dir,
        "tests/fixtures/vulnerable-project",
        false,
    );
    std::fs::write(&config_path, config_content).expect("Failed to write config");

    let output = run_scan(config_path.to_str().unwrap(), &["-q"]);

    // Should succeed
    assert!(
        output.status.success(),
        "Scan should succeed with quiet flag\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // findings.json should still be created
    let findings_path = PathBuf::from(output_dir).join("findings.json");
    assert!(
        findings_path.exists(),
        "findings.json should be created even in quiet mode"
    );

    // Non-essential log lines should NOT appear
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        !combined.contains("Starting BACO security scan"),
        "Quiet mode should suppress 'Starting BACO security scan' message\nOutput: {}",
        combined
    );
}

#[test]
fn test_scan_findings_json_respects_evidence_gate() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let output_dir = temp_dir.path().to_str().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    // Enable evidence_gate in config
    let config_content = create_minimal_config(
        &temp_dir,
        output_dir,
        "tests/fixtures/vulnerable-project",
        true,
    );
    std::fs::write(&config_path, config_content).expect("Failed to write config");

    let output = run_scan(config_path.to_str().unwrap(), &[]);

    // Should succeed
    assert!(
        output.status.success(),
        "Scan should succeed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Check findings.json exists
    let findings_path = PathBuf::from(output_dir).join("findings.json");
    assert!(findings_path.exists(), "findings.json should be created");

    let findings_content =
        std::fs::read_to_string(&findings_path).expect("Failed to read findings.json");
    let findings: serde_json::Value =
        serde_json::from_str(&findings_content).expect("findings.json should be valid JSON");

    // Verify findings is an array
    assert!(findings.is_array(), "findings.json should contain an array");

    // When evidence gate is on, findings.json contains ALL findings but with verification_tier
    if let Some(arr) = findings.as_array() {
        for finding in arr {
            // Every finding must have verification_tier set
            assert!(
                finding.get("verification_tier").is_some(),
                "findings.json must have verification_tier on every finding when gate is on"
            );
        }
    }

    // Check findings.md exists and does NOT contain unverified findings
    let md_path = PathBuf::from(output_dir).join("findings.md");
    assert!(md_path.exists(), "findings.md should be created");
    let md_content = std::fs::read_to_string(&md_path).expect("Failed to read findings.md");

    // Markdown report should exclude unverified findings (low confidence < 0.5)
    if let Some(arr) = findings.as_array() {
        for finding in arr {
            if let Some(confidence) = finding.get("confidence_score").and_then(|c| c.as_f64()) {
                if confidence < 0.5 {
                    // Unverified findings should NOT appear in markdown
                    if let Some(title) = finding.get("title").and_then(|t| t.as_str()) {
                        assert!(
                            !md_content.contains(title),
                            "findings.md should not contain unverified findings (confidence < 0.5)"
                        );
                    }
                }
            }
        }
    }
}
