//! Integration tests for the `baco doctor` subcommand.

use std::process::Command;
use tempfile::TempDir;

fn project_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Create a minimal valid config file
fn create_minimal_config(temp_dir: &TempDir) -> std::path::PathBuf {
    let config_path = temp_dir.path().join("config.toml");
    let content = r#"
[project]
name = "test-project"
path = "."
languages = ["rust"]

[output]
dir = "baco-output"

[llm]
timeout_secs = 60
max_retries = 3

[llm.phases.discovery]
base_url = "https://api.mistral.ai/v1"
api_key = "test-key"
model = "mistral-small"

[scanner]
max_file_size_kb = 1024
"#;
    std::fs::write(&config_path, content).unwrap();
    config_path
}

/// Create a config with missing LLM keys
fn create_config_missing_llm_keys(temp_dir: &TempDir) -> std::path::PathBuf {
    let config_path = temp_dir.path().join("config.toml");
    let content = r#"
[project]
name = "test-project"
path = "."
languages = ["rust"]

[output]
dir = "baco-output"

[llm.phases.discovery]
base_url = "https://api.mistral.ai/v1"
# Missing api_key and model
"#;
    std::fs::write(&config_path, content).unwrap();
    config_path
}

/// Create an invalid TOML config
fn create_invalid_toml_config(temp_dir: &TempDir) -> std::path::PathBuf {
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, "invalid {{{").unwrap();
    config_path
}

#[test]
fn test_doctor_help() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "baco", "--", "doctor", "--help"])
        .current_dir(project_root())
        .output()
        .unwrap();

    assert!(output.status.success(), "Doctor help should succeed");
    let help_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        help_text.contains("--config"),
        "Help should mention --config"
    );
    assert!(help_text.contains("--json"), "Help should mention --json");
}

#[test]
fn test_doctor_parse_success_valid_config() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = create_minimal_config(&temp_dir);

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "doctor",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .current_dir(project_root())
        .output()
        .unwrap();

    // Should succeed (exit 0) even if some checks warn/fail (like missing joern)
    assert!(
        output.status.success() || output.status.code() == Some(0),
        "Doctor with valid config should exit 0, got: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("config_parse"),
        "Output should mention config_parse check"
    );
}

#[test]
fn test_doctor_missing_key_lists_phase_by_name() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = create_config_missing_llm_keys(&temp_dir);

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "doctor",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .current_dir(project_root())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should mention the phase name that's missing config
    assert!(
        stdout.contains("discovery") || stdout.contains("llm_phases"),
        "Output should mention the phase with missing config: {}",
        stdout
    );
}

#[test]
fn test_doctor_hard_failure_exits_nonzero() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = create_invalid_toml_config(&temp_dir);

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "doctor",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .current_dir(project_root())
        .output()
        .unwrap();

    // Invalid config should cause non-zero exit
    assert_eq!(
        output.status.code(),
        Some(1),
        "Doctor with invalid config should exit 1"
    );
}

#[test]
fn test_doctor_output_dir_probe_tempdir() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = create_minimal_config(&temp_dir);
    let output_dir = temp_dir.path().join("custom-output");

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "doctor",
            "--config",
            config_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
        ])
        .current_dir(project_root())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("output_dir"),
        "Output should mention output_dir check: {}",
        stdout
    );

    // Directory should be created
    assert!(output_dir.exists(), "Output directory should be created");
}

#[test]
fn test_doctor_json_output() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = create_minimal_config(&temp_dir);

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "doctor",
            "--config",
            config_path.to_str().unwrap(),
            "--json",
        ])
        .current_dir(project_root())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should be valid JSON
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    // Should have checks array
    assert!(
        json.get("checks").is_some(),
        "JSON should have 'checks' field"
    );
    assert!(
        json.get("overall_status").is_some(),
        "JSON should have 'overall_status' field"
    );

    // Checks should be an array
    let checks = json.get("checks").unwrap().as_array().unwrap();
    assert!(!checks.is_empty(), "Should have at least one check");
}

#[test]
fn test_doctor_quiet_mode() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = create_minimal_config(&temp_dir);

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "--quiet",
            "doctor",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .current_dir(project_root())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Quiet mode should have minimal output
    assert!(
        stdout.contains("passed") || stdout.contains("failed"),
        "Quiet mode should show summary: {}",
        stdout
    );
}
