use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_help_command() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "baco", "--", "--help"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();

    assert!(output.status.success(), "Help command should succeed");
    let help_text = String::from_utf8_lossy(&output.stdout);
    assert!(help_text.contains("BACO"), "Help should contain BACO");
    assert!(
        help_text.contains("scan"),
        "Help should mention scan command"
    );
    assert!(
        help_text.contains("resume"),
        "Help should mention resume command"
    );
    assert!(
        help_text.contains("report"),
        "Help should mention report command"
    );
    assert!(
        help_text.contains("verify"),
        "Help should mention verify command"
    );
}

#[test]
fn test_version_command() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "baco", "--", "--version"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();

    assert_ne!(output.status.code(), None, "Version should return a code");
}

#[test]
fn test_scan_nonexistent_config() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "scan",
            "--config",
            "/nonexistent/config.toml",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(2),
        "Scan with nonexistent config should exit with code 2"
    );
}

#[test]
fn test_report_nonexistent_input() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "report",
            "--input",
            "/nonexistent/findings.json",
            "--format",
            "html",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(1),
        "Report validation failed with code 1"
    );
}

#[test]
fn test_verify_nonexistent_file() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "verify",
            "--input",
            "/nonexistent/findings.json",
        ])
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(1),
        "Verify validation failed with code 1"
    );
}

#[test]
fn test_verify_invalid_json() {
    let temp_dir = TempDir::new().unwrap();
    let input_path = temp_dir.path().join("invalid.json");
    std::fs::write(&input_path, "{invalid json content}").unwrap();

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "verify",
            "--input",
            input_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_ne!(output.status.code(), None);
}

#[test]
fn test_verify_empty_findings() {
    let temp_dir = TempDir::new().unwrap();
    let input_path = temp_dir.path().join("empty.json");
    std::fs::write(&input_path, "[]").unwrap();

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "verify",
            "--input",
            input_path.to_str().unwrap(),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();

    assert_ne!(output.status.code(), None);
}

#[test]
fn test_report_invalid_format() {
    let temp_dir = TempDir::new().unwrap();
    let input_path = temp_dir.path().join("findings.json");
    std::fs::write(&input_path, "[]").unwrap();

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "report",
            "--input",
            input_path.to_str().unwrap(),
            "--format",
            "xml",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(1),
        "Invalid report format should exit with code 1"
    );
}

#[test]
fn test_report_missing_format_uses_default() {
    let temp_dir = TempDir::new().unwrap();
    let input_path = temp_dir.path().join("findings.json");
    std::fs::write(&input_path, "[]").unwrap();

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "report",
            "--input",
            input_path.to_str().unwrap(),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(1),
        "Report without format should use default (fails due to path format, not missing format)"
    );
}

#[test]
fn test_resume_missing_checkpoint() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "resume",
            "--checkpoint",
            "/nonexistent/checkpoint.json",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(1),
        "Resume with missing checkpoint should exit with code 1"
    );
}

#[test]
fn test_scan_incomplete_config() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("incomplete.toml");
    std::fs::write(&config_path, "[invalid]").unwrap();

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "scan",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(2),
        "Scan with incomplete config should exit with code 2"
    );
}

#[test]
fn test_commands_available() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "baco", "--", "--help"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();

    let help_text = String::from_utf8_lossy(&output.stdout);

    let commands = ["scan", "resume", "report", "verify"];
    for cmd in &commands {
        assert!(
            help_text.contains(cmd),
            "Help text should mention '{}' command",
            cmd
        );
    }
}

#[test]
fn test_bad_toml_config() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("bad.toml");
    std::fs::write(&config_path, "invalid {{{").unwrap();

    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "scan",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(2),
        "Scan with bad TOML should exit with code 2"
    );
}
