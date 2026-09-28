//! End-to-end tests for `baco report` command with all output formats.

use serde_json::json;
use std::process::Command;
use tempfile::TempDir;

/// Create a realistic findings.json fixture in-memory.
fn create_findings_fixture() -> serde_json::Value {
    json!([
        {
            "id": "test-finding-001",
            "title": "Buffer overflow in input parsing",
            "description": "User input is not properly validated before being used in a buffer operation",
            "severity": "critical",
            "confidence_score": 0.95,
            "cwe_id": "CWE-120",
            "file_path": "src/parser.rs",
            "line_number": 42,
            "code_snippet": "strcpy(buf, user_input);",
            "diff_hunk": "@@ -40,7 +40,7 @@\n-    strcpy(buf, user_input);\n+    strncpy(buf, user_input, sizeof(buf) - 1);",
            "recommendation": "Use bounds-checked string functions like strncpy instead of strcpy",
            "code_location": "src/parser.rs:42",
            "already_reported": false,
            "sources": ["semgrep", "llm-verification"],
            "priority_score": 0.98,
            "verification_status": "confirmed",
            "agent_mode": true,
            "llm_model": "claude-3.5-sonnet"
        },
        {
            "id": "test-finding-002",
            "title": "SQL injection vulnerability",
            "description": "User-controlled input is concatenated directly into SQL query",
            "severity": "high",
            "confidence_score": 0.88,
            "cwe_id": "CWE-89",
            "file_path": "src/database.rs",
            "line_number": 127,
            "code_snippet": "let query = format!(\"SELECT * FROM users WHERE id = '{}'\", user_id);",
            "recommendation": "Use parameterized queries or prepared statements",
            "code_location": "src/database.rs:127",
            "already_reported": false,
            "sources": ["llm-verification"],
            "priority_score": 0.85,
            "verification_status": "needs_review",
            "agent_mode": false
        },
        {
            "id": "test-finding-003",
            "title": "Hardcoded API key",
            "description": "Sensitive API key is hardcoded in source code",
            "severity": "medium",
            "confidence_score": 0.92,
            "cwe_id": "CWE-798",
            "file_path": "src/config.rs",
            "line_number": 15,
            "code_snippet": "const API_KEY: &str = \"sk-live-abc123xyz789\";",
            "recommendation": "Move sensitive credentials to environment variables or a secure vault",
            "code_location": "src/config.rs:15",
            "already_reported": true,
            "sources": ["semgrep"],
            "priority_score": 0.65,
            "agent_mode": false
        },
        {
            "id": "test-finding-unverified",
            "title": "Suspicious memory access pattern",
            "description": "Potential unverified finding with low confidence",
            "severity": "low",
            "confidence_score": 0.35,
            "cwe_id": "CWE-789",
            "file_path": "src/memory.rs",
            "line_number": 88,
            "code_snippet": "let ptr = data.as_ptr();",
            "recommendation": "Review memory access patterns",
            "code_location": "src/memory.rs:88",
            "already_reported": false,
            "sources": ["heuristic"],
            "priority_score": 0.25,
            "agent_mode": false
        }
    ])
}

/// Run the baco report command with given arguments.
fn run_report(input_path: &str, format: &str) -> std::process::Output {
    Command::new("cargo")
        .args([
            "run", "--bin", "baco", "--", "report", "--input", input_path, "--format", format,
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap()
}

/// Run the baco report command with config file for evidence gate testing.
fn run_report_with_config(
    input_path: &str,
    format: &str,
    config_path: &str,
) -> std::process::Output {
    Command::new("cargo")
        .args([
            "run",
            "--bin",
            "baco",
            "--",
            "report",
            "--input",
            input_path,
            "--format",
            format,
            "--config",
            config_path,
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap()
}

#[test]
fn test_report_e2e_html() {
    let temp_dir = TempDir::new().unwrap();
    let input_path = temp_dir.path().join("findings.json");
    let output_path = temp_dir.path().join("report.html");

    // Write fixture
    let findings = create_findings_fixture();
    std::fs::write(
        &input_path,
        serde_json::to_string_pretty(&findings).unwrap(),
    )
    .unwrap();

    // Run report
    let output = run_report(input_path.to_str().unwrap(), "html");

    assert!(
        output.status.success(),
        "HTML report generation failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        output_path.exists(),
        "HTML report file should be created at {:?}",
        output_path
    );

    let html_content = std::fs::read_to_string(&output_path).unwrap();
    assert!(!html_content.is_empty(), "HTML report should not be empty");

    // Basic HTML structure
    assert!(
        html_content.contains("<!DOCTYPE html>"),
        "HTML should contain DOCTYPE declaration"
    );
    assert!(
        html_content.contains("<html"),
        "HTML should contain html element"
    );

    // Container structure
    assert!(
        html_content.contains(r#"<div class="container"#),
        "HTML should contain container div"
    );

    // Priority section exists
    assert!(
        html_content.contains(r#"<div class="priority-section">"#),
        "HTML should contain priority-section for critical/high findings"
    );

    // Container nesting regression: priority-section must be INSIDE container
    // Find the container opening, then find the priority-section, then find the container closing
    // The container closes with "</div>\n    </div>\n    {{ appendix_html" pattern
    let container_open = html_content
        .find(r#"<div class="container">"#)
        .expect("Container opening tag should exist");
    let priority_section = html_content
        .find(r#"<div class="priority-section">"#)
        .expect("Priority section should exist");

    // Find container close by looking for the pattern after findings_html
    // The container closes before appendix_html and footer
    let footer_start = html_content
        .find(r#"<div class="footer">"#)
        .expect("Footer should exist");

    assert!(
        container_open < priority_section && priority_section < footer_start,
        "Priority section must be nested inside container div (before footer): \
         container_open={} < priority_section={} < footer_start={}",
        container_open,
        priority_section,
        footer_start
    );

    // Findings content
    assert!(
        html_content.contains("Buffer overflow in input parsing"),
        "HTML should contain finding titles"
    );
    assert!(
        html_content.contains("SQL injection vulnerability"),
        "HTML should contain finding titles"
    );

    // Severity classes
    assert!(
        html_content.contains("severity critical"),
        "HTML should contain critical severity class"
    );
    assert!(
        html_content.contains("severity high"),
        "HTML should contain high severity class"
    );
}

#[test]
fn test_report_e2e_json() {
    let temp_dir = TempDir::new().unwrap();
    let input_path = temp_dir.path().join("findings.json");
    let output_path = temp_dir.path().join("findings.json"); // JSON overwrites input

    // Write fixture
    let findings = create_findings_fixture();
    let original_findings = serde_json::to_string_pretty(&findings).unwrap();
    std::fs::write(&input_path, &original_findings).unwrap();

    // Run report
    let output = run_report(input_path.to_str().unwrap(), "json");

    assert!(
        output.status.success(),
        "JSON report generation failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        output_path.exists(),
        "JSON report file should be created at {:?}",
        output_path
    );

    // Parse the output JSON
    let output_content = std::fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&output_content).expect("Output should be valid JSON");

    // Verify it has a findings array
    let findings_array = parsed.as_array().expect("JSON output should be an array");

    assert!(
        !findings_array.is_empty(),
        "JSON report should contain findings"
    );

    // Verify finding IDs are preserved
    let first_finding = &findings_array[0];
    assert!(
        first_finding.get("id").is_some(),
        "Each finding should have an id field"
    );
    assert_eq!(
        first_finding.get("id").unwrap().as_str().unwrap(),
        "test-finding-001",
        "Finding IDs should be preserved"
    );
}

#[test]
fn test_report_e2e_sarif() {
    let temp_dir = TempDir::new().unwrap();
    let input_path = temp_dir.path().join("findings.json");
    let output_path = temp_dir.path().join("report.sarif");

    // Write fixture
    let findings = create_findings_fixture();
    std::fs::write(
        &input_path,
        serde_json::to_string_pretty(&findings).unwrap(),
    )
    .unwrap();

    // Run report
    let output = run_report(input_path.to_str().unwrap(), "sarif");

    assert!(
        output.status.success(),
        "SARIF report generation failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        output_path.exists(),
        "SARIF report file should be created at {:?}",
        output_path
    );

    // Parse the SARIF JSON
    let sarif_content = std::fs::read_to_string(&output_path).unwrap();
    let sarif: serde_json::Value =
        serde_json::from_str(&sarif_content).expect("SARIF output should be valid JSON");

    // Verify SARIF structure
    let sarif_schema = sarif
        .get("$schema")
        .and_then(|s| s.as_str())
        .expect("SARIF should have $schema field");
    assert!(
        sarif_schema.contains("sarif"),
        "SARIF schema should contain 'sarif': {}",
        sarif_schema
    );

    let runs = sarif
        .get("runs")
        .and_then(|r| r.as_array())
        .expect("SARIF should have runs array");

    assert!(!runs.is_empty(), "SARIF should have at least one run");

    // Verify results array exists and is non-empty (since fixture had findings)
    let first_run = &runs[0];
    let results = first_run
        .get("results")
        .and_then(|r| r.as_array())
        .expect("SARIF run should have results array");

    assert!(
        !results.is_empty(),
        "SARIF results should be non-empty for fixture with findings"
    );
}

#[test]
fn test_report_e2e_markdown() {
    let temp_dir = TempDir::new().unwrap();
    let input_path = temp_dir.path().join("findings.json");
    let output_path = temp_dir.path().join("report.md");

    // Write fixture
    let findings = create_findings_fixture();
    std::fs::write(
        &input_path,
        serde_json::to_string_pretty(&findings).unwrap(),
    )
    .unwrap();

    // Run report
    let output = run_report(input_path.to_str().unwrap(), "markdown");

    assert!(
        output.status.success(),
        "Markdown report generation failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        output_path.exists(),
        "Markdown report file should be created at {:?}",
        output_path
    );

    let md_content = std::fs::read_to_string(&output_path).unwrap();
    assert!(
        !md_content.is_empty(),
        "Markdown report should not be empty"
    );

    // Project name/title (derived from parent directory name)
    assert!(md_content.contains("#"), "Markdown should contain headers");

    // Finding titles
    assert!(
        md_content.contains("Buffer overflow in input parsing"),
        "Markdown should contain finding titles"
    );
    assert!(
        md_content.contains("SQL injection vulnerability"),
        "Markdown should contain finding titles"
    );

    // Severity labels
    assert!(
        md_content.contains("Critical"),
        "Markdown should contain severity labels"
    );
    assert!(
        md_content.contains("High"),
        "Markdown should contain severity labels"
    );
}

#[test]
fn test_report_e2e_exit_codes() {
    // Success case
    let temp_dir = TempDir::new().unwrap();
    let input_path = temp_dir.path().join("findings.json");
    let findings = create_findings_fixture();
    std::fs::write(
        &input_path,
        serde_json::to_string_pretty(&findings).unwrap(),
    )
    .unwrap();

    let output = run_report(input_path.to_str().unwrap(), "html");
    assert!(
        output.status.success(),
        "Valid report should succeed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Validation failure: empty findings array
    let empty_dir = TempDir::new().unwrap();
    let empty_path = empty_dir.path().join("empty.json");
    std::fs::write(&empty_path, "[]").unwrap();

    let output = run_report(empty_path.to_str().unwrap(), "html");
    assert!(!output.status.success(), "Empty findings should fail");
}

/// Create a minimal config TOML with evidence_gate enabled.
fn create_evidence_gate_config(temp_dir: &TempDir) -> String {
    let output_dir = temp_dir.path().to_str().unwrap();
    format!(
        r#"
[project]
name = "test-project"
path = "{}"
languages = ["rust"]

[output]
dir = "{}/output"
evidence_gate = true

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
        output_dir, output_dir
    )
}

#[test]
fn test_report_evidence_gate_markdown() {
    let temp_dir = TempDir::new().unwrap();
    let input_path = temp_dir.path().join("findings.json");
    let output_path = temp_dir.path().join("report.md");
    let config_path = temp_dir.path().join("config.toml");

    // Write fixture with unverified finding
    let findings = create_findings_fixture();
    std::fs::write(
        &input_path,
        serde_json::to_string_pretty(&findings).unwrap(),
    )
    .unwrap();

    // Write config with evidence_gate = true
    let config_content = create_evidence_gate_config(&temp_dir);
    std::fs::write(&config_path, config_content).unwrap();

    // Run report with config
    let output = run_report_with_config(
        input_path.to_str().unwrap(),
        "markdown",
        config_path.to_str().unwrap(),
    );

    assert!(
        output.status.success(),
        "Markdown report with evidence gate failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let md_content = std::fs::read_to_string(&output_path).unwrap();

    // Verified and supported findings should be present
    assert!(
        md_content.contains("Buffer overflow in input parsing"),
        "Should contain verified finding"
    );
    assert!(
        md_content.contains("SQL injection vulnerability"),
        "Should contain supported finding"
    );
    assert!(
        md_content.contains("Hardcoded API key"),
        "Should contain supported finding"
    );

    // Unverified finding should be excluded
    assert!(
        !md_content.contains("Suspicious memory access pattern"),
        "Should NOT contain unverified finding when evidence gate is on"
    );
}

#[test]
fn test_report_evidence_gate_json() {
    let temp_dir = TempDir::new().unwrap();
    let input_path = temp_dir.path().join("findings.json");
    let output_path = temp_dir.path().join("findings.json");
    let config_path = temp_dir.path().join("config.toml");

    // Write fixture with unverified finding
    let findings = create_findings_fixture();
    std::fs::write(
        &input_path,
        serde_json::to_string_pretty(&findings).unwrap(),
    )
    .unwrap();

    // Write config with evidence_gate = true
    let config_content = create_evidence_gate_config(&temp_dir);
    std::fs::write(&config_path, config_content).unwrap();

    // Run report with config
    let output = run_report_with_config(
        input_path.to_str().unwrap(),
        "json",
        config_path.to_str().unwrap(),
    );

    assert!(
        output.status.success(),
        "JSON report with evidence gate failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output_content = std::fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&output_content).expect("Output should be valid JSON");

    let findings_array = parsed.as_array().expect("JSON output should be an array");

    // JSON includes ALL findings for transparency (not filtered)
    assert_eq!(
        findings_array.len(),
        4,
        "JSON output contains all 4 findings (unfiltered for transparency)"
    );

    // Every finding must have verification_tier set when gate is enabled
    for finding in findings_array {
        assert!(
            finding.get("verification_tier").is_some(),
            "Every finding must have verification_tier set when evidence gate is on"
        );
    }

    // Verify the unverified finding is present (not filtered) but has tier
    let unverified_finding = findings_array
        .iter()
        .find(|f| f.get("id").and_then(|id| id.as_str()) == Some("test-finding-unverified"))
        .expect("Unverified finding should be present in JSON");

    assert_eq!(
        unverified_finding
            .get("verification_tier")
            .and_then(|t| t.as_str()),
        Some("unverified"),
        "Unverified finding should have verification_tier = unverified"
    );
}

#[test]
fn test_report_no_evidence_gate_includes_all() {
    let temp_dir = TempDir::new().unwrap();
    let input_path = temp_dir.path().join("findings.json");
    let output_path = temp_dir.path().join("report.md");

    // Write fixture with unverified finding
    let findings = create_findings_fixture();
    std::fs::write(
        &input_path,
        serde_json::to_string_pretty(&findings).unwrap(),
    )
    .unwrap();

    // Run report WITHOUT config (no evidence gate)
    let output = run_report(input_path.to_str().unwrap(), "markdown");

    assert!(
        output.status.success(),
        "Markdown report without evidence gate failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let md_content = std::fs::read_to_string(&output_path).unwrap();

    // All findings including unverified should be present
    assert!(
        md_content.contains("Suspicious memory access pattern"),
        "Should contain unverified finding when evidence gate is off"
    );
}
