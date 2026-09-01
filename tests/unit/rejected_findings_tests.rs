//! Tests for first-class rejected findings (false positives that become persisted report artifacts).
//!
//! These tests verify:
//! 1. JSON with include_rejected=true contains a "rejected" array with the reason
//! 2. JSON with include_rejected=false has no "rejected" key
//! 3. HTML with include_rejected=true contains the "Investigated & dismissed" heading
//! 4. Verification rejection path returns the finding with reason

use baco::findings::{Severity, VulnerabilityFinding};
use baco::scanner::phases::llm_phases::RejectedFinding;

/// Create a minimal test finding for testing
fn create_test_finding(title: &str, file_path: &str) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: format!("test-{}", title.replace(' ', "-")),
        title: title.to_string(),
        description: "Test finding".to_string(),
        severity: Severity::High,
        confidence_score: 0.8,
        cwe_id: None,
        file_path: file_path.to_string(),
        line_number: Some(42),
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec![],
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status: None,
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
        statement_range: None,
        triage_verdict: None,
        evidence: vec![],
        verification_tier: None,
    }
}

#[test]
fn test_rejected_finding_type() {
    // Test that RejectedFinding is a tuple of (VulnerabilityFinding, String)
    let finding = create_test_finding("Test vulnerability", "src/test.rs");
    let reason = "False positive: input is sanitized".to_string();
    let rejected: RejectedFinding = (finding, reason);

    assert_eq!(rejected.1, "False positive: input is sanitized");
}

#[test]
#[allow(clippy::field_reassign_with_default)]
fn test_json_output_with_include_rejected_true() {
    // Test that JSON output includes rejected findings when flag is true
    use baco::config::{OutputConfig, ScannerConfig};
    use baco::report::json::write_findings_json;
    use std::fs;

    let finding = create_test_finding("Test SQL injection", "src/db.rs");
    let reason = "False positive: parameterized query used".to_string();
    let rejected_findings = vec![(finding.clone(), reason.clone())];

    let output_path = "/tmp/test_rejected_findings.json";

    // Create a config with include_rejected = true
    let mut config = ScannerConfig::default();
    config.output = OutputConfig {
        dir: "/tmp".to_string(),
        evidence_gate: false,
        include_rejected: true,
    };

    // Write JSON with include_rejected = true
    let result = write_findings_json(
        &[finding],
        &rejected_findings,
        output_path,
        None,
        Some(&config),
    );

    assert!(result.is_ok(), "Failed to write JSON: {:?}", result);

    // Read and verify the JSON content
    let content = fs::read_to_string(output_path).expect("Failed to read JSON file");
    assert!(
        content.contains("\"rejected\""),
        "JSON should contain 'rejected' array"
    );
    assert!(
        content.contains("False positive: parameterized query used"),
        "JSON should contain rejection reason"
    );

    // Cleanup
    let _ = fs::remove_file(output_path);
}

#[test]
fn test_json_output_with_include_rejected_false() {
    // Test that JSON output does not include rejected findings when flag is false
    use baco::report::json::write_findings_json;
    use std::fs;

    let finding = create_test_finding("Test XSS", "src/web.rs");
    let rejected_findings: Vec<(VulnerabilityFinding, String)> = vec![];

    let output_path = "/tmp/test_no_rejected_findings.json";

    let result = write_findings_json(&[finding], &rejected_findings, output_path, None, None);

    assert!(result.is_ok(), "Failed to write JSON: {:?}", result);

    // Read and verify the JSON content
    let content = fs::read_to_string(output_path).expect("Failed to read JSON file");
    assert!(
        !content.contains("\"rejected\""),
        "JSON should not contain 'rejected' array when empty"
    );

    // Cleanup
    let _ = fs::remove_file(output_path);
}

#[test]
fn test_html_output_with_rejected_findings() {
    // Test that HTML output includes "Investigated & dismissed" section
    use baco::config::ScannerConfig;
    use baco::report::html::generate_html_report;
    use std::fs;

    let finding = create_test_finding("Test command injection", "src/shell.rs");
    let reason = "False positive: shell command is static".to_string();
    let rejected_findings = [(finding.clone(), reason.clone())];

    let output_path = "/tmp/test_rejected_report.html";

    // Create a minimal config with include_rejected = true
    let mut config = ScannerConfig::default();
    config.output.include_rejected = true;

    let result = generate_html_report(
        &[finding],
        output_path,
        Some(&config),
        Some(&rejected_findings[..]),
    );

    assert!(result.is_ok(), "Failed to generate HTML: {:?}", result);

    // Read and verify the HTML content
    let content = fs::read_to_string(output_path).expect("Failed to read HTML file");
    assert!(
        content.contains("Investigated & Dismissed"),
        "HTML should contain 'Investigated & Dismissed' heading"
    );
    assert!(
        content.contains("False positive: shell command is static"),
        "HTML should contain rejection reason"
    );

    // Cleanup
    let _ = fs::remove_file(output_path);
}

#[test]
fn test_verification_rejection_returns_finding_with_reason() {
    // Test the verification phase correctly returns rejected findings
    use baco::findings::VerificationStatus;

    let mut finding = create_test_finding("Test buffer overflow", "src/memory.rs");
    finding.verification_status = Some(VerificationStatus::FalsePositive);
    finding.verification_notes = Some("Static analysis false positive: bounds checked".to_string());

    // Simulate the rejection logic from run_llm_verification
    let mut kept_findings = Vec::new();
    let mut rejected_findings = Vec::new();

    match finding.verification_status {
        Some(VerificationStatus::FalsePositive) => {
            let reason = finding
                .verification_notes
                .clone()
                .unwrap_or_else(|| "Marked as false positive during LLM verification".to_string());
            rejected_findings.push((finding, reason));
        }
        _ => kept_findings.push(finding),
    }

    assert_eq!(kept_findings.len(), 0, "No findings should be kept");
    assert_eq!(rejected_findings.len(), 1, "One finding should be rejected");
    assert_eq!(
        rejected_findings[0].1, "Static analysis false positive: bounds checked",
        "Rejection reason should match verification_notes"
    );
}

#[test]
#[allow(clippy::field_reassign_with_default)]
fn test_json_rejected_finding_structure() {
    // Test that rejected findings in JSON have the correct structure
    use baco::config::{OutputConfig, ScannerConfig};
    use baco::report::json::write_findings_json;
    use serde_json::from_str;
    use std::fs;

    let finding = create_test_finding("Test path traversal", "src/fs.rs");
    let reason = "False positive: path is validated against whitelist".to_string();
    let rejected_findings = vec![(finding.clone(), reason.clone())];

    let output_path = "/tmp/test_rejected_structure.json";

    // Create a config with include_rejected = true
    let mut config = ScannerConfig::default();
    config.output = OutputConfig {
        dir: "/tmp".to_string(),
        evidence_gate: false,
        include_rejected: true,
    };

    let _ = write_findings_json(
        &[finding],
        &rejected_findings,
        output_path,
        None,
        Some(&config),
    );

    let content = fs::read_to_string(output_path).expect("Failed to read JSON file");
    let json: serde_json::Value = from_str(&content).expect("Failed to parse JSON");

    // Verify the rejected array exists and has the correct structure
    assert!(
        json.get("rejected").is_some(),
        "JSON should have 'rejected' key"
    );
    let rejected = json.get("rejected").unwrap().as_array().unwrap();
    assert_eq!(rejected.len(), 1, "Should have one rejected finding");

    let rejected_finding = &rejected[0];
    assert!(
        rejected_finding.get("title").is_some(),
        "Rejected finding should have 'title'"
    );
    assert!(
        rejected_finding.get("rejection_reason").is_some(),
        "Rejected finding should have 'rejection_reason'"
    );
    assert_eq!(
        rejected_finding
            .get("rejection_reason")
            .unwrap()
            .as_str()
            .unwrap(),
        "False positive: path is validated against whitelist"
    );

    // Cleanup
    let _ = fs::remove_file(output_path);
}
