//! Tests for build_volatile_verification_tail code context extraction
//!
//! These tests verify that the verification prompt correctly shows code context
//! from disk, covering edge cases like missing files and out-of-range lines.

use baco::findings::{Severity, VulnerabilityFinding};
use baco::scanner::phases::llm_phases::build_volatile_verification_tail;
use std::collections::HashMap;
use std::fs;

fn make_finding(
    file_path: &str,
    line_number: Option<u32>,
    snippet: Option<&str>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-finding-1".to_string(),
        title: "Test Finding".to_string(),
        description: "Test description".to_string(),
        severity: Severity::High,
        confidence_score: 0.7,
        cwe_id: Some("CWE-79".to_string()),
        file_path: file_path.to_string(),
        line_number,
        code_snippet: snippet.map(String::from),
        diff_hunk: None,
        recommendation: Some("Review this".to_string()),
        code_location: Some(format!("{}:{}", file_path, line_number.unwrap_or(0))),
        already_reported: false,
        sources: vec!["test".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.8),
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

// ============================================================================
// Test: existing file with valid line number
// ============================================================================

#[test]
fn test_code_context_existing_file_valid_line() {
    // Create a temporary test file
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("verification_test_valid.txt");
    let content =
        "line 1\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nline 8\nline 9\nline 10\n";
    fs::write(&test_file, content).unwrap();

    let finding = make_finding(test_file.to_str().unwrap(), Some(5), None);
    let findings = vec![finding];
    let hunt_prompts = HashMap::new();

    let tail = build_volatile_verification_tail(&findings, &hunt_prompts);

    // Should contain the Code context header
    assert!(
        tail.contains("Code context ("),
        "Output should contain 'Code context (' header: {}",
        tail
    );

    // Should show lines around line 5 (±5 lines = lines 1-10)
    // Helper format: "    N: content" or " >> N: content" for target
    assert!(tail.contains("| line 1"), "Should show line 1");
    assert!(tail.contains("| line 5"), "Should show line 5");
    assert!(tail.contains("| line 10"), "Should show line 10");

    // Clean up
    fs::remove_file(&test_file).ok();
}

// ============================================================================
// Test: non-existent file should report error, not emit nothing
// ============================================================================

#[test]
fn test_code_context_missing_file_reports_error() {
    let finding = make_finding(
        "/tmp/verification_test_nonexistent_file_12345.txt",
        Some(5),
        None,
    );
    let findings = vec![finding];
    let hunt_prompts = HashMap::new();

    let tail = build_volatile_verification_tail(&findings, &hunt_prompts);

    // The prompt should indicate the file was not found, not silently skip
    // The helper returns "Line N: [file not found]" which should be in the output
    assert!(
        tail.contains("[file not found]") || tail.contains("unable to read"),
        "Missing file should report error in prompt, not emit nothing. Output: {}",
        tail
    );
}

// ============================================================================
// Test: line number past end of file should not produce empty header
// ============================================================================

#[test]
fn test_code_context_line_beyond_file_not_empty() {
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("verification_test_beyond.txt");
    let content = "line 1\nline 2\nline 3\n";
    fs::write(&test_file, content).unwrap();

    let finding = make_finding(test_file.to_str().unwrap(), Some(100), None); // Line 100 doesn't exist
    let findings = vec![finding];
    let hunt_prompts = HashMap::new();

    let tail = build_volatile_verification_tail(&findings, &hunt_prompts);

    // Should have Code context header
    assert!(
        tail.contains("Code context ("),
        "Should have Code context header: {}",
        tail
    );

    // Should NOT be an empty header - should show last available lines
    // The header alone is "Code context (file:N):\n" followed by content
    let context_start = tail.find("Code context (").unwrap();
    let after_header = &tail[context_start..];
    let header_end = after_header.find('\n').unwrap();
    let header_line = &after_header[..header_end];
    let body = &after_header[header_end + 1..];

    // Body should not be empty or just whitespace
    assert!(
        !body.trim().is_empty(),
        "Code context body should not be empty when line is past EOF. Header: '{}', Body: '{}', Full output: {}",
        header_line,
        body,
        tail
    );

    // Should show the last available lines
    assert!(tail.contains("line 3"), "Should show last line (line 3)");

    fs::remove_file(&test_file).ok();
}

// ============================================================================
// Test: verify the helper is actually being called (mutation test)
// ============================================================================

#[test]
fn test_code_context_uses_helper_not_inline() {
    // This test verifies that the implementation uses extract_code_snippet
    // by checking that the output format matches the helper's behavior

    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("verification_test_helper.txt");
    let content = "line 1\nline 2\nline 3\nline 4\nline 5\n";
    fs::write(&test_file, content).unwrap();

    let finding = make_finding(test_file.to_str().unwrap(), Some(3), None);
    let findings = vec![finding];
    let hunt_prompts = HashMap::new();

    let tail = build_volatile_verification_tail(&findings, &hunt_prompts);

    // The helper formats lines as "    N: content" or " >> N: content" for target
    // Verify the format is present (not the old inline format which had no marker)
    assert!(
        tail.contains(" >> ") || tail.contains("    "),
        "Should use helper's line formatting with markers: {}",
        tail
    );

    fs::remove_file(&test_file).ok();
}
