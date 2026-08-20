//! Unit tests for src/report/html/finding_renderer.rs
//!
//! Tests cover the render_finding function which renders a single finding as HTML.

use baco::findings::{Severity, TriageVerdict, VerificationStatus, VulnerabilityFinding};

use crate::fixtures::make_finding_html;

fn make_finding(
    id: &str,
    severity: Severity,
    file: &str,
    line: Option<u32>,
) -> VulnerabilityFinding {
    make_finding_html(id, severity, file, line)
}

// ============================================================================
// render_finding Tests - Severity Levels
// ============================================================================

#[test]
fn test_render_finding_critical_severity() {
    let finding = make_finding("f1", Severity::Critical, "src/main.rs", Some(42));
    let html = baco::report::html::finding_renderer::render_finding(&finding, 0);

    assert!(html.contains("finding critical"));
    assert!(html.contains("Critical"));
    assert!(html.contains("src/main.rs"));
    assert!(html.contains(":42"));
}

#[test]
fn test_render_finding_high_severity() {
    let finding = make_finding("f2", Severity::High, "src/app.rs", Some(10));
    let html = baco::report::html::finding_renderer::render_finding(&finding, 1);

    assert!(html.contains("finding high"));
    assert!(html.contains("High"));
}

#[test]
fn test_render_finding_medium_severity() {
    let finding = make_finding("f3", Severity::Medium, "src/lib.rs", Some(5));
    let html = baco::report::html::finding_renderer::render_finding(&finding, 2);

    assert!(html.contains("finding medium"));
    assert!(html.contains("Medium"));
}

#[test]
fn test_render_finding_low_severity() {
    let finding = make_finding("f4", Severity::Low, "src/utils.rs", Some(100));
    let html = baco::report::html::finding_renderer::render_finding(&finding, 3);

    assert!(html.contains("finding low"));
    assert!(html.contains("Low"));
}

#[test]
fn test_render_finding_info_severity() {
    let finding = make_finding("f5", Severity::Info, "src/info.rs", None);
    let html = baco::report::html::finding_renderer::render_finding(&finding, 4);

    assert!(html.contains("finding info"));
    assert!(html.contains("Info"));
}

// ============================================================================
// render_finding Tests - Line Number Handling
// ============================================================================

#[test]
fn test_render_finding_with_line_number() {
    let finding = make_finding("f6", Severity::High, "src/test.rs", Some(42));
    let html = baco::report::html::finding_renderer::render_finding(&finding, 5);

    assert!(html.contains(":42"));
    assert!(html.contains("src/test.rs"));
}

#[test]
fn test_render_finding_without_line_number() {
    let finding = make_finding("f7", Severity::High, "src/unknown.rs", None);
    let html = baco::report::html::finding_renderer::render_finding(&finding, 6);

    assert!(html.contains("src/unknown.rs"));
    assert!(!html.contains(":None"));
}

#[test]
fn test_render_finding_line_zero() {
    let finding = make_finding("f8", Severity::Medium, "src/test.rs", Some(0));
    let html = baco::report::html::finding_renderer::render_finding(&finding, 7);

    assert!(html.contains(":0"));
}

// ============================================================================
// render_finding Tests - CWE Badge
// ============================================================================

#[test]
fn test_render_finding_with_cwe_id() {
    let mut finding = make_finding("f9", Severity::High, "src/test.rs", Some(10));
    finding.cwe_id = Some("CWE-79".to_string());

    let html = baco::report::html::finding_renderer::render_finding(&finding, 8);

    assert!(html.contains("CWE-79"));
    assert!(html.contains("cwe-badge"));
}

#[test]
fn test_render_finding_without_cwe_id() {
    let finding = make_finding("f10", Severity::Medium, "src/test.rs", Some(10));
    let html = baco::report::html::finding_renderer::render_finding(&finding, 9);

    assert!(!html.contains("cwe-badge"));
}

#[test]
fn test_render_finding_cwe_id_twice() {
    // CWE badge appears twice - once in header, once in meta
    let mut finding = make_finding("f11", Severity::High, "src/test.rs", Some(10));
    finding.cwe_id = Some("CWE-89".to_string());

    let html = baco::report::html::finding_renderer::render_finding(&finding, 10);

    // Count occurrences of CWE-89
    let count = html.matches("CWE-89").count();
    assert!(
        count >= 2,
        "CWE-89 should appear at least twice (header and meta)"
    );
}

// ============================================================================
// render_finding Tests - Confidence Score
// ============================================================================

#[test]
fn test_render_finding_high_confidence() {
    let mut finding = make_finding("f12", Severity::High, "src/test.rs", Some(10));
    finding.confidence_score = 0.95;

    let html = baco::report::html::finding_renderer::render_finding(&finding, 11);

    assert!(html.contains("confidence-high"));
    assert!(html.contains("95"));
}

#[test]
fn test_render_finding_medium_confidence() {
    let mut finding = make_finding("f13", Severity::Medium, "src/test.rs", Some(10));
    finding.confidence_score = 0.5;

    let html = baco::report::html::finding_renderer::render_finding(&finding, 12);

    assert!(html.contains("confidence-medium"));
    assert!(html.contains("50"));
}

#[test]
fn test_render_finding_low_confidence() {
    let mut finding = make_finding("f14", Severity::Low, "src/test.rs", Some(10));
    finding.confidence_score = 0.3;

    let html = baco::report::html::finding_renderer::render_finding(&finding, 13);

    assert!(html.contains("confidence-low"));
    assert!(html.contains("30"));
}

#[test]
fn test_render_finding_confidence_boundary_high() {
    // Exactly at high confidence boundary (0.7)
    let mut finding = make_finding("f15", Severity::High, "src/test.rs", Some(10));
    finding.confidence_score = 0.7;

    let html = baco::report::html::finding_renderer::render_finding(&finding, 14);

    assert!(html.contains("confidence-high"));
}

#[test]
fn test_render_finding_confidence_boundary_medium() {
    // Exactly at medium confidence boundary (0.4)
    let mut finding = make_finding("f16", Severity::Medium, "src/test.rs", Some(10));
    finding.confidence_score = 0.4;

    let html = baco::report::html::finding_renderer::render_finding(&finding, 15);

    assert!(html.contains("confidence-medium"));
}

#[test]
fn test_render_finding_confidence_very_low() {
    let mut finding = make_finding("f17", Severity::Low, "src/test.rs", Some(10));
    finding.confidence_score = 0.0;

    let html = baco::report::html::finding_renderer::render_finding(&finding, 16);

    assert!(html.contains("confidence-low"));
    assert!(html.contains("0"));
}

#[test]
fn test_render_finding_confidence_very_high() {
    let mut finding = make_finding("f18", Severity::High, "src/test.rs", Some(10));
    finding.confidence_score = 1.0;

    let html = baco::report::html::finding_renderer::render_finding(&finding, 17);

    assert!(html.contains("confidence-high"));
    assert!(html.contains("100"));
}

// ============================================================================
// render_finding Tests - Code Snippet
// ============================================================================

#[test]
fn test_render_finding_with_code_snippet() {
    let mut finding = make_finding("f19", Severity::High, "src/test.rs", Some(10));
    finding.code_snippet = Some("unsafe code here".to_string());

    let html = baco::report::html::finding_renderer::render_finding(&finding, 18);

    assert!(html.contains("code-snippet-single"));
    assert!(html.contains("unsafe code here"));
}

#[test]
fn test_render_finding_without_code_snippet() {
    let finding = make_finding("f20", Severity::Medium, "src/test.rs", Some(10));
    let html = baco::report::html::finding_renderer::render_finding(&finding, 19);

    assert!(!html.contains("code-snippet-single"));
}

#[test]
fn test_render_finding_empty_code_snippet() {
    let mut finding = make_finding("f21", Severity::Low, "src/test.rs", Some(10));
    finding.code_snippet = Some("".to_string());

    let html = baco::report::html::finding_renderer::render_finding(&finding, 20);

    assert!(html.contains("code-snippet-single"));
}

// ============================================================================
// render_finding Tests - Diff Hunk
// ============================================================================

#[test]
fn test_render_finding_with_diff_hunk() {
    let mut finding = make_finding("f22", Severity::High, "src/test.rs", Some(10));
    finding.diff_hunk = Some("-old line\n+new line".to_string());

    let html = baco::report::html::finding_renderer::render_finding(&finding, 21);

    assert!(html.contains("diff-hunk"));
    assert!(html.contains("diff-header"));
    assert!(html.contains("-old line"));
    assert!(html.contains("+new line"));
}

#[test]
fn test_render_finding_without_diff_hunk() {
    let finding = make_finding("f23", Severity::Medium, "src/test.rs", Some(10));
    let html = baco::report::html::finding_renderer::render_finding(&finding, 22);

    assert!(!html.contains("diff-hunk"));
}

#[test]
fn test_render_finding_empty_diff_hunk_shows_snippet() {
    let mut finding = make_finding("f24", Severity::High, "src/test.py", Some(10));
    finding.diff_hunk = Some("".to_string());
    finding.code_snippet = Some("vulnerable code".to_string());

    let html = baco::report::html::finding_renderer::render_finding(&finding, 23);

    // Empty diff hunk should fall back to code snippet
    assert!(html.contains("code-snippet-single"));
    assert!(html.contains("vulnerable code"));
}

#[test]
fn test_render_finding_diff_hunk_with_multiline() {
    let mut finding = make_finding("f25", Severity::Critical, "src/test.rs", Some(10));
    finding.diff_hunk =
        Some("@@ -1,5 +1,6 @@\n context\n-old line\n+new line\n+added line\n context".to_string());

    let html = baco::report::html::finding_renderer::render_finding(&finding, 24);

    assert!(html.contains("diff-hunk"));
    assert!(html.contains("old line"));
    assert!(html.contains("new line"));
    assert!(html.contains("added line"));
}

// ============================================================================
// render_finding Tests - Recommendation
// ============================================================================

#[test]
fn test_render_finding_with_recommendation() {
    let mut finding = make_finding("f26", Severity::Medium, "src/test.rs", Some(10));
    finding.recommendation = Some("Use safe alternatives".to_string());

    let html = baco::report::html::finding_renderer::render_finding(&finding, 25);

    assert!(html.contains("Recommendation"));
    assert!(html.contains("Use safe alternatives"));
}

#[test]
fn test_render_finding_without_recommendation() {
    let finding = make_finding("f27", Severity::High, "src/test.rs", Some(10));
    let html = baco::report::html::finding_renderer::render_finding(&finding, 26);

    assert!(!html.contains("Recommendation"));
}

// ============================================================================
// render_finding Tests - PoC and Mitigation
// ============================================================================

#[test]
fn test_render_finding_with_poc_only() {
    let mut finding = make_finding("f28", Severity::Critical, "src/vuln.rs", Some(25));
    finding.poc_code = Some("exploit()".to_string());

    let html = baco::report::html::finding_renderer::render_finding(&finding, 27);

    assert!(html.contains("poc-section"));
    assert!(html.contains("Proof of Concept"));
    assert!(html.contains("exploit()"));
    assert!(!html.contains("Mitigation Example"));
}

#[test]
fn test_render_finding_with_mitigation_only() {
    let mut finding = make_finding("f29", Severity::High, "src/test.rs", Some(10));
    finding.mitigation_code = Some("safe_fix()".to_string());

    let html = baco::report::html::finding_renderer::render_finding(&finding, 28);

    assert!(html.contains("poc-section"));
    assert!(html.contains("Mitigation Example"));
    assert!(html.contains("safe_fix()"));
    assert!(!html.contains("Proof of Concept"));
}

#[test]
fn test_render_finding_with_both_poc_and_mitigation() {
    let mut finding = make_finding("f30", Severity::Critical, "src/vuln.rs", Some(25));
    finding.poc_code = Some("exploit()".to_string());
    finding.mitigation_code = Some("safe_fix()".to_string());
    finding.poc_format = Some("rust".to_string());

    let html = baco::report::html::finding_renderer::render_finding(&finding, 29);

    assert!(html.contains("poc-section"));
    assert!(html.contains("Proof of Concept"));
    assert!(html.contains("Mitigation Example"));
    assert!(html.contains("exploit()"));
    assert!(html.contains("safe_fix()"));
}

#[test]
fn test_render_finding_poc_format_label() {
    let mut finding = make_finding("f31", Severity::High, "src/test.py", Some(10));
    finding.poc_code = Some("attack()".to_string());
    finding.poc_format = Some("python".to_string());

    let html = baco::report::html::finding_renderer::render_finding(&finding, 30);

    assert!(html.contains("Proof of Concept (PYTHON)"));
}

// ============================================================================
// render_finding Tests - Triage Verdict
// ============================================================================

#[test]
fn test_render_finding_triage_verdict_pass() {
    let mut finding = make_finding("f32", Severity::High, "src/test.rs", Some(10));
    finding.triage_verdict = Some(TriageVerdict::Pass);

    let html = baco::report::html::finding_renderer::render_finding(&finding, 31);

    assert!(html.contains("VERIFIED TP"));
    assert!(html.contains("triage-badge true-positive"));
}

#[test]
fn test_render_finding_triage_verdict_kill() {
    let mut finding = make_finding("f33", Severity::Medium, "src/test.rs", Some(10));
    finding.triage_verdict = Some(TriageVerdict::Kill);

    let html = baco::report::html::finding_renderer::render_finding(&finding, 32);

    assert!(html.contains("FALSE POSITIVE"));
    assert!(html.contains("triage-badge false-positive"));
}

#[test]
fn test_render_finding_triage_verdict_downgrade() {
    let mut finding = make_finding("f34", Severity::High, "src/test.rs", Some(10));
    finding.triage_verdict = Some(TriageVerdict::Downgrade {
        adjusted_severity: Severity::Medium,
    });

    let html = baco::report::html::finding_renderer::render_finding(&finding, 33);

    assert!(html.contains("DOWNGRADED"));
    assert!(html.contains("triage-badge downgrade"));
}

#[test]
fn test_render_finding_triage_verdict_chain_required() {
    let mut finding = make_finding("f35", Severity::Medium, "src/test.rs", Some(10));
    finding.triage_verdict = Some(TriageVerdict::ChainRequired {
        chain_partner_ids: vec!["f1".to_string()],
    });

    let html = baco::report::html::finding_renderer::render_finding(&finding, 34);

    assert!(html.contains("CHAIN REQUIRED"));
    assert!(html.contains("triage-badge chain-required"));
}

#[test]
fn test_render_finding_without_triage_verdict() {
    let finding = make_finding("f36", Severity::High, "src/test.rs", Some(10));
    let html = baco::report::html::finding_renderer::render_finding(&finding, 35);

    assert!(!html.contains("triage-badge"));
}

// ============================================================================
// render_finding Tests - Agent Mode
// ============================================================================

#[test]
fn test_render_finding_agent_mode_with_model() {
    let mut finding = make_finding("f37", Severity::High, "src/test.rs", Some(10));
    finding.agent_mode = true;
    finding.llm_model = Some("gpt-4".to_string());

    let html = baco::report::html::finding_renderer::render_finding(&finding, 36);

    assert!(html.contains("agent-badge"));
    assert!(html.contains("Agent"));
    assert!(html.contains("gpt-4"));
}

#[test]
fn test_render_finding_agent_mode_without_model() {
    let mut finding = make_finding("f38", Severity::Medium, "src/test.rs", Some(10));
    finding.agent_mode = true;
    finding.llm_model = None;

    let html = baco::report::html::finding_renderer::render_finding(&finding, 37);

    assert!(html.contains("agent-badge"));
    assert!(html.contains("Agent"));
    assert!(html.contains("unknown"));
}

#[test]
fn test_render_finding_agent_mode_empty_model() {
    let mut finding = make_finding("f39", Severity::High, "src/test.rs", Some(10));
    finding.agent_mode = true;
    finding.llm_model = Some("".to_string());

    let html = baco::report::html::finding_renderer::render_finding(&finding, 38);

    assert!(html.contains("agent-badge"));
    // Empty model should still show Agent badge
    assert!(html.contains("Agent"));
}

#[test]
fn test_render_finding_not_agent_mode() {
    let finding = make_finding("f40", Severity::Medium, "src/test.rs", Some(10));
    let html = baco::report::html::finding_renderer::render_finding(&finding, 39);

    assert!(!html.contains("agent-badge"));
}

// ============================================================================
// render_finding Tests - HTML Escaping / XSS Protection
// ============================================================================

#[test]
fn test_render_finding_escapes_html_in_title() {
    let mut finding = make_finding("f41", Severity::High, "src/test.rs", Some(10));
    finding.title = "<script>alert('xss')</script>".to_string();

    let html = baco::report::html::finding_renderer::render_finding(&finding, 40);

    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;script&gt;"));
}

#[test]
fn test_render_finding_escapes_html_in_description() {
    let mut finding = make_finding("f42", Severity::Medium, "src/test.rs", Some(10));
    finding.description = "<img src=x onerror=alert(1)>".to_string();

    let html = baco::report::html::finding_renderer::render_finding(&finding, 41);

    assert!(!html.contains("<img"));
    assert!(html.contains("&lt;img"));
}

#[test]
fn test_render_finding_escapes_html_in_file_path() {
    let mut finding = make_finding("f43", Severity::High, "src/test.rs", Some(10));
    finding.file_path = "../<script>evil.js</script>".to_string();

    let html = baco::report::html::finding_renderer::render_finding(&finding, 42);

    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;script&gt;"));
}

#[test]
fn test_render_finding_escapes_html_in_recommendation() {
    let mut finding = make_finding("f44", Severity::Medium, "src/test.rs", Some(10));
    finding.recommendation = Some("<b>Use input validation</b>".to_string());

    let html = baco::report::html::finding_renderer::render_finding(&finding, 43);

    assert!(!html.contains("<b>"));
}

// ============================================================================
// render_finding Tests - Sources
// ============================================================================

#[test]
fn test_render_finding_with_single_source() {
    let mut finding = make_finding("f45", Severity::High, "src/test.rs", Some(10));
    finding.sources = vec!["semgrep".to_string()];

    let html = baco::report::html::finding_renderer::render_finding(&finding, 44);

    assert!(html.contains("semgrep"));
}

#[test]
fn test_render_finding_with_multiple_sources() {
    let mut finding = make_finding("f46", Severity::Medium, "src/test.rs", Some(10));
    finding.sources = vec![
        "semgrep".to_string(),
        "llm".to_string(),
        "manual".to_string(),
    ];

    let html = baco::report::html::finding_renderer::render_finding(&finding, 45);

    assert!(html.contains("semgrep"));
    assert!(html.contains("llm"));
    assert!(html.contains("manual"));
}

// ============================================================================
// render_finding Tests - Finding ID Generation
// ============================================================================

#[test]
fn test_render_finding_generates_unique_id_by_position() {
    let finding1 = make_finding("f47", Severity::High, "src/test.rs", Some(10));
    let finding2 = make_finding("f48", Severity::Medium, "src/test.rs", Some(20));

    let html1 = baco::report::html::finding_renderer::render_finding(&finding1, 0);
    let html2 = baco::report::html::finding_renderer::render_finding(&finding2, 1);

    assert!(html1.contains("id=\"finding-0\""));
    assert!(html2.contains("id=\"finding-1\""));
}

#[test]
fn test_render_finding_finding_id_in_uses() {
    let finding = make_finding("f49", Severity::High, "src/test.rs", Some(10));
    let html = baco::report::html::finding_renderer::render_finding(&finding, 42);

    assert!(html.contains("id=\"finding-42\""));
}

// ============================================================================
// render_finding Tests - Additional Metadata Fields
// ============================================================================

#[test]
fn test_render_finding_with_priority_score() {
    let mut finding = make_finding("f50", Severity::High, "src/test.rs", Some(10));
    finding.priority_score = Some(0.85);

    let html = baco::report::html::finding_renderer::render_finding(&finding, 46);

    assert!(html.contains("Priority"));
    assert!(html.contains("85.0"));
}

#[test]
fn test_render_finding_with_verification_status() {
    let mut finding = make_finding("f51", Severity::Medium, "src/test.rs", Some(10));
    finding.verification_status = Some(VerificationStatus::Confirmed);

    let html = baco::report::html::finding_renderer::render_finding(&finding, 47);

    assert!(html.contains("Verification"));
    assert!(html.contains("confirmed"));
}

#[test]
fn test_render_finding_with_ticket_reference() {
    let mut finding = make_finding("f52", Severity::High, "src/test.rs", Some(10));
    finding.ticket_reference = Some("SEC-123".to_string());

    let html = baco::report::html::finding_renderer::render_finding(&finding, 48);

    assert!(html.contains("Ticket"));
    assert!(html.contains("SEC-123"));
}

#[test]
fn test_render_finding_with_commit_reference() {
    let mut finding = make_finding("f53", Severity::Low, "src/test.rs", Some(10));
    finding.commit_reference = Some("abc123def".to_string());

    let html = baco::report::html::finding_renderer::render_finding(&finding, 49);

    assert!(html.contains("Commit"));
    assert!(html.contains("abc123def"));
}

#[test]
fn test_render_finding_with_statement_range() {
    let mut finding = make_finding("f54", Severity::High, "src/test.rs", Some(10));
    finding.statement_range = Some((15, 20));

    let html = baco::report::html::finding_renderer::render_finding(&finding, 50);

    assert!(html.contains("Statement range"));
    assert!(html.contains("lines 15-20"));
}

#[test]
fn test_render_finding_with_verification_notes() {
    let mut finding = make_finding("f55", Severity::Medium, "src/test.rs", Some(10));
    finding.verification_notes = Some("Manual review confirmed".to_string());

    let html = baco::report::html::finding_renderer::render_finding(&finding, 51);

    assert!(html.contains("Verification notes"));
    assert!(html.contains("Manual review confirmed"));
}

#[test]
fn test_render_finding_with_verification_error() {
    let mut finding = make_finding("f56", Severity::High, "src/test.rs", Some(10));
    finding.verification_error = Some("Connection timeout".to_string());

    let html = baco::report::html::finding_renderer::render_finding(&finding, 52);

    assert!(html.contains("Verification error"));
    assert!(html.contains("verification-error"));
    assert!(html.contains("Connection timeout"));
}

#[test]
fn test_render_finding_with_cross_file_references() {
    let mut finding = make_finding("f57", Severity::High, "src/test.rs", Some(10));
    finding.cross_file_references =
        Some(vec!["src/utils.rs".to_string(), "src/lib.rs".to_string()]);

    let html = baco::report::html::finding_renderer::render_finding(&finding, 53);

    assert!(html.contains("Cross-file refs"));
    assert!(html.contains("src/utils.rs"));
    assert!(html.contains("src/lib.rs"));
}

// ============================================================================
// render_finding Tests - Edge Cases
// ============================================================================

#[test]
fn test_render_finding_empty_title() {
    let mut finding = make_finding("f58", Severity::High, "src/test.rs", Some(10));
    finding.title = "".to_string();

    let html = baco::report::html::finding_renderer::render_finding(&finding, 54);

    assert!(html.contains("finding-54"));
    assert!(html.contains("finding-header"));
}

#[test]
fn test_render_finding_very_long_title() {
    let mut finding = make_finding("f59", Severity::High, "src/test.rs", Some(10));
    finding.title = "This is a very long title that contains many words and should still be rendered correctly without any issues".to_string();

    let html = baco::report::html::finding_renderer::render_finding(&finding, 55);

    assert!(html.contains("This is a very long title"));
    assert!(html.contains("finding-55"));
}

#[test]
fn test_render_finding_special_characters_in_description() {
    let mut finding = make_finding("f60", Severity::Medium, "src/test.rs", Some(10));
    finding.description = "Test with \"quotes\" and 'apostrophes' and <tags>".to_string();

    let html = baco::report::html::finding_renderer::render_finding(&finding, 56);

    assert!(html.contains("Test with"));
    // HTML tags should be escaped
    assert!(!html.contains("<tags>"));
}

#[test]
fn test_render_finding_newlines_in_description() {
    let mut finding = make_finding("f61", Severity::High, "src/test.rs", Some(10));
    finding.description = "Line 1\nLine 2\nLine 3".to_string();

    let html = baco::report::html::finding_renderer::render_finding(&finding, 57);

    assert!(html.contains("Line 1"));
    assert!(html.contains("Line 2"));
    assert!(html.contains("Line 3"));
}

// ============================================================================
// render_finding Tests - Comprehensive Finding
// ============================================================================

#[test]
fn test_render_finding_with_all_fields_populated() {
    let finding = VulnerabilityFinding {
        id: "comprehensive".to_string(),
        title: "SQL Injection Vulnerability".to_string(),
        description: "Unsanitized user input in SQL query".to_string(),
        severity: Severity::Critical,
        confidence_score: 0.95,
        cwe_id: Some("CWE-89".to_string()),
        file_path: "src/database.rs".to_string(),
        line_number: Some(42),
        code_snippet: Some("sql.query(user_input)".to_string()),
        diff_hunk: None,
        recommendation: Some("Use parameterized queries".to_string()),
        code_location: None,
        already_reported: true,
        sources: vec!["semgrep".to_string()],
        commit_reference: Some("abc123".to_string()),
        ticket_reference: Some("SEC-456".to_string()),
        priority_score: Some(0.9),
        cross_file_references: None,
        verification_status: Some(VerificationStatus::Confirmed),
        verification_notes: Some("Confirmed by security team".to_string()),
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: Some("exploit_payload()".to_string()),
        mitigation_code: Some("safe_query()".to_string()),
        poc_format: Some("rust".to_string()),
        llm_model: Some("claude-3".to_string()),
        agent_mode: true,
        statement_range: Some((40, 45)),
        triage_verdict: Some(TriageVerdict::Pass),
    };

    let html = baco::report::html::finding_renderer::render_finding(&finding, 58);

    // Verify all major elements are present
    assert!(html.contains("SQL Injection Vulnerability"));
    assert!(html.contains("Critical"));
    assert!(html.contains("CWE-89"));
    assert!(html.contains("src/database.rs"));
    assert!(html.contains(":42"));
    assert!(html.contains("95"));
    assert!(html.contains("VERIFIED TP"));
    assert!(html.contains("agent-badge"));
    assert!(html.contains("claude-3"));
    assert!(html.contains("Priority"));
    assert!(html.contains("SEC-456"));
    assert!(html.contains("abc123"));
    assert!(html.contains("exploit_payload()"));
    assert!(html.contains("safe_query()"));
    assert!(html.contains("Statement range"));
    assert!(html.contains("Verification notes"));
    assert!(html.contains("Recommendation"));
    assert!(html.contains("code-snippet-single"));
}
