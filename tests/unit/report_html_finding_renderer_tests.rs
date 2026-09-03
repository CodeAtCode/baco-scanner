use baco::findings::{Severity, TriageVerdict, VerificationStatus, VulnerabilityFinding};
use baco::report::html::finding_renderer::render_finding;

fn make_finding(severity: Severity, file: &str, line: Option<u32>) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-1".to_string(),
        title: "Test Finding".to_string(),
        description: "Test description".to_string(),
        severity,
        confidence_score: 0.8,
        cwe_id: None,
        file_path: file.to_string(),
        line_number: line,
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["test".to_string()],
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
fn test_render_finding_critical_severity() {
    let finding = make_finding(Severity::Critical, "src/main.rs", Some(42));
    let html = render_finding(&finding, 0);

    assert!(html.contains("finding critical"));
    assert!(html.contains("Critical"));
    assert!(html.contains("src/main.rs"));
    assert!(html.contains(":42"));
}

#[test]
fn test_render_finding_high_severity() {
    let finding = make_finding(Severity::High, "src/app.rs", Some(10));
    let html = render_finding(&finding, 1);

    assert!(html.contains("finding high"));
    assert!(html.contains("High"));
}

#[test]
fn test_render_finding_medium_severity() {
    let finding = make_finding(Severity::Medium, "src/lib.rs", Some(5));
    let html = render_finding(&finding, 2);

    assert!(html.contains("finding medium"));
    assert!(html.contains("Medium"));
}

#[test]
fn test_render_finding_low_severity() {
    let finding = make_finding(Severity::Low, "src/utils.rs", Some(100));
    let html = render_finding(&finding, 3);

    assert!(html.contains("finding low"));
    assert!(html.contains("Low"));
}

#[test]
fn test_render_finding_info_severity() {
    let finding = make_finding(Severity::Info, "src/info.rs", None);
    let html = render_finding(&finding, 4);

    assert!(html.contains("finding info"));
    assert!(html.contains("Info"));
}

#[test]
fn test_render_finding_without_line_number() {
    let finding = make_finding(Severity::High, "src/unknown.rs", None);
    let html = render_finding(&finding, 5);

    assert!(html.contains("src/unknown.rs"));
    assert!(!html.contains(":None"));
}

#[test]
fn test_render_finding_with_cwe_id() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.cwe_id = Some("CWE-79".to_string());

    let html = render_finding(&finding, 6);

    assert!(html.contains("CWE-79"));
    assert!(html.contains("cwe-badge"));
}

#[test]
fn test_render_finding_with_code_snippet() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.code_snippet = Some("unsafe code here".to_string());

    let html = render_finding(&finding, 8);

    assert!(html.contains("code-snippet-single"));
    assert!(html.contains("unsafe code here"));
}

#[test]
fn test_render_finding_with_recommendation() {
    let mut finding = make_finding(Severity::Medium, "src/test.rs", Some(10));
    finding.recommendation = Some("Use safe alternatives".to_string());

    let html = render_finding(&finding, 9);

    assert!(html.contains("Recommendation"));
    assert!(html.contains("Use safe alternatives"));
}

#[test]
fn test_render_finding_with_confidence_high() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.confidence_score = 0.95;

    let html = render_finding(&finding, 10);

    assert!(html.contains("confidence-high"));
    assert!(html.contains("95"));
}

#[test]
fn test_render_finding_with_confidence_medium() {
    let mut finding = make_finding(Severity::Medium, "src/test.rs", Some(10));
    finding.confidence_score = 0.5;

    let html = render_finding(&finding, 11);

    assert!(html.contains("confidence-medium"));
}

#[test]
fn test_render_finding_with_confidence_low() {
    let mut finding = make_finding(Severity::Low, "src/test.rs", Some(10));
    finding.confidence_score = 0.3;

    let html = render_finding(&finding, 12);

    assert!(html.contains("confidence-low"));
}

#[test]
fn test_render_finding_escapes_html_in_title() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.title = "<script>alert('xss')</script>".to_string();

    let html = render_finding(&finding, 13);

    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;script&gt;"));
}

#[test]
fn test_render_finding_with_multiple_sources() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.sources = vec!["semgrep".to_string(), "llm".to_string()];

    let html = render_finding(&finding, 14);

    assert!(html.contains("semgrep"));
    assert!(html.contains("llm"));
}

#[test]
fn test_render_finding_generates_unique_id() {
    let mut finding1 = make_finding(Severity::High, "src/test.rs", Some(10));
    finding1.id = "f16".to_string();
    let mut finding2 = make_finding(Severity::High, "src/test.rs", Some(10));
    finding2.id = "f17".to_string();

    let html1 = render_finding(&finding1, 0);
    let html2 = render_finding(&finding2, 1);

    assert!(html1.contains("id=\"finding-0\""));
    assert!(html2.contains("id=\"finding-1\""));
}

#[test]
fn test_render_finding_with_diff_hunk() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.diff_hunk = Some("-old line\n+new line".to_string());

    let html = render_finding(&finding, 15);

    assert!(html.contains("diff-hunk"));
    assert!(html.contains("diff-header"));
    assert!(html.contains("-old line"));
    assert!(html.contains("+new line"));
}

#[test]
fn test_render_finding_with_poc_and_mitigation() {
    let mut finding = make_finding(Severity::Critical, "src/vuln.rs", Some(25));
    finding.poc_code = Some("exploit()".to_string());
    finding.mitigation_code = Some("safe_fix()".to_string());
    finding.poc_format = Some("rust".to_string());

    let html = render_finding(&finding, 16);

    assert!(html.contains("poc-section"));
    assert!(html.contains("Proof of Concept"));
    assert!(html.contains("Mitigation Example"));
    assert!(html.contains("exploit()"));
    assert!(html.contains("safe_fix()"));
}

#[test]
fn test_render_finding_with_triage_verdict_pass() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.triage_verdict = Some(TriageVerdict::Pass);

    let html = render_finding(&finding, 17);

    assert!(html.contains("VERIFIED TP"));
    assert!(html.contains("triage-badge true-positive"));
}

#[test]
fn test_render_finding_with_triage_verdict_kill() {
    let mut finding = make_finding(Severity::Medium, "src/test.rs", Some(10));
    finding.triage_verdict = Some(TriageVerdict::Kill);

    let html = render_finding(&finding, 18);

    assert!(html.contains("FALSE POSITIVE"));
    assert!(html.contains("triage-badge false-positive"));
}

#[test]
fn test_render_finding_with_agent_mode() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.agent_mode = true;
    finding.llm_model = Some("gpt-4".to_string());

    let html = render_finding(&finding, 19);

    assert!(html.contains("agent-badge"));
    assert!(html.contains("Agent"));
    assert!(html.contains("gpt-4"));
}

#[test]
fn test_render_finding_with_priority_score() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.priority_score = Some(0.85);

    let html = render_finding(&finding, 20);

    assert!(html.contains("Priority"));
    assert!(html.contains("85.0"));
}

#[test]
fn test_render_finding_with_verification_status() {
    let mut finding = make_finding(Severity::Medium, "src/test.rs", Some(10));
    finding.verification_status = Some(VerificationStatus::Confirmed);

    let html = render_finding(&finding, 21);

    assert!(html.contains("Verification"));
    assert!(html.contains("confirmed"));
}

#[test]
fn test_render_finding_with_ticket_reference() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.ticket_reference = Some("SEC-123".to_string());

    let html = render_finding(&finding, 22);

    assert!(html.contains("Ticket"));
    assert!(html.contains("SEC-123"));
}

#[test]
fn test_render_finding_with_commit_reference() {
    let mut finding = make_finding(Severity::Low, "src/test.rs", Some(10));
    finding.commit_reference = Some("abc123def".to_string());

    let html = render_finding(&finding, 23);

    assert!(html.contains("Commit"));
    assert!(html.contains("abc123def"));
}

#[test]
fn test_render_finding_with_statement_range() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.statement_range = Some((15, 20));

    let html = render_finding(&finding, 24);

    assert!(html.contains("Statement range"));
    assert!(html.contains("lines 15-20"));
}

#[test]
fn test_render_finding_with_verification_notes() {
    let mut finding = make_finding(Severity::Medium, "src/test.rs", Some(10));
    finding.verification_notes = Some("Manual review confirmed".to_string());

    let html = render_finding(&finding, 25);

    assert!(html.contains("Verification notes"));
    assert!(html.contains("Manual review confirmed"));
}

#[test]
fn test_render_finding_with_verification_error() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.verification_error = Some("Connection timeout".to_string());

    let html = render_finding(&finding, 26);

    assert!(html.contains("Verification error"));
    assert!(html.contains("verification-error"));
    assert!(html.contains("Connection timeout"));
}

#[test]
fn test_render_finding_with_cross_file_references() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.cross_file_references =
        Some(vec!["src/utils.rs".to_string(), "src/lib.rs".to_string()]);

    let html = render_finding(&finding, 27);

    assert!(html.contains("Cross-file refs"));
    assert!(html.contains("src/utils.rs"));
}

#[test]
fn test_render_finding_with_all_metadata() {
    let finding = VulnerabilityFinding {
        id: "full-test".to_string(),
        title: "Comprehensive Test".to_string(),
        description: "Testing all fields".to_string(),
        severity: Severity::Critical,
        confidence_score: 0.95,
        cwe_id: Some("CWE-89".to_string()),
        file_path: "src/sql.rs".to_string(),
        line_number: Some(42),
        code_snippet: Some("sql.query(user_input)".to_string()),
        diff_hunk: None,
        recommendation: Some("Use parameterized queries".to_string()),
        code_location: None,
        already_reported: true,
        sources: vec!["semgrep".to_string()],
        commit_reference: Some("def456".to_string()),
        ticket_reference: Some("SEC-456".to_string()),
        priority_score: Some(0.9),
        cross_file_references: None,
        verification_status: Some(VerificationStatus::Confirmed),
        verification_notes: Some("Confirmed by security team".to_string()),
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: Some("attack_payload()".to_string()),
        mitigation_code: Some("safe_query()".to_string()),
        poc_format: Some("python".to_string()),
        llm_model: Some("claude-3".to_string()),
        agent_mode: true,
        statement_range: Some((40, 45)),
        triage_verdict: Some(TriageVerdict::Pass),
        evidence: vec![],
        verification_tier: None,
    };

    let html = render_finding(&finding, 28);

    // Verify key elements are present
    assert!(html.contains("Comprehensive Test"));
    assert!(html.contains("Critical"));
    assert!(html.contains("CWE-89"));
    assert!(html.contains("sql.rs"));
    assert!(html.contains(":42"));
    assert!(html.contains("95"));
    assert!(html.contains("VERIFIED TP"));
    assert!(html.contains("agent-badge"));
    assert!(html.contains("claude-3"));
    assert!(html.contains("Priority"));
    assert!(html.contains("SEC-456"));
    assert!(html.contains("def456"));
    assert!(html.contains("attack_payload()"));
    assert!(html.contains("safe_query()"));
    assert!(html.contains("Statement range"));
    assert!(html.contains("Verification notes"));
}
