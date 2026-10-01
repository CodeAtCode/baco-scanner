//! A finding the judge saw no code for cannot come back confirmed.
//!
//! The verification prompt puts its seven questions "against the CODE SHOWN",
//! and the prompt builder only emits code for a finding that has a line to read
//! around or a snippet attached. Without this cap, such a finding is graded
//! from its own description and `confirmed` becomes a judgement about prose.

use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::scanner::phases::llm_phases::verification::{cap_blind_verdict, judge_saw_no_code};

fn finding(line: Option<u32>, snippet: Option<&str>) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "b".to_string(),
        title: "CWE-306: Missing Authentication for AJAX Endpoint".to_string(),
        description: "the handler updates the orders table".to_string(),
        severity: Severity::High,
        confidence_score: 0.8,
        cwe_id: Some("CWE-306".to_string()),
        file_path: "/tmp/plugin.php".to_string(),
        line_number: line,
        code_snippet: snippet.map(str::to_string),
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
fn test_no_line_and_no_snippet_means_the_judge_saw_nothing() {
    assert!(judge_saw_no_code(&finding(None, None)));
}

#[test]
fn test_a_line_means_code_was_shown() {
    assert!(!judge_saw_no_code(&finding(Some(142), None)));
}

#[test]
fn test_a_snippet_alone_is_enough() {
    assert!(!judge_saw_no_code(&finding(None, Some("function f() {}"))));
}

#[test]
fn test_an_empty_snippet_is_not_a_snippet() {
    // Whitespace-only is what a parser leaves behind when it has nothing, and
    // it would otherwise count as code shown.
    assert!(judge_saw_no_code(&finding(None, Some("   \n  "))));
}

#[test]
fn test_a_confirmed_blind_verdict_becomes_needs_review() {
    let f = finding(None, None);
    let (status, notes) = cap_blind_verdict(VerificationStatus::Confirmed, &f, "looks right");
    assert_eq!(status, VerificationStatus::NeedsReview);
    assert!(
        notes.contains("no code was shown"),
        "the reason must say why, got {notes:?}"
    );
    assert!(
        notes.contains("looks right"),
        "the judge's own reasoning must survive: {notes:?}"
    );
}

#[test]
fn test_a_confirmed_verdict_with_code_is_untouched() {
    let f = finding(Some(142), None);
    let (status, notes) = cap_blind_verdict(VerificationStatus::Confirmed, &f, "gate passed");
    assert_eq!(status, VerificationStatus::Confirmed);
    assert_eq!(notes, "gate passed");
}

#[test]
fn test_a_confirmed_verdict_with_a_snippet_is_untouched() {
    let f = finding(None, Some("function dismiss_pointers() { ... }"));
    let (status, _) = cap_blind_verdict(VerificationStatus::Confirmed, &f, "ok");
    assert_eq!(status, VerificationStatus::Confirmed);
}

#[test]
fn test_a_false_positive_on_a_blind_finding_is_never_overridden() {
    // The cap only ever demotes. Rejecting a finding is not a claim that needs
    // code behind it, and rewriting it would lose the judge's reason.
    let f = finding(None, None);
    let (status, notes) = cap_blind_verdict(
        VerificationStatus::FalsePositive,
        &f,
        "protected by check_admin_referer",
    );
    assert_eq!(status, VerificationStatus::FalsePositive);
    assert_eq!(notes, "protected by check_admin_referer");
}

#[test]
fn test_an_empty_note_gets_the_reason_on_its_own() {
    let f = finding(None, None);
    let (_, notes) = cap_blind_verdict(VerificationStatus::Confirmed, &f, "  ");
    assert!(notes.starts_with("not confirmed"), "got {notes:?}");
}
