//! Regression tests for the `Confirmed` status handling in `upgrade_for_absent_primitive`.
//!
//! T10 fix: the absence-detection gate used to fire only on `NeedsReview` findings.
//! When a finding was already `Confirmed`, it would early-return unchanged, bypassing
//! the primitive-presence check that could downgrade it. The fix adds a `was_confirmed`
//! flag and extends the guard to let `Confirmed` findings through so they can be
//! downgraded if a primitive is found.
//!
//! Teeth check: on the buggy code (without `&& !was_confirmed`), tests 1, 2, and 3
//! fail because `Confirmed` findings short-circuit before the match. After the fix,
//! all four tests pass.

use std::collections::HashMap;

use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::scanner::phases::llm_phases::verification::upgrade_for_absent_primitive;
use tempfile::tempdir;

fn sensitive_finding(file_path: &str) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "p".to_string(),
        // "privilege" triggers `is_sensitive_state_mutation`; "escalate()" gives
        // `function_names_in_title` a name to look up so the read is attempted.
        title: "CWE-269: Privilege escalation in escalate()".to_string(),
        description: "user role is changed without an auth check".to_string(),
        severity: Severity::High,
        confidence_score: 0.7,
        cwe_id: Some("CWE-269".to_string()),
        file_path: file_path.to_string(),
        line_number: Some(1),
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
        verification_gate_answers: None,
    }
}

fn php_primitives() -> HashMap<String, Vec<String>> {
    HashMap::from([(
        "php".to_string(),
        vec![
            "check_ajax_referer".to_string(),
            "current_user_can".to_string(),
        ],
    )])
}

#[test]
fn confirmed_with_primitive_downgrades_to_needs_review() {
    // Write a temp PHP file with the primitive present.
    let dir = tempdir().expect("create temp dir");
    let file_path = dir.path().join("test.php");
    let php_content = "<?php\nfunction escalate() {\n    check_ajax_referer('edit');\n}\n?>";
    std::fs::write(&file_path, php_content).expect("write temp file");
    let temp_path = file_path.to_string_lossy().to_string();

    let finding = sensitive_finding(&temp_path);

    let (status, notes) = upgrade_for_absent_primitive(
        &finding,
        VerificationStatus::Confirmed,
        "model judged confirmed",
        &php_primitives(),
        true, // enable_absence_detection
    );

    // Primitive present → downgrade to NeedsReview
    assert_eq!(
        status,
        VerificationStatus::NeedsReview,
        "a confirmed finding with a primitive present must be downgraded"
    );
    assert!(
        notes.contains("downgraded from confirmed"),
        "notes should indicate downgrading, got: {notes}"
    );
}

#[test]
fn confirmed_unreadable_file_stays_confirmed() {
    // Point at a path that does NOT exist so `read_to_string` fails.
    let missing = "/tmp/baco-t10-does-not-exist.php";
    let finding = sensitive_finding(missing);

    let (status, notes) = upgrade_for_absent_primitive(
        &finding,
        VerificationStatus::Confirmed,
        "model judged confirmed",
        &php_primitives(),
        true, // enable_absence_detection
    );

    // Read error → stay at Confirmed (not downgraded)
    assert_eq!(
        status,
        VerificationStatus::Confirmed,
        "a confirmed finding with an unreadable file must stay confirmed"
    );
    assert!(
        notes.contains("cannot read file"),
        "notes should explain the read error, got: {notes}"
    );
}

#[test]
fn confirmed_absence_corroborates() {
    // Write a temp PHP file WITHOUT the primitive.
    let dir = tempdir().expect("create temp dir");
    let file_path = dir.path().join("test.php");
    let php_content = "<?php\nfunction escalate() {\n    $x = 1;\n}\n?>";
    std::fs::write(&file_path, php_content).expect("write temp file");
    let temp_path = file_path.to_string_lossy().to_string();

    let finding = sensitive_finding(&temp_path);

    let (status, notes) = upgrade_for_absent_primitive(
        &finding,
        VerificationStatus::Confirmed,
        "model judged confirmed",
        &php_primitives(),
        true, // enable_absence_detection
    );

    // Absence → stay Confirmed (corroborated)
    assert_eq!(
        status,
        VerificationStatus::Confirmed,
        "a confirmed finding with absence corroborated must stay confirmed"
    );
    assert!(
        notes.contains("corroborated by absence"),
        "notes should indicate corroboration, got: {notes}"
    );
}

#[test]
fn confirmed_non_sensitive_finding_unchanged() {
    // Build a finding whose title does NOT contain sensitive keywords.
    let finding = VulnerabilityFinding {
        id: "p".to_string(),
        title: "CWE-123: Some bug in helper()".to_string(),
        description: "a generic bug".to_string(),
        severity: Severity::Low,
        confidence_score: 0.5,
        cwe_id: Some("CWE-123".to_string()),
        file_path: "/tmp/some-file.php".to_string(),
        line_number: Some(1),
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
        verification_gate_answers: None,
    };

    let (status, notes) = upgrade_for_absent_primitive(
        &finding,
        VerificationStatus::Confirmed,
        "original notes",
        &php_primitives(),
        true, // enable_absence_detection
    );

    // Non-sensitive → passthrough (unchanged)
    assert_eq!(
        status,
        VerificationStatus::Confirmed,
        "a non-sensitive finding must remain unchanged"
    );
    assert_eq!(
        notes, "original notes",
        "notes must remain unchanged for non-sensitive findings"
    );
}
