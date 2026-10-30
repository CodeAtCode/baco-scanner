//! Regression test for the read-error arm of `upgrade_for_absent_primitive`.
//!
//! The upgrade path fires on a sensitive-state finding that is `NeedsReview`
//! and whose named function body contains no required primitive. When the file
//! *cannot be read* (missing, permissions, etc.), the function used to upgrade
//! the finding to `Confirmed` — conflating "I can't verify" with "absence is
//! proven". The fix leaves the finding at `NeedsReview` so an unreadable file
//! never becomes a sound confirmation.
//!
//! Teeth check: on the buggy code the `Some(Err(_))` arm returns `Confirmed`,
//! so `assert_ne!(status, Confirmed)` fails. After the fix it returns
//! `NeedsReview` and the assertion holds.

use std::collections::HashMap;

use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::scanner::phases::llm_phases::verification::upgrade_for_absent_primitive;

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
fn unreadable_file_does_not_upgrade_to_confirmed() {
    // Point at a path that does not exist so `read_to_string` fails, exercising
    // the `Some(Err(_))` arm of `anchored_body_containing_primitive`.
    let missing = "/tmp/baco-absence-does-not-exist.php";
    let finding = sensitive_finding(missing);

    let (status, notes) = upgrade_for_absent_primitive(
        &finding,
        VerificationStatus::NeedsReview,
        "model judged needs review",
        &php_primitives(),
        true, // enable_absence_detection
    );

    assert_ne!(
        status,
        VerificationStatus::Confirmed,
        "an unreadable file must not confirm absence; got notes: {notes}"
    );
    assert_eq!(
        status,
        VerificationStatus::NeedsReview,
        "the finding should stay at NeedsReview when the file can't be read"
    );
    assert!(
        notes.contains("cannot read file"),
        "the notes should explain why absence was not confirmed, got: {notes}"
    );
}

#[test]
fn absence_detection_disabled_leaves_status_unchanged() {
    // When the toggle is off, the function is a pass-through regardless of
    // file readability. This guards against the toggle being wired backwards.
    let missing = "/tmp/baco-absence-does-not-exist.php";
    let finding = sensitive_finding(missing);

    let (status, _notes) = upgrade_for_absent_primitive(
        &finding,
        VerificationStatus::NeedsReview,
        "model judged needs review",
        &php_primitives(),
        false, // enable_absence_detection off
    );

    assert_eq!(
        status,
        VerificationStatus::NeedsReview,
        "with absence detection off the status must not change"
    );
}
