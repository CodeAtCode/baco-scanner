//! A confirmed finding is refutable by reading the code, not by asking.
//!
//! The seven gate questions are the model judging itself: it is shown ±5 lines
//! around the anchored line and asked whether a guard is present. When the
//! guard is there but the model misreads it, it answers "no" and the finding
//! survives as `confirmed`.
//!
//! These tests use the reported case -- `dismiss_pointers`, where
//! `check_ajax_referer` and `current_user_can` are both in the function and the
//! finding was confirmed anyway.

use std::collections::HashMap;

use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::scanner::phases::llm_phases::verification::refute_with_primitive_check;

/// The reported plugin: the handler IS protected, and was confirmed anyway.
const PROTECTED: &str = r#"<?php
function dismiss_pointers() {
    check_ajax_referer( 'dismiss', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'forbidden' );
    }
    $wpdb->update( $wpdb->prefix . 'orders', array( 'status' => 'cleared' ) );
}

function pay4payment_rated() {
    $wpdb->update( $wpdb->prefix . 'orders', array( 'status' => 'paid' ) );
}
"#;

fn primitives(names: &[&str]) -> HashMap<String, Vec<String>> {
    HashMap::from([(
        "php".to_string(),
        names.iter().map(|s| s.to_string()).collect(),
    )])
}

fn finding(dir: &std::path::Path, title: &str, line: Option<u32>) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "p".to_string(),
        title: title.to_string(),
        description: String::new(),
        severity: Severity::High,
        confidence_score: 0.7,
        cwe_id: Some("CWE-352".to_string()),
        file_path: dir.join("plugin.php").to_string_lossy().to_string(),
        line_number: line,
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

fn write(dir: &std::path::Path, body: &str) {
    std::fs::write(dir.join("plugin.php"), body).expect("write fixture");
}

/// The second reported case: the guard is the very next line after the anchored
/// one, which is the smallest possible offset and still outside nothing.
const ADJACENT_GUARD: &str = r#"<?php
function enable_access() {
    check_admin_referer( 'enable', 'nonce' );
    update_option( 'my_plugin_enabled', 1 );
}

function delete_everything() {
    global $wpdb;
    $wpdb->query( "DELETE FROM {$wpdb->prefix}orders" );
}
"#;

#[test]
fn test_a_guard_on_the_next_line_is_found_by_reading_the_function_body() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write(dir.path(), ADJACENT_GUARD);
    let mut f = finding(
        dir.path(),
        "CWE-862: Missing authorization check on enable_access()",
        Some(2),
    );
    f.cwe_id = Some("CWE-862".to_string());

    // The full primitive list as presets/wordpress-plugin.toml declares it, so a
    // gap in the preset shows up here rather than only in a real scan.
    let (status, notes) = refute_with_primitive_check(
        &f,
        VerificationStatus::Confirmed,
        "the model saw no guard",
        &primitives(&[
            "wp_verify_nonce",
            "check_admin_referer",
            "check_ajax_referer",
            "current_user_can",
            "user_can",
        ]),
    );

    assert_eq!(
        status,
        VerificationStatus::FalsePositive,
        "the guard is inside the function the title names, so this is not a missing-auth finding"
    );
    assert!(
        notes.contains("check_admin_referer"),
        "the note must name the primitive that was found, got: {notes}"
    );
}

#[test]
fn test_a_genuinely_unprotected_function_stays_confirmed() {
    // The other half: the refutation must not fire on a function that really has
    // no guard, or it would be a blanket dismissal rather than a check.
    let dir = tempfile::tempdir().expect("tmpdir");
    write(dir.path(), ADJACENT_GUARD);
    let mut f = finding(
        dir.path(),
        "CWE-862: Missing authorization check on delete_everything()",
        Some(7),
    );
    f.cwe_id = Some("CWE-862".to_string());

    let (status, notes) = refute_with_primitive_check(
        &f,
        VerificationStatus::Confirmed,
        "no guard found",
        &primitives(&[
            "wp_verify_nonce",
            "check_admin_referer",
            "check_ajax_referer",
            "current_user_can",
            "user_can",
        ]),
    );

    assert_eq!(
        status,
        VerificationStatus::Confirmed,
        "there is no primitive in that function; it must survive, got notes: {notes}"
    );
}

#[test]
fn test_a_protected_handler_is_refuted_without_asking_the_model() {
    // The exact reported case. The model confirmed it; the code says otherwise.
    let dir = tempfile::tempdir().expect("tmpdir");
    write(dir.path(), PROTECTED);
    let f = finding(
        dir.path(),
        "CWE-352: Missing CSRF check on dismiss_pointers()",
        Some(2),
    );

    let (status, notes) = refute_with_primitive_check(
        &f,
        VerificationStatus::Confirmed,
        "the gate passed",
        &primitives(&["check_ajax_referer", "current_user_can"]),
    );

    assert_eq!(
        status,
        VerificationStatus::FalsePositive,
        "a guard in the body is decided by reading it, not by the judge"
    );
    assert!(
        notes.contains("check_ajax_referer"),
        "the reason must name the primitive found, got: {notes}"
    );
    assert!(
        notes.contains("the gate passed"),
        "the judge's own reasoning must survive: {notes}"
    );
}

#[test]
fn test_an_unprotected_handler_survives() {
    // The control. If this refuted, the check would be wrong in the direction
    // that loses real findings.
    let dir = tempfile::tempdir().expect("tmpdir");
    write(dir.path(), PROTECTED);
    let f = finding(
        dir.path(),
        "CWE-352: Missing CSRF check on pay4payment_rated()",
        Some(10),
    );

    let (status, notes) = refute_with_primitive_check(
        &f,
        VerificationStatus::Confirmed,
        "no guard found",
        &primitives(&["check_ajax_referer", "current_user_can"]),
    );

    assert_eq!(status, VerificationStatus::Confirmed);
    assert_eq!(notes, "no guard found");
}

#[test]
fn test_a_guard_in_another_function_does_not_refute() {
    // dismiss_pointers is protected; pay4payment_rated is not. The primitive
    // exists in the file but not in the function the finding names.
    let dir = tempfile::tempdir().expect("tmpdir");
    write(dir.path(), PROTECTED);
    let f = finding(
        dir.path(),
        "CWE-352: Missing CSRF check on pay4payment_rated()",
        Some(10),
    );

    let (status, _) = refute_with_primitive_check(
        &f,
        VerificationStatus::Confirmed,
        "",
        &primitives(&["check_ajax_referer"]),
    );
    assert_eq!(status, VerificationStatus::Confirmed);
}

#[test]
fn test_only_a_confirmed_verdict_is_refuted() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write(dir.path(), PROTECTED);
    let f = finding(
        dir.path(),
        "CWE-352: Missing CSRF check on dismiss_pointers()",
        Some(2),
    );

    for status in [
        VerificationStatus::NeedsReview,
        VerificationStatus::FalsePositive,
    ] {
        let (out, notes) = refute_with_primitive_check(
            &f,
            status,
            "original reasoning",
            &primitives(&["check_ajax_referer"]),
        );
        assert_eq!(out, status, "{status:?} must not be overridden");
        assert_eq!(notes, "original reasoning");
    }
}

#[test]
fn test_an_empty_primitive_list_refutes_nothing() {
    // No primitives configured means no opinion, not "everything is a false
    // positive".
    let dir = tempfile::tempdir().expect("tmpdir");
    write(dir.path(), PROTECTED);
    let f = finding(
        dir.path(),
        "CWE-352: Missing CSRF check on dismiss_pointers()",
        Some(2),
    );

    let (status, _) =
        refute_with_primitive_check(&f, VerificationStatus::Confirmed, "", &primitives(&[]));
    assert_eq!(status, VerificationStatus::Confirmed);
}

#[test]
fn test_no_primitives_for_the_files_language_refutes_nothing() {
    // The map is keyed by language; a python primitive list says nothing about
    // a PHP file.
    let dir = tempfile::tempdir().expect("tmpdir");
    write(dir.path(), PROTECTED);
    let f = finding(
        dir.path(),
        "CWE-352: Missing CSRF check on dismiss_pointers()",
        Some(2),
    );

    let (status, _) = refute_with_primitive_check(
        &f,
        VerificationStatus::Confirmed,
        "",
        &HashMap::from([("rust".to_string(), vec!["check_ajax_referer".to_string()])]),
    );
    assert_eq!(status, VerificationStatus::Confirmed);
}

#[test]
fn test_a_function_name_absent_from_the_file_refutes_nothing() {
    // A hallucinated name has no body to read, so there is nothing to decide.
    let dir = tempfile::tempdir().expect("tmpdir");
    write(dir.path(), PROTECTED);
    let f = finding(
        dir.path(),
        "CWE-352: Missing CSRF check on invented_handler()",
        Some(2),
    );

    let (status, _) = refute_with_primitive_check(
        &f,
        VerificationStatus::Confirmed,
        "",
        &primitives(&["check_ajax_referer"]),
    );
    assert_eq!(status, VerificationStatus::Confirmed);
}

#[test]
fn test_a_missing_file_downgrades_to_needs_review_with_reason() {
    // An unreadable file is absence of evidence, not evidence of absence.
    // The finding must not stay Confirmed when the check cannot run.
    let dir = tempfile::tempdir().expect("tmpdir");
    // No file written - path does not exist.
    let mut f = finding(
        dir.path(),
        "CWE-352: Missing CSRF check on dismiss_pointers()",
        Some(2),
    );
    // Use a path that definitely does not exist.
    f.file_path = dir
        .path()
        .join("nonexistent.php")
        .to_string_lossy()
        .to_string();

    let (status, notes) = refute_with_primitive_check(
        &f,
        VerificationStatus::Confirmed,
        "",
        &primitives(&["check_ajax_referer"]),
    );

    // Must not stay Confirmed - the check could not run.
    assert_eq!(
        status,
        VerificationStatus::NeedsReview,
        "unreadable file must not remain Confirmed, got: {status:?}"
    );
    // Reason must name the read failure and the path.
    assert!(
        notes.contains("cannot read"),
        "notes must mention read failure, got: {notes}"
    );
    assert!(
        notes.contains("nonexistent.php"),
        "notes must name the file, got: {notes}"
    );
}

#[test]
fn test_a_title_with_no_function_name_refutes_nothing() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write(dir.path(), PROTECTED);
    let f = finding(
        dir.path(),
        "CWE-798: Hardcoded credential in this file",
        Some(2),
    );

    let (status, _) = refute_with_primitive_check(
        &f,
        VerificationStatus::Confirmed,
        "",
        &primitives(&["check_ajax_referer"]),
    );
    assert_eq!(status, VerificationStatus::Confirmed);
}

#[test]
fn test_an_empty_note_gets_the_reason_on_its_own() {
    let dir = tempfile::tempdir().expect("tmpdir");
    write(dir.path(), PROTECTED);
    let f = finding(
        dir.path(),
        "CWE-352: Missing CSRF check on dismiss_pointers()",
        Some(2),
    );

    let (_, notes) = refute_with_primitive_check(
        &f,
        VerificationStatus::Confirmed,
        "   ",
        &primitives(&["current_user_can"]),
    );
    assert!(notes.starts_with("not confirmed"), "got: {notes}");
}

#[test]
fn test_the_second_primitive_in_the_body_is_the_one_named() {
    // dismiss_pointers calls check_ajax_referer before current_user_can. Either
    // refutes, and whichever is checked first may be the one named.
    let dir = tempfile::tempdir().expect("tmpdir");
    write(dir.path(), PROTECTED);
    let f = finding(
        dir.path(),
        "CWE-352: Missing CSRF check on dismiss_pointers()",
        Some(2),
    );

    let (status, notes) = refute_with_primitive_check(
        &f,
        VerificationStatus::Confirmed,
        "",
        &primitives(&["current_user_can"]),
    );
    assert_eq!(status, VerificationStatus::FalsePositive);
    assert!(notes.contains("current_user_can"), "got: {notes}");
}
