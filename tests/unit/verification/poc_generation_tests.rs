//! PoC generation decision tests for the verification phase.
//!
//! These tests cover the functions that decide whether a finding gets a
//! proof-of-concept generated. Each test must be able to fail — a test that
//! passes regardless of the production code mutation has no teeth.

use baco::findings::{Severity, VerificationStatus};
use baco::poc_generation::PoCFormat;
use baco::scanner::phases::llm_phases::verification::{
    find_finding_by_id, poc_formats_for_stack, poc_generation_gate, poc_generation_predicate,
};
use baco::scanner_types::project::ProjectStack;

fn make_finding(
    id: &str,
    severity: Severity,
    verification_status: Option<VerificationStatus>,
) -> baco::findings::VulnerabilityFinding {
    baco::findings::VulnerabilityFinding {
        id: id.to_string(),
        title: "Test finding".to_string(),
        description: "Test".to_string(),
        severity,
        confidence_score: 0.9,
        file_path: "test.rs".to_string(),
        verification_status,
        ..Default::default()
    }
}

/// T1: Rust project stack yields PoCFormat::Rust
#[test]
fn test_rust_stack_yields_rust_format() {
    let stack = ProjectStack {
        languages: vec!["rust".to_string()],
        ..Default::default()
    };
    let formats = poc_formats_for_stack(Some(&stack));
    assert_eq!(formats, vec![PoCFormat::Rust]);
}

/// T2: Go project stack yields PoCFormat::Go
#[test]
fn test_go_stack_yields_go_format() {
    let stack = ProjectStack {
        languages: vec!["go".to_string()],
        ..Default::default()
    };
    let formats = poc_formats_for_stack(Some(&stack));
    assert_eq!(formats, vec![PoCFormat::Go]);
}

/// T3: Empty stack or no stack yields default Python format
#[test]
fn test_empty_or_no_stack_yields_python_format() {
    let empty_stack = ProjectStack {
        languages: vec![],
        ..Default::default()
    };
    assert_eq!(
        poc_formats_for_stack(Some(&empty_stack)),
        vec![PoCFormat::Python]
    );
    assert_eq!(poc_formats_for_stack(None), vec![PoCFormat::Python]);
}

/// T4: Filter rejects high-severity FalsePositive, accepts Confirmed
#[test]
fn test_poc_filter_rejects_false_positive_accepts_confirmed() {
    let fp = make_finding(
        "fp",
        Severity::High,
        Some(VerificationStatus::FalsePositive),
    );
    let conf = make_finding("conf", Severity::Low, Some(VerificationStatus::Confirmed));
    let conf_high = make_finding(
        "conf_high",
        Severity::High,
        Some(VerificationStatus::Confirmed),
    );
    let unverified_high = make_finding("unverified", Severity::High, None);

    // High-severity FalsePositive is rejected
    assert!(!poc_generation_predicate(&fp));
    // Low-severity Confirmed is rejected (not high/critical)
    assert!(!poc_generation_predicate(&conf));
    // High-severity Confirmed is accepted
    assert!(poc_generation_predicate(&conf_high));
    // High-severity unverified is accepted
    assert!(poc_generation_predicate(&unverified_high));
}

/// T5: Gate blocks generation when no high-severity findings
#[test]
fn test_generation_gate_blocks_empty_findings() {
    let empty: Vec<baco::findings::VulnerabilityFinding> = vec![];
    assert!(!poc_generation_gate(&empty));
}

/// T6: Assignment matches by id, picks correct finding among many
#[test]
fn test_assignment_matches_by_id_picks_correct_finding() {
    let mut findings = vec![
        make_finding("first", Severity::High, Some(VerificationStatus::Confirmed)),
        make_finding(
            "target",
            Severity::Critical,
            Some(VerificationStatus::Confirmed),
        ),
        make_finding("third", Severity::High, Some(VerificationStatus::Confirmed)),
    ];

    let result = find_finding_by_id(&mut findings, "target");
    assert!(result.is_some());
    assert_eq!(result.unwrap().id, "target");
}
