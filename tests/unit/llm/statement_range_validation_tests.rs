//! Two fields the model supplies that reach the report unvalidated.
//!
//! Both are display-only — `statement_range` renders one row, `diff_hunk` an
//! escaped `<pre>` — so unlike `code_snippet` they cannot poison a verdict. What
//! they can do is tell a reader a line range, or show a diff, that the file does
//! not support.

use baco::findings::{Severity, VulnerabilityFinding};
use baco::llm_analysis::anchor_against_ast;

const SOURCE: &str =
    "<?php\nfunction a() {\n    return 1;\n}\n\nfunction b() {\n    return 2;\n}\n";

fn finding(statement_range: Option<(u32, u32)>) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "x".to_string(),
        title: "CWE-79: issue in a()".to_string(),
        description: String::new(),
        severity: Severity::Medium,
        confidence_score: 0.7,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "p.php".to_string(),
        line_number: Some(2),
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
        statement_range,
        triage_verdict: None,
        evidence: vec![],
        verification_tier: None,
    }
}

#[test]
fn test_a_range_inside_the_file_survives() {
    let mut f = finding(Some((2, 4)));
    anchor_against_ast(std::slice::from_mut(&mut f), SOURCE, Some("php"));
    assert_eq!(f.statement_range, Some((2, 4)));
}

#[test]
fn test_a_range_past_the_end_of_the_file_is_dropped() {
    // The file has 9 lines. 99999 is not in it.
    let mut f = finding(Some((99999, 100000)));
    anchor_against_ast(std::slice::from_mut(&mut f), SOURCE, Some("php"));
    assert_eq!(
        f.statement_range, None,
        "a range the file cannot contain must not be reported as located there"
    );
}

#[test]
fn test_a_backwards_range_is_dropped() {
    let mut f = finding(Some((6, 3)));
    anchor_against_ast(std::slice::from_mut(&mut f), SOURCE, Some("php"));
    assert_eq!(f.statement_range, None, "start > end is not a range");
}

#[test]
fn test_a_range_starting_at_zero_is_dropped() {
    let mut f = finding(Some((0, 3)));
    anchor_against_ast(std::slice::from_mut(&mut f), SOURCE, Some("php"));
    assert_eq!(f.statement_range, None, "lines are 1-indexed");
}

#[test]
fn test_no_range_is_not_a_failure() {
    let mut f = finding(None);
    anchor_against_ast(std::slice::from_mut(&mut f), SOURCE, Some("php"));
    assert_eq!(f.statement_range, None, "absence stays absence");
}

#[test]
fn test_a_range_is_checked_even_without_a_language() {
    // The check needs the file, not the language. A range past the end of the
    // file is impossible whatever language it is, so it must be dropped even
    // when the language is unknown and no function map is built.
    let mut f = finding(Some((99999, 100000)));
    anchor_against_ast(std::slice::from_mut(&mut f), SOURCE, None);
    assert_eq!(f.statement_range, None);
}

#[test]
fn test_the_last_line_of_the_file_is_a_valid_range_end() {
    // The fixture is 8 lines, so (7, 8) is the boundary case. If the check were
    // exclusive the last line of every file would lose its range.
    let mut f = finding(Some((7, 8)));
    anchor_against_ast(std::slice::from_mut(&mut f), SOURCE, Some("php"));
    assert_eq!(f.statement_range, Some((7, 8)));
}

#[test]
fn test_one_line_past_the_end_is_dropped() {
    // The fixture is 8 lines, so 9 is out of bounds by exactly one.
    let mut f = finding(Some((8, 9)));
    anchor_against_ast(std::slice::from_mut(&mut f), SOURCE, Some("php"));
    assert_eq!(f.statement_range, None);
}
