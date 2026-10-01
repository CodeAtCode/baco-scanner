//! The snippet shown to the verifier must be the file's own text.
//!
//! The model reproduces the vulnerable lines from memory, and what it
//! reproduces is what the verifier reads as `>>> VULNERABLE CODE <<<` and what
//! the patcher is asked to fix. A snippet that is not in the file is evidence
//! for a line that does not contain it.

use baco::findings::{Severity, VulnerabilityFinding};
use baco::llm_analysis::anchor_against_ast;

const PHP: &str = r#"<?php
function dismiss_pointers() {
    $wpdb->update( $wpdb->prefix . 'orders', array( 'status' => 'cleared' ) );
}

function other() {
    return 1;
}
"#;

fn finding(title: &str, line: Option<u32>, snippet: Option<&str>) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "s".to_string(),
        title: title.to_string(),
        description: String::new(),
        severity: Severity::High,
        confidence_score: 0.7,
        cwe_id: None,
        file_path: "plugin.php".to_string(),
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

fn run(f: &mut [VulnerabilityFinding]) {
    anchor_against_ast(f, PHP, Some("php"));
}

#[test]
fn test_a_hallucinated_snippet_is_replaced_with_the_real_lines() {
    let mut f = vec![finding(
        "CWE-306: Missing auth on dismiss_pointers()",
        Some(2),
        Some("$wpdb->delete( $wpdb->prefix . 'users' );"),
    )];
    run(&mut f);
    let snippet = f[0].code_snippet.as_deref().expect("restated");
    assert!(
        snippet.contains("$wpdb->update"),
        "the real line must be shown, got: {snippet}"
    );
    assert!(
        !snippet.contains("delete"),
        "the invented line must be gone, got: {snippet}"
    );
    assert!(
        snippet.contains("  2:"),
        "the restatement must be line-numbered so it is checkable, got: {snippet}"
    );
}

#[test]
fn test_a_snippet_that_matches_the_file_is_left_alone() {
    let real = "$wpdb->update( $wpdb->prefix . 'orders', array( 'status' => 'cleared' ) );";
    let mut f = vec![finding(
        "CWE-306: Missing auth on dismiss_pointers()",
        Some(2),
        Some(real),
    )];
    run(&mut f);
    assert_eq!(
        f[0].code_snippet.as_deref(),
        Some(real),
        "a faithful snippet is not decoration and must survive"
    );
}

#[test]
fn test_the_scaffolding_lines_do_not_count_as_a_mismatch() {
    // The parser wraps the snippet in context markers. Those are baco's, not
    // the model's, and must not trigger a restatement.
    let real = "$wpdb->update( $wpdb->prefix . 'orders', array( 'status' => 'cleared' ) );";
    let decorated = format!(
        "--- Context before ---\nfunction dismiss_pointers() {{\n>>> VULNERABLE CODE <<<\n{real}\n--- Context after ---\n"
    );
    let mut f = vec![finding(
        "CWE-306: Missing auth on dismiss_pointers()",
        Some(2),
        Some(&decorated),
    )];
    run(&mut f);
    assert_eq!(
        f[0].code_snippet.as_deref(),
        Some(decorated.as_str()),
        "baco's own markers must not count as invented lines"
    );
}

#[test]
fn test_one_invented_line_condemns_the_whole_snippet() {
    // The real line plus one the model made up: keeping half of it would still
    // show the verifier something the file does not contain.
    let real = "$wpdb->update( $wpdb->prefix . 'orders', array( 'status' => 'cleared' ) );";
    let mixed = format!("{real}\nsystem('rm -rf /');");
    let mut f = vec![finding(
        "CWE-306: Missing auth on dismiss_pointers()",
        Some(2),
        Some(&mixed),
    )];
    run(&mut f);
    let snippet = f[0].code_snippet.as_deref().expect("restated");
    assert!(!snippet.contains("rm -rf"), "got: {snippet}");
    assert!(snippet.contains("$wpdb->update"), "got: {snippet}");
}

#[test]
fn test_a_snippet_with_no_line_is_dropped_not_guessed() {
    // Without a line there is nothing to restate from, and guessing a window
    // would put real code next to a claim it does not support.
    let mut f = vec![finding(
        "CWE-306: Missing auth somewhere",
        None,
        Some("$wpdb->delete( $wpdb->prefix . 'users' );"),
    )];
    run(&mut f);
    assert_eq!(
        f[0].code_snippet, None,
        "an unanchored snippet has nothing to check against"
    );
}

#[test]
fn test_an_empty_snippet_becomes_absent_not_a_blank() {
    let mut f = vec![finding("CWE-306: Missing auth", Some(2), Some("   \n\t "))];
    run(&mut f);
    assert_eq!(f[0].code_snippet, None);
}

#[test]
fn test_a_file_with_no_snippet_is_untouched() {
    let mut f = vec![finding(
        "CWE-306: Missing auth on dismiss_pointers()",
        Some(2),
        None,
    )];
    run(&mut f);
    assert_eq!(f[0].code_snippet, None);
}

#[test]
fn test_restatement_still_happens_for_a_file_the_ast_cannot_parse() {
    // No ranges, no language, no functions -- the snippet check does not depend
    // on any of them, because the file text is all it needs.
    let mut f = vec![finding("CWE-306", Some(2), Some("total fabrication"))];
    anchor_against_ast(&mut f, "not code at all {{{", None);
    let snippet = f[0].code_snippet.as_deref().expect("restated");
    assert!(snippet.contains("not code at all"), "got: {snippet}");
    assert!(!snippet.contains("total fabrication"), "got: {snippet}");
}

#[test]
fn test_a_line_past_the_end_of_the_file_drops_the_snippet() {
    let mut f = vec![finding("CWE-306", Some(9000), Some("$wpdb->delete( $x );"))];
    run(&mut f);
    assert_eq!(f[0].code_snippet, None, "no such line to read");
}

#[test]
fn test_indented_snippet_lines_match_the_files_indentation() {
    // The model strips leading whitespace when it reproduces a line. That is
    // still the same line and must not be treated as invented.
    let real = "$wpdb->update( $wpdb->prefix . 'orders', array( 'status' => 'cleared' ) );";
    let mut f = vec![finding("CWE-306", Some(2), Some(real))];
    run(&mut f);
    assert_eq!(
        f[0].code_snippet.as_deref(),
        Some(real),
        "trimmed comparison is the right one; a snippet is indentation-insensitive"
    );
}
