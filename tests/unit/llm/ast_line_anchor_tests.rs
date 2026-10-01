//! Anchoring a finding's line to the function its title names.
//!
//! The model reads the function name off the code and estimates the line. The
//! name is the part it saw; the line is the part it guessed. Where they
//! disagree, the AST settles it.

use baco::findings::{Severity, VulnerabilityFinding};
use baco::llm_analysis::{LineAnchor, anchor_finding_line, function_line_ranges};

/// The shape of the finding a real scan produced: the name in the title is
/// right, the line points somewhere else in the same file.
const PHP_SOURCE: &str = r#"<?php
add_action( 'wp_ajax_nopriv_pay4payment_rated', 'dismiss_pointers' );

function dismiss_pointers() {
    $wpdb->update( $wpdb->prefix . 'orders', array( 'status' => 'cleared' ) );
}

function generate_web_link() {
    return esc_url( add_query_arg( 'rated', '1' ) );
}

function enable_access() {
    current_user_can( 'manage_options' );
}
"#;

fn finding(title: &str, line: Option<u32>) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test".to_string(),
        title: title.to_string(),
        description: String::new(),
        severity: Severity::High,
        confidence_score: 0.8,
        cwe_id: Some("CWE-306".to_string()),
        file_path: "plugin.php".to_string(),
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

#[test]
fn test_ast_gives_the_true_line_of_each_function() {
    let ranges = function_line_ranges(PHP_SOURCE, "php");
    let dismiss = ranges.get("dismiss_pointers").expect("php function");
    let web_link = ranges.get("generate_web_link").expect("php function");
    let access = ranges.get("enable_access").expect("php function");

    // These are the real definitions, and they are what the reported lines
    // should be pulled back to.
    // dismiss_pointers opens on line 4: the add_action on 2, a blank on 3.
    assert_eq!(dismiss.0, 4, "dismiss_pointers is defined at line 4");
    assert_eq!(web_link.0, 8, "generate_web_link is defined at line 8");
    assert_eq!(access.0, 12, "enable_access is defined at line 12");
    // A range covers the body, not just the signature line.
    assert!(dismiss.1 > dismiss.0, "the range must span the body");
}

#[test]
fn test_line_outside_the_named_function_is_moved_to_its_definition() {
    // The reported case: the title names dismiss_pointers, the line says 180,
    // which is nowhere near it. The AST is what settles it.
    let ranges = function_line_ranges(PHP_SOURCE, "php");
    let mut f = finding(
        "CWE-306: Missing Authentication for AJAX Endpoint dismiss_pointers()",
        Some(180),
    );
    let outcome = anchor_finding_line(&mut f, &ranges);
    assert_eq!(outcome, LineAnchor::MovedToDefinition);
    assert_eq!(
        f.line_number,
        Some(4),
        "the line must land on the function the title names"
    );
}

#[test]
fn test_line_inside_the_named_function_is_left_alone() {
    // The one case that was already right must stay right, or the correction
    // becomes its own source of wrong lines.
    let ranges = function_line_ranges(PHP_SOURCE, "php");
    let mut f = finding("CWE-352: CSRF in enable_access()", Some(12));
    let outcome = anchor_finding_line(&mut f, &ranges);
    assert_eq!(outcome, LineAnchor::AlreadyInside);
    assert_eq!(f.line_number, Some(12));
}

#[test]
fn test_a_line_inside_a_different_function_is_still_wrong() {
    // 8 is inside generate_web_link. A check of "is the line inside any
    // function" would pass this; the check is "inside the named one".
    let ranges = function_line_ranges(PHP_SOURCE, "php");
    let mut f = finding("CWE-306: Missing auth in dismiss_pointers()", Some(8));
    let outcome = anchor_finding_line(&mut f, &ranges);
    assert_eq!(outcome, LineAnchor::MovedToDefinition);
    assert_eq!(f.line_number, Some(4));
}

#[test]
fn test_each_wrong_finding_in_the_reported_set_is_corrected() {
    // Four of the five hand-checked findings had a wrong line and a correct
    // name. All four must come back pointing at their own function.
    let ranges = function_line_ranges(PHP_SOURCE, "php");
    let cases = [
        ("Missing Authentication dismiss_pointers()", 180u32, 4u32),
        ("Missing Authentication generate_web_link()", 240, 8),
        ("Missing Authorisation enable_access()", 110, 12),
    ];
    for (title, reported, expected) in cases {
        let mut f = finding(title, Some(reported));
        assert_eq!(
            anchor_finding_line(&mut f, &ranges),
            LineAnchor::MovedToDefinition,
            "{title} at {reported} should have been moved"
        );
        assert_eq!(f.line_number, Some(expected), "{title}");
    }
}

#[test]
fn test_a_name_that_is_not_in_the_file_is_reported_not_guessed() {
    // Dropping the finding here would lose a real one on a model that formats
    // titles differently, so the name is reported and the line left as-is for
    // citation verification to judge.
    let ranges = function_line_ranges(PHP_SOURCE, "php");
    let mut f = finding("CWE-306: Missing auth in not_a_function_here()", Some(180));
    let outcome = anchor_finding_line(&mut f, &ranges);
    assert_eq!(outcome, LineAnchor::NameNotInFile);
    assert_eq!(
        f.line_number,
        Some(180),
        "the line is not replaced with a guess"
    );
}

#[test]
fn test_a_title_with_no_function_name_is_untouched() {
    let ranges = function_line_ranges(PHP_SOURCE, "php");
    let mut f = finding("CWE-798: Hardcoded credential in the config block", Some(4));
    let outcome = anchor_finding_line(&mut f, &ranges);
    assert_eq!(outcome, LineAnchor::NoNameGiven);
    assert_eq!(f.line_number, Some(4));
}

#[test]
fn test_a_parenthesised_cwe_is_not_mistaken_for_a_function() {
    // "Missing auth (CWE-306)" offers "CWE" as a candidate. It is not in the
    // file, so the line is left alone -- what must not happen is anchoring to
    // a function named CWE, and nothing here can.
    let ranges = function_line_ranges(PHP_SOURCE, "php");
    let mut f = finding("Missing authentication (CWE-306) in this handler", Some(4));
    let outcome = anchor_finding_line(&mut f, &ranges);
    assert!(
        !matches!(outcome, LineAnchor::MovedToDefinition),
        "a CWE reference must never become an anchor, got {outcome:?}"
    );
    assert_eq!(f.line_number, Some(4), "the reported line is left alone");
}

#[test]
fn test_a_bare_name_without_parens_is_not_treated_as_an_anchor() {
    // Only `name(` counts. A bare identifier in prose is far more likely to be
    // a CWE, a hook name or a variable than a function, and guessing would
    // manufacture exactly the wrong line the check exists to prevent.
    let ranges = function_line_ranges(PHP_SOURCE, "php");
    let mut f = finding("CWE-306 dismiss_pointers has no nonce check", Some(180));
    assert_eq!(
        anchor_finding_line(&mut f, &ranges),
        LineAnchor::NoNameGiven
    );
    assert_eq!(f.line_number, Some(180));
}

#[test]
fn test_an_unparsable_file_yields_no_ranges_and_changes_nothing() {
    // Half a file is not an error, it is just not a map. The finding survives
    // rather than being anchored to nothing.
    let truncated = "<?php\nfunction dismiss_pointers() {\n    $x = ";
    let ranges = function_line_ranges(truncated, "php");
    let mut f = finding("CWE-306 in dismiss_pointers()", Some(2));
    anchor_finding_line(&mut f, &ranges);
    assert_eq!(f.line_number, Some(2), "no map means no correction");
}

#[test]
fn test_an_unknown_language_yields_no_ranges() {
    let ranges = function_line_ranges("anything at all", "klingon");
    assert!(ranges.is_empty());
}
