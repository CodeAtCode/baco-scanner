//! What the AST anchor already covers, measured on a realistic plugin.
//!
//! Item 3 of the review proposes anchoring WordPress findings to the hook map
//! and taking file:line from the resolver. Before starting a day of work, this
//! measures how much of that the AST anchoring already does -- so the estimate
//! is a number rather than an assumption.

use baco::findings::{Severity, VulnerabilityFinding};
use baco::llm_analysis::{LineAnchor, anchor_finding_line, function_line_ranges};

const PLUGIN: &str = include_str!("fixtures/wordpress_plugin_shape.php");

fn finding(title: &str, line: Option<u32>) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "m".to_string(),
        title: title.to_string(),
        description: String::new(),
        severity: Severity::High,
        confidence_score: 0.8,
        cwe_id: None,
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
fn test_measurement_class_methods_are_reachable_by_name() {
    // The open question for item 3: does the AST map see methods, not just free
    // functions? A plugin that registers `array( $this, 'refund' )` produces a
    // finding titled after a method.
    let ranges = function_line_ranges(PLUGIN, "php");
    assert!(
        ranges.contains_key("enable_access"),
        "a public method must be in the map, got {:?}",
        ranges.keys().collect::<Vec<_>>()
    );
    assert!(
        ranges.contains_key("refund"),
        "got {:?}",
        ranges.keys().collect::<Vec<_>>()
    );
    assert_eq!(ranges["enable_access"], (32, 34));
    assert_eq!(ranges["refund"], (36, 38));
}

#[test]
fn test_measurement_every_hooked_handler_resolves_without_the_hook_map() {
    // The four handlers this plugin registers, each reported with a wrong line
    // the way the model does. If these all resolve, the hook map adds the same
    // answer the AST already gives.
    let ranges = function_line_ranges(PLUGIN, "php");

    let cases = [
        (
            "CWE-306: Missing auth on dismiss_pointers()",
            "dismiss_pointers",
            180u32,
        ),
        (
            "CWE-862: Missing auth on process_login()",
            "process_login",
            240,
        ),
        (
            "CWE-352: CSRF on generate_web_link()",
            "generate_web_link",
            110,
        ),
        (
            "CWE-862: Missing auth on enable_access()",
            "enable_access",
            5,
        ),
        ("CWE-89: SQL injection in refund()", "refund", 900),
    ];

    let mut resolved = 0;
    let mut unresolved = Vec::new();
    for (title, name, reported) in cases {
        let mut f = finding(title, Some(reported));
        match anchor_finding_line(&mut f, &ranges) {
            LineAnchor::MovedToDefinition => {
                resolved += 1;
                let line = f.line_number.unwrap();
                let (start, end) = ranges[name];
                assert_eq!(
                    line as usize, start,
                    "{title} must land on the definition, not mid-body"
                );
                assert!(line as usize <= end);
            }
            other => unresolved.push(format!("{title}: {other:?}")),
        }
    }

    assert_eq!(
        unresolved.len(),
        0,
        "every handler in this plugin should already resolve: {unresolved:?}"
    );
    assert_eq!(resolved, cases.len());
}

#[test]
fn test_measurement_a_class_method_cited_by_its_real_line_is_left_alone() {
    let ranges = function_line_ranges(PLUGIN, "php");
    let mut f = finding("CWE-862: Missing auth on enable_access()", Some(33));
    assert_eq!(
        anchor_finding_line(&mut f, &ranges),
        LineAnchor::AlreadyInside
    );
    assert_eq!(f.line_number, Some(33));
}
