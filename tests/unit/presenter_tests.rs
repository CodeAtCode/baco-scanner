//! Unit tests for src/report/presenter.rs
//!
//! Tests cover all public functions and presenters from the presenter module.

use baco::findings::{Severity, TriageVerdict, VerificationStatus, VulnerabilityFinding};
use baco::report::presenter::*;

// ============================================================================
// Fixtures
// ============================================================================

fn make_finding_presenter(
    id: &str,
    severity: Severity,
    file: &str,
    line: Option<u32>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: format!("Finding {}", id),
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

fn make_finding_with_cwe(id: &str, cwe: &str) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: "Test finding".to_string(),
        description: "Test".to_string(),
        severity: Severity::Medium,
        confidence_score: 0.5,
        cwe_id: Some(cwe.to_string()),
        file_path: "src/test.rs".to_string(),
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
    }
}

fn make_finding_with_all_metadata() -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "meta-finding".to_string(),
        title: "Metadata test".to_string(),
        description: "Test".to_string(),
        severity: Severity::High,
        confidence_score: 0.9,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "src/test.rs".to_string(),
        line_number: Some(42),
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec![],
        commit_reference: Some("abc123def".to_string()),
        ticket_reference: Some("SEC-123".to_string()),
        priority_score: Some(0.85),
        cross_file_references: Some(vec!["src/utils.rs".to_string(), "src/lib.rs".to_string()]),
        verification_status: Some(VerificationStatus::Confirmed),
        verification_notes: Some(
            "Manual review confirmed\\n- Checked inputs\\n- Verified outputs".to_string(),
        ),
        verification_error: Some("Connection timeout during verification".to_string()),
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
        statement_range: Some((15, 20)),
        triage_verdict: Some(TriageVerdict::Pass),
        evidence: vec![],
        verification_tier: None,
    }
}

// ============================================================================
// severity_class Tests
// ============================================================================

#[test]
fn test_severity_class_critical() {
    assert_eq!(severity_class(Severity::Critical), "critical");
}

#[test]
fn test_severity_class_high() {
    assert_eq!(severity_class(Severity::High), "high");
}

#[test]
fn test_severity_class_medium() {
    assert_eq!(severity_class(Severity::Medium), "medium");
}

#[test]
fn test_severity_class_low() {
    assert_eq!(severity_class(Severity::Low), "low");
}

#[test]
fn test_severity_class_info() {
    assert_eq!(severity_class(Severity::Info), "info");
}

// ============================================================================
// confidence_class Tests - Boundary Values
// ============================================================================

#[test]
fn test_confidence_class_zero() {
    assert_eq!(confidence_class(0.0), "confidence-low");
}

#[test]
fn test_confidence_class_below_medium() {
    assert_eq!(confidence_class(0.3999), "confidence-low");
}

#[test]
fn test_confidence_class_at_medium_boundary() {
    assert_eq!(confidence_class(0.4), "confidence-medium");
}

#[test]
fn test_confidence_class_above_medium() {
    assert_eq!(confidence_class(0.5), "confidence-medium");
}

#[test]
fn test_confidence_class_below_high() {
    assert_eq!(confidence_class(0.6999), "confidence-medium");
}

#[test]
fn test_confidence_class_at_high_boundary() {
    assert_eq!(confidence_class(0.7), "confidence-high");
}

#[test]
fn test_confidence_class_above_high() {
    assert_eq!(confidence_class(0.8), "confidence-high");
}

#[test]
fn test_confidence_class_one() {
    assert_eq!(confidence_class(1.0), "confidence-high");
}

// ============================================================================
// detect_language Tests
// ============================================================================

#[test]
fn test_detect_language_python() {
    assert_eq!(detect_language("test.py"), "python");
}

#[test]
fn test_detect_language_javascript() {
    assert_eq!(detect_language("test.js"), "javascript");
}

#[test]
fn test_detect_language_typescript() {
    assert_eq!(detect_language("test.ts"), "typescript");
}

#[test]
fn test_detect_language_typescript_jsx() {
    assert_eq!(detect_language("test.tsx"), "typescript");
}

#[test]
fn test_detect_language_rust() {
    assert_eq!(detect_language("test.rs"), "rust");
}

#[test]
fn test_detect_language_go() {
    assert_eq!(detect_language("test.go"), "go");
}

#[test]
fn test_detect_language_java() {
    assert_eq!(detect_language("test.java"), "java");
}

#[test]
fn test_detect_language_c() {
    assert_eq!(detect_language("test.c"), "c");
}

#[test]
fn test_detect_language_cpp() {
    assert_eq!(detect_language("test.cpp"), "cpp");
    assert_eq!(detect_language("test.cc"), "cpp");
    assert_eq!(detect_language("test.cxx"), "cpp");
}

#[test]
fn test_detect_language_cpp_header() {
    assert_eq!(detect_language("test.h"), "cpp");
    assert_eq!(detect_language("test.hpp"), "cpp");
}

#[test]
fn test_detect_language_php() {
    assert_eq!(detect_language("test.php"), "php");
    assert_eq!(detect_language("test.phtml"), "php");
}

#[test]
fn test_detect_language_sql() {
    assert_eq!(detect_language("test.sql"), "sql");
}

#[test]
fn test_detect_language_yaml() {
    assert_eq!(detect_language("test.yml"), "yaml");
    assert_eq!(detect_language("test.yaml"), "yaml");
}

#[test]
fn test_detect_language_json() {
    assert_eq!(detect_language("test.json"), "json");
}

#[test]
fn test_detect_language_bash() {
    assert_eq!(detect_language("test.sh"), "bash");
    assert_eq!(detect_language("test.bash"), "bash");
}

#[test]
fn test_detect_language_ruby() {
    assert_eq!(detect_language("test.rb"), "ruby");
}

#[test]
fn test_detect_language_kotlin() {
    assert_eq!(detect_language("test.kt"), "kotlin");
}

#[test]
fn test_detect_language_scala() {
    assert_eq!(detect_language("test.scala"), "scala");
}

#[test]
fn test_detect_language_perl() {
    assert_eq!(detect_language("test.pl"), "perl");
    assert_eq!(detect_language("test.pm"), "perl");
}

#[test]
fn test_detect_language_lua() {
    assert_eq!(detect_language("test.lua"), "lua");
}

#[test]
fn test_detect_language_solidity() {
    assert_eq!(detect_language("test.sol"), "solidity");
}

#[test]
fn test_detect_language_csharp() {
    assert_eq!(detect_language("test.cs"), "csharp");
}

#[test]
fn test_detect_language_swift() {
    assert_eq!(detect_language("test.swift"), "swift");
}

#[test]
fn test_detect_language_unknown() {
    assert_eq!(detect_language("test.xyz"), "");
    assert_eq!(detect_language("unknown"), "");
}

#[test]
fn test_detect_language_no_extension() {
    assert_eq!(detect_language("README"), "");
}

// ============================================================================
// format_location Tests
// ============================================================================

#[test]
fn test_format_location_with_line() {
    assert_eq!(format_location("src/test.rs", Some(42)), "src/test.rs:42");
}

#[test]
fn test_format_location_without_line() {
    assert_eq!(format_location("src/test.rs", None), "src/test.rs");
}

#[test]
fn test_format_location_line_zero() {
    assert_eq!(format_location("src/test.rs", Some(0)), "src/test.rs:0");
}

// ============================================================================
// format_location_markdown Tests
// ============================================================================

#[test]
fn test_format_location_markdown_with_line() {
    assert_eq!(
        format_location_markdown("src/test.rs", Some(42)),
        "`src/test.rs`:42"
    );
}

#[test]
fn test_format_location_markdown_without_line() {
    assert_eq!(
        format_location_markdown("src/test.rs", None),
        "`src/test.rs`"
    );
}

#[test]
fn test_format_location_markdown_line_zero() {
    assert_eq!(
        format_location_markdown("src/test.rs", Some(0)),
        "`src/test.rs`:0"
    );
}

// ============================================================================
// build_cwe_badge Tests
// ============================================================================

#[test]
fn test_build_cwe_badge_with_id() {
    let cwe = Some("CWE-79".to_string());
    assert_eq!(build_cwe_badge(&cwe), "CWE-79");
}

#[test]
fn test_build_cwe_badge_without_id() {
    let cwe: Option<String> = None;
    assert_eq!(build_cwe_badge(&cwe), "");
}

// ============================================================================
// build_cwe_badge_html Tests
// ============================================================================

#[test]
fn test_build_cwe_badge_html_with_id() {
    let cwe = Some("CWE-79".to_string());
    let html = build_cwe_badge_html(&cwe);
    assert!(html.contains("<span class=\"cwe-badge\">"));
    assert!(html.contains("CWE-79"));
}

#[test]
fn test_build_cwe_badge_html_without_id() {
    let cwe: Option<String> = None;
    assert_eq!(build_cwe_badge_html(&cwe), "");
}

#[test]
fn test_build_cwe_badge_html_escapes_html() {
    let cwe = Some("<script>alert('xss')</script>".to_string());
    let html = build_cwe_badge_html(&cwe);
    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;script&gt;"));
}

// ============================================================================
// build_cwe_link_html Tests
// ============================================================================

#[test]
fn test_build_cwe_link_html_with_id() {
    let cwe = Some("CWE-79".to_string());
    let html = build_cwe_link_html(&cwe);
    assert!(html.contains("<strong>CWE:</strong>"));
    assert!(html.contains("<a href=\"https://cwe.mitre.org/data/definitions/CWE-79.html\""));
    assert!(html.contains("CWE-79"));
}

#[test]
fn test_build_cwe_link_html_without_id() {
    let cwe: Option<String> = None;
    assert_eq!(build_cwe_link_html(&cwe), "");
}

#[test]
fn test_build_cwe_link_html_escapes_html() {
    let cwe = Some("<script>alert('xss')</script>".to_string());
    let html = build_cwe_link_html(&cwe);
    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;script&gt;"));
}

// ============================================================================
// format_confidence_percentage Tests
// ============================================================================

#[test]
fn test_format_confidence_percentage_zero() {
    assert_eq!(format_confidence_percentage(0.0), "0.0%");
}

#[test]
fn test_format_confidence_percentage_half() {
    assert_eq!(format_confidence_percentage(0.5), "50.0%");
}

#[test]
fn test_format_confidence_percentage_one() {
    assert_eq!(format_confidence_percentage(1.0), "100.0%");
}

#[test]
fn test_format_confidence_percentage_boundary() {
    assert_eq!(format_confidence_percentage(0.7), "70.0%");
    assert_eq!(format_confidence_percentage(0.4), "40.0%");
}

// ============================================================================
// format_confidence_int_percentage Tests
// ============================================================================

#[test]
fn test_format_confidence_int_percentage_zero() {
    assert_eq!(format_confidence_int_percentage(0.0), "0%");
}

#[test]
fn test_format_confidence_int_percentage_half() {
    assert_eq!(format_confidence_int_percentage(0.5), "50%");
}

#[test]
fn test_format_confidence_int_percentage_one() {
    assert_eq!(format_confidence_int_percentage(1.0), "100%");
}

#[test]
fn test_format_confidence_int_percentage_rounds() {
    assert_eq!(format_confidence_int_percentage(0.555), "56%");
    assert_eq!(format_confidence_int_percentage(0.554), "55%");
}

// ============================================================================
// MetadataRows Tests
// ============================================================================

#[test]
fn test_metadata_rows_new_empty() {
    let rows = MetadataRows::new();
    assert!(rows.is_empty());
    assert_eq!(rows.join(", "), "");
}

#[test]
fn test_metadata_rows_push_and_join() {
    let mut rows = MetadataRows::new();
    rows.push("item1".to_string());
    rows.push("item2".to_string());
    assert!(!rows.is_empty());
    assert_eq!(rows.join(", "), "item1, item2");
}

#[test]
fn test_metadata_rows_default() {
    let rows = MetadataRows::default();
    assert!(rows.is_empty());
}

// ============================================================================
// build_metadata_rows Tests
// ============================================================================

#[test]
fn test_build_metadata_rows_empty() {
    let finding = make_finding_presenter("f1", Severity::Low, "src/test.rs", Some(1));
    let rows = build_metadata_rows(&finding);
    assert!(rows.is_empty());
}

#[test]
fn test_build_metadata_rows_with_cwe() {
    let finding = make_finding_with_cwe("f1", "CWE-79");
    let rows = build_metadata_rows(&finding);
    assert!(!rows.is_empty());
    assert!(rows.join("").contains("CWE:"));
    assert!(rows.join("").contains("CWE-79"));
}

#[test]
fn test_build_metadata_rows_with_verification_status() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.verification_status = Some(VerificationStatus::Confirmed);
    let rows = build_metadata_rows(&finding);
    let joined = rows.join("");
    assert!(joined.contains("<strong>Verification:</strong>"));
    assert!(joined.contains("confirmed"));
}

#[test]
fn test_build_metadata_rows_with_priority() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.priority_score = Some(0.85);
    let rows = build_metadata_rows(&finding);
    let joined = rows.join("");
    assert!(joined.contains("<strong>Priority:</strong>"));
    assert!(joined.contains("85.0"));
}

#[test]
fn test_build_metadata_rows_with_cross_file_refs() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.cross_file_references = Some(vec!["src/a.rs".to_string(), "src/b.rs".to_string()]);
    let rows = build_metadata_rows(&finding);
    let joined = rows.join("");
    assert!(joined.contains("<strong>Cross-file refs:</strong>"));
    assert!(joined.contains("src/a.rs"));
}

#[test]
fn test_build_metadata_rows_with_ticket() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.ticket_reference = Some("SEC-123".to_string());
    let rows = build_metadata_rows(&finding);
    let joined = rows.join("");
    assert!(joined.contains("<strong>Ticket:</strong>"));
    assert!(joined.contains("SEC-123"));
}

#[test]
fn test_build_metadata_rows_with_statement_range() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.statement_range = Some((10, 20));
    let rows = build_metadata_rows(&finding);
    let joined = rows.join("");
    assert!(joined.contains("<strong>Statement range:</strong>"));
    assert!(joined.contains("lines 10-20"));
}

#[test]
fn test_build_metadata_rows_with_verification_notes() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.verification_notes = Some("Manual review".to_string());
    let rows = build_metadata_rows(&finding);
    let joined = rows.join("");
    assert!(joined.contains("<strong>Verification notes:</strong>"));
}

#[test]
fn test_build_metadata_rows_with_verification_error() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.verification_error = Some("Timeout".to_string());
    let rows = build_metadata_rows(&finding);
    let joined = rows.join("");
    assert!(joined.contains("<strong>Verification error:</strong>"));
    assert!(joined.contains("verification-error"));
    assert!(joined.contains("Timeout"));
}

#[test]
fn test_build_metadata_rows_with_commit() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.commit_reference = Some("abc123".to_string());
    let rows = build_metadata_rows(&finding);
    let joined = rows.join("");
    assert!(joined.contains("<strong>Commit:</strong>"));
    assert!(joined.contains("abc123"));
}

#[test]
fn test_build_metadata_rows_with_triage_verdict_pass() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.triage_verdict = Some(TriageVerdict::Pass);
    let rows = build_metadata_rows(&finding);
    let joined = rows.join("");
    assert!(joined.contains("<strong>Triage:</strong>"));
    assert!(joined.contains("Pass"));
}

#[test]
fn test_build_metadata_rows_with_triage_verdict_kill() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.triage_verdict = Some(TriageVerdict::Kill);
    let rows = build_metadata_rows(&finding);
    let joined = rows.join("");
    assert!(joined.contains("Kill"));
}

#[test]
fn test_build_metadata_rows_with_triage_verdict_downgrade() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.triage_verdict = Some(TriageVerdict::Downgrade {
        adjusted_severity: Severity::Medium,
    });
    let rows = build_metadata_rows(&finding);
    let joined = rows.join("");
    assert!(joined.contains("Downgrade"));
}

#[test]
fn test_build_metadata_rows_with_triage_verdict_chain_required() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.triage_verdict = Some(TriageVerdict::ChainRequired {
        chain_partner_ids: vec!["f2".to_string()],
    });
    let rows = build_metadata_rows(&finding);
    let joined = rows.join("");
    assert!(joined.contains("Chain Required"));
}

#[test]
fn test_build_metadata_rows_comprehensive() {
    let finding = make_finding_with_all_metadata();
    let rows = build_metadata_rows(&finding);
    let joined = rows.join("");

    assert!(joined.contains("CWE:"));
    assert!(joined.contains("Verification:"));
    assert!(joined.contains("Priority:"));
    assert!(joined.contains("Cross-file refs:"));
    assert!(joined.contains("Ticket:"));
    assert!(joined.contains("Statement range:"));
    assert!(joined.contains("Verification notes:"));
    assert!(joined.contains("Verification error:"));
    assert!(joined.contains("Commit:"));
    assert!(joined.contains("Triage:"));
}

// ============================================================================
// CodeSnippetPresenter Tests
// ============================================================================

#[test]
fn test_code_snippet_presenter_new_with_diff() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.diff_hunk = Some("-old\n+new".to_string());
    let presenter = CodeSnippetPresenter::new(&finding);
    assert!(presenter.has_diff);
    assert!(!presenter.has_code);
    assert_eq!(presenter.diff_hunk, Some("-old\n+new".to_string()));
}

#[test]
fn test_code_snippet_presenter_new_with_code() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.code_snippet = Some("vulnerable code".to_string());
    let presenter = CodeSnippetPresenter::new(&finding);
    assert!(!presenter.has_diff);
    assert!(presenter.has_code);
    assert_eq!(presenter.code_snippet, Some("vulnerable code".to_string()));
}

#[test]
fn test_code_snippet_presenter_render_html_with_diff() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.diff_hunk = Some("-old line\n+new line".to_string());
    let presenter = CodeSnippetPresenter::new(&finding);
    let html = presenter.render_html("src/test.rs");
    assert!(html.contains("diff-hunk"));
    assert!(html.contains("diff-header"));
    assert!(html.contains("-old line"));
    assert!(html.contains("+new line"));
}

#[test]
fn test_code_snippet_presenter_render_html_empty_diff_fallback_to_code() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.py", Some(1));
    finding.diff_hunk = Some("".to_string());
    finding.code_snippet = Some("vulnerable code".to_string());
    let presenter = CodeSnippetPresenter::new(&finding);
    let html = presenter.render_html("src/test.py");
    assert!(html.contains("code-snippet-single"));
    assert!(html.contains("vulnerable code"));
    assert!(html.contains("language-python"));
}

#[test]
fn test_code_snippet_presenter_render_html_with_code_only() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.code_snippet = Some("unsafe code".to_string());
    let presenter = CodeSnippetPresenter::new(&finding);
    let html = presenter.render_html("src/test.rs");
    assert!(html.contains("code-snippet-single"));
    assert!(html.contains("unsafe code"));
}

#[test]
fn test_code_snippet_presenter_render_html_empty() {
    let finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    let presenter = CodeSnippetPresenter::new(&finding);
    let html = presenter.render_html("src/test.rs");
    assert!(html.is_empty());
}

#[test]
fn test_code_snippet_presenter_render_markdown_with_code() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.code_snippet = Some("code snippet".to_string());
    let presenter = CodeSnippetPresenter::new(&finding);
    let md = presenter.render_markdown("src/test.rs");
    assert!(md.contains("**Code:**"));
    assert!(md.contains("```text"));
    assert!(md.contains("code snippet"));
}

#[test]
fn test_code_snippet_presenter_render_markdown_with_diff() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.diff_hunk = Some("-old\n+new".to_string());
    let presenter = CodeSnippetPresenter::new(&finding);
    let md = presenter.render_markdown("src/test.rs");
    assert!(md.contains("**Diff:**"));
    assert!(md.contains("```diff"));
}

#[test]
fn test_code_snippet_presenter_render_markdown_empty() {
    let finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    let presenter = CodeSnippetPresenter::new(&finding);
    let md = presenter.render_markdown("src/test.rs");
    assert!(md.is_empty());
}

// ============================================================================
// RecommendationPresenter Tests
// ============================================================================

#[test]
fn test_recommendation_presenter_new() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.recommendation = Some("Fix this".to_string());
    let presenter = RecommendationPresenter::new(&finding);
    assert_eq!(presenter.recommendation, Some("Fix this".to_string()));
}

#[test]
fn test_recommendation_presenter_render_html_with_recommendation() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.recommendation = Some("Use safe API".to_string());
    let presenter = RecommendationPresenter::new(&finding);
    let html = presenter.render_html();
    assert!(html.contains("<div class=\"recommendation\">"));
    assert!(html.contains("<strong>Recommendation:</strong>"));
    assert!(html.contains("Use safe API"));
}

#[test]
fn test_recommendation_presenter_render_html_without_recommendation() {
    let finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    let presenter = RecommendationPresenter::new(&finding);
    let html = presenter.render_html();
    assert!(html.is_empty());
}

#[test]
fn test_recommendation_presenter_render_markdown_with_recommendation() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.recommendation = Some("Recommendation text".to_string());
    let presenter = RecommendationPresenter::new(&finding);
    let md = presenter.render_markdown();
    assert!(md.contains("**Recommendation:**"));
    assert!(md.contains("Recommendation text"));
}

#[test]
fn test_recommendation_presenter_render_markdown_without_recommendation() {
    let finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    let presenter = RecommendationPresenter::new(&finding);
    let md = presenter.render_markdown();
    assert!(md.is_empty());
}

// ============================================================================
// CodeSectionPresenter Tests
// ============================================================================

#[test]
fn test_code_section_presenter_new() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.poc_code = Some("exploit()".to_string());
    finding.mitigation_code = Some("safe_fix()".to_string());
    finding.poc_format = Some("rust".to_string());
    let presenter = CodeSectionPresenter::new(&finding);
    assert_eq!(presenter.poc_code, Some("exploit()".to_string()));
    assert_eq!(presenter.mitigation_code, Some("safe_fix()".to_string()));
    assert_eq!(presenter.poc_format, Some("rust".to_string()));
    assert_eq!(presenter.file_path, "src/test.rs");
}

#[test]
fn test_code_section_presenter_has_content() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.poc_code = Some("code".to_string());
    let presenter = CodeSectionPresenter::new(&finding);
    assert!(presenter.has_content());

    let finding = make_finding_presenter("f2", Severity::High, "src/test.rs", Some(1));
    let presenter = CodeSectionPresenter::new(&finding);
    assert!(!presenter.has_content());
}

#[test]
fn test_code_section_presenter_render_html_poc_only() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/vuln.rs", Some(1));
    finding.poc_code = Some("exploit()".to_string());
    finding.poc_format = Some("python".to_string());
    let presenter = CodeSectionPresenter::new(&finding);
    let html = presenter.render_html();
    assert!(html.contains("<div class=\"poc-section\">"));
    assert!(html.contains("Proof of Concept (PYTHON)"));
    assert!(html.contains("exploit()"));
    assert!(!html.contains("Mitigation Example"));
}

#[test]
fn test_code_section_presenter_render_html_mitigation_only() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.mitigation_code = Some("safe_fix()".to_string());
    let presenter = CodeSectionPresenter::new(&finding);
    let html = presenter.render_html();
    assert!(html.contains("Mitigation Example"));
    assert!(html.contains("safe_fix()"));
    assert!(!html.contains("Proof of Concept"));
}

#[test]
fn test_code_section_presenter_render_html_both() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.poc_code = Some("exploit()".to_string());
    finding.mitigation_code = Some("safe_fix()".to_string());
    let presenter = CodeSectionPresenter::new(&finding);
    let html = presenter.render_html();
    assert!(html.contains("Proof of Concept"));
    assert!(html.contains("Mitigation Example"));
    assert!(html.contains("exploit()"));
    assert!(html.contains("safe_fix()"));
}

#[test]
fn test_code_section_presenter_render_html_empty() {
    let finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    let presenter = CodeSectionPresenter::new(&finding);
    let html = presenter.render_html();
    assert!(html.is_empty());
}

#[test]
fn test_code_section_presenter_render_markdown_poc_only() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.poc_code = Some("poc code".to_string());
    finding.poc_format = Some("rust".to_string());
    let presenter = CodeSectionPresenter::new(&finding);
    let md = presenter.render_markdown();
    assert!(md.contains("**Proof of Concept:**"));
    assert!(md.contains("```rust"));
    assert!(md.contains("poc code"));
}

#[test]
fn test_code_section_presenter_render_markdown_mitigation_only() {
    let mut finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    finding.mitigation_code = Some("mitigation code".to_string());
    let presenter = CodeSectionPresenter::new(&finding);
    let md = presenter.render_markdown();
    assert!(md.contains("**Mitigation:**"));
    assert!(md.contains("mitigation code"));
}

#[test]
fn test_code_section_presenter_render_markdown_empty() {
    let finding = make_finding_presenter("f1", Severity::High, "src/test.rs", Some(1));
    let presenter = CodeSectionPresenter::new(&finding);
    let md = presenter.render_markdown();
    assert!(md.is_empty());
}
