//! Unit tests for HTML report generation (src/report/html/)
//!
//! Tests cover:
//! - render_finding: HTML rendering of single findings
//! - generate_html_report: Full report generation
//! - markdown_to_html: Markdown conversion
//! - Severity stats calculation
//! - Summary cards and filter buttons
//! - Language detection
//! - Empty state handling

use baco::findings::{Severity, VulnerabilityFinding};
use baco::report::html::{render_finding, utilities};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

use super::report_fixtures::make_finding;

// ============================================================================
// render_finding Tests
// ============================================================================

#[test]
fn test_render_finding_critical_severity() {
    let finding = make_finding("f1", Severity::Critical, "src/main.rs", Some(42));
    let html = render_finding(&finding, 0);

    assert!(html.contains("finding critical"));
    assert!(html.contains("Critical"));
    assert!(html.contains("src/main.rs"));
    assert!(html.contains(":42"));
}

#[test]
fn test_render_finding_high_severity() {
    let finding = make_finding("f2", Severity::High, "src/app.rs", Some(10));
    let html = render_finding(&finding, 1);

    assert!(html.contains("finding high"));
    assert!(html.contains("High"));
}

#[test]
fn test_render_finding_medium_severity() {
    let finding = make_finding("f3", Severity::Medium, "src/lib.rs", Some(5));
    let html = render_finding(&finding, 2);

    assert!(html.contains("finding medium"));
    assert!(html.contains("Medium"));
}

#[test]
fn test_render_finding_low_severity() {
    let finding = make_finding("f4", Severity::Low, "src/utils.rs", Some(100));
    let html = render_finding(&finding, 3);

    assert!(html.contains("finding low"));
    assert!(html.contains("Low"));
}

#[test]
fn test_render_finding_info_severity() {
    let finding = make_finding("f5", Severity::Info, "src/README.rs", None);
    let html = render_finding(&finding, 4);

    assert!(html.contains("finding info"));
    assert!(html.contains("Info"));
}

#[test]
fn test_render_finding_without_line_number() {
    let finding = make_finding("f6", Severity::High, "src/unknown.rs", None);
    let html = render_finding(&finding, 5);

    assert!(html.contains("src/unknown.rs"));
    assert!(!html.contains(":None"));
}

#[test]
fn test_render_finding_with_cwe_id() {
    let mut finding = make_finding("f7", Severity::High, "src/test.rs", Some(10));
    finding.cwe_id = Some("CWE-79".to_string());

    let html = render_finding(&finding, 6);

    assert!(html.contains("CWE-79"));
    assert!(html.contains("cwe-badge"));
}

#[test]
fn test_render_finding_without_cwe_id() {
    let finding = make_finding("f8", Severity::Medium, "src/test.rs", Some(10));
    let html = render_finding(&finding, 7);

    assert!(!html.contains("cwe-badge"));
}

#[test]
fn test_render_finding_with_code_snippet() {
    let mut finding = make_finding("f9", Severity::High, "src/test.rs", Some(10));
    finding.code_snippet = Some("unsafe code here".to_string());

    let html = render_finding(&finding, 8);

    assert!(html.contains("code-snippet-single"));
    assert!(html.contains("unsafe code here"));
}

#[test]
fn test_render_finding_with_recommendation() {
    let mut finding = make_finding("f10", Severity::Medium, "src/test.rs", Some(10));
    finding.recommendation = Some("Use safe alternatives".to_string());

    let html = render_finding(&finding, 9);

    assert!(html.contains("Recommendation"));
    assert!(html.contains("Use safe alternatives"));
}

#[test]
fn test_render_finding_with_confidence_score() {
    let mut finding = make_finding("f11", Severity::High, "src/test.rs", Some(10));
    finding.confidence_score = 0.95;

    let html = render_finding(&finding, 10);

    assert!(html.contains("confidence-high"));
    assert!(html.contains("95"));
}

#[test]
fn test_render_finding_with_medium_confidence() {
    let mut finding = make_finding("f12", Severity::Medium, "src/test.rs", Some(10));
    finding.confidence_score = 0.5;

    let html = render_finding(&finding, 11);

    assert!(html.contains("confidence-medium"));
}

#[test]
fn test_render_finding_with_low_confidence() {
    let mut finding = make_finding("f13", Severity::Low, "src/test.rs", Some(10));
    finding.confidence_score = 0.3;

    let html = render_finding(&finding, 12);

    assert!(html.contains("confidence-low"));
}

#[test]
fn test_render_finding_escapes_html_in_title() {
    let mut finding = make_finding("f14", Severity::High, "src/test.rs", Some(10));
    finding.title = "<script>alert('xss')</script>".to_string();

    let html = render_finding(&finding, 13);

    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;script&gt;"));
}

#[test]
fn test_render_finding_with_multiple_sources() {
    let mut finding = make_finding("f15", Severity::High, "src/test.rs", Some(10));
    finding.sources = vec!["semgrep".to_string(), "llm".to_string()];

    let html = render_finding(&finding, 14);

    assert!(html.contains("semgrep"));
    assert!(html.contains("llm"));
}

#[test]
fn test_render_finding_generates_unique_id() {
    let finding1 = make_finding("f16", Severity::High, "src/test.rs", Some(10));
    let finding2 = make_finding("f17", Severity::High, "src/test.rs", Some(10));

    let html1 = render_finding(&finding1, 0);
    let html2 = render_finding(&finding2, 1);

    assert!(html1.contains("id=\"finding-0\""));
    assert!(html2.contains("id=\"finding-1\""));
}

// ============================================================================
// markdown_to_html Tests
// ============================================================================

#[test]
fn test_markdown_to_html_heading() {
    let html = utilities::markdown_to_html("# Main Heading");

    assert!(html.contains("<h1>Main Heading</h1>"));
}

#[test]
fn test_markdown_to_html_subheading() {
    let html = utilities::markdown_to_html("## Sub Heading");

    assert!(html.contains("<h2>Sub Heading</h2>"));
}

#[test]
fn test_markdown_to_html_bold() {
    let html = utilities::markdown_to_html("**bold text**");

    assert!(html.contains("<strong>bold text</strong>"));
}

#[test]
fn test_markdown_to_html_italic() {
    let html = utilities::markdown_to_html("*italic text*");

    assert!(html.contains("<em>italic text</em>"));
}

#[test]
fn test_markdown_to_html_unordered_list() {
    let html = utilities::markdown_to_html("- item 1\n- item 2\n- item 3");

    assert!(html.contains("<ul>"));
    assert!(html.contains("<li>item 1</li>"));
    assert!(html.contains("<li>item 2</li>"));
}

#[test]
fn test_markdown_to_html_ordered_list() {
    let html = utilities::markdown_to_html("1. first\n2. second");

    assert!(html.contains("<ol>"));
    assert!(html.contains("<li>first</li>"));
}

#[test]
fn test_markdown_to_html_code_block() {
    let html = utilities::markdown_to_html("```rust\nfn main() {}\n```");

    assert!(html.contains("<code"));
    assert!(html.contains("fn main"));
}

#[test]
fn test_markdown_to_html_inline_code() {
    let html = utilities::markdown_to_html("Use `unsafe` block");

    assert!(html.contains("<code>unsafe</code>"));
}

#[test]
fn test_markdown_to_html_link() {
    let html = utilities::markdown_to_html("[CWE-79](https://cwe.mitre.org)");

    assert!(html.contains("<a href=\"https://cwe.mitre.org\">"));
    assert!(html.contains("CWE-79"));
}

#[test]
fn test_markdown_to_html_empty_input() {
    let html = utilities::markdown_to_html("");

    assert!(html.is_empty());
}

#[test]
fn test_markdown_to_html_xss_protection() {
    let html = utilities::markdown_to_html("<script>alert('xss')</script>");

    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;script&gt;"));
}

#[test]
fn test_markdown_to_html_table() {
    let html = utilities::markdown_to_html("| col1 | col2 |\n|------|------|\n| a | b |");

    assert!(html.contains("<table>"));
    assert!(html.contains("<td>"));
}

#[test]
fn test_markdown_to_html_strikethrough() {
    let html = utilities::markdown_to_html("~~deleted text~~");

    assert!(html.contains("<del>deleted text</del>"));
}

// ============================================================================
// calculate_severity_stats Tests
// ============================================================================

#[test]
fn test_calculate_severity_stats_all_severities() {
    let findings = vec![
        make_finding("c1", Severity::Critical, "src/a.rs", Some(1)),
        make_finding("h1", Severity::High, "src/b.rs", Some(2)),
        make_finding("m1", Severity::Medium, "src/c.rs", Some(3)),
        make_finding("l1", Severity::Low, "src/d.rs", Some(4)),
        make_finding("i1", Severity::Info, "src/e.rs", Some(5)),
    ];

    let stats = utilities::calculate_severity_stats(&findings);

    assert_eq!(stats.critical, 1);
    assert_eq!(stats.high, 1);
    assert_eq!(stats.medium, 1);
    assert_eq!(stats.low, 1);
    assert_eq!(stats.info, 1);
}

#[test]
fn test_calculate_severity_stats_empty() {
    let findings: Vec<VulnerabilityFinding> = vec![];
    let stats = utilities::calculate_severity_stats(&findings);

    assert_eq!(stats.critical, 0);
    assert_eq!(stats.high, 0);
    assert_eq!(stats.medium, 0);
    assert_eq!(stats.low, 0);
    assert_eq!(stats.info, 0);
}

#[test]
fn test_calculate_severity_stats_multiple_same_severity() {
    let findings = vec![
        make_finding("c1", Severity::Critical, "src/a.rs", Some(1)),
        make_finding("c2", Severity::Critical, "src/b.rs", Some(2)),
        make_finding("c3", Severity::Critical, "src/c.rs", Some(3)),
        make_finding("c4", Severity::Critical, "src/d.rs", Some(4)),
    ];

    let stats = utilities::calculate_severity_stats(&findings);

    assert_eq!(stats.critical, 4);
    assert!(stats.high == 0);
}

// ============================================================================
// build_summary_cards Tests
// ============================================================================

#[test]
fn test_build_summary_cards_all_severities() {
    let stats = utilities::calculate_severity_stats(&[
        make_finding("c1", Severity::Critical, "src/a.rs", Some(1)),
        make_finding("h1", Severity::High, "src/b.rs", Some(2)),
        make_finding("m1", Severity::Medium, "src/c.rs", Some(3)),
        make_finding("l1", Severity::Low, "src/d.rs", Some(4)),
        make_finding("i1", Severity::Info, "src/e.rs", Some(5)),
    ]);

    let cards = utilities::build_summary_cards(&stats);

    assert!(cards.contains("critical"));
    assert!(cards.contains("high"));
    assert!(cards.contains("medium"));
    assert!(cards.contains("low"));
    assert!(cards.contains("info"));
    assert!(cards.contains("1"));
}

#[test]
fn test_build_summary_cards_empty() {
    let stats = utilities::calculate_severity_stats(&[]);
    let cards = utilities::build_summary_cards(&stats);

    assert!(cards.is_empty());
}

#[test]
fn test_build_summary_cards_multiple_counts() {
    let stats = utilities::calculate_severity_stats(&[
        make_finding("c1", Severity::Critical, "src/a.rs", Some(1)),
        make_finding("c2", Severity::Critical, "src/b.rs", Some(2)),
        make_finding("h1", Severity::High, "src/c.rs", Some(3)),
    ]);

    let cards = utilities::build_summary_cards(&stats);

    assert!(cards.contains("2")); // Critical count
    assert!(cards.contains("1")); // High count
}

// ============================================================================
// build_filter_buttons Tests
// ============================================================================

#[test]
fn test_build_filter_buttons_all_severities() {
    let stats = utilities::calculate_severity_stats(&[
        make_finding("c1", Severity::Critical, "src/a.rs", Some(1)),
        make_finding("h1", Severity::High, "src/b.rs", Some(2)),
    ]);

    let buttons = utilities::build_filter_buttons(&stats);

    assert!(buttons.contains("Critical (1)"));
    assert!(buttons.contains("High (1)"));
    assert!(!buttons.contains("Medium"));
    assert!(!buttons.contains("Low"));
    assert!(!buttons.contains("Info"));
}

// ============================================================================
// detect_language Tests
// ============================================================================

#[test]
fn test_detect_language_python() {
    assert_eq!(utilities::detect_language("src/main.py"), "python");
    assert_eq!(utilities::detect_language("/path/to/script.py"), "python");
}

#[test]
fn test_detect_language_javascript() {
    assert_eq!(utilities::detect_language("app.js"), "javascript");
}

#[test]
fn test_detect_language_typescript() {
    assert_eq!(utilities::detect_language("src/app.ts"), "typescript");
    assert_eq!(
        utilities::detect_language("src/component.tsx"),
        "typescript"
    );
}

#[test]
fn test_detect_language_rust() {
    assert_eq!(utilities::detect_language("src/lib.rs"), "rust");
}

#[test]
fn test_detect_language_go() {
    assert_eq!(utilities::detect_language("main.go"), "go");
}

#[test]
fn test_detect_language_java() {
    assert_eq!(utilities::detect_language("src/Main.java"), "java");
}

#[test]
fn test_detect_language_c() {
    assert_eq!(utilities::detect_language("src/main.c"), "c");
}

#[test]
fn test_detect_language_cpp() {
    assert_eq!(utilities::detect_language("src/main.cpp"), "cpp");
    assert_eq!(utilities::detect_language("src/main.cc"), "cpp");
    assert_eq!(utilities::detect_language("src/main.cxx"), "cpp");
}

#[test]
fn test_detect_language_sql() {
    assert_eq!(utilities::detect_language("query.sql"), "sql");
}

#[test]
fn test_detect_language_yaml() {
    assert_eq!(utilities::detect_language("config.yml"), "yaml");
    assert_eq!(utilities::detect_language("config.yaml"), "yaml");
}

#[test]
fn test_detect_language_json() {
    assert_eq!(utilities::detect_language("package.json"), "json");
}

#[test]
fn test_detect_language_bash() {
    assert_eq!(utilities::detect_language("script.sh"), "bash");
    assert_eq!(utilities::detect_language("script.bash"), "bash");
}

#[test]
fn test_detect_language_unknown_extension() {
    assert_eq!(utilities::detect_language("src/unknown.xyz"), "");
}

#[test]
fn test_detect_language_no_extension() {
    assert_eq!(utilities::detect_language("README"), "");
    assert_eq!(utilities::detect_language("Makefile"), "");
}

#[test]
fn test_detect_language_case_insensitive() {
    assert_eq!(utilities::detect_language("src/main.PY"), "python");
    assert_eq!(utilities::detect_language("src/main.RS"), "rust");
}

// ============================================================================
// build_empty_state_message Tests
// ============================================================================

#[test]
fn test_build_empty_state_message_content() {
    let message = utilities::build_empty_state_message();

    assert!(message.contains("No Security Issues Found"));
    assert!(message.contains("✅"));
    assert!(message.contains("vulnerabilities detected"));
}

// ============================================================================
// generate_html_report Tests
// ============================================================================

#[test]
fn test_generate_html_report_creates_file() {
    let findings = vec![make_finding("f1", Severity::High, "src/test.rs", Some(10))];
    let output_path = "/tmp/test_html_report.html";

    // Clean up if exists
    let _ = fs::remove_file(output_path);

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());
    assert!(Path::new(output_path).exists());

    // Verify file contains expected content
    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("BACO Security Report"));
    assert!(content.contains("<!DOCTYPE html>"));

    // Clean up
    let _ = fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_empty_findings() {
    let findings: Vec<VulnerabilityFinding> = vec![];
    let output_path = "/tmp/test_empty_html_report.html";

    let result = baco::report::html::generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("No Security Issues Found"));

    // Clean up
    let _ = fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_creates_parent_dirs() {
    let findings = vec![make_finding("f1", Severity::Low, "src/lib.rs", Some(5))];
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("nested").join("report.html");

    // Parent dir doesn't exist yet — function should create it
    let result = baco::report::html::generate_html_report(
        &findings,
        output_path.to_str().unwrap(),
        None,
        None,
    );

    // After fix: function creates parent dirs and succeeds
    assert!(result.is_ok());
    assert!(output_path.exists());

    // Clean up
    let _ = fs::remove_dir_all(temp_dir.path());
}
