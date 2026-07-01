//! Tests for HTML report generation

use baco::config::ScannerConfig;
use baco::findings::{Severity, VulnerabilityFinding};
use baco::report::html::{
    generate_html_report,
    utilities::{
        build_empty_state_message, build_filter_buttons, build_summary_cards,
        calculate_severity_stats, detect_language, markdown_to_html,
    },
};

fn make_finding(
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
        cwe_id: Some("CWE-79".to_string()),
        file_path: file.to_string(),
        line_number: line,
        code_snippet: Some("test code".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this".to_string()),
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
    }
}

#[test]
fn test_markdown_to_html_empty() {
    let html = markdown_to_html("");
    assert!(html.is_empty() || html == "<p></p>");
}

#[test]
fn test_markdown_to_html_simple_text() {
    let html = markdown_to_html("Hello world");
    assert!(html.contains("Hello world"));
}

#[test]
fn test_markdown_to_html_bold() {
    let html = markdown_to_html("**bold text**");
    assert!(html.contains("<strong>bold text</strong>"));
}

#[test]
fn test_markdown_to_html_italic() {
    let html = markdown_to_html("*italic text*");
    assert!(html.contains("<em>italic text</em>"));
}

#[test]
fn test_markdown_to_html_list() {
    let html = markdown_to_html("- item 1\n- item 2");
    assert!(html.contains("<ul>"));
    assert!(html.contains("<li>"));
}

#[test]
fn test_markdown_to_html_code_block() {
    let html = markdown_to_html("```rust\nfn main() {}\n```");
    assert!(html.contains("<pre>"));
}

#[test]
fn test_markdown_to_html_escaped_newlines() {
    let html = markdown_to_html("line1\\nline2");
    assert!(html.contains("line1"));
    assert!(html.contains("line2"));
}

#[test]
fn test_calculate_severity_stats_empty() {
    let stats = calculate_severity_stats(&[]);

    assert_eq!(stats.critical, 0);
    assert_eq!(stats.high, 0);
    assert_eq!(stats.medium, 0);
    assert_eq!(stats.low, 0);
    assert_eq!(stats.info, 0);
}

#[test]
fn test_calculate_severity_stats_all_levels() {
    let findings = vec![
        make_finding("c", Severity::Critical, "src/c.rs", Some(1)),
        make_finding("h", Severity::High, "src/h.rs", Some(2)),
        make_finding("m", Severity::Medium, "src/m.rs", Some(3)),
        make_finding("l", Severity::Low, "src/l.rs", Some(4)),
        make_finding("i", Severity::Info, "src/i.rs", Some(5)),
    ];

    let stats = calculate_severity_stats(&findings);

    assert_eq!(stats.critical, 1);
    assert_eq!(stats.high, 1);
    assert_eq!(stats.medium, 1);
    assert_eq!(stats.low, 1);
    assert_eq!(stats.info, 1);
}

#[test]
fn test_calculate_severity_stats_multiple_same_level() {
    let findings = vec![
        make_finding("c1", Severity::Critical, "src/c1.rs", Some(1)),
        make_finding("c2", Severity::Critical, "src/c2.rs", Some(2)),
        make_finding("c3", Severity::Critical, "src/c3.rs", Some(3)),
    ];

    let stats = calculate_severity_stats(&findings);

    assert_eq!(stats.critical, 3);
}

#[test]
fn test_build_summary_cards_empty() {
    let stats = calculate_severity_stats(&[]);
    let cards = build_summary_cards(&stats);

    assert!(cards.is_empty());
}

#[test]
fn test_build_summary_cards_single_level() {
    let stats = baco::report::html::utilities::SeverityStats {
        critical: 5,
        ..Default::default()
    };
    let cards = build_summary_cards(&stats);

    assert!(cards.contains("5"));
    assert!(cards.contains("critical"));
}

#[test]
fn test_build_summary_cards_multiple_levels() {
    let stats = baco::report::html::utilities::SeverityStats {
        critical: 2,
        high: 3,
        medium: 1,
        ..Default::default()
    };
    let cards = build_summary_cards(&stats);

    assert!(cards.contains("2"));
    assert!(cards.contains("3"));
    assert!(cards.contains("1"));
}

#[test]
fn test_build_filter_buttons_empty() {
    let stats = calculate_severity_stats(&[]);
    let buttons = build_filter_buttons(&stats);

    assert!(buttons.is_empty());
}

#[test]
fn test_build_filter_buttons_single() {
    let stats = baco::report::html::utilities::SeverityStats {
        high: 4,
        ..Default::default()
    };
    let buttons = build_filter_buttons(&stats);

    assert!(buttons.contains("High (4)"));
    assert!(buttons.contains("filter-btn high"));
}

#[test]
fn test_build_empty_state_message() {
    let message = build_empty_state_message();

    assert!(message.contains("No Security Issues Found"));
    assert!(message.contains("empty-state"));
}

#[test]
fn test_detect_language_python() {
    assert_eq!(detect_language("script.py"), "python");
    assert_eq!(detect_language("/path/to/script.py"), "python");
}

#[test]
fn test_detect_language_javascript() {
    assert_eq!(detect_language("app.js"), "javascript");
    assert_eq!(detect_language("src/components/App.js"), "javascript");
}

#[test]
fn test_detect_language_typescript() {
    assert_eq!(detect_language("app.ts"), "typescript");
    assert_eq!(detect_language("app.tsx"), "typescript");
}

#[test]
fn test_detect_language_rust() {
    assert_eq!(detect_language("main.rs"), "rust");
    assert_eq!(detect_language("src/lib.rs"), "rust");
}

#[test]
fn test_detect_language_go() {
    assert_eq!(detect_language("main.go"), "go");
}

#[test]
fn test_detect_language_java() {
    assert_eq!(detect_language("Main.java"), "java");
}

#[test]
fn test_detect_language_c() {
    assert_eq!(detect_language("main.c"), "c");
}

#[test]
fn test_detect_language_cpp() {
    assert_eq!(detect_language("main.cpp"), "cpp");
    assert_eq!(detect_language("main.cc"), "cpp");
    assert_eq!(detect_language("main.cxx"), "cpp");
    assert_eq!(detect_language("header.h"), "cpp");
    assert_eq!(detect_language("header.hpp"), "cpp");
}

#[test]
fn test_detect_language_sql() {
    assert_eq!(detect_language("query.sql"), "sql");
}

#[test]
fn test_detect_language_yaml() {
    assert_eq!(detect_language("config.yml"), "yaml");
    assert_eq!(detect_language("config.yaml"), "yaml");
}

#[test]
fn test_detect_language_json() {
    assert_eq!(detect_language("package.json"), "json");
}

#[test]
fn test_detect_language_bash() {
    assert_eq!(detect_language("script.sh"), "bash");
    assert_eq!(detect_language("script.bash"), "bash");
}

#[test]
fn test_detect_language_unknown() {
    assert_eq!(detect_language("unknown.xyz"), "");
    assert_eq!(detect_language("README"), "");
}

#[test]
fn test_generate_html_report_empty() {
    let temp_dir = std::env::temp_dir();
    let output_path = temp_dir.join("test_report_empty.html");

    let result = generate_html_report(&[], output_path.to_str().unwrap(), None, None);

    assert!(result.is_ok());

    // Verify file was created
    assert!(output_path.exists());

    // Clean up
    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_with_findings() {
    let temp_dir = std::env::temp_dir();
    let output_path = temp_dir.join("test_report_findings.html");

    let findings = vec![
        make_finding("f1", Severity::Critical, "src/critical.rs", Some(42)),
        make_finding("f2", Severity::High, "src/high.rs", Some(100)),
    ];

    let result = generate_html_report(&findings, output_path.to_str().unwrap(), None, None);

    assert!(result.is_ok());
    assert!(output_path.exists());

    // Read and verify content
    let content = std::fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("BACO Security Vulnerability Report"));
    assert!(content.contains("Critical"));
    assert!(content.contains("High"));

    // Clean up
    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_with_config() {
    let temp_dir = std::env::temp_dir();
    let output_path = temp_dir.join("test_report_config.html");

    let findings = vec![make_finding("f1", Severity::High, "src/test.rs", Some(10))];

    let config = ScannerConfig::default();
    let result = generate_html_report(&findings, output_path.to_str().unwrap(), Some(&config), None);

    assert!(result.is_ok());
    assert!(output_path.exists());

    // Clean up
    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_with_llm_metrics() {
    let temp_dir = std::env::temp_dir();
    let output_path = temp_dir.join("test_report_metrics.html");

    let findings = vec![make_finding("f1", Severity::Medium, "src/test.rs", Some(10))];

    let llm_metrics = baco::report::json::LlmMetricsSummary {
        total_requests: 10,
        successful_requests: 8,
        failed_requests: 2,
        cached_requests: 1,
        total_tokens: 5000,
        avg_latency_ms: 250.5,
        models: vec![baco::report::json::ModelMetricsSummary {
            model_name: "test-model".to_string(),
            total_requests: 10,
            successful_requests: 8,
            failed_requests: 2,
            cached_requests: 1,
            total_tokens: 5000,
        }],
        operations: vec![baco::report::json::OperationMetricsSummary {
            operation: "analyze".to_string(),
            phase: "discovery".to_string(),
            requests: 10,
            successful: 8,
            failed: 2,
        }],
    };

    let result = generate_html_report(&findings, output_path.to_str().unwrap(), None, Some(llm_metrics));

    assert!(result.is_ok());
    assert!(output_path.exists());

    // Verify LLM metrics are in the report
    let content = std::fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("LLM Usage Statistics"));
    assert!(content.contains("test-model"));

    // Clean up
    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_html_report_contains_finding_details() {
    let temp_dir = std::env::temp_dir();
    let output_path = temp_dir.join("test_report_details.html");

    let mut finding = make_finding("f1", Severity::High, "src/test.rs", Some(42));
    finding.description = "Detailed vulnerability description".to_string();
    finding.recommendation = Some("Update to version 2.0".to_string());
    finding.code_snippet = Some("vulnerable_function()".to_string());

    let result = generate_html_report(&[finding], output_path.to_str().unwrap(), None, None);

    assert!(result.is_ok());

    let content = std::fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("Detailed vulnerability description"));
    assert!(content.contains("Update to version 2.0"));
    assert!(content.contains("vulnerable_function()"));

    // Clean up
    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_html_report_with_diff_hunk() {
    let temp_dir = std::env::temp_dir();
    let output_path = temp_dir.join("test_report_diff.html");

    let mut finding = make_finding("f1", Severity::Critical, "src/test.rs", Some(10));
    finding.diff_hunk = Some("@@ -10,7 +10,7 @@\n-vulnerable_call()\n+safe_call()".to_string());

    let result = generate_html_report(&[finding], output_path.to_str().unwrap(), None, None);

    assert!(result.is_ok());

    let content = std::fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("diff-hunk"));
    assert!(content.contains("safe_call()"));

    // Clean up
    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_html_report_with_poc_and_mitigation() {
    let temp_dir = std::env::temp_dir();
    let output_path = temp_dir.join("test_report_poc.html");

    let mut finding = make_finding("f1", Severity::High, "src/test.rs", Some(5));
    finding.poc_code = Some("exploit_code()".to_string());
    finding.mitigation_code = Some("fixed_code()".to_string());
    finding.poc_format = Some("python".to_string());

    let result = generate_html_report(&[finding], output_path.to_str().unwrap(), None, None);

    assert!(result.is_ok());

    let content = std::fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("Proof of Concept"));
    assert!(content.contains("Mitigation Example"));
    assert!(content.contains("exploit_code()"));
    assert!(content.contains("fixed_code()"));

    // Clean up
    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_html_report_severity_classes() {
    let temp_dir = std::env::temp_dir();
    let output_path = temp_dir.join("test_report_severity.html");

    let findings = vec![
        make_finding("c", Severity::Critical, "src/c.rs", Some(1)),
        make_finding("h", Severity::High, "src/h.rs", Some(2)),
        make_finding("m", Severity::Medium, "src/m.rs", Some(3)),
        make_finding("l", Severity::Low, "src/l.rs", Some(4)),
        make_finding("i", Severity::Info, "src/i.rs", Some(5)),
    ];

    let result = generate_html_report(&findings, output_path.to_str().unwrap(), None, None);

    assert!(result.is_ok());

    let content = std::fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("finding critical"));
    assert!(content.contains("finding high"));
    assert!(content.contains("finding medium"));
    assert!(content.contains("finding low"));
    assert!(content.contains("finding info"));

    // Clean up
    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_html_report_empty_findings_message() {
    let temp_dir = std::env::temp_dir();
    let output_path = temp_dir.join("test_report_empty_msg.html");

    let result = generate_html_report(&[], output_path.to_str().unwrap(), None, None);

    assert!(result.is_ok());

    let content = std::fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("No Security Issues Found"));

    // Clean up
    let _ = std::fs::remove_file(output_path);
}
