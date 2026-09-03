use baco::findings::Severity;
use baco::report::html::renderer::{generate_html_report, VulnerabilityFinding};

fn make_finding(severity: Severity, file: &str, line: Option<u32>) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-1".to_string(),
        title: "Test Finding".to_string(),
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

#[test]
fn test_generate_html_report_creates_file() {
    let findings = vec![make_finding(Severity::High, "src/test.rs", Some(10))];
    let output_path = "/tmp/test_html_report.html";

    let _ = std::fs::remove_file(output_path);

    let result = generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());
    assert!(std::path::Path::new(output_path).exists());

    let content = std::fs::read_to_string(output_path).unwrap();
    assert!(content.contains("BACO Security Report"));
    assert!(content.contains("<!DOCTYPE html>"));

    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_empty_findings() {
    let findings: Vec<VulnerabilityFinding> = vec![];
    let output_path = "/tmp/test_empty_html_report.html";

    let _ = std::fs::remove_file(output_path);

    let result = generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = std::fs::read_to_string(output_path).unwrap();
    assert!(content.contains("No Security Issues Found"));

    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_multiple_severities() {
    let findings = vec![
        make_finding(Severity::Critical, "src/critical.rs", Some(1)),
        make_finding(Severity::High, "src/high.rs", Some(2)),
        make_finding(Severity::Medium, "src/medium.rs", Some(3)),
        make_finding(Severity::Low, "src/low.rs", Some(4)),
        make_finding(Severity::Info, "src/info.rs", Some(5)),
    ];
    let output_path = "/tmp/test_multi_severity_report.html";

    let _ = std::fs::remove_file(output_path);

    let result = generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = std::fs::read_to_string(output_path).unwrap();
    assert!(content.contains("Critical"));
    assert!(content.contains("High"));
    assert!(content.contains("Medium"));
    assert!(content.contains("Low"));
    assert!(content.contains("Info"));

    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_contains_finding_elements() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(42));
    finding.title = "SQL Injection Vulnerability".to_string();
    finding.cwe_id = Some("CWE-89".to_string());
    let findings = vec![finding];
    let output_path = "/tmp/test_finding_elements.html";

    let _ = std::fs::remove_file(output_path);

    let result = generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = std::fs::read_to_string(output_path).unwrap();
    assert!(content.contains("SQL Injection Vulnerability"));
    assert!(content.contains("CWE-89"));
    assert!(content.contains("src-test.rs-0"));
    assert!(content.contains("severity high"));

    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_creates_parent_dirs() {
    let findings = vec![make_finding(Severity::Low, "src/lib.rs", Some(5))];
    let temp_dir = std::env::temp_dir().join("baco_test_nested");
    let output_path = temp_dir.join("nested").join("report.html");

    let _ = std::fs::remove_dir_all(&temp_dir);

    let result = generate_html_report(&findings, output_path.to_str().unwrap(), None, None);

    assert!(result.is_ok());
    assert!(output_path.exists());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_generate_html_report_with_confidence_stats() {
    let mut finding1 = make_finding(Severity::High, "src/test1.rs", Some(10));
    finding1.confidence_score = 0.95;
    let mut finding2 = make_finding(Severity::Medium, "src/test2.rs", Some(20));
    finding2.confidence_score = 0.65;
    let findings = vec![finding1, finding2];
    let output_path = "/tmp/test_confidence_stats.html";

    let _ = std::fs::remove_file(output_path);

    let result = generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = std::fs::read_to_string(output_path).unwrap();
    assert!(content.contains("Avg Confidence"));
    assert!(content.contains("80")); // average of 95 and 65

    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_contains_filter_buttons() {
    let findings = vec![
        make_finding(Severity::Critical, "src/crit.rs", Some(1)),
        make_finding(Severity::High, "src/high.rs", Some(2)),
    ];
    let output_path = "/tmp/test_filter_buttons.html";

    let _ = std::fs::remove_file(output_path);

    let result = generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = std::fs::read_to_string(output_path).unwrap();
    assert!(content.contains("filter-btn"));
    assert!(content.contains("Critical (1)"));
    assert!(content.contains("High (1)"));

    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_contains_summary_cards() {
    let findings = vec![
        make_finding(Severity::Critical, "src/crit.rs", Some(1)),
        make_finding(Severity::High, "src/high.rs", Some(2)),
        make_finding(Severity::Medium, "src/med.rs", Some(3)),
    ];
    let output_path = "/tmp/test_summary_cards.html";

    let _ = std::fs::remove_file(output_path);

    let result = generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = std::fs::read_to_string(output_path).unwrap();
    assert!(content.contains("card critical"));
    assert!(content.contains("card high"));
    assert!(content.contains("card medium"));

    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_with_python_file() {
    let mut finding = make_finding(Severity::High, "src/vuln.py", Some(42));
    finding.diff_hunk = Some("-old code\n+new code".to_string());
    let findings = vec![finding];
    let output_path = "/tmp/test_python_report.html";

    let _ = std::fs::remove_file(output_path);

    let result = generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = std::fs::read_to_string(output_path).unwrap();
    assert!(content.contains("languages.python"));
    assert!(content.contains("language-diff"));

    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_with_rust_file() {
    let mut finding = make_finding(Severity::Medium, "src/lib.rs", Some(100));
    finding.diff_hunk = Some("-unsafe code\n+safe code".to_string());
    let findings = vec![finding];
    let output_path = "/tmp/test_rust_report.html";

    let _ = std::fs::remove_file(output_path);

    let result = generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = std::fs::read_to_string(output_path).unwrap();
    assert!(content.contains("languages.rust"));
    assert!(content.contains("language-diff"));

    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_statistics() {
    let findings = vec![
        make_finding(Severity::Critical, "src/a.rs", Some(1)),
        make_finding(Severity::Critical, "src/b.rs", Some(2)),
        make_finding(Severity::High, "src/c.rs", Some(3)),
    ];
    let output_path = "/tmp/test_statistics.html";

    let _ = std::fs::remove_file(output_path);

    let result = generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = std::fs::read_to_string(output_path).unwrap();
    assert!(content.contains("2")); // Critical count in card
    assert!(content.contains("1")); // High count in card
    assert!(content.contains("3 findings")); // Total findings

    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_generate_html_report_contains_metadata() {
    let findings = vec![make_finding(Severity::Low, "src/test.rs", Some(1))];
    let output_path = "/tmp/test_metadata.html";

    let _ = std::fs::remove_file(output_path);

    let result = generate_html_report(&findings, output_path, None, None);

    assert!(result.is_ok());

    let content = std::fs::read_to_string(output_path).unwrap();
    assert!(content.contains("Scan Metadata"));
    assert!(content.contains("Scan Date"));
    assert!(content.contains("Total Findings"));

    let _ = std::fs::remove_file(output_path);
}
