#[cfg(test)]
mod tests {
    use crate::report::html::generate_html_report;
    use crate::findings::{Severity, VulnerabilityFinding};
    use std::path::Path;

    fn make_finding(severity: Severity, title: &str, file: &str) -> VulnerabilityFinding {
        VulnerabilityFinding {
            id: "test-id".to_string(),
            title: title.to_string(),
            description: "Test description with <script>alert('xss')</script>".to_string(),
            severity,
            confidence_score: 0.8,
            cwe_id: Some("CWE-79".to_string()),
            file_path: file.to_string(),
            line_number: Some(42),
            code_snippet: Some("printf(x)".to_string()),
            diff_hunk: Some("printf(\"%s\", user_input)".to_string()),
            recommendation: Some("Sanitize input".to_string()),
            code_location: None,
            already_reported: false,
            sources: vec!["semgrep".to_string()],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: Some(
                "cursor.execute(f'SELECT * FROM users WHERE id = {user_input})')".to_string(),
            ),
            mitigation_code: Some(
                "cursor.execute('SELECT * FROM users WHERE id = %s', (user_input,))".to_string(),
            ),
            poc_format: Some("python".to_string()),
            llm_model: None,
            agent_mode: false,
        }
    }

    fn make_minimal_finding() -> VulnerabilityFinding {
        VulnerabilityFinding {
            id: "test-id".to_string(),
            title: "Test Finding".to_string(),
            description: "Test description".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.5,
            cwe_id: None,
            file_path: "test.c".to_string(),
            line_number: None,
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
        }
    }

    #[test]
    fn test_generate_html_report_empty() {
        let empty_findings: &[VulnerabilityFinding] = &[];
        generate_html_report(empty_findings, "/tmp/empty.html", None, None).unwrap();
        let content = std::fs::read_to_string("/tmp/empty.html").unwrap();
        assert!(content.contains("<!DOCTYPE html>"));
        assert!(content.contains("<html lang=\"en\">"));
        assert!(content.contains("Showing 0 findings"));
        // With 0 findings, no severity cards should be rendered
        assert!(!content.contains("class=\"card critical\""));
        assert!(!content.contains("class=\"card high\""));
    }

    #[test]
    fn test_generate_html_report_single_finding() {
        let findings = vec![make_finding(
            Severity::Critical,
            "Critical XSS",
            "src/app.c",
        )];
        let output_path = Path::new("/tmp/single.html");
        generate_html_report(&findings, &output_path.to_string_lossy(), None, None).unwrap();
        let content = std::fs::read_to_string(Path::new("/tmp/single.html")).unwrap();
        assert!(content.contains("<h1>🔒 BACO Security Vulnerability Report</h1>"));
        assert!(content.contains("<h3>1</h3><p>Critical</p>"));
        assert!(content.contains("Critical XSS"));
        assert!(content.contains("Sanitize input"));
        assert!(content.contains("CWE-79"));
    }

    #[test]
    fn test_xss_escaping() {
        // Test that XSS is properly escaped
        let findings = vec![make_finding(
            Severity::High,
            "XSS Test <script>alert('xss')</script>",
            "test.js",
        )];
        let output_path = Path::new("/tmp/xss_test.html");
        generate_html_report(&findings, &output_path.to_string_lossy(), None, None).unwrap();
        let content = std::fs::read_to_string(Path::new("/tmp/xss_test.html")).unwrap();
        // Should contain escaped version, not raw script tags
        assert!(content.contains("&lt;script&gt;") || content.contains("&lt;script"));
        // XSS should be escaped - raw script tag should not appear
        assert!(
            !content.contains("<script>alert('xss')</script>"),
            "XSS not escaped in content"
        );
    }

    #[test]
    fn test_before_after_snippets() {
        let findings = vec![make_finding(Severity::High, "SQL Injection", "db.c")];
        let output_path = Path::new("/tmp/before_after.html");
        generate_html_report(&findings, &output_path.to_string_lossy(), None, None).unwrap();
        let content = std::fs::read_to_string(Path::new("/tmp/before_after.html")).unwrap();
        // Just verify the report was generated
        assert!(content.contains("<!DOCTYPE html>"));
    }

    #[test]
    fn test_statistics_dashboard() {
        let findings = vec![
            make_finding(Severity::Critical, "Crit 1", "f1.c"),
            make_finding(Severity::Critical, "Crit 2", "f2.c"),
            make_finding(Severity::High, "High 1", "f3.c"),
            make_finding(Severity::Medium, "Med 1", "f1.c"),
        ];
        let output_path = Path::new("/tmp/stats.html");
        generate_html_report(&findings, &output_path.to_string_lossy(), None, None).unwrap();
        let content = std::fs::read_to_string(Path::new("/tmp/stats.html")).unwrap();
        assert!(content.contains("Statistics Dashboard"));
        assert!(content.contains("Avg Confidence"));
        assert!(content.contains("Verified"));
        assert!(content.contains("Already Reported"));
        assert!(content.contains("Unique Files"));
    }

    #[test]
    fn test_llm_model_and_description_display() {
        // Test that llm_model and description are displayed in HTML report
        use crate::findings::VulnerabilityFinding;
        use std::fs;
        use tempfile::TempDir;
        
        let temp_dir = TempDir::new().unwrap();
        let report_path = temp_dir.path().join("test_report.html");
        
        // Create a finding with llm_model and description set
        let finding = VulnerabilityFinding {
            id: "test-finding-123".to_string(),
            title: "Buffer Overflow".to_string(),
            description: "Potential buffer overflow detected in vulnerable_copy function".to_string(),
            severity: Severity::High,
            confidence_score: 0.85,
            cwe_id: Some("CWE-120".to_string()),
            file_path: "src/vulnerable.c".to_string(),
            line_number: Some(42),
            code_snippet: Some("strcpy(buffer, input)".to_string()),
            diff_hunk: None,
            recommendation: Some("Use strncpy with bounds checking".to_string()),
            code_location: Some("src/vulnerable.c:42".to_string()),
            already_reported: false,
            sources: vec!["semgrep".to_string()],
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
            llm_model: Some("semgrep".to_string()),
            agent_mode: false,
        };
        
        let findings = vec![finding];
        
        // Generate HTML report
        let result = generate_html_report(&findings, &report_path.to_string_lossy(), None, None);
        assert!(result.is_ok(), "HTML report generation should succeed");
        
        // Read and verify the report
        let content = fs::read_to_string(&report_path).unwrap();
        
        // Verify that source is displayed
        assert!(content.contains("<strong>Source:</strong> semgrep"), 
                "HTML should display source value, got: {}", content);
        
        // Verify that description is displayed
        assert!(content.contains("Potential buffer overflow"), 
                "HTML should display description, got: {}", content);
        
        // Verify that file_path is displayed
        assert!(content.contains("src/vulnerable.c"), 
                "HTML should display file_path, got: {}", content);
    }

    #[test]
    fn test_interactive_filters() {
        // Create findings of all severity levels to test all filter buttons
        let mut findings = Vec::new();
        findings.push(make_finding(
            Severity::Critical,
            "Critical finding",
            "test_critical.c",
        ));
        findings.push(make_finding(Severity::High, "High finding", "test_high.c"));
        findings.push(make_finding(
            Severity::Medium,
            "Medium finding",
            "test_medium.c",
        ));
        findings.push(make_finding(Severity::Low, "Low finding", "test_low.c"));
        findings.push(make_finding(Severity::Info, "Info finding", "test_info.c"));

        let output_path = Path::new("/tmp/filters.html");
        generate_html_report(&findings, &output_path.to_string_lossy(), None, None).unwrap();
        let content = std::fs::read_to_string(Path::new("/tmp/filters.html")).unwrap();
        assert!(content.contains("filterFindings"));
        assert!(content.contains("data-filter=\"critical\""));
        assert!(content.contains("data-filter=\"high\""));
        assert!(content.contains("data-filter=\"medium\""));
        assert!(content.contains("data-filter=\"low\""));
        assert!(content.contains("data-filter=\"info\""));
        assert!(content.contains("data-filter=\"all\""));
    }

    #[test]
    fn test_search_functionality() {
        let findings = vec![make_finding(Severity::Medium, "Unique title 123", "file.c")];
        let output_path = Path::new("/tmp/search.html");
        generate_html_report(&findings, &output_path.to_string_lossy(), None, None).unwrap();
        let content = std::fs::read_to_string(Path::new("/tmp/search.html")).unwrap();
        assert!(content.contains("searchFindings"));
        assert!(content.contains("id=\"search\""));
    }

    #[test]
    fn test_minimal_finding_without_snippets() {
        let findings = vec![make_minimal_finding()];
        let output_path = Path::new("/tmp/minimal.html");
        generate_html_report(&findings, &output_path.to_string_lossy(), None, None).unwrap();
        let content = std::fs::read_to_string(Path::new("/tmp/minimal.html")).unwrap();
        // Should still render without errors
        assert!(content.contains("<!DOCTYPE html>"));
        assert!(content.contains("Test Finding"));
    }

    #[test]
    fn test_multiple_findings_severity_counts() {
        let findings = vec![
            make_finding(Severity::Critical, "C1", "f.c"),
            make_finding(Severity::Critical, "C2", "f.c"),
            make_finding(Severity::High, "H1", "f.c"),
            make_finding(Severity::Medium, "M1", "f.c"),
            make_finding(Severity::Low, "L1", "f.c"),
            make_finding(Severity::Info, "I1", "f.c"),
        ];
        let output_path = Path::new("/tmp/multi.html");
        generate_html_report(&findings, &output_path.to_string_lossy(), None, None).unwrap();
        let content = std::fs::read_to_string(Path::new("/tmp/multi.html")).unwrap();
        assert!(content.contains("<h3>2</h3><p>Critical</p>"));
        assert!(content.contains("<h3>1</h3><p>High</p>"));
        assert!(content.contains("<h3>1</h3><p>Medium</p>"));
        assert!(content.contains("<h3>1</h3><p>Low</p>"));
        assert!(content.contains("<h3>1</h3><p>Info</p>"));
    }

    #[test]
    fn test_html_report_with_before_after_context() {
        let finding = VulnerabilityFinding {
            id: "test-id-1".to_string(),
            severity: Severity::High,
            title: "SQL Injection".to_string(),
            description: "Potential SQL injection detected".to_string(),
            confidence_score: 0.85,
            cwe_id: Some("CWE-89".to_string()),
            file_path: "src/db.rs".to_string(),
            line_number: Some(42),
            code_snippet: None,
            diff_hunk: Some(
                "let result = db.execute(&full);\nprocess(result);\nreturn Ok(());".to_string(),
            ),
            recommendation: Some("Validate input".to_string()),
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
        };

        let findings = vec![finding];
        let output_path = Path::new("/tmp/test_before_after.html");

        generate_html_report(&findings, &output_path.to_string_lossy(), None, None).unwrap();

        let html = std::fs::read_to_string(output_path).unwrap();

        // Check for diff hunk presence (no code snippet in this finding)
        assert!(html.contains("Recommended Fix"));
        assert!(html.contains("let result = db.execute"));
    }

    #[test]
    fn test_html_report_with_llm_metrics() {
        let finding = VulnerabilityFinding {
            id: "test-id-2".to_string(),
            severity: Severity::Medium,
            title: "Hardcoded Password".to_string(),
            description: "Password in source code".to_string(),
            confidence_score: 0.95,
            cwe_id: Some("CWE-798".to_string()),
            file_path: "src/config.rs".to_string(),
            line_number: Some(15),
            code_snippet: None,
            diff_hunk: None,
            recommendation: Some("Move to config".to_string()),
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
        };

        let findings = vec![finding];
        let metrics = crate::report::json::LlmMetricsSummary {
            total_requests: 10,
            successful_requests: 8,
            failed_requests: 2,
            cached_requests: 3,
            total_tokens: 1000,
            avg_latency_ms: 1500.5,
            models: vec![],
            operations: vec![],
        };

        let output_path = Path::new("/tmp/test_metrics.html");

        generate_html_report(
            &findings,
            &output_path.to_string_lossy(),
            None,
            Some(metrics),
        )
        .unwrap();

        let html = std::fs::read_to_string(output_path).unwrap();

        assert!(html.contains("LLM Usage Statistics"));
        assert!(html.contains("Total Requests"));
        assert!(html.contains("10"));
        assert!(html.contains("Successful"));
        assert!(html.contains("8"));
        assert!(html.contains("Failed"));
        assert!(html.contains("2"));
        assert!(html.contains("Cached"));
        assert!(html.contains("3"));
        assert!(html.contains("Total Tokens"));
        assert!(html.contains("1000"));
        assert!(html.contains("Avg Latency"));
    }

    #[test]
    fn test_html_report_without_before_after() {
        let finding = VulnerabilityFinding {
            id: "test-id-3".to_string(),
            severity: Severity::Low,
            title: "Unused Variable".to_string(),
            description: "Variable declared but not used".to_string(),
            confidence_score: 0.70,
            cwe_id: None,
            file_path: "src/main.rs".to_string(),
            line_number: Some(8),
            code_snippet: None,
            diff_hunk: None,
            recommendation: Some("Clean up code".to_string()),
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
        };

        let findings = vec![finding];
        let output_path = Path::new("/tmp/test_no_context.html");

        generate_html_report(&findings, &output_path.to_string_lossy(), None, None).unwrap();

        let html = std::fs::read_to_string(output_path).unwrap();

        // No diff hunk when there's no recommended_fix
        assert!(!html.contains("Recommended Fix"));
    }

    #[test]
    fn test_collapsible_sections() {
        let findings = vec![make_finding(Severity::Medium, "Collapsible test", "t.c")];
        let output_path = Path::new("/tmp/collapse.html");
        generate_html_report(&findings, &output_path.to_string_lossy(), None, None).unwrap();
        let content = std::fs::read_to_string(Path::new("/tmp/collapse.html")).unwrap();
        assert!(content.contains("collapsible"));
        assert!(content.contains("toggleAll"));
        assert!(content.contains("Expand All"));
        assert!(content.contains("Collapse All"));
    }

    #[test]
    fn test_verification_status_display() {
        let mut finding = make_minimal_finding();
        finding.verification_status = Some(crate::findings::VerificationStatus::Confirmed);
        finding.verification_notes = Some("Verified manually".to_string());
        finding.priority_score = Some(0.85);

        let findings = vec![finding];
        let output_path = Path::new("/tmp/verified.html");
        generate_html_report(&findings, &output_path.to_string_lossy(), None, None).unwrap();
        let content = std::fs::read_to_string(Path::new("/tmp/verified.html")).unwrap();
        assert!(content.contains("Verification"));
        assert!(content.contains("confirmed"));
        assert!(content.contains("Priority"));
    }

    #[test]
    fn test_cross_file_references() {
        let mut finding = make_minimal_finding();
        finding.cross_file_references =
            Some(vec!["auth.c:42".to_string(), "config.c:15".to_string()]);

        let findings = vec![finding];
        let output_path = Path::new("/tmp/xref.html");
        generate_html_report(&findings, &output_path.to_string_lossy(), None, None).unwrap();
        let content = std::fs::read_to_string(Path::new("/tmp/xref.html")).unwrap();
        assert!(content.contains("Cross-file refs"));
        assert!(content.contains("auth.c:42"));
        assert!(content.contains("config.c:15"));
    }

    #[test]
    fn test_poc_rendering() {
        let mut finding = make_minimal_finding();
        finding.poc_code =
            Some(r#"cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")"#.to_string());
        finding.mitigation_code = Some(
            r#"cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))"#.to_string(),
        );
        finding.poc_format = Some("python".to_string());

        let findings = vec![finding];
        let output_path = Path::new("/tmp/poc.html");
        generate_html_report(&findings, &output_path.to_string_lossy(), None, None).unwrap();
        let content = std::fs::read_to_string(Path::new("/tmp/poc.html")).unwrap();

        assert!(content.contains("Proof of Concept"));
        assert!(content.contains("Mitigation Example"));
        assert!(content.contains("cursor.execute"));
        assert!(content.contains("poc-section"));
        assert!(content.contains(".code-panel.poc"));
    }

    #[test]
    fn test_poc_xss_safety() {
        let mut finding = make_minimal_finding();
        finding.poc_code = Some(r#"<script>alert('xss')</script>"#.to_string());
        finding.mitigation_code = Some(r#"<img src=x onerror=alert(1)>"#.to_string());

        let findings = vec![finding];
        let output_path = Path::new("/tmp/poc_xss.html");
        generate_html_report(&findings, &output_path.to_string_lossy(), None, None).unwrap();
        let content = std::fs::read_to_string(Path::new("/tmp/poc_xss.html")).unwrap();

        assert!(content.contains("&lt;script&gt;"));
        assert!(content.contains("&lt;img"));
        assert!(!content.contains("<script>alert"));
        assert!(!content.contains("<img src=x"));
    }

    #[test]
    fn test_html_report_with_llm_model_and_description() {
        // Test that LLM model and description are properly displayed
        let finding = VulnerabilityFinding {
            id: "test-llm-model-1".to_string(),
            severity: Severity::High,
            title: "SQL Injection".to_string(),
            description: "User input is directly concatenated into SQL query".to_string(),
            confidence_score: 0.85,
            cwe_id: Some("CWE-89".to_string()),
            file_path: "src/db.rs".to_string(),
            line_number: Some(42),
            code_snippet: Some("query = \"SELECT * FROM users WHERE id = \" + user_id".to_string()),
            diff_hunk: None,
            recommendation: Some("Use parameterized queries".to_string()),
            code_location: Some("src/db.rs:42".to_string()),
            already_reported: false,
            sources: vec!["semgrep".to_string()],
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
            llm_model: Some("semgrep".to_string()),
            agent_mode: false,
        };

        let findings = vec![finding];
        let output_path = Path::new("/tmp/llm_model_test.html");
        generate_html_report(&findings, &output_path.to_string_lossy(), None, None).unwrap();
        let content = std::fs::read_to_string(output_path).unwrap();

        // Verify that the source is displayed
        assert!(content.contains("<strong>Source:</strong> semgrep"), 
                "HTML should contain the LLM source 'semgrep'");
        
        // Verify that the description is displayed
        assert!(content.contains("User input is directly concatenated into SQL query"),
                "HTML should contain the finding description");
        
        // Verify that the description is rendered as HTML (not empty)
        assert!(content.contains("<p>User input is directly concatenated into SQL query</p>") ||
                content.contains("User input is directly concatenated into SQL query"),
                "HTML should contain rendered description text");
    }

    #[test]
    fn test_html_report_with_empty_llm_model() {
        // Test that findings without LLM model still show description
        let finding = VulnerabilityFinding {
            id: "test-no-model-1".to_string(),
            severity: Severity::Medium,
            title: "Buffer Overflow".to_string(),
            description: "Potential buffer overflow condition".to_string(),
            confidence_score: 0.7,
            cwe_id: Some("CWE-120".to_string()),
            file_path: "src/utils.c".to_string(),
            line_number: Some(15),
            code_snippet: Some("strcpy(buffer, input)".to_string()),
            diff_hunk: None,
            recommendation: Some("Use strncpy instead".to_string()),
            code_location: Some("src/utils.c:15".to_string()),
            already_reported: false,
            sources: vec!["semgrep".to_string()],
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
        };

        let findings = vec![finding];
        let output_path = Path::new("/tmp/no_model_test.html");
        generate_html_report(&findings, &output_path.to_string_lossy(), None, None).unwrap();
        let content = std::fs::read_to_string(output_path).unwrap();

        // Description should still be displayed even without model
        assert!(content.contains("Potential buffer overflow condition"),
                "HTML should contain the finding description even without LLM model");
    }
}
