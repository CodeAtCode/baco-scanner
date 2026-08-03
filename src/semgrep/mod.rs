mod parser;
mod rules;
mod runner;

pub use rules::SemgrepRunner;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Severity, VulnerabilityFinding};

    #[test]
    fn test_parse_semgrep_output() {
        let mock_json = r#"{
            "results": [
                {
                    "check_id": "python.security.high.injection",
                    "path": "test.py",
                    "start": {"line": 42, "col": 10},
                    "extra": {
                        "message": "Potential SQL injection",
                        "metadata": {"cwe": ["CWE-89"]},
                        "severity": "High"
                    }
                }
            ]
        }"#;

        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file_path, "test.py");
        assert_eq!(findings[0].line_number, Some(42));
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_parse_semgrep_output_empty_results() {
        let mock_json = r#"{"results": []}"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_parse_semgrep_output_empty_array() {
        let mock_json = r#"[]"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let result = parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_semgrep_output_no_results_key() {
        let mock_json = r#"{"data": []}"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_parse_semgrep_output_multiple_findings() {
        let mock_json = r#"{
            "results": [
                {"check_id": "cve.2024.1", "path": "file1.py", "start": {"line": 1}, "extra": {"message": "Issue 1", "metadata": {"cwe": ["CWE-1"]}}},
                {"check_id": "cve.2024.2", "path": "file2.py", "start": {"line": 2}, "extra": {"message": "Issue 2", "metadata": {"cwe": ["CWE-2"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_parse_semgrep_output_critical_severity() {
        let mock_json = r#"{
            "results": [
                {"check_id": "critical.issue", "path": "test.py", "start": {"line": 1}, "extra": {"message": "Critical", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_parse_semgrep_output_medium_severity() {
        let mock_json = r#"{
            "results": [
                {"check_id": "medium.issue", "path": "test.py", "start": {"line": 1}, "extra": {"message": "Medium", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_parse_semgrep_output_missing_cwe() {
        let mock_json = r#"{
            "results": [
                {"check_id": "test.issue", "path": "test.py", "start": {"line": 1}, "extra": {"message": "No CWE"}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings[0].cwe_id, None);
    }

    #[test]
    fn test_parse_semgrep_output_missing_snippet() {
        let mock_json = r#"{
            "results": [
                {"check_id": "test.issue", "path": "test.py", "start": {"line": 1}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        assert!(findings[0].code_snippet.is_some());
    }

    #[test]
    fn test_parse_semgrep_output_json_parse_error() {
        let mock_json = r#"{"invalid json}"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let result = parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules);
        assert!(result.unwrap_err().contains("Failed to parse"));
    }

    #[test]
    fn test_parse_semgrep_output_no_start_line() {
        let mock_json = r#"{
            "results": [
                {"check_id": "test.issue", "path": "test.py"}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let result = parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules);
        let findings = result.unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_parse_semgrep_output_no_path() {
        let mock_json = r#"{
            "results": [
                {"check_id": "test.issue", "start": {"line": 1}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let result = parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules);
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_run_stubbed() {
        let runner = SemgrepRunner::new(None, vec![]);
        assert!(runner.config_path.is_none());
    }

    #[test]
    fn test_run_with_config() {
        let runner = SemgrepRunner::new(Some("/path/to/config.yml".to_string()), vec![]);
        assert_eq!(runner.config_path, Some("/path/to/config.yml".to_string()));
    }

    #[test]
    fn test_run_invalid_json() {
        let mock_json = b"not valid json";
        let runner = SemgrepRunner::new(None, vec![]);
        let result = parser::parse_json_output(mock_json, &runner.exclude_rules);
        assert!(result.is_err());
    }

    #[test]
    fn test_should_exclude_rule_exact_match() {
        let runner = SemgrepRunner::new(None, vec!["python.lang.security".to_string()]);
        assert!(runner.should_exclude_rule("python.lang.security"));
        // Prefix match: "python.lang.security" matches "python.lang.security.audit"
        assert!(runner.should_exclude_rule("python.lang.security.audit"));
    }

    #[test]
    fn test_should_exclude_rule_prefix_match() {
        let runner = SemgrepRunner::new(None, vec!["python.lang.security".to_string()]);
        // Prefix match should exclude all sub-rules
        assert!(runner.should_exclude_rule("python.lang.security.audit"));
        assert!(runner.should_exclude_rule("python.lang.security.injection"));
        assert!(runner.should_exclude_rule("python.lang.security.audit.danger"));
    }

    #[test]
    fn test_should_exclude_rule_no_match() {
        let runner = SemgrepRunner::new(None, vec!["python.lang.security".to_string()]);
        assert!(!runner.should_exclude_rule("javascript.security"));
        assert!(!runner.should_exclude_rule("python.lang.ast"));
        assert!(!runner.should_exclude_rule("rust.security"));
    }

    #[test]
    fn test_should_exclude_rule_multiple_patterns() {
        let runner = SemgrepRunner::new(
            None,
            vec!["python.lang".to_string(), "javascript.security".to_string()],
        );
        assert!(runner.should_exclude_rule("python.lang.security"));
        assert!(runner.should_exclude_rule("javascript.security.xss"));
        assert!(!runner.should_exclude_rule("rust.security"));
    }

    #[test]
    fn test_should_exclude_rule_empty_patterns() {
        let runner = SemgrepRunner::new(None, vec![]);
        assert!(!runner.should_exclude_rule("any.rule"));
        assert!(!runner.should_exclude_rule("python.lang.security"));
    }

    #[test]
    fn test_extract_code_snippet_file_not_found() {
        let snippet = parser::extract_code_snippet("/nonexistent/file.rs", 42, 2);
        assert!(snippet.contains("file not found"));
        assert!(snippet.contains("Line 42"));
    }

    #[test]
    fn test_extract_code_snippet_with_context() {
        // Create a temp file for testing
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_extract_snippet.txt");
        let content = "line 1\nline 2\nline 3\nline 4\nline 5\n";
        std::fs::write(&test_file, content).unwrap();

        let snippet = parser::extract_code_snippet(test_file.to_str().unwrap(), 3, 1);

        // Should include lines 2, 3, 4 with line 3 marked
        assert!(
            snippet.contains("line 2"),
            "snippet should contain line 2: {}",
            snippet
        );
        assert!(snippet.contains("line 3"));
        assert!(snippet.contains("line 4"));
        assert!(snippet.contains(">>")); // Marker for target line

        // Clean up
        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_extract_code_snippet_target_line_at_start() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_extract_snippet_start.txt");
        let content = "line 1\nline 2\nline 3\n";
        std::fs::write(&test_file, content).unwrap();

        let snippet = parser::extract_code_snippet(test_file.to_str().unwrap(), 1, 2);

        // Should start from line 1 (can't go negative)
        assert!(snippet.contains("line 1"));
        assert!(snippet.contains(">>"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_extract_code_snippet_target_line_beyond_file() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_extract_snippet_beyond.txt");
        let content = "line 1\nline 2\nline 3\n";
        std::fs::write(&test_file, content).unwrap();

        let snippet = parser::extract_code_snippet(test_file.to_str().unwrap(), 100, 2);

        // Should show last available lines
        assert!(snippet.contains("line 3"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_parse_semgrep_output_low_severity() {
        let mock_json = r#"{
            "results": [
                {"check_id": "low.issue", "path": "test.py", "start": {"line": 1}, "extra": {"message": "Low", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn test_parse_semgrep_output_info_severity() {
        let mock_json = r#"{
            "results": [
                {"check_id": "info.issue", "path": "test.py", "start": {"line": 1}, "extra": {"message": "Info", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_parse_semgrep_output_missing_message() {
        let mock_json = r#"{
            "results": [
                {"check_id": "test.issue", "path": "test.py", "start": {"line": 1}, "extra": {"metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        // Should use fallback description
        assert!(findings[0].description.contains("test.issue"));
    }

    #[test]
    fn test_parse_semgrep_aggregated_multiple_locations() {
        let mock_json = r#"{
            "results": [
                {"check_id": "multi.issue", "path": "file1.py", "start": {"line": 1}, "extra": {"message": "Issue", "metadata": {"cwe": ["CWE-1"]}}},
                {"check_id": "multi.issue", "path": "file2.py", "start": {"line": 2}, "extra": {"message": "Issue", "metadata": {"cwe": ["CWE-1"]}}},
                {"check_id": "multi.issue", "path": "file3.py", "start": {"line": 3}, "extra": {"message": "Issue", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        // Multiple findings with same check_id should be aggregated
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file_path, "multiple_files");
        // Code snippet shows "Found in 3 files:" format
        assert!(findings[0]
            .code_snippet
            .as_ref()
            .unwrap()
            .contains("3 files"));
    }

    #[test]
    fn test_parse_semgrep_aggregated_single_location() {
        let mock_json = r#"{
            "results": [
                {"check_id": "single.issue", "path": "file1.py", "start": {"line": 1}, "extra": {"message": "Single issue", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file_path, "file1.py");
        assert_eq!(findings[0].line_number, Some(1));
    }

    /// Test helper: parse semgrep JSON with missing extra fields
    fn parse_test_json_missing_fields() -> Vec<VulnerabilityFinding> {
        let mock_json = r#"{
            "results": [
                {"check_id": "test.issue", "path": "test.py", "start": {"line": 1}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap()
    }

    #[test]
    fn test_parse_semgrep_missing_extra_field() {
        let findings = parse_test_json_missing_fields();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info); // Default severity
        assert_eq!(findings[0].cwe_id, None);
    }

    #[test]
    fn test_parse_semgrep_with_empty_check_id() {
        let mock_json = r#"{
            "results": [
                {"check_id": "", "path": "test.py", "start": {"line": 1}, "extra": {"message": "Test"}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "");
    }

    #[test]
    fn test_semgrep_runner_new_with_exclude_rules() {
        let runner = SemgrepRunner::new(
            Some("/path/to/config.yml".to_string()),
            vec!["rule1".to_string(), "rule2".to_string()],
        );
        assert_eq!(runner.config_path, Some("/path/to/config.yml".to_string()));
        assert_eq!(runner.exclude_rules.len(), 2);
        assert!(runner.exclude_rules.contains(&"rule1".to_string()));
        assert!(runner.exclude_rules.contains(&"rule2".to_string()));
    }

    #[test]
    fn test_extract_code_snippet_file_read_error() {
        // Test case where file exists but cannot be read (permission denied, etc.)
        // We use a directory instead of a file to trigger the error path
        let temp_dir = std::env::temp_dir();
        let snippet = parser::extract_code_snippet(temp_dir.to_str().unwrap(), 1, 2);
        // Directory read will fail, triggering the Err path
        assert!(snippet.contains("[unable to read file]") || snippet.contains("[file not found]"));
    }

    #[test]
    fn test_extract_code_snippet_fewer_lines_than_context() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_short_file.txt");
        let content = "line 1\n"; // Only 1 line
        std::fs::write(&test_file, content).unwrap();

        // Request context of 5 lines for a file with only 1 line
        let snippet = parser::extract_code_snippet(test_file.to_str().unwrap(), 1, 5);

        // Should show the single available line
        assert!(snippet.contains("line 1"));
        assert!(snippet.contains(">>"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_parse_semgrep_aggregated_empty_message() {
        let mock_json = r#"{
            "results": [
                {"check_id": "empty.msg.issue", "path": "file1.py", "start": {"line": 1}, "extra": {"message": "", "metadata": {"cwe": ["CWE-1"]}}},
                {"check_id": "empty.msg.issue", "path": "file2.py", "start": {"line": 2}, "extra": {"message": "", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings.len(), 1);
        // When base_message is empty and other_count > 0, uses "detected in N locations"
        assert!(findings[0].description.contains("detected in 2 locations"));
    }

    #[test]
    fn test_parse_semgrep_aggregated_single_with_empty_message() {
        let mock_json = r#"{
            "results": [
                {"check_id": "single.empty.msg", "path": "file1.py", "start": {"line": 1}, "extra": {"message": "", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings.len(), 1);
        // For single finding with empty message, description is the empty message (not fallback)
        assert_eq!(findings[0].description, "");
    }

    #[test]
    fn test_parse_semgrep_missing_extra_metadata() {
        let mock_json = r#"{
            "results": [
                {"check_id": "test.issue", "path": "test.py", "start": {"line": 1}, "extra": {"message": "Test message"}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].cwe_id, None);
    }

    #[test]
    fn test_parse_semgrep_missing_extra_object() {
        let findings = parse_test_json_missing_fields();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].cwe_id, None);
    }

    #[test]
    fn test_parse_semgrep_missing_message_in_extra() {
        let mock_json = r#"{
            "results": [
                {"check_id": "no.msg.test", "path": "test.py", "start": {"line": 1}, "extra": {"metadata": {"cwe": ["CWE-89"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings.len(), 1);
        // Should use fallback description when message is missing
        assert!(findings[0].description.contains("no.msg.test"));
    }

    #[test]
    fn test_parse_semgrep_missing_check_id() {
        let mock_json = r#"{
            "results": [
                {"path": "test.py", "start": {"line": 1}, "extra": {"message": "Test"}},
                {"check_id": "valid.rule", "path": "test2.py", "start": {"line": 2}, "extra": {"message": "Valid"}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        // Entry without check_id should be skipped
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "valid.rule");
    }

    #[test]
    fn test_parse_semgrep_with_excluded_rule() {
        let mock_json = r#"{
            "results": [
                {"check_id": "python.lang.security.injection", "path": "test.py", "start": {"line": 1}, "extra": {"message": "Should be excluded"}},
                {"check_id": "other.rule", "path": "test2.py", "start": {"line": 2}, "extra": {"message": "Should be included"}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec!["python.lang.security".to_string()]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        // python.lang.security.* should be excluded
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "other.rule");
    }

    #[test]
    fn test_parse_semgrep_aggregated_with_base_message_and_multiple() {
        let mock_json = r#"{
            "results": [
                {"check_id": "multi.with.msg", "path": "file1.py", "start": {"line": 1}, "extra": {"message": "Base issue found", "metadata": {"cwe": ["CWE-1"]}}},
                {"check_id": "multi.with.msg", "path": "file2.py", "start": {"line": 2}, "extra": {"message": "Base issue found", "metadata": {"cwe": ["CWE-1"]}}},
                {"check_id": "multi.with.msg", "path": "file3.py", "start": {"line": 3}, "extra": {"message": "Base issue found", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings.len(), 1);
        // When base_message is not empty and other_count > 1: "Base issue found (and 2 other locations)"
        assert!(findings[0].description.contains("Base issue found"));
        assert!(findings[0].description.contains("2 other locations"));
    }

    #[test]
    fn test_parse_semgrep_aggregated_with_base_message_single_other() {
        let mock_json = r#"{
            "results": [
                {"check_id": "multi.two.msg", "path": "file1.py", "start": {"line": 1}, "extra": {"message": "Found issue", "metadata": {"cwe": ["CWE-1"]}}},
                {"check_id": "multi.two.msg", "path": "file2.py", "start": {"line": 2}, "extra": {"message": "Found issue", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings.len(), 1);
        // When base_message is not empty and other_count == 1: "Found issue (and 1 other location)" - singular
        assert!(findings[0].description.contains("Found issue"));
        assert!(findings[0].description.contains("1 other location"));
        // Should NOT have "locations" (plural)
        assert!(!findings[0].description.contains("locations"));
    }

    #[test]
    fn test_parse_semgrep_aggregated_empty_message_single_location() {
        let mock_json = r#"{
            "results": [
                {"check_id": "empty.single", "path": "file1.py", "start": {"line": 1}, "extra": {"message": "", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings =
            parser::parse_json_output(mock_json.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings.len(), 1);
        // Single location with empty message returns empty string as description
        assert_eq!(findings[0].description, "");
    }

    #[test]
    fn test_extract_code_snippet_exact_context_fit() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_exact_context.txt");
        // File has exactly context_lines * 2 + 1 lines, target in middle
        let content = "line 1\nline 2\nline 3\nline 4\nline 5\n";
        std::fs::write(&test_file, content).unwrap();

        // Request 2 context lines around line 3 - should fit exactly
        let snippet = parser::extract_code_snippet(test_file.to_str().unwrap(), 3, 2);

        assert!(snippet.contains("line 1"));
        assert!(snippet.contains("line 2"));
        assert!(snippet.contains(">>")); // line 3 marked
        assert!(snippet.contains("line 4"));
        assert!(snippet.contains("line 5"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_extract_code_snippet_file_with_single_line() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_single_line.txt");
        let content = "only line 1\n"; // Exactly 1 line
        std::fs::write(&test_file, content).unwrap();

        // Request context of 2 for a 1-line file, target beyond file - should show all lines
        let snippet = parser::extract_code_snippet(test_file.to_str().unwrap(), 5, 2);

        assert!(snippet.contains("only line 1"));
        // When target is beyond file and lines.len() <= context_lines, shows all lines from start

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_semgrep_runner_clone() {
        let runner = SemgrepRunner::new(Some("config.yml".into()), vec!["rule1".into()]);
        let cloned = runner.clone();
        assert_eq!(runner.config_path, cloned.config_path);
        assert_eq!(runner.exclude_rules, cloned.exclude_rules);
    }

    #[test]
    fn test_semgrep_runner_new_empty() {
        let runner = SemgrepRunner::new(None, vec![]);
        assert!(runner.config_path.is_none());
        assert!(runner.exclude_rules.is_empty());
    }

    #[test]
    fn test_semgrep_runner_new_with_config() {
        let runner = SemgrepRunner::new(Some("/path/config.yml".into()), vec![]);
        assert_eq!(runner.config_path, Some("/path/config.yml".into()));
    }

    #[test]
    fn test_semgrep_runner_new_with_multiple_exclude_rules() {
        let runner = SemgrepRunner::new(None, vec!["rule1".into(), "rule2".into(), "rule3".into()]);
        assert_eq!(runner.exclude_rules.len(), 3);
    }

    #[test]
    fn test_should_exclude_rule_exact_and_prefix() {
        let runner = SemgrepRunner::new(None, vec!["python".into()]);
        assert!(runner.should_exclude_rule("python"));
        assert!(runner.should_exclude_rule("python.lang"));
        assert!(runner.should_exclude_rule("python.lang.security"));
        assert!(!runner.should_exclude_rule("javascript"));
    }

    #[test]
    fn test_should_exclude_rule_multiple_patterns_additional() {
        let runner = SemgrepRunner::new(
            None,
            vec!["python".into(), "javascript".into(), "rust".into()],
        );
        assert!(runner.should_exclude_rule("python.lang"));
        assert!(runner.should_exclude_rule("javascript.security"));
        assert!(runner.should_exclude_rule("rust.security"));
        assert!(!runner.should_exclude_rule("go"));
    }

    #[test]
    fn test_should_exclude_rule_empty_list() {
        let runner = SemgrepRunner::new(None, vec![]);
        assert!(!runner.should_exclude_rule("any.rule"));
    }

    #[test]
    fn test_should_exclude_rule_no_match_additional() {
        let runner = SemgrepRunner::new(None, vec!["python".into()]);
        assert!(!runner.should_exclude_rule("javascript.security"));
        assert!(!runner.should_exclude_rule("rust.lang"));
    }

    #[test]
    fn test_extract_code_snippet_line_zero() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_line_zero.txt");
        std::fs::write(&test_file, "line 1\nline 2\n").unwrap();

        let snippet = parser::extract_code_snippet(test_file.to_str().unwrap(), 0, 1);
        assert!(snippet.contains("line 1"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_extract_code_snippet_large_context() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_large_context.txt");
        std::fs::write(&test_file, "line 1\nline 2\nline 3\n").unwrap();

        let snippet = parser::extract_code_snippet(test_file.to_str().unwrap(), 2, 100);
        assert!(snippet.contains("line 1"));
        assert!(snippet.contains("line 2"));
        assert!(snippet.contains("line 3"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_extract_code_snippet_target_at_end() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_target_end.txt");
        std::fs::write(&test_file, "line 1\nline 2\nline 3\n").unwrap();

        let snippet = parser::extract_code_snippet(test_file.to_str().unwrap(), 3, 1);
        assert!(snippet.contains("line 2"));
        assert!(snippet.contains("line 3"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_extract_code_snippet_target_at_start() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_target_start.txt");
        std::fs::write(&test_file, "line 1\nline 2\nline 3\n").unwrap();

        let snippet = parser::extract_code_snippet(test_file.to_str().unwrap(), 1, 1);
        assert!(snippet.contains("line 1"));
        assert!(snippet.contains("line 2"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_extract_code_snippet_empty_file() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_empty.txt");
        std::fs::write(&test_file, "").unwrap();

        let snippet = parser::extract_code_snippet(test_file.to_str().unwrap(), 1, 2);
        assert!(
            snippet.is_empty()
                || snippet.contains("[unable to read file]")
                || snippet.contains("Line 1")
        );

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_extract_code_snippet_marker_position() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_marker.txt");
        std::fs::write(&test_file, "line 1\nline 2\nline 3\nline 4\nline 5\n").unwrap();

        let snippet = parser::extract_code_snippet(test_file.to_str().unwrap(), 3, 1);
        let lines: Vec<&str> = snippet.lines().collect();

        let marker_line = lines.iter().find(|l| l.contains(">>")).unwrap();
        assert!(marker_line.contains("line 3"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_raw_finding_struct() {
        use super::rules::RawFinding;
        let raw = RawFinding {
            path: "test.rs".into(),
            line: 42,
            end_line: 45,
            severity: Severity::High,
            cwe_id: Some("CWE-79".into()),
            message: Some("Test message".into()),
        };

        assert_eq!(raw.path, "test.rs");
        assert_eq!(raw.line, 42);
        assert_eq!(raw.end_line, 45);
        assert_eq!(raw.severity, Severity::High);
        assert_eq!(raw.cwe_id, Some("CWE-79".into()));
        assert_eq!(raw.message, Some("Test message".into()));
    }

    #[test]
    fn test_raw_finding_with_none_fields() {
        use super::rules::RawFinding;
        let raw = RawFinding {
            path: "test.rs".into(),
            line: 1,
            end_line: 5,
            severity: Severity::Info,
            cwe_id: None,
            message: None,
        };

        assert_eq!(raw.end_line, 5);
        assert!(raw.cwe_id.is_none());
        assert!(raw.message.is_none());
    }

    #[test]
    fn test_severity_mapping_all_variants() {
        use super::rules::parse_severity;

        assert_eq!(parse_severity("critical.issue"), Severity::Critical);
        assert_eq!(parse_severity("high.issue"), Severity::High);
        assert_eq!(parse_severity("medium.issue"), Severity::Medium);
        assert_eq!(parse_severity("low.issue"), Severity::Low);
        assert_eq!(parse_severity("info.issue"), Severity::Info);
    }

    #[test]
    fn test_parse_json_output_with_missing_optional_fields() {
        let runner = SemgrepRunner::new(None, vec![]);

        // Missing extra.metadata
        let json = r#"{"results": [{"check_id": "test", "path": "f.py", "start": {"line": 1}, "extra": {"message": "m"}}]}"#;
        let findings = parser::parse_json_output(json.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].cwe_id.is_none());
    }

    #[test]
    fn test_parse_json_output_aggregation_logic() {
        let runner = SemgrepRunner::new(None, vec![]);

        // Single finding - no aggregation
        let json_single = r#"{"results": [{"check_id": "single", "path": "f1.py", "start": {"line": 1}, "extra": {"message": "m"}}]}"#;
        let findings =
            parser::parse_json_output(json_single.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file_path, "f1.py");

        // Multiple findings with same check_id - aggregation
        let json_multi = r#"{"results": [{"check_id": "multi", "path": "f1.py", "start": {"line": 1}, "extra": {"message": "m"}}, {"check_id": "multi", "path": "f2.py", "start": {"line": 2}, "extra": {"message": "m"}}]}"#;
        let findings =
            parser::parse_json_output(json_multi.as_bytes(), &runner.exclude_rules).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file_path, "multiple_files");
    }
}
