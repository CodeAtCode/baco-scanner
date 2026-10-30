// Failure injection tests for Semgrep parser
// Tests that parse_json_output handles various error conditions correctly

#[cfg(test)]
mod tests {
    use baco::semgrep::parser::parse_json_output;

    #[test]
    fn test_parse_invalid_json_returns_error() {
        let result = parse_json_output(b"not json at all", &[], &[]);

        assert!(result.is_err(), "Invalid JSON should return an error");
    }

    #[test]
    fn test_parse_missing_results_key_returns_empty() {
        let result = parse_json_output(br#"{"other":"value"}"#, &[], &[]);

        assert!(result.is_ok(), "Missing 'results' key should return Ok");
        let findings = result.unwrap();
        assert!(
            findings.is_empty(),
            "Missing 'results' key should return empty vector"
        );
    }

    #[test]
    fn test_parse_empty_results_array_returns_empty() {
        let result = parse_json_output(br#"{"results":[]}"#, &[], &[]);

        assert!(result.is_ok(), "Empty results array should return Ok");
        let findings = result.unwrap();
        assert!(
            findings.is_empty(),
            "Empty results array should return empty vector"
        );
    }

    #[test]
    fn test_parse_malformed_json_returns_error() {
        let result = parse_json_output(b"{\"results\": [invalid syntax here", &[], &[]);

        assert!(result.is_err(), "Malformed JSON should return an error");
    }

    #[test]
    fn test_parse_result_with_missing_fields_skipped() {
        let result = parse_json_output(br#"{"results":[{"other_field":"value"}]}"#, &[], &[]);

        assert!(
            result.is_ok(),
            "Result with missing required fields should return Ok"
        );
        let findings = result.unwrap();
        assert!(
            findings.is_empty(),
            "Results missing check_id/path should be skipped, returning empty vector"
        );
    }

    #[test]
    fn test_parse_valid_result_produces_finding() {
        let json = br#"{"results":[{"check_id":"test.rule","path":"foo.php","start":{"line":1},"end":{"line":1},"extra":{"severity":"ERROR","message":"test vuln"}}]}"#;
        let result = parse_json_output(json, &[], &[]);

        assert!(result.is_ok(), "Valid JSON should return Ok");
        let findings = result.unwrap();

        assert_eq!(
            findings.len(),
            1,
            "Valid result should produce exactly one finding"
        );

        let finding = &findings[0];
        assert_eq!(
            finding.title, "test.rule",
            "Finding title should match check_id"
        );
        assert_eq!(
            finding.file_path, "foo.php",
            "Finding file_path should match path"
        );
    }

    #[test]
    fn test_parse_exclude_rules_filters_findings() {
        let json = br#"{"results":[{"check_id":"test.rule","path":"foo.php","start":{"line":1},"end":{"line":1},"extra":{"severity":"ERROR","message":"test vuln"}}]}"#;
        let exclude_rules = vec!["test.rule".to_string()];
        let result = parse_json_output(json, &exclude_rules, &[]);

        assert!(
            result.is_ok(),
            "Valid JSON with exclude rules should return Ok"
        );
        let findings = result.unwrap();

        assert!(
            findings.is_empty(),
            "Finding matching exclude rule should be filtered out"
        );
    }
}
