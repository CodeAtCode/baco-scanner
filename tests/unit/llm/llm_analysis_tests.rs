//! Unit tests for src/llm_analysis.rs
//!
//! Tests cover:
//! 1. Basic analysis flow with mock LLM
//! 2. Empty input handling
//! 3. Response parsing (JSON extraction)
//! 4. Confidence score assignment
//! 5. Severity mapping from LLM output
//! 6. CWE ID extraction
//! 7. Recommendation generation
//! 8. PoC and mitigation code generation
//! 9. Edge cases: malformed responses, missing fields

use baco::findings::Severity;
use baco::llm_analysis::{
    extract_cwe_id, format_cwe_specs, generate_mitigation_code, generate_poc_code,
    generate_recommendation,
};
use baco::retrieval::CweDocument;

// ============================================================================
// CWE Formatting Tests
// ============================================================================

#[test]
fn test_format_cwe_specs_multiple() {
    let docs = [
        CweDocument {
            cwe_id: "CWE-89".to_string(),
            name: "SQL Injection".to_string(),
            description: "SQL injection vulnerabilities occur when...".to_string(),
            examples: vec!["Example 1: unsanitized input".to_string()],
            mitigation: "Use parameterized queries".to_string(),
        },
        CweDocument {
            cwe_id: "CWE-79".to_string(),
            name: "XSS".to_string(),
            description: "Cross-site scripting vulnerabilities...".to_string(),
            examples: vec![],
            mitigation: "Escape user output".to_string(),
        },
    ];
    let doc_refs: Vec<&CweDocument> = docs.iter().collect();

    let formatted = format_cwe_specs(&doc_refs);
    assert!(formatted.contains("CWE-89"));
    assert!(formatted.contains("SQL Injection"));
    assert!(formatted.contains("CWE-79"));
    assert!(formatted.contains("XSS"));
}

#[test]
fn test_format_cwe_specs_empty() {
    let docs: Vec<&CweDocument> = vec![];
    let formatted = format_cwe_specs(&docs);
    assert!(formatted.is_empty());
}

// ============================================================================
// CWE Extraction Tests
// ============================================================================

#[test]
fn test_extract_cwe_id_found() {
    let text = "This vulnerability is related to CWE-89 (SQL Injection)";
    let cwe = extract_cwe_id(text);
    assert_eq!(cwe, Some("CWE-89".to_string()));
}

#[test]
fn test_extract_cwe_id_not_found() {
    let text = "This is a generic vulnerability";
    let cwe = extract_cwe_id(text);
    assert!(cwe.is_none());
}

#[test]
fn test_extract_cwe_id_multiple() {
    let text = "See CWE-89 and CWE-79 for details";
    let cwe = extract_cwe_id(text);
    assert_eq!(cwe, Some("CWE-89".to_string())); // Returns first match
}

// ============================================================================
// Recommendation Generation Tests
// ============================================================================

#[test]
fn test_generate_recommendation_sql_injection() {
    let rec = generate_recommendation("SQL Injection", "User input is used in SQL query");
    assert!(rec.contains("parameterized"));
    assert!(rec.contains("prepared statements"));
}

#[test]
fn test_generate_recommendation_xss() {
    let rec = generate_recommendation("Cross-Site Scripting", "User input rendered in HTML");
    assert!(rec.contains("Escape"));
    assert!(rec.contains("encoding"));
}

#[test]
fn test_generate_recommendation_command_injection() {
    let rec = generate_recommendation("Command Injection", "Shell command with user input");
    assert!(rec.contains("shell"));
    assert!(rec.contains("validate"));
}

#[test]
fn test_generate_recommendation_buffer_overflow() {
    let rec = generate_recommendation("Buffer Overflow", "Fixed-size buffer with user input");
    assert!(rec.contains("bounds"));
    assert!(rec.contains("Validate input lengths"));
}

#[test]
fn test_generate_recommendation_generic() {
    let rec = generate_recommendation("Unknown Vulnerability", "Some security issue");
    assert!(rec.contains("Review and fix"));
}

// ============================================================================
// PoC Code Generation Tests
// ============================================================================

#[test]
fn test_generate_poc_code_buffer_overflow() {
    let poc = generate_poc_code("Buffer Overflow", "src/vuln.c", 42);
    assert!(poc.is_some());
    let poc_code = poc.unwrap();
    assert!(poc_code.contains("PoC"));
    assert!(poc_code.contains("Buffer overflow"));
    assert!(poc_code.contains("src/vuln.c"));
    assert!(poc_code.contains("42"));
}

#[test]
fn test_generate_poc_code_use_after_free() {
    let poc = generate_poc_code("Use After Free", "src/mem.c", 100);
    assert!(poc.is_some());
    let poc_code = poc.unwrap();
    assert!(poc_code.contains("Use-after-free"));
    assert!(poc_code.contains("src/mem.c"));
}

#[test]
fn test_generate_poc_code_double_free() {
    let poc = generate_poc_code("Double Free", "src/heap.c", 55);
    assert!(poc.is_some());
    let poc_code = poc.unwrap();
    assert!(poc_code.contains("Double-free"));
}

#[test]
fn test_generate_poc_code_format_string() {
    let poc = generate_poc_code("Format String Vulnerability", "src/log.c", 23);
    assert!(poc.is_some());
    let poc_code = poc.unwrap();
    assert!(poc_code.contains("Format string"));
}

#[test]
fn test_generate_poc_code_unknown_type() {
    let poc = generate_poc_code("Unknown Vulnerability", "src/code.rs", 10);
    assert!(poc.is_none());
}

// ============================================================================
// Mitigation Code Generation Tests
// ============================================================================

#[test]
fn test_generate_mitigation_code_buffer_overflow() {
    let mit = generate_mitigation_code("Buffer Overflow", "src/vuln.c", 42);
    assert!(mit.is_some());
    let mit_code = mit.unwrap();
    assert!(mit_code.contains("Mitigation"));
    assert!(mit_code.contains("bounds-checked"));
    assert!(mit_code.contains("Validate input length"));
}

#[test]
fn test_generate_mitigation_code_use_after_free() {
    let mit = generate_mitigation_code("Use After Free", "src/mem.c", 100);
    assert!(mit.is_some());
    let mit_code = mit.unwrap();
    assert!(mit_code.contains("Nullify pointer"));
    assert!(mit_code.contains("free"));
}

#[test]
fn test_generate_mitigation_code_double_free() {
    let mit = generate_mitigation_code("Double Free", "src/heap.c", 55);
    assert!(mit.is_some());
    let mit_code = mit.unwrap();
    assert!(mit_code.contains("Track allocation state"));
}

#[test]
fn test_generate_mitigation_code_format_string() {
    let mit = generate_mitigation_code("Format String", "src/log.c", 23);
    assert!(mit.is_some());
    let mit_code = mit.unwrap();
    assert!(mit_code.contains("Use fixed format specifier"));
}

#[test]
fn test_generate_mitigation_code_unknown_type() {
    let mit = generate_mitigation_code("Unknown", "src/code.rs", 10);
    assert!(mit.is_none());
}

// ============================================================================
// LLM Response Parsing Tests (using LlmAnalyzer.parse_llm_response)
// ============================================================================

#[cfg(test)]
mod parse_response_tests {
    use super::*;
    use baco::llm::{LlmClient, LlmConfig};
    use baco::llm_analysis::LlmAnalyzer;

    fn create_test_analyzer() -> LlmAnalyzer {
        let config = LlmConfig {
            base_url: "https://api.test.com/v1".to_string(),
            api_key: "test-key".to_string(),
            model: "test-model".to_string(),
            models: vec![],
            timeout: 30,
            max_retries: 3,
            retry_backoff_ms: 1000,
            temperature: 0.5,
            max_reasoning_tokens: None,
        };
        let client = LlmClient::new(config);
        LlmAnalyzer::new(client, vec!["rust".to_string()], 1024, &Default::default())
    }

    #[test]
    fn test_parse_llm_response_valid_json() {
        let analyzer = create_test_analyzer();
        let json_response = r#"[
            {
                "severity": "high",
                "title": "SQL Injection",
                "description": "User input not sanitized",
                "line": 42,
                "cwe_id": "CWE-89"
            }
        ]"#;

        let result = analyzer.parse_llm_response(json_response, "src/db.rs", "test-model");
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "SQL Injection");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].line_number, Some(42));
        assert_eq!(findings[0].cwe_id, Some("CWE-89".to_string()));
    }

    #[test]
    fn test_parse_llm_response_empty_array() {
        let analyzer = create_test_analyzer();
        let result = analyzer.parse_llm_response("[]", "src/empty.rs", "test-model");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_llm_response_multiple_findings() {
        let analyzer = create_test_analyzer();
        let json_response = r#"[
            {
                "severity": "critical",
                "title": "RCE",
                "description": "Remote code execution",
                "line": 10,
                "cwe_id": "CWE-94"
            },
            {
                "severity": "medium",
                "title": "Information Disclosure",
                "description": "Sensitive data exposed",
                "line": 25
            }
        ]"#;

        let result = analyzer.parse_llm_response(json_response, "src/multi.rs", "test-model");
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].severity, Severity::Medium);
    }

    #[test]
    fn test_parse_llm_response_malformed_json() {
        let analyzer = create_test_analyzer();
        let result = analyzer.parse_llm_response("{ invalid json }", "src/bad.rs", "test-model");
        assert!(result.is_ok()); // Returns empty vec on parse error
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_llm_response_missing_required_fields() {
        let analyzer = create_test_analyzer();
        let json_response = r#"[
            {
                "severity": "high",
                "title": "Missing line number"
            }
        ]"#;

        let result = analyzer.parse_llm_response(json_response, "src/missing.rs", "test-model");
        assert!(result.is_ok());
        // Missing line should result in empty findings
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_llm_response_code_snippet_object() {
        let analyzer = create_test_analyzer();
        let json_response = r#"[
            {
                "severity": "high",
                "title": "SQL Injection",
                "description": "Test",
                "line": 42,
                "code_snippet": {
                    "before": "fn query() {",
                    "code": "db.execute(user_input)",
                    "after": "}"
                }
            }
        ]"#;

        let result = analyzer.parse_llm_response(json_response, "src/snippet.rs", "test-model");
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].code_snippet.is_some());
        let snippet = findings[0].code_snippet.as_ref().unwrap();
        assert!(snippet.contains("before"));
        assert!(snippet.contains("VULNERABLE CODE"));
    }

    #[test]
    fn test_parse_llm_response_statement_range() {
        let analyzer = create_test_analyzer();
        let json_response = r#"[
            {
                "severity": "high",
                "title": "Buffer Overflow",
                "description": "Test",
                "line": 42,
                "statement_range": [40, 45]
            }
        ]"#;

        let result = analyzer.parse_llm_response(json_response, "src/range.rs", "test-model");
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].statement_range, Some((40, 45)));
    }

    #[test]
    fn test_parse_llm_response_severity_mapping() {
        let analyzer = create_test_analyzer();

        let test_cases = vec![
            ("critical", Severity::Critical),
            ("high", Severity::High),
            ("medium", Severity::Medium),
            ("low", Severity::Low),
            ("unknown", Severity::Low), // Default for unknown severities
        ];

        for (severity_str, expected_severity) in test_cases {
            let json_response = format!(
                r#"[{{"severity": "{}", "title": "Test", "description": "Test", "line": 1}}]"#,
                severity_str
            );
            let result = analyzer.parse_llm_response(&json_response, "src/test.rs", "test-model");
            assert!(result.is_ok());
            let findings = result.unwrap();
            assert_eq!(
                findings[0].severity, expected_severity,
                "Failed for severity: {}",
                severity_str
            );
        }
    }
}
