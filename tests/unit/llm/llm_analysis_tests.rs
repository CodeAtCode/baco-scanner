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
            enable_llm_cache: false,
            cache_dir: None,
            max_concurrent: 3,
            pricing: Default::default(),
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
        // Missing line defaults to 1 instead of dropping the finding
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line_number, Some(1));
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
            ("unknown", Severity::Medium), // Unknown severity strings map to Medium
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

// ============================================================================
// Truncate Code Tests
// ============================================================================

#[cfg(test)]
mod truncate_code_tests {
    use baco::llm::LlmClient;
    use baco::llm::LlmConfig;
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
            enable_llm_cache: false,
            cache_dir: None,
            max_concurrent: 3,
            pricing: Default::default(),
        };
        let client = LlmClient::new(config);
        LlmAnalyzer::new(client, vec!["rust".to_string()], 1024, &Default::default())
    }

    #[test]
    fn test_truncate_code_under_budget() {
        let analyzer = create_test_analyzer();
        let code = "fn main() { println!(\"hello\"); }";

        let result = analyzer.truncate_code(code);

        // Code under 8000 bytes should be returned unchanged
        assert_eq!(result, code);
        assert!(!result.contains("[truncated"));
    }

    #[test]
    fn test_truncate_code_exact_budget() {
        let analyzer = create_test_analyzer();
        // Create code exactly 8000 bytes
        let code = "x".repeat(8000);

        let result = analyzer.truncate_code(&code);

        // Should be returned unchanged (at the boundary)
        assert_eq!(result.len(), 8000);
        assert!(!result.contains("[truncated"));
    }

    #[test]
    fn test_truncate_code_over_budget() {
        let analyzer = create_test_analyzer();
        // Create code over 8000 bytes
        let code = "y".repeat(10000);

        let result = analyzer.truncate_code(&code);

        // Should be truncated with notice
        assert!(result.contains("[truncated"));
        assert!(result.contains("omitted]"));
        // Total should be under budget (content + notice)
        assert!(result.len() <= 8000);
    }

    #[test]
    fn test_truncate_code_preserves_start() {
        let analyzer = create_test_analyzer();
        let prefix = "IMPORTANT_PREFIX_CODE";
        let code = format!("{}{}", prefix, "z".repeat(10000));

        let result = analyzer.truncate_code(&code);

        // Start of code should be preserved
        assert!(result.starts_with(prefix));
    }

    #[test]
    fn test_truncate_code_multi_byte_chars() {
        let analyzer = create_test_analyzer();
        // Unicode multi-byte characters (emoji, etc.)
        let code = "Hello \u{1F600}".repeat(2000); // 2000 emojis = ~10000 bytes

        let result = analyzer.truncate_code(&code);

        // Should handle multi-byte chars correctly (no invalid UTF-8)
        assert!(result.is_ascii() || result.chars().all(|c| c.is_ascii() || c == '\u{1F600}'));
        assert!(result.len() <= 8000);
    }

    #[test]
    fn test_truncate_code_omitted_count() {
        let analyzer = create_test_analyzer();
        let code = "a".repeat(10000);

        let result = analyzer.truncate_code(&code);

        // Should report approximately 2000 chars omitted (8000 budget - notice)
        assert!(result.contains("[truncated -"));
        assert!(result.contains("chars omitted]"));
    }
}

// ============================================================================
// Language for Extension Tests
// ============================================================================

#[cfg(test)]
mod language_for_extension_tests {
    use baco::llm_analysis::LlmAnalyzer;

    #[test]
    fn test_language_for_extension_rust() {
        let lang = LlmAnalyzer::language_for_extension("rs");
        // Rust has a bundled tree-sitter grammar
        assert!(lang.is_some());
        assert_eq!(lang.unwrap(), "rust");
    }

    #[test]
    fn test_language_for_extension_c() {
        let lang = LlmAnalyzer::language_for_extension("c");
        // C has a bundled tree-sitter grammar
        assert!(lang.is_some());
        assert_eq!(lang.unwrap(), "c");
    }

    #[test]
    fn test_language_for_extension_cpp() {
        let lang = LlmAnalyzer::language_for_extension("cpp");
        // C++ has a bundled tree-sitter grammar
        assert!(lang.is_some());
        assert_eq!(lang.unwrap(), "cpp");
    }

    #[test]
    fn test_language_for_extension_go() {
        // Go is indexed via the unified extension map but has no bundled
        // tree-sitter grammar, so the chunker-facing lookup returns None
        let lang = LlmAnalyzer::language_for_extension("go");
        assert!(lang.is_none());
    }

    #[test]
    fn test_language_for_extension_java() {
        // Java is indexed via the unified extension map but has no bundled
        // tree-sitter grammar, so the chunker-facing lookup returns None
        let lang = LlmAnalyzer::language_for_extension("java");
        assert!(lang.is_none());
    }

    #[test]
    fn test_language_for_extension_unknown() {
        let lang = LlmAnalyzer::language_for_extension("unknown_ext_xyz");
        // Unknown extension should return None
        assert!(lang.is_none());
    }

    #[test]
    fn test_language_for_extension_case_insensitive() {
        let lang_upper = LlmAnalyzer::language_for_extension("RS");
        let lang_lower = LlmAnalyzer::language_for_extension("rs");

        // Should be case-insensitive
        assert_eq!(lang_upper, lang_lower);
        assert!(lang_upper.is_some());
    }
}
#[test]
fn chunk_file_with_ranges_groups_rust_functions() {
    let code = "fn alpha() {\n    let a = 1;\n}\nfn beta() {\n    let b = 2;\n}\n";
    let chunks = baco::llm_analysis::LlmAnalyzer::chunk_file_with_ranges(code, "rust", 1024);
    assert!(!chunks.is_empty());
    let all_text = chunks
        .iter()
        .map(|c| c.text.clone())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(all_text.contains("fn alpha"));
    assert!(all_text.contains("fn beta"));
    for chunk in &chunks {
        assert!(chunk.end_line >= chunk.start_line);
    }
}

#[test]
fn chunk_file_with_ranges_unknown_language_empty() {
    let chunks =
        baco::llm_analysis::LlmAnalyzer::chunk_file_with_ranges("x = 1\n", "klingon", 1024);
    assert!(chunks.is_empty());
}
#[test]
fn map_chunk_line_absolute_relative_and_clamped() {
    use baco::llm_analysis::map_chunk_line;
    assert_eq!(map_chunk_line(15, 10, 20), 15);
    assert_eq!(map_chunk_line(3, 10, 20), 12);
    assert_eq!(map_chunk_line(99, 10, 20), 10);
    assert_eq!(map_chunk_line(0, 10, 20), 10);
}
#[tokio::test]
async fn analyze_file_chunked_path_with_mockito() {
    let mut server = mockito::Server::new_async().await;
    let _mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"choices": [{"message": {"content": "[{\"severity\": \"high\", \"title\": \"X\", \"description\": \"d\", \"line\": 1, \"cwe_id\": \"CWE-79\"}]"}}]}"#,
        )
        .create();

    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("big.rs");
    let body = (0..60)
        .map(|i| format!("fn f{i}() {{\n    let x{i} = {i};\n}}\n"))
        .collect::<Vec<_>>()
        .join("");
    std::fs::write(&path, &body).unwrap();

    let llm_config = baco::llm::LlmConfig {
        base_url: server.url(),
        api_key: "test".to_string(),
        model: "m".to_string(),
        models: vec![],
        timeout: 5,
        max_retries: 0,
        retry_backoff_ms: 0,
        temperature: 0.5,
        max_reasoning_tokens: None,
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 3,
        pricing: Default::default(),
    };
    let client = baco::llm::LlmClient::new(llm_config);
    let scanner_config = baco::config::ScannerConfig::default();
    let analyzer = baco::llm_analysis::LlmAnalyzer::new(
        client,
        vec!["rust".to_string()],
        100,
        &scanner_config,
    );
    let findings = analyzer.analyze_file(&path).await.unwrap();
    assert!(
        !findings.is_empty(),
        "chunked analysis should report mocked findings"
    );
}
#[tokio::test]
async fn analyze_file_llm_error_yields_empty() {
    let mut server = mockito::Server::new_async().await;
    let _mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(500)
        .with_body("internal error")
        .create();

    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("small.rs");
    std::fs::write(&path, "fn a() {}\n").unwrap();

    let llm_config = baco::llm::LlmConfig {
        base_url: server.url(),
        api_key: "test".to_string(),
        model: "m".to_string(),
        models: vec![],
        timeout: 5,
        max_retries: 0,
        retry_backoff_ms: 0,
        temperature: 0.5,
        max_reasoning_tokens: None,
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 3,
        pricing: Default::default(),
    };
    let client = baco::llm::LlmClient::new(llm_config);
    let scanner_config = baco::config::ScannerConfig::default();
    let analyzer = baco::llm_analysis::LlmAnalyzer::new(
        client,
        vec!["rust".to_string()],
        1024,
        &scanner_config,
    );
    let findings = analyzer.analyze_file(&path).await.unwrap();
    assert!(findings.is_empty());
}
#[tokio::test]
async fn analyze_file_structured_output_path_with_mockito() {
    let mut server = mockito::Server::new_async().await;
    let _mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"choices": [{"message": {"content": "{\"findings\": [{\"severity\": \"high\", \"title\": \"X\", \"description\": \"d\", \"line\": 1, \"cwe_id\": \"CWE-79\"}]}"}}]}"#,
        )
        .create();

    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("s.rs");
    std::fs::write(&path, "fn a() {}\n").unwrap();

    let llm_config = baco::llm::LlmConfig {
        base_url: server.url(),
        api_key: "test".to_string(),
        model: "m".to_string(),
        models: vec![],
        timeout: 5,
        max_retries: 0,
        retry_backoff_ms: 0,
        temperature: 0.5,
        max_reasoning_tokens: None,
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 3,
        pricing: Default::default(),
    };
    let client = baco::llm::LlmClient::new(llm_config);
    let scanner_config = baco::config::ScannerConfig::default();
    let analyzer = baco::llm_analysis::LlmAnalyzer::new(
        client,
        vec!["rust".to_string()],
        1024,
        &scanner_config,
    )
    .with_structured_output(true);
    let findings = analyzer.analyze_file(&path).await.unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "X");
}
