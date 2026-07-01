//! Unit tests for LLM analysis functionality
//!
//! Tests cover: CWE extraction, recommendation generation, PoC/mitigation code
//! generation, LLM response parsing, and analyzer behavior.

use baco::llm_analysis::{
    extract_cwe_id, generate_recommendation, generate_poc_code, generate_mitigation_code,
    LlmAnalyzer
};
use baco::llm::LlmConfig;
use baco::config::ScannerConfig;
use std::path::Path;

// ============================================================================
// CWE Extraction Tests
// ============================================================================

#[test]
fn test_extract_cwe_id_basic() {
    assert_eq!(
        extract_cwe_id("This is CWE-611 vulnerability"),
        Some("CWE-611".to_string())
    );
}

#[test]
fn test_extract_cwe_id_in_sentence() {
    assert_eq!(
        extract_cwe_id("XXE attack CWE-611 in XML parser"),
        Some("CWE-611".to_string())
    );
}

#[test]
fn test_extract_cwe_id_various_numbers() {
    assert_eq!(extract_cwe_id("Path traversal CWE-22 vulnerability"), Some("CWE-22".to_string()));
    assert_eq!(extract_cwe_id("SQL injection CWE-89 detected"), Some("CWE-89".to_string()));
    assert_eq!(extract_cwe_id("Buffer overflow CWE-119"), Some("CWE-119".to_string()));
}

#[test]
fn test_extract_cwe_id_no_match() {
    assert_eq!(extract_cwe_id("No CWE mentioned here"), None);
    assert_eq!(extract_cwe_id(""), None);
    assert_eq!(extract_cwe_id("Just some text"), None);
}

// ============================================================================
// Recommendation Generation Tests
// ============================================================================

#[test]
fn test_recommendation_sql_injection() {
    let rec = generate_recommendation("SQL Injection", "User input in SQL query");
    assert!(rec.contains("parameterized"));
    assert!(rec.contains("prepared statements"));
}

#[test]
fn test_recommendation_command_injection() {
    let rec = generate_recommendation("Command Injection", "Shell command with user input");
    assert!(rec.contains("shell command"));
    assert!(rec.contains("validate"));
}

#[test]
fn test_recommendation_xss() {
    let rec = generate_recommendation("XSS Vulnerability", "Cross-site scripting");
    assert!(rec.contains("Escape"));
    assert!(rec.contains("encoding"));
}

#[test]
fn test_recommendation_buffer_overflow() {
    let rec = generate_recommendation("Buffer Overflow", "Stack buffer overflow");
    assert!(rec.contains("bounds checking"));
    assert!(rec.contains("Validate input lengths"));
}

#[test]
fn test_recommendation_use_after_free() {
    let rec = generate_recommendation("Use After Free", "UAF vulnerability");
    assert!(rec.contains("smart pointers") || rec.contains("lifetime"));
}

#[test]
fn test_recommendation_null_dereference() {
    let rec = generate_recommendation("Null Pointer Dereference", "Possible null access");
    assert!(rec.contains("Check for null"));
}

#[test]
fn test_recommendation_format_string() {
    let rec = generate_recommendation("Format String Vulnerability", "Unsafe format");
    assert!(rec.contains("format specifiers"));
}

#[test]
fn test_recommendation_generic_user_input() {
    let rec = generate_recommendation("Input Validation", "User input not validated");
    assert!(rec.contains("Validate and sanitize"));
}

#[test]
fn test_recommendation_generic_untrusted() {
    let rec = generate_recommendation("Trust Issue", "Untrusted data processed");
    assert!(rec.contains("Treat all external data as untrusted"));
}

#[test]
fn test_recommendation_fallback() {
    let rec = generate_recommendation("Unknown Issue", "Some generic problem");
    assert!(rec.contains("Review and fix"));
}

// ============================================================================
// PoC Generation Tests
// ============================================================================

#[test]
fn test_poc_buffer_overflow() {
    let poc = generate_poc_code("Buffer Overflow", "test.c", 42).unwrap();
    assert!(poc.contains("PoC: Buffer overflow"));
    assert!(poc.contains("test.c:42"));
    assert!(poc.contains("vulnerable_copy"));
}

#[test]
fn test_poc_use_after_free() {
    let poc = generate_poc_code("Use After Free", "src/main.c", 100).unwrap();
    assert!(poc.contains("PoC: Use-after-free"));
    assert!(poc.contains("src/main.c:100"));
    assert!(poc.contains("malloc"));
    assert!(poc.contains("free"));
}

#[test]
fn test_poc_double_free() {
    let poc = generate_poc_code("Double Free", "heap.c", 25).unwrap();
    assert!(poc.contains("PoC: Double-free"));
    assert!(poc.contains("heap.c:25"));
    assert!(poc.contains("Double free"));
}

#[test]
fn test_poc_format_string() {
    let poc = generate_poc_code("Format String", "fmt.c", 55).unwrap();
    assert!(poc.contains("PoC: Format string"));
    assert!(poc.contains("fmt.c:55"));
    assert!(poc.contains("%s%s%s%s%s%s%n"));
}

#[test]
fn test_poc_sql_injection_none() {
    // PoC not generated for all vulnerability types
    let poc = generate_poc_code("SQL Injection", "db.c", 10);
    assert!(poc.is_none());
}

#[test]
fn test_poc_path_traversal_none() {
    let poc = generate_poc_code("Path Traversal", "file.c", 20);
    assert!(poc.is_none());
}

// ============================================================================
// Mitigation Generation Tests
// ============================================================================

#[test]
fn test_mitigation_buffer_overflow() {
    let mit = generate_mitigation_code("Buffer Overflow", "test.c", 42).unwrap();
    assert!(mit.contains("Mitigation: Use bounds-checked"));
    assert!(mit.contains("test.c:42"));
    assert!(mit.contains("strncpy"));
    assert!(mit.contains("Validate input length"));
}

#[test]
fn test_mitigation_use_after_free() {
    let mit = generate_mitigation_code("Use After Free", "src/main.c", 100).unwrap();
    assert!(mit.contains("Mitigation: Nullify pointer after free"));
    assert!(mit.contains("ptr = NULL"));
}

#[test]
fn test_mitigation_double_free() {
    let mit = generate_mitigation_code("Double Free", "heap.c", 25).unwrap();
    assert!(mit.contains("Mitigation: Track allocation state"));
    assert!(mit.contains("is_allocated"));
}

#[test]
fn test_mitigation_format_string() {
    let mit = generate_mitigation_code("Format String", "fmt.c", 55).unwrap();
    assert!(mit.contains("Mitigation: Use fixed format specifier"));
    assert!(mit.contains("printf(\"%s\""));
}

#[test]
fn test_mitigation_sql_injection_none() {
    let mit = generate_mitigation_code("SQL Injection", "db.c", 10);
    assert!(mit.is_none());
}

// ============================================================================
// LlmAnalyzer File Extension Tests
// ============================================================================

#[test]
fn test_should_analyze_c_file() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    assert!(analyzer.should_analyze(Path::new("test.c")));
    assert!(analyzer.should_analyze(Path::new("test.h")));
    assert!(!analyzer.should_analyze(Path::new("test.py")));
}

#[test]
fn test_should_analyze_cpp_file() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["cpp".to_string()], 512, &scanner_config);

    assert!(analyzer.should_analyze(Path::new("test.cpp")));
    assert!(analyzer.should_analyze(Path::new("test.hpp")));
    assert!(analyzer.should_analyze(Path::new("test.cc")));
    assert!(analyzer.should_analyze(Path::new("test.cxx")));
}

#[test]
fn test_should_analyze_python_file() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["python".to_string()], 512, &scanner_config);

    assert!(analyzer.should_analyze(Path::new("test.py")));
    assert!(analyzer.should_analyze(Path::new("test.pyw")));
    assert!(!analyzer.should_analyze(Path::new("test.js")));
}

#[test]
fn test_should_analyze_javascript_file() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["javascript".to_string()], 512, &scanner_config);

    assert!(analyzer.should_analyze(Path::new("test.js")));
    assert!(analyzer.should_analyze(Path::new("test.jsx")));
}

#[test]
fn test_should_analyze_typescript_file() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["typescript".to_string()], 512, &scanner_config);

    assert!(analyzer.should_analyze(Path::new("test.ts")));
    assert!(analyzer.should_analyze(Path::new("test.tsx")));
}

#[test]
fn test_should_analyze_rust_file() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["rust".to_string()], 512, &scanner_config);

    assert!(analyzer.should_analyze(Path::new("test.rs")));
    assert!(!analyzer.should_analyze(Path::new("test.go")));
}

#[test]
fn test_should_analyze_go_file() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["go".to_string()], 512, &scanner_config);

    assert!(analyzer.should_analyze(Path::new("test.go")));
}

#[test]
fn test_should_analyze_java_file() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["java".to_string()], 512, &scanner_config);

    assert!(analyzer.should_analyze(Path::new("Test.java")));
}

#[test]
fn test_should_analyze_multiple_languages() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(
        client,
        vec!["c".to_string(), "python".to_string()],
        512,
        &scanner_config
    );

    assert!(analyzer.should_analyze(Path::new("test.c")));
    assert!(analyzer.should_analyze(Path::new("test.py")));
    assert!(!analyzer.should_analyze(Path::new("test.rs")));
}

// ============================================================================
// Code Truncation Tests
// ============================================================================

#[test]
fn test_truncate_code_short() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let short_code = "int main() { return 0; }";
    let result = analyzer.truncate_code(short_code);
    assert_eq!(result, short_code);
    assert!(!result.contains("truncated"));
}

#[test]
fn test_truncate_code_long() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    // Create code longer than 8000 chars
    let long_code = "a".repeat(10000);
    let result = analyzer.truncate_code(&long_code);

    assert!(result.contains("truncated"));
    assert!(result.contains("chars omitted"));
    // Result should be around 8000 + suffix length
    assert!(result.len() < 8100);
}

// ============================================================================
// LLM Response Parsing Tests
// ============================================================================

#[test]
fn test_parse_llm_response_simple_json() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = r#"[
        {
            "severity": "critical",
            "title": "XXE Vulnerability",
            "description": "XML External Entity injection CWE-611",
            "line": 65,
            "cwe_id": "CWE-611"
        }
    ]"#;

    let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings.len(), 1);

    let finding = &findings[0];
    assert_eq!(finding.title, "XXE Vulnerability");
    assert_eq!(finding.severity, baco::findings::Severity::Critical);
    assert_eq!(finding.cwe_id, Some("CWE-611".to_string()));
    assert_eq!(finding.line_number, Some(65));
}

#[test]
fn test_parse_llm_response_json_with_code_snippet_object() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = r#"[
        {
            "severity": "high",
            "title": "SQL Injection",
            "description": "SQL injection detected",
            "line": 42,
            "cwe_id": "CWE-89",
            "code_snippet": {
                "before": "old code",
                "code": "vulnerable()",
                "after": "new code"
            }
        }
    ]"#;

    let result = analyzer.parse_llm_response(json_response, "src/db.rs", "test-model");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings.len(), 1);

    let finding = &findings[0];
    assert!(finding.code_snippet.is_some());
    let snippet = finding.code_snippet.as_ref().unwrap();
    assert!(snippet.contains("old code"));
    assert!(snippet.contains("vulnerable()"));
    assert!(snippet.contains("new code"));
    assert!(snippet.contains("Context before"));
    assert!(snippet.contains(">>> VULNERABLE CODE <<<"));
}

#[test]
fn test_parse_llm_response_with_fix_code() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = r#"[
        {
            "severity": "critical",
            "title": "XXE Vulnerability",
            "description": "XML External Entity injection CWE-611",
            "line": 65,
            "cwe_id": "CWE-611",
            "fix_code": "reader = xmlReaderForFile(filename, NULL, XML_PARSE_NOENT | XML_PARSE_NONET);"
        }
    ]"#;

    let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings.len(), 1);

    let finding = &findings[0];
    assert_eq!(finding.diff_hunk, Some("reader = xmlReaderForFile(filename, NULL, XML_PARSE_NOENT | XML_PARSE_NONET);".to_string()));
}

#[test]
fn test_parse_llm_response_without_fix_code_uses_after() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = r#"[
        {
            "severity": "high",
            "title": "Path Traversal",
            "description": "CWE-22 path traversal vulnerability",
            "line": 100,
            "code_snippet": {
                "before": "char *path = input;",
                "code": "open(path, O_RDONLY);",
                "after": "char *validated = validate_path(input); open(validated, O_RDONLY);"
            }
        }
    ]"#;

    let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings.len(), 1);

    let finding = &findings[0];
    assert_eq!(finding.cwe_id, Some("CWE-22".to_string()));
    assert_eq!(finding.diff_hunk, Some("char *validated = validate_path(input); open(validated, O_RDONLY);".to_string()));
}

#[test]
fn test_parse_llm_response_extracts_cwe_from_description() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = r#"[
        {
            "severity": "medium",
            "title": "XSS Vulnerability",
            "description": "Cross-site scripting vulnerability - this is CWE-79 vulnerability",
            "line": 42
        }
    ]"#;

    let result = analyzer.parse_llm_response(json_response, "test.js", "test-model");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings.len(), 1);

    let finding = &findings[0];
    assert_eq!(finding.cwe_id, Some("CWE-79".to_string()));
}

#[test]
fn test_parse_llm_response_empty_code_snippet() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = r#"[
        {
            "severity": "medium",
            "title": "Hardcoded Password",
            "description": "Password hardcoded",
            "line": 15,
            "cwe_id": "CWE-798",
            "fix_code": "Use env vars",
            "code_snippet": {
                "before": "",
                "code": "const PW = \"admin123\";",
                "after": ""
            }
        }
    ]"#;

    let result = analyzer.parse_llm_response(json_response, "src/config.rs", "test-model");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings.len(), 1);

    let finding = &findings[0];
    assert_eq!(finding.diff_hunk, Some("Use env vars".to_string()));
}

#[test]
fn test_parse_llm_response_missing_code_snippet() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = r#"[
        {
            "severity": "low",
            "title": "Unused Variable",
            "description": "Variable not used",
            "line": 8,
            "fix_code": "Remove var"
        }
    ]"#;

    let result = analyzer.parse_llm_response(json_response, "src/main.rs", "test-model");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings.len(), 1);

    let finding = &findings[0];
    assert_eq!(finding.diff_hunk, Some("Remove var".to_string()));
}

#[test]
fn test_parse_llm_response_markdown_fence_json() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = r#"```json
[
    {
        "severity": "high",
        "title": "Test Vulnerability",
        "description": "A test issue",
        "line": 10
    }
]
```"#;

    let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings.len(), 1);
}

#[test]
fn test_parse_llm_response_markdown_fence_plain() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = r#"```
[
    {
        "severity": "medium",
        "title": "Test Issue",
        "description": "Test description",
        "line": 20
    }
]
```"#;

    let result = analyzer.parse_llm_response(json_response, "test.py", "test-model");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings.len(), 1);
}

#[test]
fn test_parse_llm_response_multiple_findings() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = r#"[
        {"severity": "critical", "title": "Issue 1", "description": "Desc 1", "line": 1},
        {"severity": "high", "title": "Issue 2", "description": "Desc 2", "line": 5},
        {"severity": "medium", "title": "Issue 3", "description": "Desc 3", "line": 10},
        {"severity": "low", "title": "Issue 4", "description": "Desc 4", "line": 15}
    ]"#;

    let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings.len(), 4);

    assert_eq!(findings[0].severity, baco::findings::Severity::Critical);
    assert_eq!(findings[1].severity, baco::findings::Severity::High);
    assert_eq!(findings[2].severity, baco::findings::Severity::Medium);
    assert_eq!(findings[3].severity, baco::findings::Severity::Low);
}

#[test]
fn test_parse_llm_response_invalid_json() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = "not valid json";
    let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings.len(), 0);
}

#[test]
fn test_parse_llm_response_missing_required_fields() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    // Missing severity
    let json_response = r#"[{"title": "Test", "description": "Desc", "line": 1}]"#;
    let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);

    // Missing title
    let json_response = r#"[{"severity": "high", "description": "Desc", "line": 1}]"#;
    let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);

    // Missing line
    let json_response = r#"[{"severity": "high", "title": "Test", "description": "Desc"}]"#;
    let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn test_parse_llm_response_model_name_none_when_fallback() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = r#"[
        {"severity": "high", "title": "Test", "description": "Desc", "line": 1}
    ]"#;

    let result = analyzer.parse_llm_response(json_response, "test.c", "fallback");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings[0].llm_model, None);
}

#[test]
fn test_parse_llm_response_model_name_present() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = r#"[
        {"severity": "high", "title": "Test", "description": "Desc", "line": 1}
    ]"#;

    let result = analyzer.parse_llm_response(json_response, "test.c", "gpt-4");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings[0].llm_model, Some("gpt-4".to_string()));
}

#[test]
fn test_parse_llm_response_confidence_score() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = r#"[
        {"severity": "high", "title": "Test", "description": "Desc", "line": 1}
    ]"#;

    let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings[0].confidence_score, 0.7);
}

#[test]
fn test_parse_llm_response_sources_llm_analysis() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = r#"[
        {"severity": "high", "title": "Test", "description": "Desc", "line": 1}
    ]"#;

    let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings[0].sources, vec!["llm_analysis".to_string()]);
}

#[test]
fn test_parse_llm_response_code_location_format() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = r#"[
        {"severity": "high", "title": "Test", "description": "Desc", "line": 42}
    ]"#;

    let result = analyzer.parse_llm_response(json_response, "/path/to/file.c", "test-model");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings[0].code_location, Some("/path/to/file.c:42".to_string()));
}

#[test]
fn test_parse_llm_response_empty_array() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = "[]";
    let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn test_parse_llm_response_empty_description() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = r#"[
        {"severity": "high", "title": "Test", "description": "", "line": 1}
    ]"#;

    let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].description, "");
}

// ============================================================================
// Severity Mapping Tests
// ============================================================================

#[test]
fn test_severity_mapping_critical() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = "[{\"severity\":\"CRITICAL\",\"title\":\"Test\",\"description\":\"Desc\",\"line\":1}]";
    let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
    assert!(result.is_ok());
    assert_eq!(result.unwrap()[0].severity, baco::findings::Severity::Critical);
}

#[test]
fn test_severity_mapping_high() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = "[{\"severity\":\"HIGH\",\"title\":\"Test\",\"description\":\"Desc\",\"line\":1}]";
    let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
    assert!(result.is_ok());
    assert_eq!(result.unwrap()[0].severity, baco::findings::Severity::High);
}

#[test]
fn test_severity_mapping_medium() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = "[{\"severity\":\"MEDIUM\",\"title\":\"Test\",\"description\":\"Desc\",\"line\":1}]";
    let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
    assert!(result.is_ok());
    assert_eq!(result.unwrap()[0].severity, baco::findings::Severity::Medium);
}

#[test]
fn test_severity_mapping_unknown_defaults_low() {
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let json_response = "[{\"severity\":\"UNKNOWN\",\"title\":\"Test\",\"description\":\"Desc\",\"line\":1}]";
    let result = analyzer.parse_llm_response(json_response, "test.c", "test-model");
    assert!(result.is_ok());
    assert_eq!(result.unwrap()[0].severity, baco::findings::Severity::Low);
}
