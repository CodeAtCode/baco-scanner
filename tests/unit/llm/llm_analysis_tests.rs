//! Tests for LLM analysis functionality
//!
//! Covers: generate_recommendation, generate_poc_code, generate_mitigation_code,
//! extract_cwe_id, parse_llm_response, truncate_code

use baco::llm_analysis::{
    extract_cwe_id, generate_mitigation_code, generate_poc_code, generate_recommendation,
};

#[test]
fn test_generate_recommendation_sql_injection() {
    let rec = generate_recommendation(
        "SQL Injection",
        "Potential SQL injection vulnerability detected",
    );

    assert!(rec.contains("parameterized"));
    assert!(rec.contains("prepared statements"));
}

#[test]
fn test_generate_recommendation_command_injection() {
    let rec = generate_recommendation(
        "Command Injection",
        "Shell command execution with user input",
    );

    assert!(rec.contains("shell"));
    assert!(rec.contains("safe"));
}

#[test]
fn test_generate_recommendation_xss() {
    let rec = generate_recommendation("XSS", "Cross-site scripting vulnerability");

    assert!(rec.contains("Escape"));
    assert!(rec.contains("encoding"));
}

#[test]
fn test_generate_recommendation_buffer_overflow() {
    let rec = generate_recommendation("Buffer Overflow", "Potential buffer overflow");

    assert!(rec.contains("bounds"));
    assert!(rec.contains("Validate"));
}

#[test]
fn test_generate_recommendation_use_after_free() {
    let rec = generate_recommendation("Use After Free", "UAF vulnerability");

    assert!(rec.contains("smart"));
    assert!(rec.contains("nullification"));
}

#[test]
fn test_generate_recommendation_null_dereference() {
    let rec = generate_recommendation("Null Dereference", "Potential null pointer dereference");

    assert!(rec.contains("null"));
    assert!(rec.contains("Option"));
}

#[test]
fn test_generate_recommendation_format_string() {
    let rec = generate_recommendation("Format String", "Format string vulnerability");

    assert!(rec.contains("format"));
    assert!(rec.contains("format string"));
}

#[test]
fn test_generate_recommendation_user_input() {
    let rec = generate_recommendation("Generic", "User input not validated");

    assert!(rec.contains("Validate"));
    assert!(rec.contains("sanitize"));
}

#[test]
fn test_generate_recommendation_untrusted() {
    let rec = generate_recommendation("Generic", "Processing untrusted data");

    assert!(rec.contains("untrusted"));
    assert!(rec.contains("strict"));
}

#[test]
fn test_generate_recommendation_unknown() {
    let rec = generate_recommendation("Unknown Vulnerability", "Some description");

    assert!(rec.contains("Unknown Vulnerability"));
    assert!(rec.contains("secure coding"));
}

#[test]
fn test_generate_poc_code_buffer_overflow() {
    let poc = generate_poc_code("Buffer Overflow", "src/vuln.c", 42);

    assert!(poc.is_some());
    let poc_str = poc.unwrap();
    assert!(poc_str.contains("Buffer overflow"));
    assert!(poc_str.contains("src/vuln.c"));
    assert!(poc_str.contains("42"));
    assert!(poc_str.contains("vulnerable_copy"));
}

#[test]
fn test_generate_poc_code_use_after_free() {
    let poc = generate_poc_code("Use After Free", "src/uaf.c", 100);

    assert!(poc.is_some());
    let poc_str = poc.unwrap();
    assert!(poc_str.contains("Use-after-free"));
    assert!(poc_str.contains("src/uaf.c"));
    assert!(poc_str.contains("100"));
    assert!(poc_str.contains("free"));
}

#[test]
fn test_generate_poc_code_double_free() {
    let poc = generate_poc_code("Double Free", "src/double_free.c", 50);

    assert!(poc.is_some());
    let poc_str = poc.unwrap();
    assert!(poc_str.contains("Double-free"));
    assert!(poc_str.contains("src/double_free.c"));
    assert!(poc_str.contains("50"));
}

#[test]
fn test_generate_poc_code_format_string() {
    let poc = generate_poc_code("Format String", "src/format.c", 25);

    assert!(poc.is_some());
    let poc_str = poc.unwrap();
    assert!(poc_str.contains("Format string"));
    assert!(poc_str.contains("src/format.c"));
    assert!(poc_str.contains("25"));
}

#[test]
fn test_generate_poc_code_unknown_vulnerability() {
    let poc = generate_poc_code("Unknown Vuln", "src/unknown.c", 1);

    assert!(poc.is_none());
}

#[test]
fn test_generate_mitigation_code_buffer_overflow() {
    let mitigation = generate_mitigation_code("Buffer Overflow", "src/vuln.c", 42);

    assert!(mitigation.is_some());
    let mitigation_str = mitigation.unwrap();
    assert!(mitigation_str.contains("Mitigation"));
    assert!(mitigation_str.contains("bounds-checked"));
    assert!(mitigation_str.contains("strncpy"));
}

#[test]
fn test_generate_mitigation_code_use_after_free() {
    let mitigation = generate_mitigation_code("Use After Free", "src/uaf.c", 100);

    assert!(mitigation.is_some());
    let mitigation_str = mitigation.unwrap();
    assert!(mitigation_str.contains("Nullify"));
    assert!(mitigation_str.contains("NULL"));
}

#[test]
fn test_generate_mitigation_code_double_free() {
    let mitigation = generate_mitigation_code("Double Free", "src/double_free.c", 50);

    assert!(mitigation.is_some());
    let mitigation_str = mitigation.unwrap();
    assert!(mitigation_str.contains("Track"));
    assert!(mitigation_str.contains("is_allocated"));
}

#[test]
fn test_generate_mitigation_code_format_string() {
    let mitigation = generate_mitigation_code("Format String", "src/format.c", 25);

    assert!(mitigation.is_some());
    let mitigation_str = mitigation.unwrap();
    assert!(mitigation_str.contains("fixed"));
    assert!(mitigation_str.contains("printf"));
}

#[test]
fn test_generate_mitigation_code_unknown_vulnerability() {
    let mitigation = generate_mitigation_code("Unknown Vuln", "src/unknown.c", 1);

    assert!(mitigation.is_none());
}

#[test]
fn test_extract_cwe_id_basic() {
    assert_eq!(
        extract_cwe_id("This is CWE-611 vulnerability"),
        Some("CWE-611".to_string())
    );
    assert_eq!(
        extract_cwe_id("Path traversal CWE-22 here"),
        Some("CWE-22".to_string())
    );
    assert_eq!(extract_cwe_id("No CWE mentioned"), None);
    assert_eq!(extract_cwe_id(""), None);
}

#[test]
fn test_extract_cwe_id_multiple() {
    // Should extract first match
    assert_eq!(
        extract_cwe_id("CWE-123 and CWE-456"),
        Some("CWE-123".to_string())
    );
}

#[test]
fn test_extract_cwe_id_case_sensitivity() {
    assert_eq!(extract_cwe_id("cwe-123"), None); // lowercase doesn't match
    assert_eq!(extract_cwe_id("CWE-123"), Some("CWE-123".to_string()));
}

#[test]
fn test_truncate_code_no_truncation_needed() {
    use baco::llm::{LlmClient, LlmConfig};
    use baco::llm_analysis::LlmAnalyzer;

    let config = LlmConfig::default();
    let client = LlmClient::new(config);
    let scanner_config = baco::config::ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let short_code = "fn main() {}";
    let result = analyzer.truncate_code(short_code);

    assert_eq!(result, short_code);
    assert!(!result.contains("[truncated"));
}

#[test]
fn test_truncate_code_requires_truncation() {
    use baco::llm::{LlmClient, LlmConfig};
    use baco::llm_analysis::LlmAnalyzer;

    let config = LlmConfig::default();
    let client = LlmClient::new(config);
    let scanner_config = baco::config::ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let long_code = "A".repeat(10000);
    let result = analyzer.truncate_code(&long_code);

    assert!(result.len() <= 8000);
    assert!(result.contains("[truncated"));
    assert!(result.contains("chars omitted"));
}

#[test]
fn test_truncate_code_exact_boundary() {
    use baco::llm::{LlmClient, LlmConfig};
    use baco::llm_analysis::LlmAnalyzer;

    let config = LlmConfig::default();
    let client = LlmClient::new(config);
    let scanner_config = baco::config::ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let exact_code = "A".repeat(8000);
    let result = analyzer.truncate_code(&exact_code);

    assert_eq!(result.len(), 8000);
    assert!(!result.contains("[truncated"));
}

#[tokio::test]
async fn test_analyzer_should_analyze_extensions() {
    use baco::llm::{LlmClient, LlmConfig};
    use baco::llm_analysis::LlmAnalyzer;
    use std::path::Path;

    let config = LlmConfig::default();
    let client = LlmClient::new(config);
    let scanner_config = baco::config::ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(
        client,
        vec!["c".to_string(), "python".to_string(), "rust".to_string()],
        512,
        &scanner_config,
    );

    assert!(analyzer.should_analyze(Path::new("test.c")));
    assert!(analyzer.should_analyze(Path::new("test.h")));
    assert!(analyzer.should_analyze(Path::new("test.py")));
    assert!(analyzer.should_analyze(Path::new("test.rs")));
    assert!(analyzer.should_analyze(Path::new("test.go")));
    assert!(analyzer.should_analyze(Path::new("test.java")));
    assert!(analyzer.should_analyze(Path::new("test.js")));
    assert!(analyzer.should_analyze(Path::new("test.ts")));

    assert!(!analyzer.should_analyze(Path::new("test.md")));
    assert!(!analyzer.should_analyze(Path::new("test.txt")));
}

#[tokio::test]
async fn test_analyzer_read_file_content() {
    use baco::llm::{LlmClient, LlmConfig};
    use baco::llm_analysis::LlmAnalyzer;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let config = LlmConfig::default();
    let client = LlmClient::new(config);
    let scanner_config = baco::config::ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(
        client,
        vec!["c".to_string()],
        1, // 1KB max
        &scanner_config,
    );

    // Create temp file with content
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"fn main() {}").unwrap();

    let result = analyzer.read_file_content(temp_file.path());
    assert!(result.is_some());
    assert_eq!(result.unwrap(), "fn main() {}");
}

#[tokio::test]
async fn test_analyzer_read_file_too_large() {
    use baco::llm::{LlmClient, LlmConfig};
    use baco::llm_analysis::LlmAnalyzer;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let config = LlmConfig::default();
    let client = LlmClient::new(config);
    let scanner_config = baco::config::ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(
        client,
        vec!["c".to_string()],
        1, // 1KB max
        &scanner_config,
    );

    // Create temp file with large content
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&vec![b'A'; 2000]).unwrap();

    let result = analyzer.read_file_content(temp_file.path());
    assert!(result.is_none()); // File too large
}

#[tokio::test]
async fn test_analyzer_read_file_nonexistent() {
    use baco::llm::{LlmClient, LlmConfig};
    use baco::llm_analysis::LlmAnalyzer;
    use std::path::Path;

    let config = LlmConfig::default();
    let client = LlmClient::new(config);
    let scanner_config = baco::config::ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["c".to_string()], 512, &scanner_config);

    let result = analyzer.read_file_content(Path::new("/nonexistent/file.c"));
    assert!(result.is_none());
}
