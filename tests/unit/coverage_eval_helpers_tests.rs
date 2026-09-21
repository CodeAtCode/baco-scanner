// Coverage tests: eval + llm_phases helpers

use baco::eval::{eval_floor, parse_oracle, score_findings, ExpectedFinding, ExpectedSuppressed, OracleFile};
use baco::findings::VulnerabilityFinding;
use baco::scanner::phases::llm_phases::{detect_language, extract_function_name_from_finding};
use std::path::Path;

// ============================================================================
// detect_language tests
// ============================================================================

#[test]
fn detect_language_rust_file() {
    let path = Path::new("src/main.rs");
    let lang = detect_language(path);
    assert!(matches!(lang, baco::context::control_path::Language::Rust));
}

#[test]
fn detect_language_python_file() {
    let path = Path::new("tests/test_utils.py");
    let lang = detect_language(path);
    assert!(matches!(lang, baco::context::control_path::Language::Python));
}

#[test]
fn detect_language_c_file() {
    let path = Path::new("src/util.c");
    let lang = detect_language(path);
    assert!(matches!(lang, baco::context::control_path::Language::C));
}

#[test]
fn detect_language_header_file() {
    let path = Path::new("include/header.h");
    let lang = detect_language(path);
    assert!(matches!(lang, baco::context::control_path::Language::C));
}

#[test]
fn detect_language_unknown_extension() {
    let path = Path::new("data/config.xyz");
    let lang = detect_language(path);
    assert!(matches!(lang, baco::context::control_path::Language::C));
}

#[test]
fn detect_language_no_extension() {
    let path = Path::new("Makefile");
    let lang = detect_language(path);
    assert!(matches!(lang, baco::context::control_path::Language::C));
}

#[test]
fn detect_language_uppercase_extension() {
    let path = Path::new("src/MAIN.RS");
    let lang = detect_language(path);
    assert!(matches!(lang, baco::context::control_path::Language::C));
}

#[test]
fn detect_language_javascript_file() {
    let path = Path::new("app.js");
    let lang = detect_language(path);
    assert!(matches!(lang, baco::context::control_path::Language::JavaScript));
}

#[test]
fn detect_language_typescript_file() {
    let path = Path::new("src/app.ts");
    let lang = detect_language(path);
    assert!(matches!(lang, baco::context::control_path::Language::JavaScript));
}

// ============================================================================
// extract_function_name_from_finding tests
// ============================================================================

#[test]
fn extract_function_name_rust_fn() {
    let finding = VulnerabilityFinding {
        title: "Buffer overflow risk".to_string(),
        cwe_id: Some("CWE-120".to_string()),
        line_number: Some(42),
        file_path: "src/main.rs".to_string(),
        code_snippet: Some("fn process_data(input: &str) {".to_string()),
        severity: None,
        description: None,
        remediation: None,
        chain_id: None,
    };
    let name = extract_function_name_from_finding(&finding);
    assert_eq!(name, Some("process_data".to_string()));
}

#[test]
fn extract_function_name_python_def() {
    let finding = VulnerabilityFinding {
        title: "SQL injection".to_string(),
        cwe_id: Some("CWE-89".to_string()),
        line_number: Some(15),
        file_path: "app.py".to_string(),
        code_snippet: Some("def execute_query(user_input):".to_string()),
        severity: None,
        description: None,
        remediation: None,
        chain_id: None,
    };
    let name = extract_function_name_from_finding(&finding);
    assert_eq!(name, Some("execute_query".to_string()));
}

#[test]
fn extract_function_name_javascript_function() {
    let finding = VulnerabilityFinding {
        title: "XSS vulnerability".to_string(),
        cwe_id: Some("CWE-79".to_string()),
        line_number: Some(100),
        file_path: "app.js".to_string(),
        code_snippet: Some("function handleRequest(req, res) {".to_string()),
        severity: None,
        description: None,
        remediation: None,
        chain_id: None,
    };
    let name = extract_function_name_from_finding(&finding);
    assert_eq!(name, Some("handleRequest".to_string()));
}

#[test]
fn extract_function_name_no_context() {
    let finding = VulnerabilityFinding {
        title: "Potential buffer overflow".to_string(),
        cwe_id: Some("CWE-120".to_string()),
        line_number: Some(42),
        file_path: "src/main.rs".to_string(),
        code_snippet: None,
        severity: None,
        description: None,
        remediation: None,
        chain_id: None,
    };
    let name = extract_function_name_from_finding(&finding);
    assert_eq!(name, None);
}

#[test]
fn extract_function_name_empty_context() {
    let finding = VulnerabilityFinding {
        title: "Security issue".to_string(),
        cwe_id: Some("CWE-120".to_string()),
        line_number: Some(42),
        file_path: "src/main.rs".to_string(),
        code_snippet: Some("".to_string()),
        severity: None,
        description: None,
        remediation: None,
        chain_id: None,
    };
    let name = extract_function_name_from_finding(&finding);
    assert_eq!(name, None);
}

#[test]
fn extract_function_name_filters_keywords() {
    let finding = VulnerabilityFinding {
        title: "Control flow issue".to_string(),
        cwe_id: Some("CWE-120".to_string()),
        line_number: Some(42),
        file_path: "src/main.rs".to_string(),
        code_snippet: Some("if (condition) { do_something(); }".to_string()),
        severity: None,
        description: None,
        remediation: None,
        chain_id: None,
    };
    let name = extract_function_name_from_finding(&finding);
    // Should skip "if" and find "do_something"
    assert_eq!(name, Some("do_something".to_string()));
}

// ============================================================================
// parse_oracle tests
// ============================================================================

#[test]
fn parse_oracle_valid_json() {
    let json = r#"{
        "target": "test_target",
        "description": "Test oracle",
        "expected_findings": [
            {
                "file_path": "src/vuln.c",
                "line": 42,
                "cwe_id": "CWE-120",
                "class": "Buffer Overflow"
            }
        ],
        "expected_suppressed": []
    }"#;
    let oracle = parse_oracle(json);
    assert!(oracle.is_ok());
    let oracle = oracle.unwrap();
    assert_eq!(oracle.target, "test_target");
    assert_eq!(oracle.expected_findings.len(), 1);
}

#[test]
fn parse_oracle_malformed_json() {
    let json = r#"{ invalid json }"#;
    let result = parse_oracle(json);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Failed to parse"));
}

#[test]
fn parse_oracle_empty_string() {
    let result = parse_oracle("");
    assert!(result.is_err());
}

#[test]
fn parse_oracle_missing_fields_defaults() {
    let json = r#"{
        "target": "test_target",
        "description": "Test"
    }"#;
    let oracle = parse_oracle(json).unwrap();
    assert!(oracle.expected_findings.is_empty());
    assert!(oracle.expected_suppressed.is_empty());
}

// ============================================================================
// eval_floor tests
// ============================================================================

#[test]
fn eval_floor_valid_config() {
    std::env::remove_var("BACO_EVAL_FLOOR");
    let result = eval_floor(0.75);
    assert!(result.is_ok());
    let (floor, source) = result.unwrap();
    assert_eq!(floor, 0.75);
    assert_eq!(source, "eval.floor");
}

#[test]
fn eval_floor_env_override() {
    std::env::set_var("BACO_EVAL_FLOOR", "0.85");
    let result = eval_floor(0.75);
    assert!(result.is_ok());
    let (floor, source) = result.unwrap();
    assert_eq!(floor, 0.85);
    assert_eq!(source, "BACO_EVAL_FLOOR");
    std::env::remove_var("BACO_EVAL_FLOOR");
}

#[test]
fn eval_floor_invalid_env() {
    std::env::set_var("BACO_EVAL_FLOOR", "invalid");
    let result = eval_floor(0.75);
    assert!(result.is_err());
    std::env::remove_var("BACO_EVAL_FLOOR");
}

#[test]
fn eval_floor_out_of_range() {
    let result = eval_floor(1.5);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("must be between 0.0 and 1.0"));
}

#[test]
fn eval_floor_zero_valid() {
    let result = eval_floor(0.0);
    assert!(result.is_ok());
}

#[test]
fn eval_floor_one_valid() {
    let result = eval_floor(1.0);
    assert!(result.is_ok());
}

// ============================================================================
// score_findings tests
// ============================================================================

#[test]
fn score_findings_perfect_match() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "Test oracle".to_string(),
        expected_findings: vec![
            ExpectedFinding {
                file_path: "src/vuln.c".to_string(),
                line: 42,
                cwe_id: "CWE-120".to_string(),
                class: "Buffer Overflow".to_string(),
            }
        ],
        expected_suppressed: vec![],
    };
    let findings = vec![
        VulnerabilityFinding {
            title: "Buffer overflow".to_string(),
            cwe_id: Some("CWE-120".to_string()),
            line_number: Some(42),
            file_path: "src/vuln.c".to_string(),
            code_snippet: None,
            severity: None,
            description: None,
            remediation: None,
            chain_id: None,
        }
    ];
    let report = score_findings(&oracle, &findings);
    assert_eq!(report.expected, 1);
    assert_eq!(report.matched, 1);
    assert_eq!(report.recall, 1.0);
    assert_eq!(report.precision, 1.0);
}

#[test]
fn score_findings_missed_finding() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "Test oracle".to_string(),
        expected_findings: vec![
            ExpectedFinding {
                file_path: "src/vuln.c".to_string(),
                line: 42,
                cwe_id: "CWE-120".to_string(),
                class: "Buffer Overflow".to_string(),
            }
        ],
        expected_suppressed: vec![],
    };
    let findings: Vec<VulnerabilityFinding> = vec![];
    let report = score_findings(&oracle, &findings);
    assert_eq!(report.expected, 1);
    assert_eq!(report.matched, 0);
    assert_eq!(report.recall, 0.0);
    assert_eq!(report.precision, 1.0);
}

#[test]
fn score_findings_false_flag() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "Test oracle".to_string(),
        expected_findings: vec![],
        expected_suppressed: vec![
            ExpectedSuppressed {
                file_path: "src/safe.c".to_string(),
                reason: "Input validated".to_string(),
            }
        ],
    };
    let findings = vec![
        VulnerabilityFinding {
            title: "False positive".to_string(),
            cwe_id: Some("CWE-120".to_string()),
            line_number: Some(10),
            file_path: "src/safe.c".to_string(),
            code_snippet: None,
            severity: None,
            description: None,
            remediation: None,
            chain_id: None,
        }
    ];
    let report = score_findings(&oracle, &findings);
    assert_eq!(report.expected, 0);
    assert_eq!(report.matched, 0);
    assert_eq!(report.false_flags, 1);
}

#[test]
fn score_findings_line_tolerance() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "Test oracle".to_string(),
        expected_findings: vec![
            ExpectedFinding {
                file_path: "src/vuln.c".to_string(),
                line: 42,
                cwe_id: "CWE-120".to_string(),
                class: "Buffer Overflow".to_string(),
            }
        ],
        expected_suppressed: vec![],
    };
    let findings = vec![
        VulnerabilityFinding {
            title: "Buffer overflow".to_string(),
            cwe_id: Some("CWE-120".to_string()),
            line_number: Some(45), // Within ±5
            file_path: "src/vuln.c".to_string(),
            code_snippet: None,
            severity: None,
            description: None,
            remediation: None,
            chain_id: None,
        }
    ];
    let report = score_findings(&oracle, &findings);
    assert_eq!(report.matched, 1);
}

#[test]
fn score_findings_line_outside_tolerance() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "Test oracle".to_string(),
        expected_findings: vec![
            ExpectedFinding {
                file_path: "src/vuln.c".to_string(),
                line: 42,
                cwe_id: "CWE-120".to_string(),
                class: "Buffer Overflow".to_string(),
            }
        ],
        expected_suppressed: vec![],
    };
    let findings = vec![
        VulnerabilityFinding {
            title: "Buffer overflow".to_string(),
            cwe_id: Some("CWE-120".to_string()),
            line_number: Some(50), // Outside ±5
            file_path: "src/vuln.c".to_string(),
            code_snippet: None,
            severity: None,
            description: None,
            remediation: None,
            chain_id: None,
        }
    ];
    let report = score_findings(&oracle, &findings);
    assert_eq!(report.matched, 0);
}

#[test]
fn score_findings_cwe_mismatch() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "Test oracle".to_string(),
        expected_findings: vec![
            ExpectedFinding {
                file_path: "src/vuln.c".to_string(),
                line: 42,
                cwe_id: "CWE-120".to_string(),
                class: "Buffer Overflow".to_string(),
            }
        ],
        expected_suppressed: vec![],
    };
    let findings = vec![
        VulnerabilityFinding {
            title: "Different vuln".to_string(),
            cwe_id: Some("CWE-79".to_string()), // Different CWE
            line_number: Some(42),
            file_path: "src/vuln.c".to_string(),
            code_snippet: None,
            severity: None,
            description: None,
            remediation: None,
            chain_id: None,
        }
    ];
    let report = score_findings(&oracle, &findings);
    assert_eq!(report.matched, 0);
}