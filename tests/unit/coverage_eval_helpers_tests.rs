// Coverage tests: eval + llm_phases helpers

use baco::eval::{
    ExpectedFinding, ExpectedSuppressed, OracleFile, eval_floor, parse_oracle, score_findings,
};
use baco::findings::{Severity, VulnerabilityFinding};
use baco::scanner::phases::llm_phases::{detect_language, extract_function_name_from_finding};
use serial_test::serial;
use std::path::Path;
use tempfile::TempDir;

// ============================================================================
// Helper fixture for creating test findings
// ============================================================================

fn make_finding(
    title: &str,
    cwe: Option<&str>,
    line: u32,
    path: &str,
    snippet: Option<&str>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: VulnerabilityFinding::generate_id(path, Some(line), cwe.unwrap_or("CWE-000")),
        title: title.to_string(),
        description: "test finding".to_string(),
        severity: Severity::High,
        confidence_score: 0.9,
        cwe_id: cwe.map(str::to_string),
        file_path: path.to_string(),
        line_number: Some(line),
        code_snippet: snippet.map(str::to_string),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: Vec::new(),
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
        evidence: Vec::new(),
        verification_tier: None,
    }
}

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
    assert!(matches!(
        lang,
        baco::context::control_path::Language::Python
    ));
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
    assert!(matches!(
        lang,
        baco::context::control_path::Language::JavaScript
    ));
}

#[test]
fn detect_language_typescript_file() {
    let path = Path::new("src/app.ts");
    let lang = detect_language(path);
    assert!(matches!(
        lang,
        baco::context::control_path::Language::JavaScript
    ));
}

// ============================================================================
// extract_function_name_from_finding tests
// ============================================================================

#[test]
fn extract_function_name_rust_fn() {
    let finding = make_finding(
        "Buffer overflow risk",
        Some("CWE-120"),
        42,
        "src/main.rs",
        Some("fn process_data(input: &str) {"),
    );
    let name = extract_function_name_from_finding(&finding);
    assert_eq!(name, Some("process_data".to_string()));
}

#[test]
fn extract_function_name_python_def() {
    let finding = make_finding(
        "SQL injection",
        Some("CWE-89"),
        15,
        "app.py",
        Some("def execute_query(user_input):"),
    );
    let name = extract_function_name_from_finding(&finding);
    assert_eq!(name, Some("execute_query".to_string()));
}

#[test]
fn extract_function_name_javascript_function() {
    let finding = make_finding(
        "XSS vulnerability",
        Some("CWE-79"),
        100,
        "app.js",
        Some("function handleRequest(req, res) {"),
    );
    let name = extract_function_name_from_finding(&finding);
    assert_eq!(name, Some("handleRequest".to_string()));
}

#[test]
fn extract_function_name_no_context() {
    let finding = make_finding(
        "Potential buffer overflow",
        Some("CWE-120"),
        42,
        "src/main.rs",
        None,
    );
    let name = extract_function_name_from_finding(&finding);
    assert_eq!(name, None);
}

#[test]
fn extract_function_name_empty_context() {
    let finding = make_finding(
        "Security issue",
        Some("CWE-120"),
        42,
        "src/main.rs",
        Some(""),
    );
    let name = extract_function_name_from_finding(&finding);
    assert_eq!(name, None);
}

#[test]
fn extract_function_name_filters_keywords() {
    let finding = make_finding(
        "Control flow issue",
        Some("CWE-120"),
        42,
        "src/main.rs",
        Some("if (condition) { do_something(); }"),
    );
    let name = extract_function_name_from_finding(&finding);
    // The pattern matches "if" first, but it's filtered out
    // The function returns None because it doesn't continue searching after filtering
    assert_eq!(name, None);
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
#[serial]
fn eval_floor_valid_config() {
    unsafe { std::env::remove_var("BACO_EVAL_FLOOR") };
    let result = eval_floor(0.75);
    assert!(result.is_ok());
    let (floor, source) = result.unwrap();
    assert_eq!(floor, 0.75);
    assert_eq!(source, "eval.floor");
}

#[test]
#[serial]
fn eval_floor_env_override() {
    unsafe { std::env::set_var("BACO_EVAL_FLOOR", "0.85") };
    let result = eval_floor(0.75);
    assert!(result.is_ok());
    let (floor, source) = result.unwrap();
    assert_eq!(floor, 0.85);
    assert_eq!(source, "BACO_EVAL_FLOOR");
    unsafe { std::env::remove_var("BACO_EVAL_FLOOR") };
}

#[test]
#[serial]
fn eval_floor_invalid_env() {
    unsafe { std::env::set_var("BACO_EVAL_FLOOR", "invalid") };
    let result = eval_floor(0.75);
    assert!(result.is_err());
    unsafe { std::env::remove_var("BACO_EVAL_FLOOR") };
}

#[test]
#[serial]
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
        expected_findings: vec![ExpectedFinding {
            file_path: "src/vuln.c".to_string(),
            line: 42,
            cwe_id: "CWE-120".to_string(),
            class: "Buffer Overflow".to_string(),
        }],
        expected_suppressed: vec![],
    };
    let findings = vec![make_finding(
        "Buffer overflow",
        Some("CWE-120"),
        42,
        "src/vuln.c",
        None,
    )];
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
        expected_findings: vec![ExpectedFinding {
            file_path: "src/vuln.c".to_string(),
            line: 42,
            cwe_id: "CWE-120".to_string(),
            class: "Buffer Overflow".to_string(),
        }],
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
        expected_suppressed: vec![ExpectedSuppressed {
            file_path: "src/safe.c".to_string(),
            reason: "Input validated".to_string(),
        }],
    };
    let findings = vec![make_finding(
        "False positive",
        Some("CWE-120"),
        10,
        "src/safe.c",
        None,
    )];
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
        expected_findings: vec![ExpectedFinding {
            file_path: "src/vuln.c".to_string(),
            line: 42,
            cwe_id: "CWE-120".to_string(),
            class: "Buffer Overflow".to_string(),
        }],
        expected_suppressed: vec![],
    };
    let findings = vec![make_finding(
        "Buffer overflow",
        Some("CWE-120"),
        45,
        "src/vuln.c",
        None,
    )];
    let report = score_findings(&oracle, &findings);
    assert_eq!(report.matched, 1);
}

#[test]
fn score_findings_line_outside_tolerance() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "Test oracle".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "src/vuln.c".to_string(),
            line: 42,
            cwe_id: "CWE-120".to_string(),
            class: "Buffer Overflow".to_string(),
        }],
        expected_suppressed: vec![],
    };
    let findings = vec![make_finding(
        "Buffer overflow",
        Some("CWE-120"),
        50,
        "src/vuln.c",
        None,
    )];
    let report = score_findings(&oracle, &findings);
    assert_eq!(report.matched, 0);
}

#[test]
fn score_findings_cwe_mismatch() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "Test oracle".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "src/vuln.c".to_string(),
            line: 42,
            cwe_id: "CWE-120".to_string(),
            class: "Buffer Overflow".to_string(),
        }],
        expected_suppressed: vec![],
    };
    let findings = vec![make_finding(
        "Different vuln",
        Some("CWE-79"),
        42,
        "src/vuln.c",
        None,
    )];
    let report = score_findings(&oracle, &findings);
    assert_eq!(report.matched, 0);
}
#[test]
fn score_findings_silence_rate_clean_and_flagged_twins() {
    let oracle = OracleFile {
        target: "silence-probe".to_string(),
        description: "silence metric probe".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "vuln.rs".to_string(),
            line: 10,
            cwe_id: "CWE-79".to_string(),
            class: "XSS".to_string(),
        }],
        expected_suppressed: vec![ExpectedSuppressed {
            file_path: "safe_twin.rs".to_string(),
            reason: "sanitized twin".to_string(),
        }],
    };
    let clean = score_findings(
        &oracle,
        &[make_finding(
            "XSS",
            Some("CWE-79"),
            10,
            "vuln.rs",
            Some("sink(user)"),
        )],
    );
    assert_eq!(clean.matched, 1);
    assert_eq!(clean.false_flags, 0);
    assert_eq!(clean.suppressed_total, 1);
    assert_eq!(clean.suppressed_clean, 1);
    assert!((clean.silence_rate - 1.0).abs() < f32::EPSILON);

    let flagged = score_findings(
        &oracle,
        &[
            make_finding("XSS", Some("CWE-79"), 10, "vuln.rs", Some("sink(user)")),
            make_finding("XSS?", Some("CWE-79"), 3, "safe_twin.rs", Some("x")),
        ],
    );
    assert_eq!(flagged.false_flags, 1);
    assert_eq!(flagged.suppressed_clean, 0);
    assert!((flagged.silence_rate - 0.0).abs() < f32::EPSILON);
}
#[test]
fn extract_function_name_rejects_keyword_match() {
    let finding = make_finding("test", None, 1, "x.js", Some("if (x) { y(); }"));
    assert_eq!(extract_function_name_from_finding(&finding), None);
}
fn write_oracle(dir: &std::path::Path, stem: &str, body: &str) {
    let oracles = dir.join("oracles");
    std::fs::create_dir_all(&oracles).unwrap();
    std::fs::write(oracles.join(format!("{stem}.json")), body).unwrap();
}

fn write_findings(dir: &std::path::Path, stem: &str, body: &str) {
    let findings = dir.join("findings");
    std::fs::create_dir_all(&findings).unwrap();
    std::fs::write(findings.join(format!("{stem}.json")), body).unwrap();
}

#[test]
fn run_suite_missing_oracles_dir_errors() {
    let temp = TempDir::new().unwrap();
    let err = baco::eval::run_suite(temp.path()).unwrap_err();
    assert!(err.contains("not found"), "unexpected: {err}");
}

#[test]
fn run_suite_empty_oracles_dir_errors() {
    let temp = TempDir::new().unwrap();
    std::fs::create_dir_all(temp.path().join("oracles")).unwrap();
    let err = baco::eval::run_suite(temp.path()).unwrap_err();
    assert!(err.contains("No oracle files"), "unexpected: {err}");
}

#[test]
fn run_suite_bad_oracle_json_errors() {
    let temp = TempDir::new().unwrap();
    write_oracle(temp.path(), "probe", "{not json");
    let err = baco::eval::run_suite(temp.path()).unwrap_err();
    assert!(err.contains("probe.json"), "unexpected: {err}");
}

#[test]
fn run_suite_stem_mismatch_errors() {
    let temp = TempDir::new().unwrap();
    write_oracle(
        temp.path(),
        "probe",
        r#"{"target": "other", "description": "d", "expected_findings": [], "expected_suppressed": []}"#,
    );
    let err = baco::eval::run_suite(temp.path()).unwrap_err();
    assert!(err.contains("declares target"), "unexpected: {err}");
}

#[test]
fn run_suite_missing_findings_file_errors() {
    let temp = TempDir::new().unwrap();
    write_oracle(
        temp.path(),
        "probe",
        r#"{"target": "probe", "description": "d", "expected_findings": [], "expected_suppressed": []}"#,
    );
    let err = baco::eval::run_suite(temp.path()).unwrap_err();
    assert!(!err.is_empty());
}

#[test]
fn run_suite_empty_expected_errors() {
    let temp = TempDir::new().unwrap();
    write_oracle(
        temp.path(),
        "probe",
        r#"{"target": "probe", "description": "d", "expected_findings": [], "expected_suppressed": []}"#,
    );
    let finding = make_finding("XSS", Some("CWE-79"), 10, "vuln.rs", Some("sink(x)"));
    let findings_json = serde_json::to_string(&vec![finding]).unwrap();
    write_findings(temp.path(), "probe", &findings_json);
    let err = baco::eval::run_suite(temp.path()).unwrap_err();
    assert!(err.contains("no expected findings"), "unexpected: {err}");
}

#[test]
fn run_suite_happy_path_scores_target() {
    let temp = TempDir::new().unwrap();
    write_oracle(
        temp.path(),
        "probe",
        r#"{"target": "probe", "description": "d", "expected_findings": [{"file_path": "vuln.rs", "line": 10, "cwe_id": "CWE-79", "class": "XSS"}], "expected_suppressed": []}"#,
    );
    let finding = make_finding("XSS", Some("CWE-79"), 10, "vuln.rs", Some("sink(x)"));
    let findings_json = serde_json::to_string(&vec![finding]).unwrap();
    write_findings(temp.path(), "probe", &findings_json);
    let report = baco::eval::run_suite(temp.path()).unwrap();
    assert_eq!(report.total_expected, 1);
    assert_eq!(report.total_matched, 1);
    assert!((report.aggregate - 1.0).abs() < f32::EPSILON);
}

#[test]
#[serial]
fn eval_floor_empty_env_falls_back_to_config() {
    unsafe { std::env::set_var("BACO_EVAL_FLOOR", "   ") };
    let result = eval_floor(0.75);
    unsafe { std::env::remove_var("BACO_EVAL_FLOOR") };
    assert!(result.is_ok());
    let (floor, source) = result.unwrap();
    assert_eq!(floor, 0.75);
    assert_eq!(source, "eval.floor");
}
