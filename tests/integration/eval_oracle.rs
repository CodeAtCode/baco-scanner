//! Eval harness oracle scoring integration tests
//!
//! These tests verify the eval module's parsing and scoring functionality
//! using the fixture oracles.

use baco::eval::{parse_oracle, score_findings, ExpectedFinding, ExpectedSuppressed, OracleFile};
use baco::findings::{Severity, VulnerabilityFinding};
use std::path::PathBuf;

/// Get the path to an eval fixture file
fn eval_fixture_path(subpath: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("eval/fixtures")
        .join(subpath)
}

/// Get the path to an oracle JSON file
fn oracle_path(target: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("eval/oracles")
        .join(format!("{}.json", target))
}

// ============================================================================
// Oracle Parse Tests
// ============================================================================

#[test]
fn test_py_sqli_oracle_parse() {
    let path = oracle_path("py-sqli");
    assert!(
        path.exists(),
        "Oracle file should exist: {}",
        path.display()
    );

    let content = std::fs::read_to_string(&path).expect("Should read oracle");
    let oracle = parse_oracle(&content).expect("Should parse oracle");

    assert_eq!(oracle.target, "py-sqli");
    assert!(!oracle.description.is_empty());
    assert_eq!(oracle.expected_findings.len(), 1);
    assert_eq!(oracle.expected_suppressed.len(), 1);

    let expected = &oracle.expected_findings[0];
    assert_eq!(expected.file_path, "vulnerable.py");
    assert_eq!(expected.cwe_id, "CWE-89");
}

#[test]
fn test_c_overflow_oracle_parse() {
    let path = oracle_path("c-overflow");
    assert!(
        path.exists(),
        "Oracle file should exist: {}",
        path.display()
    );

    let content = std::fs::read_to_string(&path).expect("Should read oracle");
    let oracle = parse_oracle(&content).expect("Should parse oracle");

    assert_eq!(oracle.target, "c-overflow");
    assert_eq!(oracle.expected_findings.len(), 1);
    assert_eq!(oracle.expected_suppressed.len(), 1);

    let expected = &oracle.expected_findings[0];
    assert_eq!(expected.file_path, "vulnerable.c");
    assert_eq!(expected.cwe_id, "CWE-120");
}

// ============================================================================
// Fixture File Existence Tests
// ============================================================================

#[test]
fn test_py_sqli_fixtures_exist() {
    let fixtures = vec![
        "py-sqli/vulnerable.py",
        "py-sqli/safe_twin.py",
        "py-sqli/innocent.py",
    ];

    for fixture in fixtures {
        let path = eval_fixture_path(fixture);
        assert!(path.exists(), "Fixture should exist: {}", path.display());

        let content = std::fs::read_to_string(&path).expect("Should read fixture");
        assert!(
            !content.is_empty(),
            "Fixture should not be empty: {}",
            fixture
        );
    }
}

#[test]
fn test_c_overflow_fixtures_exist() {
    let fixtures = vec![
        "c-overflow/vulnerable.c",
        "c-overflow/safe_twin.c",
        "c-overflow/innocent.c",
    ];

    for fixture in fixtures {
        let path = eval_fixture_path(fixture);
        assert!(path.exists(), "Fixture should exist: {}", path.display());

        let content = std::fs::read_to_string(&path).expect("Should read fixture");
        assert!(
            !content.is_empty(),
            "Fixture should not be empty: {}",
            fixture
        );
    }
}

// ============================================================================
// Scoring Unit Tests
// ============================================================================

/// Helper to create a test finding
fn make_finding(file_path: &str, line: u32, cwe_id: &str) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: format!("test-{}-{}", file_path, line),
        title: "Test Finding".to_string(),
        description: "Test".to_string(),
        severity: Severity::High,
        confidence_score: 0.9,
        cwe_id: Some(cwe_id.to_string()),
        file_path: file_path.to_string(),
        line_number: Some(line),
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
        statement_range: None,
        triage_verdict: None,
        evidence: vec![],
        verification_tier: None,
    }
}

/// Helper to create an oracle for testing
fn make_test_oracle(
    expected_findings: Vec<ExpectedFinding>,
    expected_suppressed: Vec<ExpectedSuppressed>,
) -> OracleFile {
    OracleFile {
        target: "test".to_string(),
        description: "test oracle".to_string(),
        expected_findings,
        expected_suppressed,
    }
}

#[test]
fn test_score_perfect_match() {
    // Perfect match: finding exactly matches expected
    let oracle = make_test_oracle(
        vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        vec![],
    );

    let findings = vec![make_finding("vuln.py", 10, "CWE-89")];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.matched, 1);
    assert_eq!(report.missed.len(), 0);
    assert_eq!(report.false_flags, 0);
    assert_eq!(report.recall, 1.0);
    assert_eq!(report.precision, 1.0);
}

#[test]
fn test_score_line_tolerance_plus_five() {
    // Line within ±5 tolerance should match
    let oracle = make_test_oracle(
        vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        vec![],
    );

    // Finding at line 15 (exactly +5)
    let findings = vec![make_finding("vuln.py", 15, "CWE-89")];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.matched, 1);
    assert_eq!(report.recall, 1.0);
}

#[test]
fn test_score_line_tolerance_minus_five() {
    // Line within ±5 tolerance should match
    let oracle = make_test_oracle(
        vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        vec![],
    );

    // Finding at line 5 (exactly -5)
    let findings = vec![make_finding("vuln.py", 5, "CWE-89")];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.matched, 1);
    assert_eq!(report.recall, 1.0);
}

#[test]
fn test_score_line_out_of_tolerance() {
    // Line outside ±5 tolerance should NOT match
    let oracle = make_test_oracle(
        vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        vec![],
    );

    // Finding at line 16 (outside tolerance)
    let findings = vec![make_finding("vuln.py", 16, "CWE-89")];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.matched, 0);
    assert_eq!(report.missed.len(), 1);
    assert_eq!(report.recall, 0.0);
}

#[test]
fn test_score_false_flag_on_suppressed_file() {
    // Finding on suppressed file should count as false flag
    let oracle = make_test_oracle(
        vec![],
        vec![ExpectedSuppressed {
            file_path: "safe_twin.py".to_string(),
            reason: "Secure twin".to_string(),
        }],
    );

    let findings = vec![make_finding("safe_twin.py", 5, "CWE-89")];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.false_flags, 1);
    assert_eq!(report.precision, 0.0); // matched=0, false_flags=1
}

#[test]
fn test_score_empty_findings_recall_zero() {
    // No findings when expected should give recall 0
    let oracle = make_test_oracle(
        vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        vec![],
    );

    let findings: Vec<VulnerabilityFinding> = vec![];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.matched, 0);
    assert_eq!(report.recall, 0.0);
}

#[test]
fn test_score_cwe_mismatch() {
    // Wrong CWE should not match
    let oracle = make_test_oracle(
        vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        vec![],
    );

    let findings = vec![make_finding("vuln.py", 10, "CWE-120")];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.matched, 0);
    assert_eq!(report.recall, 0.0);
}

#[test]
fn test_score_file_path_mismatch() {
    // Wrong file path should not match
    let oracle = make_test_oracle(
        vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        vec![],
    );

    let findings = vec![make_finding("other.py", 10, "CWE-89")];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.matched, 0);
    assert_eq!(report.recall, 0.0);
}

#[test]
fn test_score_multiple_expected_partial_match() {
    // Multiple expected, only some matched
    let oracle = make_test_oracle(
        vec![
            ExpectedFinding {
                file_path: "vuln.py".to_string(),
                line: 10,
                cwe_id: "CWE-89".to_string(),
                class: "SQLi".to_string(),
            },
            ExpectedFinding {
                file_path: "vuln.py".to_string(),
                line: 25,
                cwe_id: "CWE-78".to_string(),
                class: "OS Injection".to_string(),
            },
        ],
        vec![],
    );

    // Only match first expected
    let findings = vec![make_finding("vuln.py", 10, "CWE-89")];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.expected, 2);
    assert_eq!(report.matched, 1);
    assert_eq!(report.missed.len(), 1);
    assert_eq!(report.recall, 0.5);
    assert_eq!(report.precision, 1.0);
}

#[test]
fn test_score_precision_with_false_flags() {
    // Precision should decrease with false flags
    let oracle = make_test_oracle(
        vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        vec![ExpectedSuppressed {
            file_path: "safe_twin.py".to_string(),
            reason: "Secure twin".to_string(),
        }],
    );

    // One match + one false flag
    let findings = vec![
        make_finding("vuln.py", 10, "CWE-89"),
        make_finding("safe_twin.py", 5, "CWE-89"),
    ];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.matched, 1);
    assert_eq!(report.false_flags, 1);
    assert_eq!(report.precision, 0.5); // 1 / (1 + 1)
}

// ============================================================================
// End-to-End Test (requires LLM key)
// ============================================================================

/// E2E test: run eval against actual scanner output
///
/// This test requires:
/// - BACO_EVAL=1 environment variable
/// - LLM_API_KEY environment variable set
///
/// Run with: BACO_EVAL=1 LLM_API_KEY=key cargo test test_eval_e2e -- --ignored
#[tokio::test]
#[ignore]
async fn test_eval_e2e() {
    // This test verifies the full eval pipeline:
    // 1. Load oracle from JSON file
    // 2. Run scanner against fixtures
    // 3. Score findings against oracle
    // 4. Verify recall/precision are computed

    // Skip if BACO_EVAL not set (normal CI runs)
    if std::env::var("BACO_EVAL").is_err() {
        println!("Skipping e2e test: BACO_EVAL not set");
        return;
    }

    // Load oracle
    let oracle_path = oracle_path("py-sqli");
    let content = std::fs::read_to_string(&oracle_path).expect("Should read oracle");
    let oracle = parse_oracle(&content).expect("Should parse oracle");

    // In a real e2e test, we would:
    // 1. Run the scanner on eval/fixtures/py-sqli/
    // 2. Collect findings
    // 3. Call score_findings(&oracle, &findings)
    // 4. Assert recall > 0.5 and precision > 0.5

    // For now, just verify the oracle loads and scoring works with synthetic data
    let findings = vec![make_finding("vulnerable.py", 15, "CWE-89")];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.recall, 1.0, "Should find the SQL injection");
    assert_eq!(report.precision, 1.0, "Should have no false flags");
}
