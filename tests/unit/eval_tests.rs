//! Tests for eval module - extracted from inline #[cfg(test)] mod

use baco::eval::{parse_oracle, score_findings, ExpectedFinding, ExpectedSuppressed, OracleFile};
use baco::findings::{Severity, VulnerabilityFinding};

#[test]
fn test_parse_oracle_valid() {
    let json = r#"{
        "target": "py-sqli",
        "description": "SQL injection test",
        "expected_findings": [
            {
                "file_path": "vulnerable.py",
                "line": 15,
                "cwe_id": "CWE-89",
                "class": "SQL Injection"
            }
        ],
        "expected_suppressed": [
            {
                "file_path": "safe_twin.py",
                "reason": "Parameterized query twin"
            }
        ]
    }"#;

    let oracle = parse_oracle(json).unwrap();
    assert_eq!(oracle.target, "py-sqli");
    assert_eq!(oracle.expected_findings.len(), 1);
    assert_eq!(oracle.expected_suppressed.len(), 1);
    assert_eq!(oracle.expected_findings[0].cwe_id, "CWE-89");
}

#[test]
fn test_parse_oracle_invalid_json() {
    let result = parse_oracle("not valid json");
    assert!(result.is_err());
}

#[test]
fn test_parse_oracle_defaults() {
    let json = r#"{"target": "test", "description": "test desc"}"#;
    let oracle = parse_oracle(json).unwrap();
    assert!(oracle.expected_findings.is_empty());
    assert!(oracle.expected_suppressed.is_empty());
}

fn make_test_finding(
    id: &str,
    title: &str,
    file_path: &str,
    line: u32,
    cwe_id: &str,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
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

#[test]
fn test_score_perfect_match() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        expected_suppressed: vec![],
    };

    let findings = vec![make_test_finding(
        "test-1",
        "SQL Injection",
        "vuln.py",
        10,
        "CWE-89",
    )];

    let report = score_findings(&oracle, &findings);
    assert_eq!(report.matched, 1);
    assert_eq!(report.missed.len(), 0);
    assert_eq!(report.false_flags, 0);
    assert_eq!(report.recall, 1.0);
    assert_eq!(report.precision, 1.0);
}

#[test]
fn test_score_line_tolerance() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        expected_suppressed: vec![],
    };

    // Finding at line 14 (within ±5 tolerance)
    let findings = vec![make_test_finding(
        "test-1",
        "SQL Injection",
        "vuln.py",
        14,
        "CWE-89",
    )];

    let report = score_findings(&oracle, &findings);
    assert_eq!(report.matched, 1);
    assert_eq!(report.recall, 1.0);
}

#[test]
fn test_score_line_out_of_tolerance() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        expected_suppressed: vec![],
    };

    // Finding at line 20 (outside ±5 tolerance)
    let findings = vec![make_test_finding(
        "test-1",
        "SQL Injection",
        "vuln.py",
        20,
        "CWE-89",
    )];

    let report = score_findings(&oracle, &findings);
    assert_eq!(report.matched, 0);
    assert_eq!(report.missed.len(), 1);
    assert_eq!(report.recall, 0.0);
}

#[test]
fn test_score_false_flag_on_suppressed() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![],
        expected_suppressed: vec![ExpectedSuppressed {
            file_path: "safe_twin.py".to_string(),
            reason: "Secure twin".to_string(),
        }],
    };

    let findings = vec![make_test_finding(
        "test-1",
        "False Positive",
        "safe_twin.py",
        5,
        "CWE-89",
    )];

    let report = score_findings(&oracle, &findings);
    assert_eq!(report.false_flags, 1);
    assert_eq!(report.precision, 0.0); // matched=0, false_flags=1
}

#[test]
fn test_score_empty_findings() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        expected_suppressed: vec![],
    };

    let findings: Vec<VulnerabilityFinding> = vec![];

    let report = score_findings(&oracle, &findings);
    assert_eq!(report.matched, 0);
    assert_eq!(report.missed.len(), 1);
    assert_eq!(report.recall, 0.0);
}

#[test]
fn test_score_cwe_mismatch() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        expected_suppressed: vec![],
    };

    // Finding with wrong CWE
    let findings = vec![make_test_finding(
        "test-1",
        "Buffer Overflow",
        "vuln.py",
        10,
        "CWE-120",
    )];

    let report = score_findings(&oracle, &findings);
    assert_eq!(report.matched, 0);
    assert_eq!(report.recall, 0.0);
}

#[test]
fn test_score_multiple_expected() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![
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
        expected_suppressed: vec![],
    };

    // Only match first expected
    let findings = vec![make_test_finding(
        "test-1",
        "SQL Injection",
        "vuln.py",
        10,
        "CWE-89",
    )];

    let report = score_findings(&oracle, &findings);
    assert_eq!(report.expected, 2);
    assert_eq!(report.matched, 1);
    assert_eq!(report.missed.len(), 1);
    assert_eq!(report.recall, 0.5);
    assert_eq!(report.precision, 1.0);
}
// ============================================================================
// F1 Score and Precision/Recall Math Tests
// ============================================================================

#[test]
fn test_f1_symmetric_property() {
    // F1 should be symmetric - swapping precision/recall gives same F1
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![
            ExpectedFinding {
                file_path: "vuln.py".to_string(),
                line: 10,
                cwe_id: "CWE-89".to_string(),
                class: "SQLi".to_string(),
            },
            ExpectedFinding {
                file_path: "vuln.py".to_string(),
                line: 20,
                cwe_id: "CWE-78".to_string(),
                class: "OSi".to_string(),
            },
        ],
        expected_suppressed: vec![],
    };

    // Match 1 of 2 expected, no false flags
    let findings = vec![make_test_finding(
        "test-1",
        "SQL Injection",
        "vuln.py",
        10,
        "CWE-89",
    )];
    let report = score_findings(&oracle, &findings);

    let precision = report.precision;
    let recall = report.recall;

    // F1 = 2 * P * R / (P + R)
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };

    assert!((f1 - 0.666).abs() < 0.01); // Approximately 2/3
}

#[test]
fn test_precision_calculation_no_false_flags() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        expected_suppressed: vec![],
    };

    let findings = vec![make_test_finding(
        "test-1",
        "SQL Injection",
        "vuln.py",
        10,
        "CWE-89",
    )];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.precision, 1.0); // 1 matched / (1 matched + 0 false flags)
}

#[test]
fn test_recall_calculation_partial_match() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![
            ExpectedFinding {
                file_path: "vuln.py".to_string(),
                line: 10,
                cwe_id: "CWE-89".to_string(),
                class: "SQLi".to_string(),
            },
            ExpectedFinding {
                file_path: "vuln.py".to_string(),
                line: 20,
                cwe_id: "CWE-78".to_string(),
                class: "OSi".to_string(),
            },
            ExpectedFinding {
                file_path: "vuln.py".to_string(),
                line: 30,
                cwe_id: "CWE-22".to_string(),
                class: "Path Traversal".to_string(),
            },
        ],
        expected_suppressed: vec![],
    };

    // Match 2 of 3
    let findings = vec![
        make_test_finding("test-1", "SQL Injection", "vuln.py", 10, "CWE-89"),
        make_test_finding("test-2", "OS Injection", "vuln.py", 20, "CWE-78"),
    ];

    let report = score_findings(&oracle, &findings);
    assert_eq!(report.recall, 2.0 / 3.0);
}

#[test]
fn test_empty_expected_handling() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![],
        expected_suppressed: vec![],
    };

    let findings = vec![make_test_finding(
        "test-1", "Random", "vuln.py", 10, "CWE-89",
    )];
    let report = score_findings(&oracle, &findings);

    // When nothing is expected, recall = 1.0 by definition
    assert_eq!(report.recall, 1.0);
    assert_eq!(report.expected, 0);
    assert_eq!(report.matched, 0);
}

#[test]
fn test_all_suppressed_empty_findings() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![],
        expected_suppressed: vec![
            ExpectedSuppressed {
                file_path: "safe1.py".to_string(),
                reason: "Secure".to_string(),
            },
            ExpectedSuppressed {
                file_path: "safe2.py".to_string(),
                reason: "Also secure".to_string(),
            },
        ],
    };

    let findings: Vec<VulnerabilityFinding> = vec![];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.false_flags, 0);
    assert_eq!(report.precision, 1.0); // No false flags
}

// ============================================================================
// Line Tolerance Edge Cases
// ============================================================================

#[test]
fn test_line_tolerance_exactly_minus_five() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        expected_suppressed: vec![],
    };

    // Finding at line 5 (exactly -5)
    let findings = vec![make_test_finding(
        "test-1",
        "SQL Injection",
        "vuln.py",
        5,
        "CWE-89",
    )];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.matched, 1);
    assert_eq!(report.recall, 1.0);
}

#[test]
fn test_line_tolerance_exactly_plus_five() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        expected_suppressed: vec![],
    };

    // Finding at line 15 (exactly +5)
    let findings = vec![make_test_finding(
        "test-1",
        "SQL Injection",
        "vuln.py",
        15,
        "CWE-89",
    )];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.matched, 1);
    assert_eq!(report.recall, 1.0);
}

#[test]
fn test_line_tolerance_minus_six() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        expected_suppressed: vec![],
    };

    // Finding at line 4 (outside tolerance: -6)
    let findings = vec![make_test_finding(
        "test-1",
        "SQL Injection",
        "vuln.py",
        4,
        "CWE-89",
    )];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.matched, 0);
    assert_eq!(report.recall, 0.0);
}

#[test]
fn test_line_tolerance_plus_six() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        expected_suppressed: vec![],
    };

    // Finding at line 16 (outside tolerance: +6)
    let findings = vec![make_test_finding(
        "test-1",
        "SQL Injection",
        "vuln.py",
        16,
        "CWE-89",
    )];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.matched, 0);
    assert_eq!(report.recall, 0.0);
}

#[test]
fn test_line_tolerance_zero_offset() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        expected_suppressed: vec![],
    };

    // Finding at exact line 10
    let findings = vec![make_test_finding(
        "test-1",
        "SQL Injection",
        "vuln.py",
        10,
        "CWE-89",
    )];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.matched, 1);
    assert_eq!(report.recall, 1.0);
}

// ============================================================================
// File Path Matching Tests
// ============================================================================

#[test]
fn test_file_path_must_match_exactly() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "src/vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        expected_suppressed: vec![],
    };

    // Finding in different file
    let findings = vec![make_test_finding(
        "test-1",
        "SQL Injection",
        "lib/vuln.py",
        10,
        "CWE-89",
    )];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.matched, 0);
    assert_eq!(report.recall, 0.0);
}

#[test]
fn test_cwe_id_case_sensitive() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        expected_suppressed: vec![],
    };

    // Finding with different CWE
    let findings = vec![make_test_finding(
        "test-1",
        "Buffer Overflow",
        "vuln.py",
        10,
        "CWE-120",
    )];
    let report = score_findings(&oracle, &findings);

    assert_eq!(report.matched, 0);
}

// ============================================================================
// Multiple Expected Findings Tests
// ============================================================================

#[test]
fn test_multiple_expected_all_matched() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![
            ExpectedFinding {
                file_path: "vuln.py".to_string(),
                line: 10,
                cwe_id: "CWE-89".to_string(),
                class: "SQLi".to_string(),
            },
            ExpectedFinding {
                file_path: "vuln.py".to_string(),
                line: 20,
                cwe_id: "CWE-78".to_string(),
                class: "OSi".to_string(),
            },
            ExpectedFinding {
                file_path: "vuln.py".to_string(),
                line: 30,
                cwe_id: "CWE-22".to_string(),
                class: "Path Traversal".to_string(),
            },
        ],
        expected_suppressed: vec![],
    };

    let findings = vec![
        make_test_finding("test-1", "SQL Injection", "vuln.py", 10, "CWE-89"),
        make_test_finding("test-2", "OS Injection", "vuln.py", 20, "CWE-78"),
        make_test_finding("test-3", "Path Traversal", "vuln.py", 30, "CWE-22"),
    ];

    let report = score_findings(&oracle, &findings);
    assert_eq!(report.expected, 3);
    assert_eq!(report.matched, 3);
    assert_eq!(report.recall, 1.0);
    assert_eq!(report.precision, 1.0);
}

#[test]
fn test_multiple_expected_with_false_flags() {
    let oracle = OracleFile {
        target: "test".to_string(),
        description: "test".to_string(),
        expected_findings: vec![ExpectedFinding {
            file_path: "vuln.py".to_string(),
            line: 10,
            cwe_id: "CWE-89".to_string(),
            class: "SQLi".to_string(),
        }],
        expected_suppressed: vec![ExpectedSuppressed {
            file_path: "safe.py".to_string(),
            reason: "Secure".to_string(),
        }],
    };

    let findings = vec![
        make_test_finding("test-1", "SQL Injection", "vuln.py", 10, "CWE-89"),
        make_test_finding("test-2", "False Positive", "safe.py", 5, "CWE-89"),
    ];

    let report = score_findings(&oracle, &findings);
    assert_eq!(report.matched, 1);
    assert_eq!(report.false_flags, 1);
    // Precision = matched / (matched + false_flags) = 1 / 2 = 0.5
    assert_eq!(report.precision, 0.5);
}
