//! Known-answer oracle scoring for evaluation fixtures.
//!
//! Parses oracle JSON files and scores scan findings against expected/expected-suppressed sets.

use crate::findings::VulnerabilityFinding;
use serde::{Deserialize, Serialize};

/// Expected vulnerability location from an oracle file
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExpectedFinding {
    pub file_path: String,
    pub line: u32,
    pub cwe_id: String,
    pub class: String,
}

/// Expected suppressed finding (secure twin - any finding here is a false flag)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExpectedSuppressed {
    pub file_path: String,
    pub reason: String,
}

/// Oracle file describing expected findings for a test target
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OracleFile {
    pub target: String,
    pub description: String,
    #[serde(default)]
    pub expected_findings: Vec<ExpectedFinding>,
    #[serde(default)]
    pub expected_suppressed: Vec<ExpectedSuppressed>,
}

/// Scoring report comparing findings against oracle expectations
#[derive(Debug, Clone, Serialize)]
pub struct ScoreReport {
    pub target: String,
    pub expected: usize,
    pub matched: usize,
    pub missed: Vec<ExpectedFinding>,
    pub false_flags: usize,
    pub recall: f32,
    pub precision: f32,
}

/// Parse an oracle JSON string into an OracleFile
pub fn parse_oracle(json: &str) -> Result<OracleFile, String> {
    serde_json::from_str(json).map_err(|e| format!("Failed to parse oracle JSON: {}", e))
}

/// Score findings against an oracle, returning a detailed report
pub fn score_findings(oracle: &OracleFile, findings: &[VulnerabilityFinding]) -> ScoreReport {
    let expected_count = oracle.expected_findings.len();
    let mut matched_findings: Vec<bool> = vec![false; expected_count];
    let mut false_flags = 0usize;

    // Check each finding against expected and suppressed lists
    for finding in findings {
        // Check if finding is on a suppressed file (false flag)
        let is_suppressed = oracle
            .expected_suppressed
            .iter()
            .any(|supp| finding.file_path == supp.file_path);

        if is_suppressed {
            false_flags += 1;
            continue;
        }

        // Try to match this finding to an expected finding
        for (idx, expected) in oracle.expected_findings.iter().enumerate() {
            if matched_findings[idx] {
                continue; // Already matched
            }

            // Match criteria: file_path equal AND cwe_id equal AND line within ±5
            let file_match = finding.file_path == expected.file_path;
            let cwe_match = finding
                .cwe_id
                .as_ref()
                .is_some_and(|cwe| cwe == &expected.cwe_id);
            let line_match = finding
                .line_number
                .is_some_and(|line| (line as i32 - expected.line as i32).abs() <= 5);

            if file_match && cwe_match && line_match {
                matched_findings[idx] = true;
            }
        }
    }

    let matched = matched_findings.iter().filter(|&&m| m).count();
    let missed: Vec<ExpectedFinding> = oracle
        .expected_findings
        .iter()
        .enumerate()
        .filter(|&(idx, _)| !matched_findings[idx])
        .map(|(_, e)| e.clone())
        .collect();

    // Calculate metrics
    let recall = if expected_count > 0 {
        matched as f32 / expected_count as f32
    } else {
        1.0
    };

    let precision_denom = matched + false_flags;
    let precision = if precision_denom > 0 {
        matched as f32 / precision_denom as f32
    } else {
        1.0
    };

    ScoreReport {
        target: oracle.target.clone(),
        expected: expected_count,
        matched,
        missed,
        false_flags,
        recall,
        precision,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let findings = vec![VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "SQL Injection".to_string(),
            description: "Test".to_string(),
            severity: crate::findings::Severity::High,
            confidence_score: 0.9,
            cwe_id: Some("CWE-89".to_string()),
            file_path: "vuln.py".to_string(),
            line_number: Some(10),
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
        }];

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
        let findings = vec![VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "SQL Injection".to_string(),
            description: "Test".to_string(),
            severity: crate::findings::Severity::High,
            confidence_score: 0.9,
            cwe_id: Some("CWE-89".to_string()),
            file_path: "vuln.py".to_string(),
            line_number: Some(14),
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
        }];

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
        let findings = vec![VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "SQL Injection".to_string(),
            description: "Test".to_string(),
            severity: crate::findings::Severity::High,
            confidence_score: 0.9,
            cwe_id: Some("CWE-89".to_string()),
            file_path: "vuln.py".to_string(),
            line_number: Some(20),
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
        }];

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

        let findings = vec![VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "False Positive".to_string(),
            description: "Test".to_string(),
            severity: crate::findings::Severity::Medium,
            confidence_score: 0.5,
            cwe_id: Some("CWE-89".to_string()),
            file_path: "safe_twin.py".to_string(),
            line_number: Some(5),
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
        }];

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
        let findings = vec![VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "Buffer Overflow".to_string(),
            description: "Test".to_string(),
            severity: crate::findings::Severity::High,
            confidence_score: 0.9,
            cwe_id: Some("CWE-120".to_string()),
            file_path: "vuln.py".to_string(),
            line_number: Some(10),
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
        }];

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
        let findings = vec![VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "SQL Injection".to_string(),
            description: "Test".to_string(),
            severity: crate::findings::Severity::High,
            confidence_score: 0.9,
            cwe_id: Some("CWE-89".to_string()),
            file_path: "vuln.py".to_string(),
            line_number: Some(10),
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
        }];

        let report = score_findings(&oracle, &findings);
        assert_eq!(report.expected, 2);
        assert_eq!(report.matched, 1);
        assert_eq!(report.missed.len(), 1);
        assert_eq!(report.recall, 0.5);
        assert_eq!(report.precision, 1.0);
    }
}
