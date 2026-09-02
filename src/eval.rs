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
