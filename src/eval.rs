//! Known-answer oracle scoring for evaluation fixtures.
//!
//! Parses oracle JSON files and scores scan findings against expected/expected-suppressed sets.
//! Also provides the offline eval-suite runner that scores every bundled target
//! against its oracle using its findings fixture.

use crate::findings::VulnerabilityFinding;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Default aggregate pass-rate floor for the eval suite.
/// Overridden by the `BACO_EVAL_FLOOR` environment variable.
pub const DEFAULT_EVAL_FLOOR: f32 = 0.70;

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
    pub suppressed_total: usize,
    pub suppressed_clean: usize,
    pub silence_rate: f32,
    pub recall: f32,
    pub precision: f32,
}

/// Parse an oracle JSON string into an OracleFile
pub fn parse_oracle(json: &str) -> Result<OracleFile, String> {
    serde_json::from_str(json).map_err(|e| format!("Failed to parse oracle JSON: {}", e))
}

/// Per-target score within a suite run
#[derive(Debug, Clone, Serialize)]
pub struct TargetScore {
    pub report: ScoreReport,
    /// Fraction of expected findings matched (recall); 1.0 when nothing is expected
    pub pass_rate: f32,
}

/// Aggregate result of scoring every target in an eval suite
#[derive(Debug, Clone, Serialize)]
pub struct SuiteReport {
    pub targets: Vec<TargetScore>,
    pub total_expected: usize,
    pub total_matched: usize,
    /// Micro-average pass rate: total matched / total expected
    pub aggregate: f32,
    pub total_suppressed: usize,
    pub total_suppressed_clean: usize,
    /// Micro-average silence rate over suppressed twins
    pub silence: f32,
    /// Total findings on suppressed twins across targets
    pub total_false_flags: usize,
}

/// Resolve the eval-suite floor: `BACO_EVAL_FLOOR` env override (must parse as f32
/// in 0.0..=1.0), otherwise the `[eval] floor` config value. Returns the winning
/// value together with a label naming its source.
pub fn eval_floor(config_floor: f32) -> Result<(f32, &'static str), String> {
    let Ok(raw) = std::env::var("BACO_EVAL_FLOOR") else {
        return validate_floor(config_floor, "eval.floor");
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return validate_floor(config_floor, "eval.floor");
    }
    let floor: f32 = raw
        .parse()
        .map_err(|e| format!("Invalid BACO_EVAL_FLOOR '{}': {}", raw, e))?;
    validate_floor(floor, "BACO_EVAL_FLOOR")
}

fn validate_floor(floor: f32, source: &'static str) -> Result<(f32, &'static str), String> {
    if !(0.0..=1.0).contains(&floor) {
        return Err(format!(
            "{} must be between 0.0 and 1.0, got {}",
            source, floor
        ));
    }
    Ok((floor, source))
}

/// Run the offline eval suite over every target discovered under `eval_root`.
///
/// Targets are discovered from `<eval_root>/oracles/*.json`; each must be paired with
/// a findings fixture `<eval_root>/findings/<target>.json`, which is scored against
/// its oracle. Discovery is deterministic (oracles are processed in sorted order).
pub fn run_suite(eval_root: &Path) -> Result<SuiteReport, String> {
    let oracles_dir = eval_root.join("oracles");
    let findings_dir = eval_root.join("findings");

    if !oracles_dir.is_dir() {
        return Err(format!(
            "Eval oracles directory not found: {}",
            oracles_dir.display()
        ));
    }

    let mut oracle_paths: Vec<PathBuf> = std::fs::read_dir(&oracles_dir)
        .map_err(|e| format!("Failed to read {}: {}", oracles_dir.display(), e))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
        .collect();
    oracle_paths.sort();

    if oracle_paths.is_empty() {
        return Err(format!(
            "No oracle files found in {}",
            oracles_dir.display()
        ));
    }

    let mut targets = Vec::with_capacity(oracle_paths.len());
    for oracle_path in &oracle_paths {
        let stem = oracle_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let oracle_json = std::fs::read_to_string(oracle_path)
            .map_err(|e| format!("Failed to read {}: {}", oracle_path.display(), e))?;
        let oracle =
            parse_oracle(&oracle_json).map_err(|e| format!("{}: {}", oracle_path.display(), e))?;
        if oracle.target != stem {
            return Err(format!(
                "Oracle {} declares target '{}' but the file stem is '{}'",
                oracle_path.display(),
                oracle.target,
                stem
            ));
        }

        let findings_path = findings_dir.join(format!("{}.json", stem));
        let findings = crate::validation::validate_findings(&findings_path)
            .map_err(|e| format!("Target {}: {}", oracle.target, e))?;
        let report = score_findings(&oracle, &findings);
        let pass_rate = if report.expected > 0 {
            report.matched as f32 / report.expected as f32
        } else {
            1.0
        };
        targets.push(TargetScore { report, pass_rate });
    }

    let total_expected: usize = targets.iter().map(|t| t.report.expected).sum();
    let total_matched: usize = targets.iter().map(|t| t.report.matched).sum();
    if total_expected == 0 {
        return Err("Eval suite contains no expected findings".to_string());
    }
    let total_suppressed: usize = targets.iter().map(|t| t.report.suppressed_total).sum();
    let total_suppressed_clean: usize = targets.iter().map(|t| t.report.suppressed_clean).sum();
    let total_false_flags: usize = targets.iter().map(|t| t.report.false_flags).sum();
    let silence = if total_suppressed > 0 {
        total_suppressed_clean as f32 / total_suppressed as f32
    } else {
        1.0
    };

    Ok(SuiteReport {
        targets,
        total_expected,
        total_matched,
        aggregate: total_matched as f32 / total_expected as f32,
        total_suppressed,
        total_suppressed_clean,
        silence,
        total_false_flags,
    })
}

/// Score findings against an oracle, returning a detailed report
pub fn score_findings(oracle: &OracleFile, findings: &[VulnerabilityFinding]) -> ScoreReport {
    let expected_count = oracle.expected_findings.len();
    let mut matched_findings: Vec<bool> = vec![false; expected_count];
    let mut false_flags = 0usize;
    let mut suppressed_hits = vec![false; oracle.expected_suppressed.len()];

    // Check each finding against expected and suppressed lists
    for finding in findings {
        // Check if finding is on a suppressed file (false flag)
        let suppressed_idx = oracle
            .expected_suppressed
            .iter()
            .position(|supp| finding.file_path == supp.file_path);

        if let Some(idx) = suppressed_idx {
            suppressed_hits[idx] = true;
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

    let suppressed_total = oracle.expected_suppressed.len();
    let suppressed_clean = suppressed_hits.iter().filter(|&&h| !h).count();
    let silence_rate = if suppressed_total > 0 {
        suppressed_clean as f32 / suppressed_total as f32
    } else {
        1.0
    };

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
        suppressed_total,
        suppressed_clean,
        silence_rate,
        recall,
        precision,
    }
}
