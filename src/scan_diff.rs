//! Scan-to-scan diff engine for comparing findings across runs.
//!
//! Provides diff computation, snapshot capture, and markdown formatting
//! for scan result comparisons.

use crate::findings::VulnerabilityFinding;
use crate::run_store::stable_finding_key;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::Path;

/// Status of a finding in the diff comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffStatus {
    /// Finding is new in the current scan.
    New,
    /// Finding was present in previous scan but not in current (potentially fixed).
    Fixed,
    /// Finding exists in both scans.
    Persisted,
}

impl fmt::Display for DiffStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiffStatus::New => write!(f, "New"),
            DiffStatus::Fixed => write!(f, "Fixed"),
            DiffStatus::Persisted => write!(f, "Persisted"),
        }
    }
}

/// Snapshot of a finding at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSnapshot {
    pub severity: String,
    pub verification_tier: Option<String>,
    pub confidence: f32,
}

impl FindingSnapshot {
    fn from_finding(f: &VulnerabilityFinding) -> Self {
        Self {
            severity: format!("{:?}", f.severity),
            verification_tier: f.verification_tier.as_ref().map(|t| format!("{:?}", t)),
            confidence: f.confidence_score,
        }
    }
}

/// A single finding diff entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingDiff {
    pub key: String,
    pub title: String,
    pub file_path: String,
    pub status: DiffStatus,
    pub previous: Option<FindingSnapshot>,
    pub current: Option<FindingSnapshot>,
    pub severity_changed: bool,
}

/// Compute diff between two scan results.
///
/// Classifies findings as:
/// - New: in current only
/// - Fixed: in previous only
/// - Persisted: in both
pub fn diff_scans(
    previous: &[VulnerabilityFinding],
    current: &[VulnerabilityFinding],
) -> Vec<FindingDiff> {
    let mut result = Vec::new();

    // Build key -> finding maps
    let prev_map: std::collections::HashMap<String, &VulnerabilityFinding> = previous
        .iter()
        .map(|f| (stable_finding_key(f), f))
        .collect();
    let cur_map: std::collections::HashMap<String, &VulnerabilityFinding> =
        current.iter().map(|f| (stable_finding_key(f), f)).collect();

    // Find new and persisted findings
    for (key, cur_finding) in &cur_map {
        if let Some(prev_finding) = prev_map.get(key) {
            // Persisted: exists in both
            let prev_sev = format!("{:?}", prev_finding.severity);
            let cur_sev = format!("{:?}", cur_finding.severity);
            let severity_changed = prev_sev != cur_sev;

            result.push(FindingDiff {
                key: key.clone(),
                title: cur_finding.title.clone(),
                file_path: cur_finding.file_path.clone(),
                status: DiffStatus::Persisted,
                previous: Some(FindingSnapshot::from_finding(prev_finding)),
                current: Some(FindingSnapshot::from_finding(cur_finding)),
                severity_changed,
            });
        } else {
            // New: only in current
            result.push(FindingDiff {
                key: key.clone(),
                title: cur_finding.title.clone(),
                file_path: cur_finding.file_path.clone(),
                status: DiffStatus::New,
                previous: None,
                current: Some(FindingSnapshot::from_finding(cur_finding)),
                severity_changed: false,
            });
        }
    }

    // Find fixed findings (in previous but not in current)
    for (key, prev_finding) in &prev_map {
        if !cur_map.contains_key(key) {
            result.push(FindingDiff {
                key: key.clone(),
                title: prev_finding.title.clone(),
                file_path: prev_finding.file_path.clone(),
                status: DiffStatus::Fixed,
                previous: Some(FindingSnapshot::from_finding(prev_finding)),
                current: None,
                severity_changed: false,
            });
        }
    }

    result
}

/// Format diff as markdown report.
///
/// Sections: "## New", "## Fixed", "## Persisted"
/// Persisted findings with severity changes are sorted first within their section.
/// Summary line at the top with counts.
pub fn format_diff_markdown(diff: &[FindingDiff]) -> String {
    let new_count = diff.iter().filter(|d| d.status == DiffStatus::New).count();
    let fixed_count = diff
        .iter()
        .filter(|d| d.status == DiffStatus::Fixed)
        .count();
    let persisted_count = diff
        .iter()
        .filter(|d| d.status == DiffStatus::Persisted)
        .count();

    let mut lines = Vec::new();

    // Summary header
    lines.push(format!(
        "# Scan Diff Report\n\nNew: {}, Fixed: {}, Persisted: {}\n",
        new_count, fixed_count, persisted_count
    ));

    // New section
    lines.push("## New\n".to_string());
    let new_findings: Vec<_> = diff
        .iter()
        .filter(|d| d.status == DiffStatus::New)
        .collect();
    if new_findings.is_empty() {
        lines.push("- None\n".to_string());
    } else {
        for d in &new_findings {
            lines.push(format_diff_item(d, None));
        }
        lines.push("\n".to_string());
    }

    // Fixed section
    lines.push("## Fixed\n".to_string());
    let fixed_findings: Vec<_> = diff
        .iter()
        .filter(|d| d.status == DiffStatus::Fixed)
        .collect();
    if fixed_findings.is_empty() {
        lines.push("- None\n".to_string());
    } else {
        for d in &fixed_findings {
            lines.push(format_diff_item(d, None));
        }
        lines.push("\n".to_string());
    }

    // Persisted section
    lines.push("## Persisted\n".to_string());
    let mut persisted_findings: Vec<_> = diff
        .iter()
        .filter(|d| d.status == DiffStatus::Persisted)
        .collect();
    // Sort: severity_changed first
    persisted_findings.sort_by_key(|f| std::cmp::Reverse(f.severity_changed));
    if persisted_findings.is_empty() {
        lines.push("- None\n".to_string());
    } else {
        for d in &persisted_findings {
            lines.push(format_diff_item(d, Some(d.severity_changed)));
        }
        lines.push("\n".to_string());
    }

    lines.concat()
}

fn format_diff_item(d: &FindingDiff, severity_changed: Option<bool>) -> String {
    let sev = d
        .current
        .as_ref()
        .or(d.previous.as_ref())
        .map(|s| s.severity.clone())
        .unwrap_or_else(|| "Unknown".to_string());

    // We don't have line_number in FindingSnapshot, so just show file
    let line_str = " (file)".to_string();

    let tier_str = d
        .current
        .as_ref()
        .or(d.previous.as_ref())
        .and_then(|s| s.verification_tier.clone())
        .map(|_| " [+tier]".to_string())
        .unwrap_or_default();

    let sev_marker = if severity_changed == Some(true) {
        " ⚠️ severity changed"
    } else {
        ""
    };

    format!(
        "- [{}] {}{}{}{}\n",
        sev, d.title, line_str, tier_str, sev_marker
    )
}

/// Load findings from previous scan in the output directory.
///
/// Reads `findings.json` from the given directory.
/// Returns an error if the file doesn't exist or is invalid JSON.
pub fn load_previous_findings(
    output_dir: &Path,
) -> Result<Vec<VulnerabilityFinding>, LoadFindingsError> {
    let findings_path = output_dir.join("findings.json");

    if !findings_path.exists() {
        return Err(LoadFindingsError::FileNotFound(findings_path));
    }

    let content = fs::read_to_string(&findings_path)
        .map_err(|e| LoadFindingsError::ReadError(findings_path.clone(), e))?;

    serde_json::from_str(&content)
        .map_err(|e| LoadFindingsError::ParseError(findings_path.clone(), e))
}

/// Error type for loading previous findings.
#[derive(Debug)]
pub enum LoadFindingsError {
    FileNotFound(std::path::PathBuf),
    ReadError(std::path::PathBuf, std::io::Error),
    ParseError(std::path::PathBuf, serde_json::Error),
}

impl fmt::Display for LoadFindingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadFindingsError::FileNotFound(path) => {
                write!(f, "Findings file not found: {:?}", path)
            }
            LoadFindingsError::ReadError(path, e) => {
                write!(f, "Failed to read findings file {:?}: {}", path, e)
            }
            LoadFindingsError::ParseError(path, e) => {
                write!(f, "Failed to parse findings file {:?}: {}", path, e)
            }
        }
    }
}

impl std::error::Error for LoadFindingsError {}
