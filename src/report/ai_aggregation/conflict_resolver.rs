//! Conflict resolution logic for AI aggregation

use super::ScanError;
use super::models::*;
use crate::findings::{Severity, VulnerabilityFinding};

/// Resolves conflicts between findings
pub struct ConflictResolver;

impl ConflictResolver {
    /// Resolve severity conflict by keeping highest severity
    ///
    /// Returns an error if findings is empty, as this indicates a logic error
    /// in the caller's conflict detection.
    pub fn resolve_severity_conflict(
        location: &str,
        findings: &[&VulnerabilityFinding],
    ) -> Result<FindingConflict, ScanError> {
        if findings.is_empty() {
            return Err(ScanError::Parse {
                message: format!(
                    "severity conflict resolution failed: empty findings slice at {}",
                    location
                ),
                source: None,
            });
        }

        let mut sorted: Vec<_> = findings.iter().collect();
        sorted.sort_by(|a, b| {
            let severity_order = |s: &Severity| match s {
                Severity::Critical => 5,
                Severity::High => 4,
                Severity::Medium => 3,
                Severity::Low => 2,
                Severity::Info => 1,
            };
            severity_order(&b.severity).cmp(&severity_order(&a.severity))
        });

        let highest = sorted.first().expect("findings is non-empty");
        let conflict_type = ConflictType::SeverityMismatch;
        let resolution = ConflictResolution::HighestSeverity;

        Ok(FindingConflict {
            findings: findings.iter().map(|f| (*f).clone()).collect(),
            conflict_type,
            resolution,
            resolution_reason: format!(
                "Selected highest severity '{}' for {}",
                highest.severity, location
            ),
        })
    }

    /// Resolve CWE conflict by keeping most specific (lowest CWE number)
    ///
    /// Returns an error if any finding has an unparseable CWE ID.
    /// Unparseable CWEs indicate data corruption or model hallucination;
    /// silently sorting them last biases conflict resolution toward findings
    /// with parseable CWEs, which is worse than failing explicitly.
    pub fn resolve_cwe_conflict(
        location: &str,
        findings: &[&VulnerabilityFinding],
    ) -> Result<FindingConflict, ScanError> {
        // Validate all CWEs first - fail fast on unparseable values
        for (i, finding) in findings.iter().enumerate() {
            if let Some(cwe) = &finding.cwe_id {
                // Check if CWE is parseable (format: CWE-NNN or just NNN)
                let cwe_num = cwe.trim_start_matches("CWE-").parse::<u32>();

                if cwe_num.is_err() {
                    return Err(ScanError::Parse {
                        message: format!(
                            "CWE conflict resolution failed: finding {} has unparseable CWE '{}' at {} \
                             - findings with invalid CWEs are not comparable",
                            i + 1,
                            cwe,
                            location
                        ),
                        source: None,
                    });
                }
            }
        }

        let mut sorted: Vec<_> = findings.iter().collect();
        sorted.sort_by(|a, b| {
            let cwe_num = |cwe: &Option<String>| {
                cwe.as_ref()
                    .and_then(|s| s.trim_start_matches("CWE-").parse::<u32>().ok())
                    .unwrap_or(u32::MAX)
            };
            cwe_num(&a.cwe_id).cmp(&cwe_num(&b.cwe_id))
        });

        let most_specific = *sorted.first().unwrap();
        let conflict_type = ConflictType::CweMismatch;
        let resolution = ConflictResolution::KeptOne;

        Ok(FindingConflict {
            findings: findings.iter().map(|f| (*f).clone()).collect(),
            conflict_type,
            resolution,
            resolution_reason: format!(
                "Selected most specific CWE '{}' for {}",
                most_specific.cwe_id.as_deref().unwrap_or("unknown"),
                location
            ),
        })
    }

    /// Resolve confidence conflict by averaging
    pub fn resolve_confidence_conflict(
        _location: &str,
        findings: &[&VulnerabilityFinding],
    ) -> FindingConflict {
        let avg_confidence: f32 =
            findings.iter().map(|f| f.confidence_score).sum::<f32>() / findings.len() as f32;

        let min_conf = findings
            .iter()
            .map(|f| f.confidence_score)
            .fold(f32::INFINITY, f32::min);
        let max_conf = findings
            .iter()
            .map(|f| f.confidence_score)
            .fold(f32::NEG_INFINITY, f32::max);

        FindingConflict {
            findings: findings.iter().map(|f| (*f).clone()).collect(),
            conflict_type: ConflictType::ConfidenceConflict,
            resolution: ConflictResolution::HighestConfidence,
            resolution_reason: format!(
                "Conflicting confidence scores (range: {:.2}). Averaged to {:.2}",
                max_conf - min_conf,
                avg_confidence
            ),
        }
    }
}
