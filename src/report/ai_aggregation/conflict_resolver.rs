//! Conflict resolution logic for AI aggregation

use super::models::*;
use crate::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use std::collections::HashMap;

/// Resolves conflicts between findings
pub struct ConflictResolver;

impl ConflictResolver {
    /// Detect conflicts between findings grouped by location
    pub fn detect_conflicts(
        grouped: &HashMap<String, Vec<&VulnerabilityFinding>>,
    ) -> Vec<FindingConflict> {
        let mut conflicts = Vec::new();

        for (location, findings) in grouped {
            if findings.len() < 2 {
                continue;
            }

            // Check for severity mismatches
            let severities: Vec<_> = findings.iter().map(|f| f.severity).collect();
            if severities
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                > 1
            {
                let conflict = Self::resolve_severity_conflict(location, findings);
                conflicts.push(conflict);
                continue;
            }

            // Check for CWE mismatches
            let cwes: Vec<_> = findings.iter().filter_map(|f| f.cwe_id.as_ref()).collect();
            if cwes.iter().collect::<std::collections::HashSet<_>>().len() > 1 {
                let conflict = Self::resolve_cwe_conflict(location, findings);
                conflicts.push(conflict);
                continue;
            }

            // Check for verification conflicts
            let has_verified = findings
                .iter()
                .any(|f| f.verification_status == Some(VerificationStatus::Confirmed));
            let has_fp = findings
                .iter()
                .any(|f| f.verification_status == Some(VerificationStatus::FalsePositive));

            if has_verified && has_fp {
                let conflict = Self::resolve_verification_conflict(location, findings);
                conflicts.push(conflict);
                continue;
            }

            // Check for confidence conflicts
            let confidences: Vec<f32> = findings.iter().map(|f| f.confidence_score).collect();
            let min_conf = confidences.iter().cloned().fold(f32::INFINITY, f32::min);
            let max_conf = confidences
                .iter()
                .cloned()
                .fold(f32::NEG_INFINITY, f32::max);

            if max_conf - min_conf > 0.3 {
                let conflict = Self::resolve_confidence_conflict(location, findings);
                conflicts.push(conflict);
            }
        }

        conflicts
    }

    /// Resolve severity conflict by keeping highest severity
    pub fn resolve_severity_conflict(
        location: &str,
        findings: &[&VulnerabilityFinding],
    ) -> FindingConflict {
        if findings.is_empty() {
            return FindingConflict {
                findings: vec![],
                conflict_type: ConflictType::SeverityMismatch,
                resolution: ConflictResolution::HighestSeverity,
                resolution_reason: "No findings to resolve".to_string(),
            };
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

        let highest = *sorted.first().unwrap();
        let conflict_type = ConflictType::SeverityMismatch;
        let resolution = ConflictResolution::HighestSeverity;

        FindingConflict {
            findings: findings.iter().map(|f| (*f).clone()).collect(),
            conflict_type,
            resolution,
            resolution_reason: format!(
                "Selected highest severity '{}' for {}",
                highest.severity, location
            ),
        }
    }

    /// Resolve CWE conflict by keeping most specific (lowest CWE number)
    pub fn resolve_cwe_conflict(
        location: &str,
        findings: &[&VulnerabilityFinding],
    ) -> FindingConflict {
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

        FindingConflict {
            findings: findings.iter().map(|f| (*f).clone()).collect(),
            conflict_type,
            resolution,
            resolution_reason: format!(
                "Selected most specific CWE '{}' for {}",
                most_specific.cwe_id.as_deref().unwrap_or("unknown"),
                location
            ),
        }
    }

    /// Resolve verification conflict by preferring verified findings
    pub fn resolve_verification_conflict(
        location: &str,
        findings: &[&VulnerabilityFinding],
    ) -> FindingConflict {
        let confirmed = findings
            .iter()
            .find(|f| f.verification_status == Some(VerificationStatus::Confirmed));

        let conflict_type = ConflictType::VerificationConflict;
        let (resolution, reason) = if let Some(c) = confirmed {
            (
                ConflictResolution::PreferVerified,
                format!("Kept verified finding '{}' over false positive", c.title),
            )
        } else {
            (
                ConflictResolution::MarkedFalsePositive,
                format!("Marked as false positive due to conflict at {}", location),
            )
        };

        FindingConflict {
            findings: findings.iter().map(|f| (*f).clone()).collect(),
            conflict_type,
            resolution,
            resolution_reason: reason,
        }
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
