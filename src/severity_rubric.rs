//! Severity Rubric Scoring Module
//!
//! Implements the BACO v3 severity scoring system based on Anthropic's methodology.
//! Uses 6 dimensions to compute a final severity score mapped to CVSS-compatible levels.

use crate::scanner_types::severity::{
    AccessType, BlastRadius, RubricDimensions, RubricScore, SeverityRubric, V3Severity,
};

/// FROZEN SeverityRubric const - MUST NOT be changed after T3 freeze
pub const DEFAULT_RUBRIC: SeverityRubric = SeverityRubric {
    reachability: 0.9,
    attacker_control: 0.8,
    preconditions_factor: 0.7,
    auth_required: false,
    access_type: AccessType::Write,
    blast_radius: BlastRadius::High,
};

/// Severity rubric scorer for computing severity scores from findings
pub struct SeverityRubricScorer;

impl SeverityRubricScorer {
    /// Score a finding using the severity rubric formula
    ///
    /// Formula: reachability * attacker_control * preconditions_factor * auth_factor * access_weight * blast_radius_weight
    pub fn score(rubric: &SeverityRubric) -> RubricScore {
        let raw_score = Self::compute_raw_score(rubric);
        let dimensions = RubricDimensions::from(*rubric);

        RubricScore::new(raw_score, dimensions, None)
    }

    /// Compute the raw severity score using the formula
    pub fn compute_raw_score(rubric: &SeverityRubric) -> f32 {
        let auth_factor = rubric.auth_factor();
        let access_weight = rubric.access_weight();
        let blast_radius_weight = rubric.blast_radius_weight();

        // Formula: reachability * attacker_control * preconditions_factor * auth_factor * access_weight * blast_radius_weight
        let raw_score = rubric.reachability
            * rubric.attacker_control
            * rubric.preconditions_factor
            * auth_factor
            * access_weight
            * blast_radius_weight;

        // Clamp to valid range
        raw_score.clamp(0.0, 1.0)
    }

    /// Map raw score to CVSS-compatible severity level
    ///
    /// - 0.0 - 0.2: Low
    /// - 0.2 - 0.5: Medium  
    /// - 0.5 - 0.8: High
    /// - 0.8 - 1.0: Critical
    pub fn map_to_severity(raw_score: f32) -> V3Severity {
        if raw_score >= 0.8 {
            V3Severity::Critical
        } else if raw_score >= 0.5 {
            V3Severity::High
        } else if raw_score >= 0.2 {
            V3Severity::Medium
        } else {
            V3Severity::Low
        }
    }

    /// Explain how the score was computed (for debugging/audit)
    pub fn explain_score(rubric: &SeverityRubric) -> String {
        let raw_score = Self::compute_raw_score(rubric);
        let severity = Self::map_to_severity(raw_score);

        format!(
            "Severity computation:\n\
             - reachability: {:.2}\n\
             - attacker_control: {:.2}\n\
             - preconditions_factor: {:.2}\n\
             - auth_factor: {:.2} {}\n\
             - access_weight: {:.2} ({:?})\n\
             - blast_radius_weight: {:.2} ({:?})\n\
             = raw_score: {:.3}\n\
             => severity: {:?}",
            rubric.reachability,
            rubric.attacker_control,
            rubric.preconditions_factor,
            rubric.auth_factor(),
            if rubric.auth_required {
                "(auth required - reduced)"
            } else {
                "(no auth)"
            },
            rubric.access_weight(),
            rubric.access_type,
            rubric.blast_radius_weight(),
            rubric.blast_radius,
            raw_score,
            severity
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_risk_finding_critical_severity() {
        // High-risk finding: easily reachable, full attacker control, no auth needed
        let rubric = SeverityRubric::new(
            1.0,                   // High reachability
            1.0,                   // Full attacker control
            1.0,                   // No preconditions
            false,                 // No auth required
            AccessType::Both,      // Read + Write access
            BlastRadius::Critical, // Critical blast radius
        );

        let result = SeverityRubricScorer::score(&rubric);

        assert_eq!(result.severity(), V3Severity::Critical);
        assert!(result.raw_score >= 0.8);
    }

    #[test]
    fn test_low_risk_finding_low_severity() {
        // Low-risk finding: hard to reach, limited control, auth required
        let rubric = SeverityRubric::new(
            0.1,              // Low reachability
            0.2,              // Limited attacker control
            0.3,              // Many preconditions
            true,             // Auth required
            AccessType::Read, // Read only
            BlastRadius::Low, // Low blast radius
        );

        let result = SeverityRubricScorer::score(&rubric);

        assert_eq!(result.severity(), V3Severity::Low);
        assert!(result.raw_score < 0.2);
    }

    #[test]
    fn test_medium_risk_finding() {
        // Medium-risk: typical web vulnerability
        let rubric = SeverityRubric::new(
            0.9,               // High reachability
            0.8,               // Good attacker control
            0.7,               // Some preconditions
            false,             // No auth required (common in web apps)
            AccessType::Write, // Write access
            BlastRadius::High, // High blast radius
        );

        let result = SeverityRubricScorer::score(&rubric);

        assert_eq!(result.severity(), V3Severity::Medium);
    }

    #[test]
    fn test_auth_reduces_severity() {
        let rubric_no_auth = SeverityRubric::new(
            0.8,
            0.8,
            0.8,
            false, // No auth
            AccessType::Both,
            BlastRadius::High,
        );

        let rubric_with_auth = SeverityRubric::new(
            0.8,
            0.8,
            0.8,
            true, // Auth required
            AccessType::Both,
            BlastRadius::High,
        );

        let score_no_auth = SeverityRubricScorer::score(&rubric_no_auth);
        let score_with_auth = SeverityRubricScorer::score(&rubric_with_auth);

        // Auth should reduce the score
        assert!(score_with_auth.raw_score < score_no_auth.raw_score);
    }

    #[test]
    fn test_explain_score_contains_details() {
        let rubric =
            SeverityRubric::new(0.5, 0.6, 0.7, false, AccessType::Write, BlastRadius::Medium);

        let explanation = SeverityRubricScorer::explain_score(&rubric);

        assert!(explanation.contains("reachability: 0.50"));
        assert!(explanation.contains("raw_score:"));
    }

    #[test]
    fn test_default_rubric_scores_medium() {
        let score = SeverityRubricScorer::score(&DEFAULT_RUBRIC);

        // Default rubric should produce Medium severity
        assert_eq!(score.severity(), V3Severity::Medium);
    }

    #[test]
    fn test_severity_mapping_boundaries() {
        // Test exact boundary values
        assert_eq!(SeverityRubricScorer::map_to_severity(0.0), V3Severity::Low);
        assert_eq!(SeverityRubricScorer::map_to_severity(0.19), V3Severity::Low);
        assert_eq!(
            SeverityRubricScorer::map_to_severity(0.2),
            V3Severity::Medium
        );
        assert_eq!(
            SeverityRubricScorer::map_to_severity(0.49),
            V3Severity::Medium
        );
        assert_eq!(SeverityRubricScorer::map_to_severity(0.5), V3Severity::High);
        assert_eq!(
            SeverityRubricScorer::map_to_severity(0.79),
            V3Severity::High
        );
        assert_eq!(
            SeverityRubricScorer::map_to_severity(0.8),
            V3Severity::Critical
        );
        assert_eq!(
            SeverityRubricScorer::map_to_severity(1.0),
            V3Severity::Critical
        );
    }

    #[test]
    fn test_rubric_values_clamped() {
        let rubric = SeverityRubric::new(
            1.5,  // Should clamp to 1.0
            -0.5, // Should clamp to 0.0
            2.0,  // Should clamp to 1.0
            false,
            AccessType::Read,
            BlastRadius::Low,
        );

        assert_eq!(rubric.reachability, 1.0);
        assert_eq!(rubric.attacker_control, 0.0);
        assert_eq!(rubric.preconditions_factor, 1.0);
    }
}
