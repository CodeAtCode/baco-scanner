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
