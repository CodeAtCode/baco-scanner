//! Unit tests for the severity rubric scoring system.
//!
//! Tests cover all public APIs in src/severity_rubric.rs including
//! the SeverityRubricScorer, scoring logic, severity mapping, and edge cases.

use baco::scanner_types::severity::{AccessType, BlastRadius, SeverityRubric, V3Severity};
use baco::severity_rubric::{SeverityRubricScorer, DEFAULT_RUBRIC};

// ============================================================================
// compute_raw_score tests
// ============================================================================

#[test]
fn test_compute_raw_score_max_values_no_auth() {
    // All factors at maximum, no auth required = highest possible score
    let rubric = SeverityRubric::new(
        1.0,
        1.0,
        1.0,
        false,
        AccessType::Both,
        BlastRadius::Critical,
    );

    let raw_score = SeverityRubricScorer::compute_raw_score(&rubric);

    // Formula: 1.0 * 1.0 * 1.0 * 1.0 (auth) * 1.0 (access) * 1.0 (blast) = 1.0
    assert!((raw_score - 1.0).abs() < 0.001);
}

#[test]
fn test_compute_raw_score_min_values() {
    // All factors at minimum = lowest possible score
    let rubric = SeverityRubric::new(0.0, 0.0, 0.0, true, AccessType::Read, BlastRadius::Low);

    let raw_score = SeverityRubricScorer::compute_raw_score(&rubric);

    // Any factor of 0.0 makes the whole product 0.0
    assert!((raw_score - 0.0).abs() < 0.001);
}

#[test]
fn test_compute_raw_score_auth_factor_applied() {
    // Test that auth_required reduces the score by half
    let rubric_no_auth =
        SeverityRubric::new(0.5, 0.5, 0.5, false, AccessType::Write, BlastRadius::High);

    let rubric_with_auth =
        SeverityRubric::new(0.5, 0.5, 0.5, true, AccessType::Write, BlastRadius::High);

    let score_no_auth = SeverityRubricScorer::compute_raw_score(&rubric_no_auth);
    let score_with_auth = SeverityRubricScorer::compute_raw_score(&rubric_with_auth);

    // Auth factor is 0.5, so score_with_auth should be half of score_no_auth
    assert!((score_with_auth - score_no_auth * 0.5).abs() < 0.001);
}

#[test]
fn test_compute_raw_score_access_type_weights() {
    // Test all access type weights
    let rubric_read =
        SeverityRubric::new(1.0, 1.0, 1.0, false, AccessType::Read, BlastRadius::High);
    let rubric_write =
        SeverityRubric::new(1.0, 1.0, 1.0, false, AccessType::Write, BlastRadius::High);
    let rubric_both =
        SeverityRubric::new(1.0, 1.0, 1.0, false, AccessType::Both, BlastRadius::High);

    let score_read = SeverityRubricScorer::compute_raw_score(&rubric_read);
    let score_write = SeverityRubricScorer::compute_raw_score(&rubric_write);
    let score_both = SeverityRubricScorer::compute_raw_score(&rubric_both);

    // Access weights: Read=0.5, Write=0.8, Both=1.0
    assert!((score_read - 0.85 * 0.5).abs() < 0.001);
    assert!((score_write - 0.85 * 0.8).abs() < 0.001);
    assert!((score_both - 0.85 * 1.0).abs() < 0.001);
}

#[test]
fn test_compute_raw_score_blast_radius_weights() {
    // Test all blast radius weights
    let rubric_low = SeverityRubric::new(1.0, 1.0, 1.0, false, AccessType::Both, BlastRadius::Low);
    let rubric_medium =
        SeverityRubric::new(1.0, 1.0, 1.0, false, AccessType::Both, BlastRadius::Medium);
    let rubric_high =
        SeverityRubric::new(1.0, 1.0, 1.0, false, AccessType::Both, BlastRadius::High);
    let rubric_critical = SeverityRubric::new(
        1.0,
        1.0,
        1.0,
        false,
        AccessType::Both,
        BlastRadius::Critical,
    );

    let score_low = SeverityRubricScorer::compute_raw_score(&rubric_low);
    let score_medium = SeverityRubricScorer::compute_raw_score(&rubric_medium);
    let score_high = SeverityRubricScorer::compute_raw_score(&rubric_high);
    let score_critical = SeverityRubricScorer::compute_raw_score(&rubric_critical);

    // Blast radius weights: Low=0.3, Medium=0.6, High=0.85, Critical=1.0
    assert!((score_low - 1.0 * 0.3).abs() < 0.001);
    assert!((score_medium - 1.0 * 0.6).abs() < 0.001);
    assert!((score_high - 1.0 * 0.85).abs() < 0.001);
    assert!((score_critical - 1.0 * 1.0).abs() < 0.001);
}

// ============================================================================
// map_to_severity tests
// ============================================================================

#[test]
fn test_map_to_severity_low_range() {
    // Scores below 0.2 are Low
    assert_eq!(SeverityRubricScorer::map_to_severity(0.0), V3Severity::Low);
    assert_eq!(SeverityRubricScorer::map_to_severity(0.05), V3Severity::Low);
    assert_eq!(SeverityRubricScorer::map_to_severity(0.1), V3Severity::Low);
    assert_eq!(SeverityRubricScorer::map_to_severity(0.19), V3Severity::Low);
    assert_eq!(
        SeverityRubricScorer::map_to_severity(0.199),
        V3Severity::Low
    );
}

#[test]
fn test_map_to_severity_medium_range() {
    // Scores >= 0.2 and < 0.5 are Medium
    assert_eq!(
        SeverityRubricScorer::map_to_severity(0.2),
        V3Severity::Medium
    );
    assert_eq!(
        SeverityRubricScorer::map_to_severity(0.3),
        V3Severity::Medium
    );
    assert_eq!(
        SeverityRubricScorer::map_to_severity(0.4),
        V3Severity::Medium
    );
    assert_eq!(
        SeverityRubricScorer::map_to_severity(0.49),
        V3Severity::Medium
    );
    assert_eq!(
        SeverityRubricScorer::map_to_severity(0.499),
        V3Severity::Medium
    );
}

#[test]
fn test_map_to_severity_high_range() {
    // Scores >= 0.5 and < 0.8 are High
    assert_eq!(SeverityRubricScorer::map_to_severity(0.5), V3Severity::High);
    assert_eq!(SeverityRubricScorer::map_to_severity(0.6), V3Severity::High);
    assert_eq!(SeverityRubricScorer::map_to_severity(0.7), V3Severity::High);
    assert_eq!(
        SeverityRubricScorer::map_to_severity(0.79),
        V3Severity::High
    );
    assert_eq!(
        SeverityRubricScorer::map_to_severity(0.799),
        V3Severity::High
    );
}

#[test]
fn test_map_to_severity_critical_range() {
    // Scores >= 0.8 are Critical
    assert_eq!(
        SeverityRubricScorer::map_to_severity(0.8),
        V3Severity::Critical
    );
    assert_eq!(
        SeverityRubricScorer::map_to_severity(0.85),
        V3Severity::Critical
    );
    assert_eq!(
        SeverityRubricScorer::map_to_severity(0.9),
        V3Severity::Critical
    );
    assert_eq!(
        SeverityRubricScorer::map_to_severity(0.99),
        V3Severity::Critical
    );
    assert_eq!(
        SeverityRubricScorer::map_to_severity(1.0),
        V3Severity::Critical
    );
}

#[test]
fn test_map_to_severity_boundary_values() {
    // Test exact boundary transitions
    assert_eq!(
        SeverityRubricScorer::map_to_severity(0.199_999),
        V3Severity::Low
    );
    assert_eq!(
        SeverityRubricScorer::map_to_severity(0.2),
        V3Severity::Medium
    );
    assert_eq!(
        SeverityRubricScorer::map_to_severity(0.499_999),
        V3Severity::Medium
    );
    assert_eq!(SeverityRubricScorer::map_to_severity(0.5), V3Severity::High);
    assert_eq!(
        SeverityRubricScorer::map_to_severity(0.799_999),
        V3Severity::High
    );
    assert_eq!(
        SeverityRubricScorer::map_to_severity(0.8),
        V3Severity::Critical
    );
}

// ============================================================================
// score tests (full scoring pipeline)
// ============================================================================

#[test]
fn test_score_returns_rubric_score_with_dimensions() {
    let rubric = SeverityRubric::new(0.7, 0.6, 0.8, false, AccessType::Write, BlastRadius::Medium);

    let result = SeverityRubricScorer::score(&rubric);

    // Verify the result has correct dimensions
    assert!((result.dimensions.reachability - 0.7).abs() < 0.001);
    assert!((result.dimensions.attacker_control - 0.6).abs() < 0.001);
    assert!((result.dimensions.preconditions_factor - 0.8).abs() < 0.001);
    assert_eq!(result.dimensions.access_type, AccessType::Write);
    assert_eq!(result.dimensions.blast_radius, BlastRadius::Medium);
}

#[test]
fn test_score_all_severity_levels() {
    // Critical: all max, no auth
    let critical_rubric = SeverityRubric::new(
        1.0,
        1.0,
        1.0,
        false,
        AccessType::Both,
        BlastRadius::Critical,
    );
    assert_eq!(
        SeverityRubricScorer::score(&critical_rubric).severity(),
        V3Severity::Critical
    );

    // High: strong factors (0.9 * 0.8 * 0.8 * 1.0 * 0.8 * 0.85 = 0.391, still Medium, need higher)
    // Use: 0.95 * 0.9 * 0.85 * 1.0 * 0.8 * 0.85 = 0.496, still just under High
    // Use: 1.0 * 0.9 * 0.8 * 1.0 * 0.8 * 0.85 = 0.4896, still Medium
    // Use: 1.0 * 1.0 * 0.8 * 1.0 * 0.8 * 0.85 = 0.544 = High!
    let high_rubric =
        SeverityRubric::new(1.0, 1.0, 0.8, false, AccessType::Write, BlastRadius::High);
    assert_eq!(
        SeverityRubricScorer::score(&high_rubric).severity(),
        V3Severity::High
    );

    // Medium: moderate factors (0.5 * 0.5 * 0.6 * 1.0 * 0.8 * 0.6 = 0.072, too low)
    // Need score >= 0.2 and < 0.5
    // Try: 0.8 * 0.7 * 0.6 * 1.0 * 0.8 * 0.6 = 0.16128, still too low
    // Try: 0.9 * 0.8 * 0.7 * 1.0 * 0.8 * 0.6 = 0.24192 = Medium!
    let medium_rubric =
        SeverityRubric::new(0.9, 0.8, 0.7, false, AccessType::Write, BlastRadius::Medium);
    assert_eq!(
        SeverityRubricScorer::score(&medium_rubric).severity(),
        V3Severity::Medium
    );

    // Low: weak factors
    let low_rubric = SeverityRubric::new(0.3, 0.2, 0.3, true, AccessType::Read, BlastRadius::Low);
    assert_eq!(
        SeverityRubricScorer::score(&low_rubric).severity(),
        V3Severity::Low
    );
}

// ============================================================================
// explain_score tests
// ============================================================================

#[test]
fn test_explain_score_contains_all_dimensions() {
    let rubric = SeverityRubric::new(0.5, 0.6, 0.7, false, AccessType::Write, BlastRadius::Medium);

    let explanation = SeverityRubricScorer::explain_score(&rubric);

    assert!(explanation.contains("reachability: 0.50"));
    assert!(explanation.contains("attacker_control: 0.60"));
    assert!(explanation.contains("preconditions_factor: 0.70"));
    assert!(explanation.contains("auth_factor"));
    assert!(explanation.contains("access_weight"));
    assert!(explanation.contains("blast_radius_weight"));
    assert!(explanation.contains("raw_score"));
    assert!(explanation.contains("severity:"));
}

#[test]
fn test_explain_score_shows_auth_status() {
    let rubric_no_auth =
        SeverityRubric::new(0.5, 0.5, 0.5, false, AccessType::Read, BlastRadius::Low);
    let rubric_with_auth =
        SeverityRubric::new(0.5, 0.5, 0.5, true, AccessType::Read, BlastRadius::Low);

    let explanation_no_auth = SeverityRubricScorer::explain_score(&rubric_no_auth);
    let explanation_with_auth = SeverityRubricScorer::explain_score(&rubric_with_auth);

    assert!(explanation_no_auth.contains("no auth"));
    assert!(explanation_with_auth.contains("auth required"));
}

#[test]
fn test_explain_score_shows_access_type() {
    let rubric = SeverityRubric::new(0.5, 0.5, 0.5, false, AccessType::Both, BlastRadius::Low);
    let explanation = SeverityRubricScorer::explain_score(&rubric);

    assert!(explanation.contains("Both"));
}

// ============================================================================
// DEFAULT_RUBRIC tests
// ============================================================================

#[test]
fn test_default_rubric_values() {
    assert!((DEFAULT_RUBRIC.reachability - 0.9).abs() < 0.001);
    assert!((DEFAULT_RUBRIC.attacker_control - 0.8).abs() < 0.001);
    assert!((DEFAULT_RUBRIC.preconditions_factor - 0.7).abs() < 0.001);
    assert_eq!(DEFAULT_RUBRIC.access_type, AccessType::Write);
    assert_eq!(DEFAULT_RUBRIC.blast_radius, BlastRadius::High);
}

#[test]
fn test_default_rubric_scores_medium() {
    let score = SeverityRubricScorer::score(&DEFAULT_RUBRIC);

    // Default rubric should produce Medium severity
    assert_eq!(score.severity(), V3Severity::Medium);
}

// ============================================================================
// SeverityRubric::new clamping tests
// ============================================================================

#[test]
fn test_rubric_new_clamps_reachability() {
    let rubric = SeverityRubric::new(1.5, 0.5, 0.5, false, AccessType::Read, BlastRadius::Low);
    assert!((rubric.reachability - 1.0).abs() < 0.001);
}

#[test]
fn test_rubric_new_clamps_attacker_control() {
    let rubric = SeverityRubric::new(0.5, -0.5, 0.5, false, AccessType::Read, BlastRadius::Low);
    assert!((rubric.attacker_control - 0.0).abs() < 0.001);
}

#[test]
fn test_rubric_new_clamps_preconditions() {
    let rubric = SeverityRubric::new(0.5, 0.5, 2.0, false, AccessType::Read, BlastRadius::Low);
    assert!((rubric.preconditions_factor - 1.0).abs() < 0.001);
}

#[test]
fn test_rubric_new_clamps_all_at_once() {
    let rubric = SeverityRubric::new(
        1.5,  // Should clamp to 1.0
        -0.5, // Should clamp to 0.0
        2.0,  // Should clamp to 1.0
        false,
        AccessType::Read,
        BlastRadius::Low,
    );

    assert!((rubric.reachability - 1.0).abs() < 0.001);
    assert!((rubric.attacker_control - 0.0).abs() < 0.001);
    assert!((rubric.preconditions_factor - 1.0).abs() < 0.001);
}

// ============================================================================
// Edge case tests
// ============================================================================

#[test]
fn test_zero_reachability_yields_zero_score() {
    let rubric = SeverityRubric::new(
        0.0,
        1.0,
        1.0,
        false,
        AccessType::Both,
        BlastRadius::Critical,
    );
    let score = SeverityRubricScorer::compute_raw_score(&rubric);
    assert!((score - 0.0).abs() < 0.001);
}

#[test]
fn test_zero_attacker_control_yields_zero_score() {
    let rubric = SeverityRubric::new(
        1.0,
        0.0,
        1.0,
        false,
        AccessType::Both,
        BlastRadius::Critical,
    );
    let score = SeverityRubricScorer::compute_raw_score(&rubric);
    assert!((score - 0.0).abs() < 0.001);
}

#[test]
fn test_zero_preconditions_factor_yields_zero_score() {
    let rubric = SeverityRubric::new(
        1.0,
        1.0,
        0.0,
        false,
        AccessType::Both,
        BlastRadius::Critical,
    );
    let score = SeverityRubricScorer::compute_raw_score(&rubric);
    assert!((score - 0.0).abs() < 0.001);
}

#[test]
fn test_extreme_low_score_maps_to_low() {
    let rubric = SeverityRubric::new(0.1, 0.1, 0.1, true, AccessType::Read, BlastRadius::Low);
    let score = SeverityRubricScorer::score(&rubric);
    assert_eq!(score.severity(), V3Severity::Low);
    assert!(score.raw_score < 0.2);
}

#[test]
fn test_extreme_high_score_maps_to_critical() {
    let rubric = SeverityRubric::new(
        1.0,
        1.0,
        1.0,
        false,
        AccessType::Both,
        BlastRadius::Critical,
    );
    let score = SeverityRubricScorer::score(&rubric);
    assert_eq!(score.severity(), V3Severity::Critical);
    assert!(score.raw_score >= 0.8);
}

#[test]
fn test_score_is_always_non_negative() {
    // Test various combinations to ensure score never goes negative
    let test_cases = vec![
        (0.0, 0.0, 0.0, true, AccessType::Read, BlastRadius::Low),
        (0.1, 0.1, 0.1, true, AccessType::Read, BlastRadius::Low),
        (0.5, 0.5, 0.5, true, AccessType::Read, BlastRadius::Low),
    ];

    for (r, a, p, auth, access, blast) in test_cases {
        let rubric = SeverityRubric::new(r, a, p, auth, access, blast);
        let score = SeverityRubricScorer::compute_raw_score(&rubric);
        assert!(score >= 0.0, "Score {} should be non-negative", score);
    }
}

#[test]
fn test_score_is_always_at_most_one() {
    // Test various combinations to ensure score never exceeds 1.0
    let test_cases = vec![
        (
            1.0,
            1.0,
            1.0,
            false,
            AccessType::Both,
            BlastRadius::Critical,
        ),
        (0.9, 0.9, 0.9, false, AccessType::Write, BlastRadius::High),
        (0.5, 0.5, 0.5, false, AccessType::Read, BlastRadius::Medium),
    ];

    for (r, a, p, auth, access, blast) in test_cases {
        let rubric = SeverityRubric::new(r, a, p, auth, access, blast);
        let score = SeverityRubricScorer::compute_raw_score(&rubric);
        assert!(score <= 1.0, "Score {} should not exceed 1.0", score);
    }
}
