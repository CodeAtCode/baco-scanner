//! Unit tests for the confidence calculator.
//!
//! Tests cover all public APIs in src/confidence.rs including
//! calculate_composite, recalculate_priority, and edge cases.

use baco::confidence::ConfidenceCalculator;
use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};

/// Helper to create a minimal VulnerabilityFinding for testing
fn create_finding(
    severity: Severity,
    sources: Vec<&str>,
    verification_status: Option<VerificationStatus>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-finding".to_string(),
        title: "Test Finding".to_string(),
        description: "Test description".to_string(),
        severity,
        confidence_score: 0.0,
        cwe_id: None,
        file_path: "src/test.rs".to_string(),
        line_number: Some(42),
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: sources.into_iter().map(String::from).collect(),
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status,
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
    }
}

// ============================================================================
// calculate_composite tests - base scores
// ============================================================================

#[test]
fn test_composite_base_score_critical() {
    let mut finding = create_finding(Severity::Critical, vec![], None);
    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    // Base 80.0 + 5.0 (high/critical boost) = 85.0
    assert!((score - 85.0).abs() < 0.001);
}

#[test]
fn test_composite_base_score_high() {
    let mut finding = create_finding(Severity::High, vec![], None);
    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    // Base 60.0 + 5.0 (high/critical boost) = 65.0
    assert!((score - 65.0).abs() < 0.001);
}

#[test]
fn test_composite_base_score_medium() {
    let mut finding = create_finding(Severity::Medium, vec![], None);
    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    assert!((score - 40.0).abs() < 0.001);
}

#[test]
fn test_composite_base_score_low() {
    let mut finding = create_finding(Severity::Low, vec![], None);
    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    assert!((score - 20.0).abs() < 0.001);
}

#[test]
fn test_composite_base_score_info() {
    let mut finding = create_finding(Severity::Info, vec![], None);
    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    assert!((score - 10.0).abs() < 0.001);
}

// ============================================================================
// calculate_composite tests - source bonuses
// ============================================================================

#[test]
fn test_composite_empty_sources_no_bonus() {
    let mut finding = create_finding(Severity::High, vec![], None);
    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    // Base 60.0 + 5.0 (high/critical boost) = 65.0
    assert!((score - 65.0).abs() < 0.001);
}

#[test]
fn test_composite_single_source_bonus() {
    let mut finding = create_finding(Severity::High, vec!["semgrep"], None);
    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    // Base 60.0 + 10.0 (source) + 5.0 (high/critical boost) = 75.0
    assert!((score - 75.0).abs() < 0.001);
}

#[test]
fn test_composite_multiple_sources_bonus() {
    let mut finding = create_finding(Severity::High, vec!["semgrep", "llm"], None);
    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    // Base 60.0 + 10.0 (source) + 15.0 (multiple) + 5.0 (high/critical boost) = 90.0
    assert!((score - 90.0).abs() < 0.001);
}

#[test]
fn test_composite_three_sources_same_as_two() {
    let mut finding = create_finding(Severity::High, vec!["semgrep", "llm", "manual"], None);
    let score_two = ConfidenceCalculator::calculate_composite(&mut create_finding(
        Severity::High,
        vec!["semgrep", "llm"],
        None,
    ));
    let score_three = ConfidenceCalculator::calculate_composite(&mut finding);
    // Multiple sources bonus is the same regardless of how many (>1)
    assert!((score_three - score_two).abs() < 0.001);
}

// ============================================================================
// calculate_composite tests - severity boost
// ============================================================================

#[test]
fn test_composite_high_severity_boost() {
    let mut finding = create_finding(Severity::High, vec!["semgrep"], None);
    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    // Base 60.0 + 10.0 (source) + 5.0 (high/critical boost) = 75.0
    assert!((score - 75.0).abs() < 0.001);
}

#[test]
fn test_composite_critical_severity_boost() {
    let mut finding = create_finding(Severity::Critical, vec!["semgrep"], None);
    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    // Base 80.0 + 10.0 (source) + 5.0 (high/critical boost) = 95.0
    assert!((score - 95.0).abs() < 0.001);
}

#[test]
fn test_composite_medium_no_severity_boost() {
    let mut finding = create_finding(Severity::Medium, vec!["semgrep"], None);
    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    // Base 40.0 + 10.0 (source), no severity boost
    assert!((score - 50.0).abs() < 0.001);
}

// ============================================================================
// calculate_composite tests - verification status
// ============================================================================

#[test]
fn test_composite_confirmed_verification_boost() {
    let mut finding = create_finding(
        Severity::High,
        vec!["semgrep"],
        Some(VerificationStatus::Confirmed),
    );
    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    // Base 60.0 + 10.0 (source) + 5.0 (severity boost) + 20.0 (confirmed) = 95.0
    assert!((score - 95.0).abs() < 0.001);
}

#[test]
fn test_composite_needs_review_no_boost() {
    let mut finding = create_finding(
        Severity::High,
        vec!["semgrep"],
        Some(VerificationStatus::NeedsReview),
    );
    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    // Base 60.0 + 10.0 (source) + 5.0 (severity boost), no verification boost
    assert!((score - 75.0).abs() < 0.001);
}

#[test]
fn test_composite_false_positive_no_boost() {
    let mut finding = create_finding(
        Severity::High,
        vec!["semgrep"],
        Some(VerificationStatus::FalsePositive),
    );
    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    // Base 60.0 + 10.0 (source) + 5.0 (severity boost), no verification boost
    assert!((score - 75.0).abs() < 0.001);
}

// ============================================================================
// calculate_composite tests - clamping
// ============================================================================

#[test]
fn test_composite_clamped_at_100() {
    // Maximum possible score: Critical (80) + source (10) + multiple (15) + high/critical (5) + confirmed (20) = 130
    // Should clamp to 100
    let mut finding = create_finding(
        Severity::Critical,
        vec!["semgrep", "llm"],
        Some(VerificationStatus::Confirmed),
    );
    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    assert!((score - 100.0).abs() < 0.001);
}

#[test]
fn test_composite_clamped_at_0() {
    // Minimum possible score: Info (10) with no sources
    // Can't go below 0, but let's verify it stays at 10
    let mut finding = create_finding(Severity::Info, vec![], None);
    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    assert!(score >= 0.0);
    assert!((score - 10.0).abs() < 0.001);
}

// ============================================================================
// recalculate_priority tests
// ============================================================================

#[test]
fn test_recalculate_priority_sets_confidence_score() {
    let mut finding = create_finding(Severity::High, vec![], None);
    finding.confidence_score = 0.5; // Initial value

    ConfidenceCalculator::recalculate_priority(&mut finding);

    // After recalculation, confidence_score should be updated
    assert!(finding.confidence_score > 0.0);
}

#[test]
fn test_recalculate_priority_sets_priority_score() {
    let mut finding = create_finding(Severity::High, vec![], None);

    ConfidenceCalculator::recalculate_priority(&mut finding);

    assert!(finding.priority_score.is_some());
}

#[test]
fn test_recalculate_priority_critical_multiplier() {
    let mut finding = create_finding(Severity::Critical, vec![], None);

    ConfidenceCalculator::recalculate_priority(&mut finding);

    // For Critical, priority = confidence * 1.0
    let confidence = finding.confidence_score;
    let priority = finding.priority_score.unwrap();
    assert!((priority - confidence).abs() < 0.001);
}

#[test]
fn test_recalculate_priority_high_multiplier() {
    let mut finding = create_finding(Severity::High, vec![], None);

    ConfidenceCalculator::recalculate_priority(&mut finding);

    // For High, priority = confidence * 0.8
    let confidence = finding.confidence_score;
    let priority = finding.priority_score.unwrap();
    assert!((priority - confidence * 0.8).abs() < 0.001);
}

#[test]
fn test_recalculate_priority_medium_multiplier() {
    let mut finding = create_finding(Severity::Medium, vec![], None);

    ConfidenceCalculator::recalculate_priority(&mut finding);

    // For Medium, priority = confidence * 0.6
    let confidence = finding.confidence_score;
    let priority = finding.priority_score.unwrap();
    assert!((priority - confidence * 0.6).abs() < 0.001);
}

#[test]
fn test_recalculate_priority_low_multiplier() {
    let mut finding = create_finding(Severity::Low, vec![], None);

    ConfidenceCalculator::recalculate_priority(&mut finding);

    // For Low, priority = confidence * 0.4
    let confidence = finding.confidence_score;
    let priority = finding.priority_score.unwrap();
    assert!((priority - confidence * 0.4).abs() < 0.001);
}

#[test]
fn test_recalculate_priority_info_multiplier() {
    let mut finding = create_finding(Severity::Info, vec![], None);

    ConfidenceCalculator::recalculate_priority(&mut finding);

    // For Info, priority = confidence * 0.2
    let confidence = finding.confidence_score;
    let priority = finding.priority_score.unwrap();
    assert!((priority - confidence * 0.2).abs() < 0.001);
}

// ============================================================================
// Edge case tests
// ============================================================================

#[test]
fn test_minimum_score_info_no_sources() {
    let mut finding = create_finding(Severity::Info, vec![], None);
    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    assert!(score >= 0.0);
    assert!(score <= 100.0);
}

#[test]
fn test_maximum_score_all_bonuses() {
    let mut finding = create_finding(
        Severity::Critical,
        vec!["semgrep", "llm"],
        Some(VerificationStatus::Confirmed),
    );
    finding.commit_reference = Some("abc123".to_string());
    finding.ticket_reference = Some("SEC-123".to_string());

    let score = ConfidenceCalculator::calculate_composite(&mut finding);

    // Even with all bonuses, should be clamped to 100
    assert!((score - 100.0).abs() < 0.001);
}

#[test]
fn test_score_always_in_valid_range() {
    let severities = vec![
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    let verification_statuses = vec![
        None,
        Some(VerificationStatus::Confirmed),
        Some(VerificationStatus::FalsePositive),
        Some(VerificationStatus::NeedsReview),
        Some(VerificationStatus::Failed),
    ];

    for severity in severities {
        for status in &verification_statuses {
            let mut finding = create_finding(severity, vec!["semgrep"], *status);
            let score = ConfidenceCalculator::calculate_composite(&mut finding);
            assert!(score >= 0.0, "Score {} should be >= 0", score);
            assert!(score <= 100.0, "Score {} should be <= 100", score);
        }
    }
}

#[test]
fn test_priority_score_always_positive() {
    let severities = vec![
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    for severity in severities {
        let mut finding = create_finding(severity, vec![], None);
        ConfidenceCalculator::recalculate_priority(&mut finding);
        assert!(finding.priority_score.unwrap() >= 0.0);
    }
}
