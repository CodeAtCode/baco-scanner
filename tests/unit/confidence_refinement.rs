//! Unit tests for confidence refinement phase.
//!
//! Tests cover:
//! - Confidence scoring adjustments
//! - Verification impact (Confirmed, FalsePositive, NeedsReview, Failed)
//! - False positive detection via historical patterns
//! - Multi-source confirmation
//! - Cross-file reachability
//! - Severity-based adjustments
//! - Test/third-party code detection
//! - Historical data operations

use baco::confidence_refinement::{
    ConfidenceFactor, ConfidenceRefinementPhase, HistoricalData, RefinedConfidence,
};
use baco::context::AnalysisContext;
use baco::findings::{Severity, VerificationStatus};
use baco::phase::helpers::create_finding_with_params;
use std::collections::HashMap;

/// Creates a finding with custom confidence, file path, and verification status
fn make_finding(
    id: &str,
    confidence: f32,
    file_path: &str,
    verification_status: Option<VerificationStatus>,
) -> baco::findings::VulnerabilityFinding {
    let mut finding = create_finding_with_params(id, "Test finding", Severity::Medium);
    finding.confidence_score = confidence;
    finding.file_path = file_path.to_string();
    finding.sources = Vec::new();
    finding.cross_file_references = None;
    finding.severity = Severity::Medium;
    finding.cwe_id = Some("CWE-79".to_string());
    finding.verification_status = verification_status;
    finding.code_snippet = Some("let x = 1;".to_string());
    finding
}

// ============================================================================
// ConfidenceRefinementPhase Tests
// ============================================================================

#[test]
fn test_phase_creation() {
    let phase = ConfidenceRefinementPhase::new();
    assert_eq!(phase.historical_data().get_stats("CWE-79").total, 0);
}

#[test]
fn test_phase_default() {
    let phase = ConfidenceRefinementPhase::default();
    assert_eq!(phase.historical_data().get_stats("CWE-89").total, 0);
}

#[test]
fn test_verification_confirmed_boosts_confidence() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let finding = make_finding(
        "f1",
        0.8,
        "src/main.rs",
        Some(VerificationStatus::Confirmed),
    );

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    // 0.8 + 0.15 = 0.95
    assert!((refined.refined_score - 0.95).abs() < 0.001);
    assert!(refined.factors.contains(&ConfidenceFactor::VerifiedByLlm));
}

#[test]
fn test_verification_false_positive_reduces_confidence() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let finding = make_finding(
        "f1",
        0.8,
        "src/main.rs",
        Some(VerificationStatus::FalsePositive),
    );

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    // 0.8 - 0.3 = 0.5
    assert!((refined.refined_score - 0.5).abs() < 0.001);
    assert!(refined
        .factors
        .contains(&ConfidenceFactor::FalsePositiveDetected));
}

#[test]
fn test_verification_needs_review_no_change() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let finding = make_finding(
        "f1",
        0.8,
        "src/main.rs",
        Some(VerificationStatus::NeedsReview),
    );

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    // No change for NeedsReview
    assert!((refined.refined_score - 0.8).abs() < 0.001);
}

#[test]
fn test_verification_failed_slight_reduction() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let finding = make_finding("f1", 0.8, "src/main.rs", Some(VerificationStatus::Failed));

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    // 0.8 - 0.1 = 0.7
    assert!((refined.refined_score - 0.7).abs() < 0.001);
}

#[test]
fn test_multi_source_confirmation_boost() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = make_finding(
        "f1",
        0.71,
        "src/main.rs",
        Some(VerificationStatus::NeedsReview),
    );
    finding.sources = vec!["semgrep".to_string(), "llm".to_string()];

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    // 0.71 + 0.1 = 0.81
    assert!((refined.refined_score - 0.81).abs() < 0.001);
    assert!(refined
        .factors
        .contains(&ConfidenceFactor::MultiSourceConfirmation));
}

#[test]
fn test_single_source_no_multi_confirmation() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = make_finding(
        "f1",
        0.71,
        "src/main.rs",
        Some(VerificationStatus::NeedsReview),
    );
    finding.sources = vec!["semgrep".to_string()];

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    // No multi-source boost
    assert!(!refined
        .factors
        .contains(&ConfidenceFactor::MultiSourceConfirmation));
}

#[test]
fn test_cross_file_reachability_boost() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = make_finding(
        "f1",
        0.71,
        "src/main.rs",
        Some(VerificationStatus::NeedsReview),
    );
    finding.cross_file_references = Some(vec!["src/util.rs".to_string()]);

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    // 0.71 + 0.08 = 0.79
    assert!((refined.refined_score - 0.79).abs() < 0.001);
    assert!(refined
        .factors
        .contains(&ConfidenceFactor::CrossFileReachability));
}

#[test]
fn test_test_code_detection() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let finding = make_finding(
        "f1",
        0.8,
        "src/test_utils.rs",
        Some(VerificationStatus::NeedsReview),
    );

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    // 0.8 - 0.1 = 0.7
    assert!((refined.refined_score - 0.7).abs() < 0.001);
    assert!(refined.factors.contains(&ConfidenceFactor::TestCodeRelated));
}

#[test]
fn test_mock_code_detection() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let finding = make_finding(
        "f1",
        0.8,
        "tests/mocks/api_mock.rs",
        Some(VerificationStatus::NeedsReview),
    );

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    assert!(refined.factors.contains(&ConfidenceFactor::TestCodeRelated));
}

#[test]
fn test_vendor_code_reduction() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let finding = make_finding(
        "f1",
        0.8,
        "vendor/serde/src/ser.rs",
        Some(VerificationStatus::NeedsReview),
    );

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    // 0.8 - 0.15 = 0.65
    assert!((refined.refined_score - 0.65).abs() < 0.001);
    assert!(refined.factors.contains(&ConfidenceFactor::ThirdPartyCode));
}

#[test]
fn test_node_modules_reduction() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let finding = make_finding(
        "f1",
        0.8,
        "node_modules/lodash/index.js",
        Some(VerificationStatus::NeedsReview),
    );

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    assert!(refined.factors.contains(&ConfidenceFactor::ThirdPartyCode));
}

#[test]
fn test_low_confidence_source_bandit() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = make_finding(
        "f1",
        0.8,
        "src/main.rs",
        Some(VerificationStatus::NeedsReview),
    );
    finding.sources = vec!["bandit".to_string()];

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    // 0.8 - 0.05 = 0.75
    assert!((refined.refined_score - 0.75).abs() < 0.001);
    assert!(refined
        .factors
        .contains(&ConfidenceFactor::LowConfidenceSource));
}

#[test]
fn test_low_confidence_source_gosec() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = make_finding(
        "f1",
        0.8,
        "src/main.rs",
        Some(VerificationStatus::NeedsReview),
    );
    finding.sources = vec!["gosec".to_string()];

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    assert!((refined.refined_score - 0.75).abs() < 0.001);
    assert!(refined
        .factors
        .contains(&ConfidenceFactor::LowConfidenceSource));
}

#[test]
fn test_severity_boost_high() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = make_finding(
        "f1",
        0.8,
        "src/main.rs",
        Some(VerificationStatus::NeedsReview),
    );
    finding.severity = Severity::High;

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    // 0.8 + 0.05 = 0.85 (high severity with confidence > 0.7)
    assert!((refined.refined_score - 0.85).abs() < 0.001);
    assert!(refined.factors.contains(&ConfidenceFactor::SeverityBoost));
}

#[test]
fn test_severity_no_boost_low_confidence() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = make_finding(
        "f1",
        0.5,
        "src/main.rs",
        Some(VerificationStatus::NeedsReview),
    );
    finding.severity = Severity::High;

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    // No boost because confidence is not > 0.7
    assert!(!refined.factors.contains(&ConfidenceFactor::SeverityBoost));
}

#[test]
fn test_severity_boost_critical() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = make_finding(
        "f1",
        0.9,
        "src/main.rs",
        Some(VerificationStatus::NeedsReview),
    );
    finding.severity = Severity::Critical;

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    assert!(refined.factors.contains(&ConfidenceFactor::SeverityBoost));
}

// ============================================================================
// HistoricalData Tests
// ============================================================================

#[test]
fn test_historical_data_default() {
    let data = HistoricalData::default();
    assert_eq!(data.get_stats("CWE-123").total, 0);
}

#[test]
fn test_historical_data_new() {
    let data = HistoricalData::new();
    assert_eq!(data.get_stats("CWE-79").total, 0);
}

#[test]
fn test_record_verification_confirmed() {
    let mut data = HistoricalData::new();

    data.record_verification("CWE-79", false);
    data.record_verification("CWE-79", false);

    let stats = data.get_stats("CWE-79");
    assert_eq!(stats.total, 2);
    assert_eq!(stats.confirmed, 2);
    assert_eq!(stats.false_positives, 0);
}

#[test]
fn test_record_verification_false_positive() {
    let mut data = HistoricalData::new();

    data.record_verification("CWE-89", true);
    data.record_verification("CWE-89", true);
    data.record_verification("CWE-89", false);

    let stats = data.get_stats("CWE-89");
    assert_eq!(stats.total, 3);
    assert_eq!(stats.confirmed, 1);
    assert_eq!(stats.false_positives, 2);
}

#[test]
fn test_matches_false_positive_pattern_html_escape() {
    let data = HistoricalData::new();

    assert!(data.matches_false_positive_pattern("CWE-79", "html_escape(input)"));
    assert!(data.matches_false_positive_pattern("CWE-79", "escape_html(x)"));
    assert!(data.matches_false_positive_pattern("CWE-79", "sanitize_html(data)"));
}

#[test]
fn test_matches_false_positive_pattern_orm() {
    let data = HistoricalData::new();

    assert!(data.matches_false_positive_pattern("CWE-89", "User.find_by(name: name)"));
    assert!(data.matches_false_positive_pattern("CWE-89", "ORM.query(id)"));
}

#[test]
fn test_matches_false_positive_pattern_path_traversal() {
    let data = HistoricalData::new();

    assert!(data.matches_false_positive_pattern("CWE-22", "normalize_path(base, input)"));
    assert!(data.matches_false_positive_pattern("CWE-22", "realpath(user_input)"));
}

#[test]
fn test_matches_high_confidence_pattern_innerhtml() {
    let data = HistoricalData::new();

    assert!(data.matches_high_confidence_pattern("CWE-79", "element.innerHTML = userInput"));
    assert!(data.matches_high_confidence_pattern("CWE-79", "div.dangerouslySetInnerHTML = html"));
}

#[test]
fn test_matches_high_confidence_pattern_raw_sql() {
    let data = HistoricalData::new();

    assert!(data.matches_high_confidence_pattern("CWE-89", "execute(\"SELECT * \" + query)"));
    assert!(data.matches_high_confidence_pattern("CWE-89", "raw_sql(\"SELECT \" + param)"));
}

#[test]
fn test_no_pattern_match() {
    let data = HistoricalData::new();

    assert!(!data.matches_false_positive_pattern("CWE-79", "some_random_code()"));
    assert!(!data.matches_high_confidence_pattern("CWE-89", "safe_query()"));
}

#[test]
fn test_unknown_cwe_no_stats() {
    let data = HistoricalData::new();

    let stats = data.get_stats("CWE-UNKNOWN");
    assert_eq!(stats.total, 0);
}

// ============================================================================
// Edge Cases and Boundary Conditions
// ============================================================================

#[test]
fn test_confidence_upper_bound_clamp() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = make_finding(
        "f1",
        0.95,
        "src/main.rs",
        Some(VerificationStatus::Confirmed),
    );
    finding.sources = vec!["semgrep".to_string(), "llm".to_string()];

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    // Should be clamped to 1.0
    assert_eq!(refined.refined_score, 1.0);
}

#[test]
fn test_confidence_lower_bound_clamp() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let finding = make_finding(
        "f1",
        0.1,
        "src/main.rs",
        Some(VerificationStatus::FalsePositive),
    );

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    // Should be clamped to 0.0
    assert_eq!(refined.refined_score, 0.0);
}

#[test]
fn test_confidence_zero_input() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let finding = make_finding(
        "f1",
        0.0,
        "src/main.rs",
        Some(VerificationStatus::NeedsReview),
    );

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    assert_eq!(refined.refined_score, 0.0);
}

#[test]
fn test_confidence_one_input() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let finding = make_finding(
        "f1",
        1.0,
        "src/main.rs",
        Some(VerificationStatus::NeedsReview),
    );

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    assert_eq!(refined.refined_score, 1.0);
}

#[test]
fn test_empty_findings_vector() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let refinements = phase.run(vec![], &context);

    assert!(refinements.is_empty());
}

#[test]
fn test_multiple_factors_combined() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = make_finding(
        "f1",
        0.75,
        "src/main.rs",
        Some(VerificationStatus::Confirmed),
    );
    finding.sources = vec!["semgrep".to_string(), "llm".to_string()];
    finding.cross_file_references = Some(vec!["src/util.rs".to_string()]);
    finding.severity = Severity::Critical;

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    // 0.75 + 0.15 (verified) + 0.1 (multi-source) + 0.08 (cross-file) + 0.05 (severity) = 1.13 -> clamped to 1.0
    assert_eq!(refined.refined_score, 1.0);
    assert_eq!(refined.factors.len(), 4);
}

#[test]
fn test_multiple_negative_factors_combined() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = make_finding(
        "f1",
        0.5,
        "vendor/lib/src/code.rs",
        Some(VerificationStatus::FalsePositive),
    );
    finding.sources = vec!["bandit".to_string()];

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    // 0.5 - 0.3 (FP) - 0.15 (vendor) - 0.05 (bandit) = 0.0
    assert_eq!(refined.refined_score, 0.0);
}

#[test]
fn test_explanation_contains_factors() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = make_finding(
        "f1",
        0.8,
        "src/main.rs",
        Some(VerificationStatus::Confirmed),
    );
    finding.sources = vec!["semgrep".to_string(), "llm".to_string()];

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    assert!(refined.explanation.len() >= 2);
}

// ============================================================================
// Apply Refinements Tests
// ============================================================================

#[test]
fn test_apply_refinements_updates_all_findings() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let f1 = make_finding(
        "f1",
        0.8,
        "src/main.rs",
        Some(VerificationStatus::Confirmed),
    );
    let f2 = make_finding(
        "f2",
        0.6,
        "src/main.rs",
        Some(VerificationStatus::NeedsReview),
    );

    let mut findings = vec![f1, f2];
    let refinements = phase.run(findings.clone(), &context);

    phase.apply_refinements(&mut findings, &refinements);

    assert!((findings[0].confidence_score - refinements["f1"].refined_score).abs() < 0.001);
    assert!((findings[1].confidence_score - refinements["f2"].refined_score).abs() < 0.001);
}

#[test]
fn test_apply_refinements_missing_key() {
    let phase = ConfidenceRefinementPhase::new();
    let _context = AnalysisContext::default();

    let finding = make_finding(
        "f1",
        0.8,
        "src/main.rs",
        Some(VerificationStatus::NeedsReview),
    );
    let original_score = finding.confidence_score;

    let mut findings = vec![finding];
    let refinements: HashMap<String, RefinedConfidence> = HashMap::new();

    phase.apply_refinements(&mut findings, &refinements);

    // Should remain unchanged
    assert_eq!(findings[0].confidence_score, original_score);
}

// ============================================================================
// RefinedConfidence Structure Tests
// ============================================================================

#[test]
fn test_refined_confidence_serialization() {
    let refined = RefinedConfidence {
        original_score: 0.8,
        refined_score: 0.9,
        explanation: vec!["Test explanation".to_string()],
        factors: vec![ConfidenceFactor::VerifiedByLlm],
    };

    let json = serde_json::to_string(&refined).unwrap();
    let deserialized: RefinedConfidence = serde_json::from_str(&json).unwrap();

    assert_eq!(refined.original_score, deserialized.original_score);
    assert_eq!(refined.refined_score, deserialized.refined_score);
    assert_eq!(refined.explanation, deserialized.explanation);
    assert_eq!(refined.factors, deserialized.factors);
}

#[test]
fn test_confidence_factor_equality() {
    assert_eq!(
        ConfidenceFactor::VerifiedByLlm,
        ConfidenceFactor::VerifiedByLlm
    );
    assert_ne!(
        ConfidenceFactor::VerifiedByLlm,
        ConfidenceFactor::FalsePositiveDetected
    );
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_full_refinement_pipeline() {
    let mut phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    phase.record_verification_result("CWE-79", false);
    phase.record_verification_result("CWE-79", true);

    let findings = vec![
        make_finding(
            "f1",
            0.7,
            "src/main.rs",
            Some(VerificationStatus::NeedsReview),
        ),
        make_finding(
            "f2",
            0.6,
            "src/main.rs",
            Some(VerificationStatus::NeedsReview),
        ),
    ];

    let refinements = phase.run(findings, &context);

    assert_eq!(refinements.len(), 2);
    for refined in refinements.values() {
        assert!(refined.refined_score >= 0.0);
        assert!(refined.refined_score <= 1.0);
    }
}

#[test]
fn test_cwe_specific_pattern_matching() {
    let data = HistoricalData::new();

    assert!(data.matches_false_positive_pattern("CWE-79", "textContent = x"));
    assert!(!data.matches_false_positive_pattern("CWE-89", "textContent = x"));

    assert!(data.matches_false_positive_pattern("CWE-89", "ActiveRecord.find(id)"));
    assert!(!data.matches_false_positive_pattern("CWE-79", "ActiveRecord.find(id)"));
}

#[test]
fn test_case_insensitive_file_path_check() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let finding = make_finding(
        "f1",
        0.8,
        "SRC/TEST/Utils.RS",
        Some(VerificationStatus::NeedsReview),
    );

    let refinements = phase.run(vec![finding], &context);
    let refined = refinements.get("f1").unwrap();

    assert!(refined.factors.contains(&ConfidenceFactor::TestCodeRelated));
}
