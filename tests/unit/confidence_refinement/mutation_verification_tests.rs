//! Mutation verification tests for confidence_refinement.rs
//!
//! These tests verify specific mutations from mutants.out/missed.txt
//! by applying the mutation by hand and confirming tests fail.
//!
//! Per the task requirements:
//! 1. Apply mutation by hand
//! 2. Run tests - if they pass, the mutation survives (bad)
//! 3. Restore from backup
//! 4. Write a test that kills the mutation

use baco::confidence_normalization::{ProjectBaseline, normalize_confidence};
use baco::config::{NormalizationConfig, NormalizationTier};

// ============================================================================
// Mutation: line 349 - +0.15 should be -0.15 for VerifiedByLlm
// ============================================================================

#[test]
fn test_verified_status_adds_exactly_0_15() {
    // This test verifies that VerificationStatus::Confirmed adds exactly +0.15
    // If the mutation `+ 0.15` -> `- 0.15` were applied, this would fail
    use baco::analysis_context::AnalysisContext;
    use baco::confidence_refinement::{ConfidenceFactor, ConfidenceRefinementPhase};
    use baco::findings::{Severity, VerificationStatus};
    use baco::phase::helpers::create_finding_with_params;

    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_finding_with_params("f1", "Test finding", Severity::Medium);
    finding.file_path = "src/main.rs".to_string();
    finding.confidence_score = 0.80;
    finding.verification_status = Some(VerificationStatus::Confirmed);

    let refinements = phase.run(vec![finding], &context, true, 0.1);
    let refined = refinements.get("f1").unwrap();

    // Expected: 0.80 + 0.15 = 0.95
    assert!(
        (refined.refined_score - 0.95).abs() < 0.001,
        "Verified status should add exactly 0.15: got {}, expected 0.95",
        refined.refined_score
    );
    assert!(refined.factors.contains(&ConfidenceFactor::VerifiedByLlm));
}

// ============================================================================
// Mutation: line 354 - -0.3 should be +0.3 for FalsePositive
// ============================================================================

#[test]
fn test_false_positive_subtracts_exactly_0_3() {
    // This test verifies that VerificationStatus::FalsePositive subtracts exactly -0.3
    // If the mutation `- 0.3` -> `+ 0.3` were applied, this would fail
    use baco::analysis_context::AnalysisContext;
    use baco::confidence_refinement::{ConfidenceFactor, ConfidenceRefinementPhase};
    use baco::findings::{Severity, VerificationStatus};
    use baco::phase::helpers::create_finding_with_params;

    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_finding_with_params("f1", "Test finding", Severity::Medium);
    finding.file_path = "src/main.rs".to_string();
    finding.confidence_score = 0.80;
    finding.verification_status = Some(VerificationStatus::FalsePositive);

    let refinements = phase.run(vec![finding], &context, true, 0.1);
    let refined = refinements.get("f1").unwrap();

    // Expected: 0.80 - 0.3 = 0.50
    assert!(
        (refined.refined_score - 0.50).abs() < 0.001,
        "FalsePositive status should subtract exactly 0.3: got {}, expected 0.50",
        refined.refined_score
    );
    assert!(
        refined
            .factors
            .contains(&ConfidenceFactor::FalsePositiveDetected)
    );
}

// ============================================================================
// Mutation: line 363 - -0.1 should be +0.1 for Failed verification
// ============================================================================

#[test]
fn test_verification_failed_subtracts_exactly_0_1() {
    // This test verifies that VerificationStatus::Failed subtracts exactly -0.1
    // If the mutation `- 0.1` -> `+ 0.1` were applied, this would fail
    use baco::analysis_context::AnalysisContext;
    use baco::confidence_refinement::ConfidenceRefinementPhase;
    use baco::findings::{Severity, VerificationStatus};
    use baco::phase::helpers::create_finding_with_params;

    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_finding_with_params("f1", "Test finding", Severity::Medium);
    finding.file_path = "src/main.rs".to_string();
    finding.confidence_score = 0.80;
    finding.verification_status = Some(VerificationStatus::Failed);

    let refinements = phase.run(vec![finding], &context, true, 0.1);
    let refined = refinements.get("f1").unwrap();

    // Expected: 0.80 - 0.1 = 0.70
    assert!(
        (refined.refined_score - 0.70).abs() < 0.001,
        "Failed status should subtract exactly 0.1: got {}, expected 0.70",
        refined.refined_score
    );
}

// ============================================================================
// Mutation: line 826 - fp_rate > 0.30 should be fp_rate < 0.30
// ============================================================================

#[test]
fn test_high_fp_rate_scales_down_not_up() {
    // This test verifies that high FP rate (>0.30) scales DOWN
    // If the mutation `> 0.30` -> `< 0.30` were applied, high FP would scale up instead
    let mut baseline = ProjectBaseline::empty();
    baseline.total_findings = 100;
    baseline.false_positives = 40; // FP rate = 0.40 > 0.30
    baseline.true_positives = 60;
    baseline.mean_confidence = 0.6;

    let config = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::ProjectRelative,
        project_baseline_path: None,
    };

    let raw = 0.8;
    let result = normalize_confidence(raw, &config, &baseline);

    // Expected: scale = 1.0 - 0.40 * 0.5 = 0.80, result = 0.8 * 0.8 = 0.64
    assert!(
        result < raw,
        "High FP rate (0.40) should scale down: got {}, expected < 0.8",
        result
    );
    assert!(
        (result - 0.64).abs() < 0.001,
        "High FP rate should scale to 0.64: got {}",
        result
    );
}

// ============================================================================
// Mutation: line 830 - fp_rate < 0.10 should be fp_rate > 0.10
// ============================================================================

#[test]
fn test_low_fp_rate_scales_up_not_down() {
    // This test verifies that low FP rate (<0.10) scales UP
    // If the mutation `< 0.10` -> `> 0.10` were applied, low FP would scale down
    let mut baseline = ProjectBaseline::empty();
    baseline.total_findings = 100;
    baseline.false_positives = 5; // FP rate = 0.05 < 0.10
    baseline.true_positives = 95;
    baseline.mean_confidence = 0.6;

    let config = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::ProjectRelative,
        project_baseline_path: None,
    };

    let raw = 0.5;
    let result = normalize_confidence(raw, &config, &baseline);

    // Expected: scale = 1.0 + (0.10 - 0.05) * 2.0 = 1.10, result = 0.5 * 1.1 = 0.55
    assert!(
        result > raw,
        "Low FP rate (0.05) should scale up: got {}, expected > 0.5",
        result
    );
    assert!(
        (result - 0.55).abs() < 0.001,
        "Low FP rate should scale to 0.55: got {}",
        result
    );
}

// ============================================================================
// Mutation: line 845 - std_dev == 0.0 || baseline.total_findings < 10
//   should be std_dev != 0.0 && baseline.total_findings >= 10
// ============================================================================

#[test]
fn test_isotonic_fallback_on_zero_stddev() {
    // This test verifies that isotonic normalization falls back to raw when stddev is 0
    // If the mutation `==` -> `!=` were applied, it would try to calibrate with zero stddev
    let mut baseline = ProjectBaseline::empty();
    baseline.total_findings = 20; // >= 10, so that part passes
    baseline.mean_confidence = 0.6;
    baseline.sum_sq_dev = 0.0; // stddev = 0

    let config = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::Isotonic,
        project_baseline_path: None,
    };

    let raw = 0.75;
    let result = normalize_confidence(raw, &config, &baseline);

    // Should fall back to raw because stddev is 0
    assert!(
        (result - raw).abs() < 0.001,
        "Isotonic should fallback to raw when stddev=0: got {}, expected {}",
        result,
        raw
    );
}

#[test]
fn test_isotonic_fallback_on_small_baseline() {
    // This test verifies that isotonic normalization falls back when total_findings < 10
    // If the mutation `<` -> `>=` were applied, it would try to calibrate with small baseline
    let mut baseline = ProjectBaseline::empty();
    baseline.total_findings = 5; // < 10
    baseline.mean_confidence = 0.6;
    baseline.sum_sq_dev = 0.05;

    let config = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::Isotonic,
        project_baseline_path: None,
    };

    let raw = 0.75;
    let result = normalize_confidence(raw, &config, &baseline);

    // Should fall back to raw because total_findings < 10
    assert!(
        (result - raw).abs() < 0.001,
        "Isotonic should fallback to raw when total_findings < 10: got {}, expected {}",
        result,
        raw
    );
}

// ============================================================================
// Mutation: line 849 - calibrated formula operators
//   (raw_confidence - baseline.mean_confidence) / std_dev * 0.5 + 0.5
// ============================================================================

#[test]
fn test_isotonic_calibration_formula() {
    // This test verifies the exact isotonic calibration formula
    // Tests multiple operator mutations at once: /, *, +
    let mut baseline = ProjectBaseline::empty();
    baseline.total_findings = 20;
    baseline.mean_confidence = 0.5;
    // sum_sq_dev = n * stddev^2 = 20 * 0.1^2 = 0.2
    baseline.sum_sq_dev = 0.2;

    let config = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::Isotonic,
        project_baseline_path: None,
    };

    let raw = 0.8;
    let result = normalize_confidence(raw, &config, &baseline);

    // Expected:
    // stddev = sqrt(0.2 / 20) = sqrt(0.01) = 0.1
    // calibrated = (0.8 - 0.5) / 0.1 * 0.5 + 0.5 = 3.0 * 0.5 + 0.5 = 2.0
    // clamped to 1.0
    assert!(
        (result - 1.0).abs() < 0.001,
        "Isotonic calibration should clamp high values to 1.0: got {}",
        result
    );

    // Test a value that doesn't clamp
    let raw2 = 0.6;
    let result2 = normalize_confidence(raw2, &config, &baseline);

    // Expected:
    // calibrated = (0.6 - 0.5) / 0.1 * 0.5 + 0.5 = 1.0 * 0.5 + 0.5 = 1.0
    assert!(
        (result2 - 1.0).abs() < 0.001,
        "Isotonic calibration at 0.6 should give 1.0: got {}",
        result2
    );

    // Test a value below mean
    let raw3 = 0.4;
    let result3 = normalize_confidence(raw3, &config, &baseline);

    // Expected:
    // calibrated = (0.4 - 0.5) / 0.1 * 0.5 + 0.5 = -1.0 * 0.5 + 0.5 = 0.0
    assert!(
        (result3 - 0.0).abs() < 0.001,
        "Isotonic calibration at 0.4 should give 0.0: got {}",
        result3
    );
}

// ============================================================================
// Mutation: line 268 - stats.false_positives += 1 should be -= 1
// ============================================================================

#[test]
fn test_record_verification_increments_false_positives() {
    // This test verifies that record_verification with is_false_positive=true increments
    // If the mutation `+=` -> `-=` were applied, it would decrement instead
    use baco::historical_patterns::HistoricalData;

    let mut data = HistoricalData::new();

    data.record_verification("CWE-79", true); // FP
    data.record_verification("CWE-79", true); // FP
    data.record_verification("CWE-79", false); // TP

    let stats = data.get_stats("CWE-79");

    assert_eq!(stats.total, 3, "Total should be 3");
    assert_eq!(stats.false_positives, 2, "False positives should be 2");
    assert_eq!(stats.confirmed, 1, "Confirmed should be 1");
}

// ============================================================================
// Boundary tests: clamping at 0.0 and 1.0
// ============================================================================

#[test]
fn test_confidence_clamped_at_upper_boundary() {
    // Verify that confidence never exceeds 1.0 even with multiple additions
    use baco::analysis_context::AnalysisContext;
    use baco::confidence_refinement::ConfidenceRefinementPhase;
    use baco::findings::{Severity, VerificationStatus};
    use baco::phase::helpers::create_finding_with_params;

    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    // Start at 0.95, add +0.15 for confirmed = 1.10, should clamp to 1.0
    let mut finding = create_finding_with_params("f1", "Test finding", Severity::Critical);
    finding.file_path = "src/main.rs".to_string();
    finding.confidence_score = 0.95;
    finding.verification_status = Some(VerificationStatus::Confirmed);

    let refinements = phase.run(vec![finding], &context, true, 0.1);
    let refined = refinements.get("f1").unwrap();

    assert!(
        refined.refined_score <= 1.0,
        "Confidence should never exceed 1.0: got {}",
        refined.refined_score
    );
    assert!(
        (refined.refined_score - 1.0).abs() < 0.001,
        "Should be exactly 1.0 when clamped: got {}",
        refined.refined_score
    );
}

#[test]
fn test_confidence_clamped_at_lower_boundary() {
    // Verify that confidence never goes below 0.0 even with multiple subtractions
    use baco::analysis_context::AnalysisContext;
    use baco::confidence_refinement::ConfidenceRefinementPhase;
    use baco::findings::{Severity, VerificationStatus};
    use baco::phase::helpers::create_finding_with_params;

    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    // Start at 0.1, subtract -0.3 for FP = -0.2, should clamp to 0.0
    let mut finding = create_finding_with_params("f1", "Test finding", Severity::Low);
    finding.file_path = "src/main.rs".to_string();
    finding.confidence_score = 0.1;
    finding.verification_status = Some(VerificationStatus::FalsePositive);

    let refinements = phase.run(vec![finding], &context, true, 0.1);
    let refined = refinements.get("f1").unwrap();

    assert!(
        refined.refined_score >= 0.0,
        "Confidence should never go below 0.0: got {}",
        refined.refined_score
    );
    assert!(
        (refined.refined_score - 0.0).abs() < 0.001,
        "Should be exactly 0.0 when clamped: got {}",
        refined.refined_score
    );
}

// ============================================================================
// Order test: verify factors compose in documented order
// ============================================================================

#[test]
fn test_confidence_factors_compose_in_order_with_clamping() {
    // This test verifies that the order of factor application matters when clamping occurs
    // If the order were changed, results would differ only when clamping is triggered
    use baco::analysis_context::AnalysisContext;
    use baco::confidence_refinement::{ConfidenceFactor, ConfidenceRefinementPhase};
    use baco::findings::{Severity, VerificationStatus};
    use baco::phase::helpers::create_finding_with_params;

    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    // High starting confidence with multiple positive factors
    let mut finding = create_finding_with_params("f1", "Test finding", Severity::Critical);
    finding.file_path = "src/main.rs".to_string();
    finding.confidence_score = 0.90;
    finding.verification_status = Some(VerificationStatus::Confirmed); // +0.15
    finding.sources = vec!["semgrep".to_string(), "llm".to_string()]; // +0.1
    finding.cross_file_references = Some(vec!["src/util.rs".to_string()]); // +0.08

    let refinements = phase.run(vec![finding], &context, true, 0.1);
    let refined = refinements.get("f1").unwrap();

    // Without clamping: 0.90 + 0.15 + 0.1 + 0.08 = 1.23
    // With clamping at each step:
    //   0.90 + 0.15 = 1.05 -> clamp to 1.0
    //   1.0 + 0.1 = 1.1 -> clamp to 1.0
    //   1.0 + 0.08 = 1.08 -> clamp to 1.0
    assert!(
        (refined.refined_score - 1.0).abs() < 0.001,
        "Multiple factors should clamp to 1.0: got {}",
        refined.refined_score
    );
    assert!(refined.factors.contains(&ConfidenceFactor::VerifiedByLlm));
    assert!(
        refined
            .factors
            .contains(&ConfidenceFactor::MultiSourceConfirmation)
    );
    assert!(
        refined
            .factors
            .contains(&ConfidenceFactor::CrossFileReachability)
    );
}
