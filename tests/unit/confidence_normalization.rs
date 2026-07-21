//! Unit tests for confidence normalization (X.4).
//!
//! Tests per-project confidence calibration based on:
//! Paper: Closing the Gap — arxiv:2412.14306
//!
//! Covers:
//! - NormalizationTier::None returns raw confidence
//! - ProjectRelative scaling based on FP rate
//! - Isotonic calibration with fallback conditions
//! - ProjectBaseline save/load roundtrip
//! - Empty baseline handling

use baco::confidence_refinement::{normalize_confidence, ProjectBaseline};
use baco::config::{NormalizationConfig, NormalizationTier};
use std::path::PathBuf;
use tempfile::NamedTempFile;

// ============================================================================
// Normalization Tier Tests
// ============================================================================

#[test]
fn test_no_normalization_returns_raw() {
    let config = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::None,
        project_baseline_path: None,
    };
    let baseline = ProjectBaseline::empty();

    let result = normalize_confidence(0.8, &config, &baseline);
    assert!(
        (result - 0.8).abs() < 0.001,
        "None tier should return raw confidence"
    );
}

#[test]
fn test_normalization_disabled_returns_raw() {
    let config = NormalizationConfig {
        enabled: false,
        normalization_tier: NormalizationTier::ProjectRelative,
        project_baseline_path: None,
    };
    let baseline = ProjectBaseline::empty();

    let result = normalize_confidence(0.8, &config, &baseline);
    assert!(
        (result - 0.8).abs() < 0.001,
        "Disabled normalization should return raw"
    );
}

// ============================================================================
// Project Relative Normalization Tests
// ============================================================================

#[test]
fn test_project_relative_high_fp_scales_down() {
    // FP rate 40% — should scale down
    let mut baseline = ProjectBaseline::empty();
    baseline.total_findings = 100;
    baseline.false_positives = 40;
    baseline.true_positives = 60;
    baseline.mean_confidence = 0.7;

    let config = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::ProjectRelative,
        project_baseline_path: None,
    };

    let raw = 0.8;
    let result = normalize_confidence(raw, &config, &baseline);

    // fp_rate = 0.4, scale = 1.0 - 0.4 * 0.5 = 0.8
    // expected = 0.8 * 0.8 = 0.64
    let expected = raw * 0.8;
    assert!(
        (result - expected).abs() < 0.001,
        "High FP rate should scale down: got {}, expected {}",
        result,
        expected
    );
    assert!(result < raw, "Scaled confidence should be lower than raw");
}

#[test]
fn test_project_relative_low_fp_scales_up() {
    // FP rate 5% — should scale up
    let mut baseline = ProjectBaseline::empty();
    baseline.total_findings = 100;
    baseline.false_positives = 5;
    baseline.true_positives = 95;
    baseline.mean_confidence = 0.6;

    let config = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::ProjectRelative,
        project_baseline_path: None,
    };

    let raw = 0.5;
    let result = normalize_confidence(raw, &config, &baseline);

    // fp_rate = 0.05, scale = 1.0 + (0.10 - 0.05) * 2.0 = 1.1
    // expected = 0.5 * 1.1 = 0.55
    let expected = raw * 1.1;
    assert!(
        (result - expected).abs() < 0.001,
        "Low FP rate should scale up: got {}, expected {}",
        result,
        expected
    );
    assert!(result > raw, "Scaled confidence should be higher than raw");
}

#[test]
fn test_project_relative_capped_at_one() {
    // FP rate 5% — should scale up but cap at 1.0
    let mut baseline = ProjectBaseline::empty();
    baseline.total_findings = 100;
    baseline.false_positives = 5;
    baseline.true_positives = 95;

    let config = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::ProjectRelative,
        project_baseline_path: None,
    };

    let raw = 0.95;
    let result = normalize_confidence(raw, &config, &baseline);

    // Would be 0.95 * 1.1 = 1.045, but capped at 1.0
    assert!(
        result <= 1.0,
        "Confidence should be capped at 1.0: got {}",
        result
    );
    assert_eq!(result, 1.0, "Should be exactly 1.0 when capped");
}

#[test]
fn test_project_relative_medium_fp_no_adjustment() {
    // FP rate 20% — medium, no adjustment
    let mut baseline = ProjectBaseline::empty();
    baseline.total_findings = 100;
    baseline.false_positives = 20;
    baseline.true_positives = 80;

    let config = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::ProjectRelative,
        project_baseline_path: None,
    };

    let raw = 0.7;
    let result = normalize_confidence(raw, &config, &baseline);

    assert!(
        (result - raw).abs() < 0.001,
        "Medium FP rate should not adjust: got {}, expected {}",
        result,
        raw
    );
}

// ============================================================================
// Isotonic Normalization Tests
// ============================================================================

#[test]
fn test_isotonic_calibrates() {
    // Baseline with known mean and std dev
    let mut baseline = ProjectBaseline::empty();
    baseline.total_findings = 20;
    baseline.mean_confidence = 0.6;
    baseline.sum_sq_dev = 20.0 * 0.1 * 0.1; // std_dev = 0.1

    let config = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::Isotonic,
        project_baseline_path: None,
    };

    let raw = 0.8;
    let result = normalize_confidence(raw, &config, &baseline);

    // calibrated = (0.8 - 0.6) / 0.1 * 0.5 + 0.5 = 2.0 * 0.5 + 0.5 = 1.5 -> clamped to 1.0
    let expected = 1.0;
    assert!(
        (result - expected).abs() < 0.001,
        "Isotonic calibration: got {}, expected {}",
        result,
        expected
    );
}

#[test]
fn test_isotonic_falls_back_with_small_baseline() {
    // <10 findings — should fall back to raw
    let mut baseline = ProjectBaseline::empty();
    baseline.total_findings = 5;
    baseline.mean_confidence = 0.6;
    baseline.sum_sq_dev = 0.05;

    let config = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::Isotonic,
        project_baseline_path: None,
    };

    let raw = 0.75;
    let result = normalize_confidence(raw, &config, &baseline);

    assert!(
        (result - raw).abs() < 0.001,
        "Small baseline should fall back to raw: got {}, expected {}",
        result,
        raw
    );
}

#[test]
fn test_isotonic_falls_back_with_zero_stddev() {
    // All same confidence — std_dev = 0, should fall back to raw
    let mut baseline = ProjectBaseline::empty();
    baseline.total_findings = 15;
    baseline.mean_confidence = 0.7;
    baseline.sum_sq_dev = 0.0;

    let config = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::Isotonic,
        project_baseline_path: None,
    };

    let raw = 0.7;
    let result = normalize_confidence(raw, &config, &baseline);

    assert!(
        (result - raw).abs() < 0.001,
        "Zero stddev should fall back to raw: got {}, expected {}",
        result,
        raw
    );
}

#[test]
fn test_isotonic_clamps_to_range() {
    // Extreme case that would go out of bounds
    let mut baseline = ProjectBaseline::empty();
    baseline.total_findings = 20;
    baseline.mean_confidence = 0.5;
    baseline.sum_sq_dev = 20.0 * 0.05 * 0.05; // std_dev = 0.05

    let config = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::Isotonic,
        project_baseline_path: None,
    };

    // Very low raw confidence
    let raw_low = 0.1;
    let result_low = normalize_confidence(raw_low, &config, &baseline);
    assert!(
        result_low >= 0.0,
        "Low confidence should clamp to >= 0.0: got {}",
        result_low
    );

    // Very high raw confidence
    let raw_high = 0.95;
    let result_high = normalize_confidence(raw_high, &config, &baseline);
    assert!(
        result_high <= 1.0,
        "High confidence should clamp to <= 1.0: got {}",
        result_high
    );
}

// ============================================================================
// ProjectBaseline Save/Load Tests
// ============================================================================

#[test]
fn test_baseline_save_load_roundtrip() {
    let mut baseline = ProjectBaseline::empty();
    baseline.total_findings = 100;
    baseline.true_positives = 70;
    baseline.false_positives = 30;
    baseline.mean_confidence = 0.65;
    baseline.sum_sq_dev = 1.0;

    // Create a temporary file
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let path = PathBuf::from(temp_file.path());

    // Save
    baseline.save(&path).expect("Failed to save baseline");

    // Load
    let loaded = ProjectBaseline::load(&path);

    // Verify
    assert_eq!(loaded.total_findings, baseline.total_findings);
    assert_eq!(loaded.true_positives, baseline.true_positives);
    assert_eq!(loaded.false_positives, baseline.false_positives);
    assert!((loaded.mean_confidence - baseline.mean_confidence).abs() < 0.001);
    assert!((loaded.sum_sq_dev - baseline.sum_sq_dev).abs() < 0.001);
}

#[test]
fn test_baseline_load_nonexistent_file_returns_empty() {
    let path = PathBuf::from("/tmp/nonexistent_baseline_12345.json");
    let baseline = ProjectBaseline::load(&path);

    assert_eq!(baseline, ProjectBaseline::empty());
}

#[test]
fn test_baseline_load_invalid_json_returns_empty() {
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let path = PathBuf::from(temp_file.path());

    // Write invalid JSON
    std::fs::write(&path, "not valid json {{{").expect("Failed to write test file");

    let baseline = ProjectBaseline::load(&path);

    assert_eq!(baseline, ProjectBaseline::empty());
}

// ============================================================================
// Empty Baseline Tests
// ============================================================================

#[test]
fn test_empty_baseline() {
    let baseline = ProjectBaseline::empty();

    assert_eq!(baseline.total_findings, 0);
    assert_eq!(baseline.true_positives, 0);
    assert_eq!(baseline.false_positives, 0);
    assert_eq!(baseline.mean_confidence, 0.0);
    assert_eq!(baseline.sum_sq_dev, 0.0);
    assert_eq!(baseline.false_positive_rate(), 0.0);
    assert_eq!(baseline.std_dev(), 0.0);
}

#[test]
fn test_empty_baseline_normalization() {
    // Empty baseline should handle all tiers gracefully
    let baseline = ProjectBaseline::empty();

    // None tier
    let config_none = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::None,
        project_baseline_path: None,
    };
    assert_eq!(normalize_confidence(0.8, &config_none, &baseline), 0.8);

    // ProjectRelative with empty baseline (fp_rate = 0)
    let config_rel = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::ProjectRelative,
        project_baseline_path: None,
    };
    // fp_rate = 0 < 0.10, so scale up
    let result = normalize_confidence(0.5, &config_rel, &baseline);
    assert!(
        result > 0.5,
        "Empty baseline should scale up (treated as low FP)"
    );

    // Isotonic with empty baseline (<10 findings)
    let config_iso = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::Isotonic,
        project_baseline_path: None,
    };
    assert_eq!(
        normalize_confidence(0.7, &config_iso, &baseline),
        0.7,
        "Empty baseline should fall back to raw for Isotonic"
    );
}

// ============================================================================
// Baseline Update Tests
// ============================================================================

#[test]
fn test_baseline_update_accumulates() {
    let mut baseline = ProjectBaseline::empty();

    baseline.update(0.9, true);
    baseline.update(0.8, true);
    baseline.update(0.3, false);
    baseline.update(0.7, true);

    assert_eq!(baseline.total_findings, 4);
    assert_eq!(baseline.true_positives, 3);
    assert_eq!(baseline.false_positives, 1);

    // Mean should be approximately (0.9 + 0.8 + 0.3 + 0.7) / 4 = 0.675
    assert!((baseline.mean_confidence - 0.675).abs() < 0.01);
}

#[test]
fn test_baseline_fp_rate_calculation() {
    let mut baseline = ProjectBaseline::empty();

    baseline.total_findings = 100;
    baseline.false_positives = 25;

    assert!((baseline.false_positive_rate() - 0.25).abs() < 0.001);

    // Edge case: no findings
    baseline.total_findings = 0;
    baseline.false_positives = 0;
    assert_eq!(baseline.false_positive_rate(), 0.0);
}

#[test]
fn test_baseline_std_dev_calculation() {
    let mut baseline = ProjectBaseline::empty();

    // With 20 findings and known variance
    baseline.total_findings = 20;
    baseline.sum_sq_dev = 20.0 * 0.1 * 0.1; // variance = 0.01, std_dev = 0.1

    assert!((baseline.std_dev() - 0.1).abs() < 0.001);

    // Edge case: single finding
    baseline.total_findings = 1;
    assert_eq!(baseline.std_dev(), 0.0);

    // Edge case: no findings
    baseline.total_findings = 0;
    assert_eq!(baseline.std_dev(), 0.0);
}
