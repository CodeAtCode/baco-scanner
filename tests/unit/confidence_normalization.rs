//! Unit tests for confidence normalization.
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
fn test_normalization_disabled_various_cases() {
    let test_cases = vec![
        (
            "none_tier",
            NormalizationConfig {
                enabled: true,
                normalization_tier: NormalizationTier::None,
                project_baseline_path: None,
            },
            0.8,
            0.8,
        ),
        (
            "disabled",
            NormalizationConfig {
                enabled: false,
                normalization_tier: NormalizationTier::ProjectRelative,
                project_baseline_path: None,
            },
            0.8,
            0.8,
        ),
    ];

    for (name, config, input, expected) in test_cases {
        let baseline = ProjectBaseline::empty();
        let result = normalize_confidence(input, &config, &baseline);
        assert!(
            (result - expected).abs() < 0.001,
            "{} should return raw: got {}, expected {}",
            name,
            result,
            expected
        );
    }
}

// ============================================================================
// Project Relative Normalization Tests
// ============================================================================

#[test]
fn test_project_relative_fp_rate_scaling() {
    let test_cases = vec![
        (
            "high_fp_scales_down",
            (100, 40, 60, 0.7),
            0.8,
            0.64,
            "High FP rate should scale down",
        ),
        (
            "low_fp_scales_up",
            (100, 5, 95, 0.6),
            0.5,
            0.55,
            "Low FP rate should scale up",
        ),
        (
            "medium_fp_no_adjustment",
            (100, 20, 80, 0.6),
            0.7,
            0.7,
            "Medium FP rate should not adjust",
        ),
    ];

    for (name, (total, fp, tp, _mean), raw, expected, description) in test_cases {
        let mut baseline = ProjectBaseline::empty();
        baseline.total_findings = total;
        baseline.false_positives = fp;
        baseline.true_positives = tp;
        baseline.mean_confidence = _mean;

        let config = NormalizationConfig {
            enabled: true,
            normalization_tier: NormalizationTier::ProjectRelative,
            project_baseline_path: None,
        };

        let result = normalize_confidence(raw, &config, &baseline);
        assert!(
            (result - expected).abs() < 0.001,
            "{}: got {}, expected {}. {}",
            name,
            result,
            expected,
            description
        );
    }
}

#[test]
fn test_project_relative_capped_at_one() {
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

    assert!(
        result <= 1.0,
        "Confidence should be capped at 1.0: got {}",
        result
    );
    assert_eq!(result, 1.0, "Should be exactly 1.0 when capped");
}

// ============================================================================
// Isotonic Normalization Tests
// ============================================================================

#[test]
fn test_isotonic_various_cases() {
    let test_cases = vec![
        (
            "calibrates",
            (20, 0.6, 20.0 * 0.1 * 0.1),
            0.8,
            1.0,
            "Isotonic calibration should work",
        ),
        (
            "small_baseline_fallback",
            (5, 0.6, 0.05),
            0.75,
            0.75,
            "Small baseline should fall back to raw",
        ),
        (
            "zero_stddev_fallback",
            (15, 0.7, 0.0),
            0.7,
            0.7,
            "Zero stddev should fall back to raw",
        ),
    ];

    for (name, (total, mean, sum_sq_dev), raw, expected, description) in test_cases {
        let mut baseline = ProjectBaseline::empty();
        baseline.total_findings = total;
        baseline.mean_confidence = mean;
        baseline.sum_sq_dev = sum_sq_dev;

        let config = NormalizationConfig {
            enabled: true,
            normalization_tier: NormalizationTier::Isotonic,
            project_baseline_path: None,
        };

        let result = normalize_confidence(raw, &config, &baseline);
        assert!(
            (result - expected).abs() < 0.001,
            "{}: got {}, expected {}. {}",
            name,
            result,
            expected,
            description
        );
    }
}

#[test]
fn test_isotonic_clamps_to_range() {
    let mut baseline = ProjectBaseline::empty();
    baseline.total_findings = 20;
    baseline.mean_confidence = 0.5;
    baseline.sum_sq_dev = 20.0 * 0.05 * 0.05;

    let config = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::Isotonic,
        project_baseline_path: None,
    };

    let test_cases = vec![
        ("low", 0.1, 0.0, "Low confidence should clamp to >= 0.0"),
        ("high", 0.95, 1.0, "High confidence should clamp to <= 1.0"),
    ];

    for (name, raw, boundary, description) in test_cases {
        let result = normalize_confidence(raw, &config, &baseline);
        assert!(
            (result - boundary).abs() < 0.001
                || (boundary == 0.0 && result >= 0.0)
                || (boundary == 1.0 && result <= 1.0),
            "{}: {} should be at boundary {}: got {}",
            name,
            description,
            boundary,
            result
        );
    }
}

// ============================================================================
// ProjectBaseline Save/Load Tests
// ============================================================================

#[test]
fn test_baseline_save_load_various_cases() {
    let test_cases = vec![
        ("roundtrip", Some((100, 70, 30, 0.65, 1.0)), true),
        ("nonexistent_file", None, true),
        ("invalid_json", None, true),
    ];

    for (name, data, _should_succeed) in test_cases {
        match name {
            "roundtrip" => {
                let (total, tp, fp, mean, sum_sq) = data.unwrap();
                let mut baseline = ProjectBaseline::empty();
                baseline.total_findings = total;
                baseline.true_positives = tp;
                baseline.false_positives = fp;
                baseline.mean_confidence = mean;
                baseline.sum_sq_dev = sum_sq;

                let temp_file = NamedTempFile::new().expect("Failed to create temp file");
                let path = PathBuf::from(temp_file.path());

                baseline.save(&path).expect("Failed to save baseline");
                let loaded = ProjectBaseline::load(&path);

                assert_eq!(loaded.total_findings, baseline.total_findings);
                assert_eq!(loaded.true_positives, baseline.true_positives);
                assert_eq!(loaded.false_positives, baseline.false_positives);
                assert!((loaded.mean_confidence - baseline.mean_confidence).abs() < 0.001);
                assert!((loaded.sum_sq_dev - baseline.sum_sq_dev).abs() < 0.001);
            }
            "nonexistent_file" => {
                let path = PathBuf::from("/tmp/nonexistent_baseline_12345.json");
                let baseline = ProjectBaseline::load(&path);
                assert_eq!(baseline, ProjectBaseline::empty());
            }
            "invalid_json" => {
                let temp_file = NamedTempFile::new().expect("Failed to create temp file");
                let path = PathBuf::from(temp_file.path());

                std::fs::write(&path, "not valid json {{{").expect("Failed to write test file");

                let baseline = ProjectBaseline::load(&path);
                assert_eq!(baseline, ProjectBaseline::empty());
            }
            _ => panic!("Unknown test case: {}", name),
        }
    }
}

// ============================================================================
// Empty Baseline Tests
// ============================================================================

#[test]
fn test_empty_baseline_various_cases() {
    let baseline = ProjectBaseline::empty();

    // Test field initialization
    assert_eq!(baseline.total_findings, 0);
    assert_eq!(baseline.true_positives, 0);
    assert_eq!(baseline.false_positives, 0);
    assert_eq!(baseline.mean_confidence, 0.0);
    assert_eq!(baseline.sum_sq_dev, 0.0);
    assert_eq!(baseline.false_positive_rate(), 0.0);
    assert_eq!(baseline.std_dev(), 0.0);

    // Test normalization behavior with empty baseline
    let config_none = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::None,
        project_baseline_path: None,
    };
    assert_eq!(normalize_confidence(0.8, &config_none, &baseline), 0.8);

    let config_rel = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::ProjectRelative,
        project_baseline_path: None,
    };
    let result = normalize_confidence(0.5, &config_rel, &baseline);
    assert!(
        result > 0.5,
        "Empty baseline should scale up (treated as low FP)"
    );

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
fn test_baseline_update_and_calculation() {
    let mut baseline = ProjectBaseline::empty();

    baseline.update(0.9, true);
    baseline.update(0.8, true);
    baseline.update(0.3, false);
    baseline.update(0.7, true);

    assert_eq!(baseline.total_findings, 4);
    assert_eq!(baseline.true_positives, 3);
    assert_eq!(baseline.false_positives, 1);

    assert!((baseline.mean_confidence - 0.675).abs() < 0.01);
}

#[test]
fn test_baseline_edge_cases() {
    let mut baseline = ProjectBaseline::empty();

    // FP rate calculation
    baseline.total_findings = 100;
    baseline.false_positives = 25;
    assert!((baseline.false_positive_rate() - 0.25).abs() < 0.001);

    // Edge case: no findings
    baseline.total_findings = 0;
    baseline.false_positives = 0;
    assert_eq!(baseline.false_positive_rate(), 0.0);

    // Std dev calculation
    baseline.total_findings = 20;
    baseline.sum_sq_dev = 20.0 * 0.1 * 0.1;
    assert!((baseline.std_dev() - 0.1).abs() < 0.001);

    // Edge case: single finding
    baseline.total_findings = 1;
    assert_eq!(baseline.std_dev(), 0.0);

    // Edge case: no findings
    baseline.total_findings = 0;
    assert_eq!(baseline.std_dev(), 0.0);
}
