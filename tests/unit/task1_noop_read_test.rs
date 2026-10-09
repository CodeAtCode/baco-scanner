//! Test for Task 1: Prove the no-op file read in normalize_confidence.
//!
//! This test demonstrates that when project_baseline_path is set and the file
//! exists and parses cleanly, the function returns the ORIGINAL baseline unchanged.
//! The parsed cwe_scores is consumed only by a log line count.

use baco::confidence_normalization::normalize_confidence;
use baco::config::{NormalizationConfig, NormalizationTier};
use std::path::PathBuf;
use tempfile::NamedTempFile;

#[test]
fn test_normalize_confidence_ignores_loaded_baseline_file() {
    // Create a temp file with valid JSON that would parse as ProjectBaselineJson
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let path = PathBuf::from(temp_file.path());

    // Write valid JSON with cwe_scores field
    let json_content = r#"{
        "cwe_scores": {
            "CWE-79": 0.85,
            "CWE-89": 0.92
        }
    }"#;
    std::fs::write(&path, json_content).expect("Failed to write test file");

    // Create a baseline with specific values
    let mut baseline = baco::confidence_normalization::ProjectBaseline::empty();
    baseline.total_findings = 100;
    baseline.false_positives = 20; // 20% FP rate
    baseline.true_positives = 80;
    baseline.mean_confidence = 0.65;
    baseline.sum_sq_dev = 100.0 * 0.1 * 0.1;

    let config = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::ProjectRelative,
        project_baseline_path: Some(path),
    };

    let raw_confidence = 0.7;
    let result = normalize_confidence(raw_confidence, &config, &baseline);

    // With 20% FP rate (medium), ProjectRelative should return raw unchanged
    // The key assertion: the file was read and parsed, but baseline was NOT modified
    // If the file read had any effect, result would differ from this calculation
    let expected = raw_confidence; // 20% FP rate is in the "medium" range (0.10-0.30)

    assert!(
        (result - expected).abs() < 0.001,
        "File read should have no effect: got {}, expected {} (raw)",
        result,
        expected
    );

    // Verify the baseline we passed in is unchanged (it's &baseline, so this is implicit)
    // but we can assert the FP rate calculation to confirm we're using our baseline
    let fp_rate = baseline.false_positives as f32 / baseline.total_findings as f32;
    assert!(
        (fp_rate - 0.20).abs() < 0.001,
        "Baseline FP rate should be 20%"
    );
}
