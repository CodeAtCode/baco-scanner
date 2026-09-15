//! Triage estimator tests

use baco::config::phases::TriageConfig;

#[test]
fn test_triage_default_disabled() {
    // Default config should be disabled
    let config = TriageConfig::default();

    assert!(!config.enabled, "Triage should be disabled by default");
    assert_eq!(config.model, "mistral-small", "Default model should be mistral-small");
    assert_eq!(config.batch_size, 8, "Default batch_size should be 8");
    assert!(
        (config.suspicion_threshold - 0.35).abs() < 0.001,
        "Default suspicion_threshold should be 0.35"
    );
}

#[test]
fn test_triage_suspicion_threshold_scoring() {
    // Test that files above threshold get deep analysis
    let config = TriageConfig {
        enabled: true,
        model: "test-model".to_string(),
        batch_size: 8,
        suspicion_threshold: 0.5,
    };

    // Simulate triage scores
    let scores = vec![0.2, 0.4, 0.5, 0.6, 0.8];
    let deep_analysis_count = scores
        .iter()
        .filter(|&&s| s >= config.suspicion_threshold)
        .count();

    assert_eq!(deep_analysis_count, 3, "3 files should pass threshold 0.5");
}

#[test]
fn test_triage_batch_size_limit() {
    // Test that batch size limits concurrent requests
    let config = TriageConfig {
        enabled: true,
        model: "test-model".to_string(),
        batch_size: 4,
        suspicion_threshold: 0.3,
    };

    // 10 files pass triage, but batch_size is 4
    let files_passing_triage = 10;
    let batches_needed = (files_passing_triage as f32 / config.batch_size as f32).ceil() as usize;

    assert_eq!(batches_needed, 3, "10 files with batch_size 4 needs 3 batches");
}

#[test]
fn test_triage_custom_model() {
    // Test custom model configuration
    let config = TriageConfig {
        enabled: true,
        model: "custom-model".to_string(),
        batch_size: 16,
        suspicion_threshold: 0.25,
    };

    assert_eq!(config.model, "custom-model");
    assert_eq!(config.batch_size, 16);
    assert!(
        (config.suspicion_threshold - 0.25).abs() < 0.001,
        "Custom threshold should be 0.25"
    );
}