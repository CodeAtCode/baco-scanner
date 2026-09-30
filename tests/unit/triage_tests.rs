//! Triage estimator tests
//!
//! The threshold decision itself lives in `should_analyze_file` and is covered
//! in `scanner/static_analysis_tests.rs`, `coverage_llm_phase_pure_tests.rs`,
//! `coverage_static_orchestrator_tests.rs` and `triage_rag_tests.rs`, including
//! the boundary at the threshold. The model actually reaching the triage
//! request is covered in `scanner/other_phases_tests.rs`.
//!
//! Three tests that used to live here reimplemented that logic against local
//! arrays and local arithmetic, so they passed no matter what the product did.
//! They are gone rather than rewritten, because the real coverage is elsewhere.

use baco::config::phases::TriageConfig;

#[test]
fn test_triage_default_disabled() {
    // Default config should be disabled
    let config = TriageConfig::default();

    assert!(!config.enabled, "Triage should be disabled by default");
    assert_eq!(
        config.model, "mistral-small",
        "Default model should be mistral-small"
    );
    assert_eq!(config.batch_size, 8, "Default batch_size should be 8");
    assert!(
        (config.suspicion_threshold - 0.35).abs() < 0.001,
        "Default suspicion_threshold should be 0.35"
    );
}

#[test]
fn test_triage_defaults_are_accepted_from_toml() {
    // The defaults above are only useful if they also survive parsing, since
    // that is how every user reaches them.
    let toml_str = r#"
        [triage]
    "#;
    let config: TriageConfig = toml::from_str(toml_str).expect("triage defaults must parse");
    assert!(!config.enabled);
    assert_eq!(config.batch_size, 8);
    assert!((config.suspicion_threshold - 0.35).abs() < 0.001);
}
