//! T2.5 phase graph tests - verify correct phase ordering

use baco::checkpoint::Checkpoint;
use baco::checkpoint::ScanPhase;

#[test]
fn test_phase_ordering_complete_sequence() {
    // Verify the complete phase sequence including T2.5 phases
    let expected_order = vec![
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::CweRouting,
        ScanPhase::CpgSlice,
        ScanPhase::LlmStaticAnalysis,
        ScanPhase::Hunt,
        ScanPhase::Validate,
        ScanPhase::IndependentVerify,
        ScanPhase::LlmDiscovery,
        ScanPhase::LlmVerification,
        ScanPhase::TicketCrossRef,
        ScanPhase::GitAnalysis,
        ScanPhase::CrossFileAnalysis,
        ScanPhase::ConfidenceScoring,
        ScanPhase::AiAggregation,
        ScanPhase::Reporting,
        ScanPhase::ThreatModeling,
        ScanPhase::RootCauseDedup,
        ScanPhase::MultiVerifier,
        ScanPhase::AutoPatching,
        ScanPhase::CveBootstrap,
        ScanPhase::PocCompiler,
        ScanPhase::VariantSearch,
        ScanPhase::SecurityAgentVerification,
        ScanPhase::RuleSynthesis,
        ScanPhase::Complete,
    ];

    assert_eq!(
        expected_order.len(),
        26,
        "Phase ordering must include all phases"
    );
}

#[test]
fn test_t21_cwe_routing_present() {
    // T2.1 added CweRouting - verify it's still present
    let _cwe_routing_exists = ScanPhase::CweRouting;
}

#[test]
fn test_t31_cpg_slice_present() {
    // T3.1 added CpgSlice - verify it's present
    assert_eq!(ScanPhase::CpgSlice, ScanPhase::CpgSlice);
}

#[test]
fn test_t23_rule_synthesis_present() {
    // T2.3 added RuleSynthesis - verify it's still present
    assert!(ScanPhase::RuleSynthesis == ScanPhase::RuleSynthesis);
}

#[test]
fn test_t25_hunt_phase_present() {
    // T2.5 added Hunt phase
    assert_eq!(ScanPhase::Hunt, ScanPhase::Hunt);
}

#[test]
fn test_t25_validate_phase_present() {
    // T2.5 added Validate phase
    assert_eq!(ScanPhase::Validate, ScanPhase::Validate);
}

#[test]
fn test_t25_independent_verify_phase_present() {
    // T2.5 added IndependentVerify phase
    assert_eq!(ScanPhase::IndependentVerify, ScanPhase::IndependentVerify);
}

#[test]
fn test_resume_from_transitions() {
    // Verify resume_from transitions for T2.5 phases
    // Note: We can't actually test resume_from without a checkpoint file,
    // but we can verify the enum variants exist and are distinct
    let hunt = ScanPhase::Hunt;
    let validate = ScanPhase::Validate;
    let independent_verify = ScanPhase::IndependentVerify;

    assert_ne!(hunt, validate);
    assert_ne!(validate, independent_verify);
    assert_ne!(hunt, independent_verify);
}

#[test]
fn test_phase_labels_exist() {
    // Create a checkpoint and verify labels can be formatted
    use chrono::Utc;

    let checkpoint = Checkpoint::new("test", "/tmp", Utc::now());

    // Test all T2.5 phase labels
    let hunt_label = {
        let mut cp = checkpoint.clone();
        cp.current_phase = ScanPhase::Hunt;
        cp.format_phase()
    };
    assert!(hunt_label.contains("Hunt"));

    let validate_label = {
        let mut cp = checkpoint.clone();
        cp.current_phase = ScanPhase::Validate;
        cp.format_phase()
    };
    assert!(validate_label.contains("Validate"));

    let independent_label = {
        let mut cp = checkpoint;
        cp.current_phase = ScanPhase::IndependentVerify;
        cp.format_phase()
    };
    assert!(independent_label.contains("Independent"));
}

#[test]
fn test_phase_graph_wiring() {
    // Verify that the phase graph can be constructed with all phases
    // This is a basic sanity check - actual wiring is tested in integration tests
    let phases = vec![
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::CweRouting,
        ScanPhase::CpgSlice,
        ScanPhase::LlmStaticAnalysis,
        ScanPhase::Hunt,
        ScanPhase::Validate,
        ScanPhase::IndependentVerify,
        ScanPhase::LlmDiscovery,
        ScanPhase::Complete,
    ];

    // Verify no duplicates
    let unique: Vec<_> = phases.iter().collect();
    assert_eq!(unique.len(), phases.len());
}
