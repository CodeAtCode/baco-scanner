//! Unit tests for confidence refinement phase.
//!
//! Tests confidence score calculations, refinement factors, and HistoricalData.

use baco::confidence_refinement::{
    ConfidenceFactor, ConfidenceRefinementPhase, HistoricalData, RefinedConfidence,
};
use baco::findings::{Severity, TriageVerdict, VerificationStatus, VulnerabilityFinding};
use tests::fixtures::{create_minimal_finding, create_test_finding};

// ============================================================================
// HistoricalData Tests
// ============================================================================

#[test]
fn test_historical_data_new() {
    let data = HistoricalData::new();

    // Verify default patterns are loaded
    assert!(!data.false_positive_patterns.is_empty());
    assert!(!data.high_confidence_patterns.is_empty());
}

#[test]
fn test_historical_data_matches_false_positive_pattern() {
    let data = HistoricalData::new();

    // CWE-89 with ORM should match false positive pattern
    let code = "User.find_by(name: 'test')";
    assert!(data.matches_false_positive_pattern("CWE-89", code));

    // Random code should not match
    let random_code = "some_random_function()";
    assert!(!data.matches_false_positive_pattern("CWE-89", random_code));
}

#[test]
fn test_historical_data_matches_high_confidence_pattern() {
    let data = HistoricalData::new();

    // CWE-79 with innerHTML should match high confidence pattern
    let code = "element.innerHTML = userInput";
    assert!(data.matches_high_confidence_pattern("CWE-79", code));

    // Safe code should not match
    let safe_code = "element.textContent = userInput";
    assert!(!data.matches_high_confidence_pattern("CWE-79", safe_code));
}

#[test]
fn test_historical_data_check_never_submit_pattern() {
    let data = HistoricalData::new();

    // Missing CSP header should match
    let result = data.check_never_submit_pattern(
        "Missing Header",
        "Content-Security-Policy header not set",
        Some(&"CWE-693".to_string()),
    );
    assert!(result.is_some());

    // Non-matching finding should not match
    let result = data.check_never_submit_pattern(
        "SQL Injection",
        "Direct SQL query",
        Some(&"CWE-89".to_string()),
    );
    assert!(result.is_none());
}

#[test]
fn test_historical_data_record_verification() {
    let mut data = HistoricalData::new();

    data.record_verification("CWE-89", false); // confirmed
    data.record_verification("CWE-89", true); // false positive
    data.record_verification("CWE-89", false); // confirmed

    let stats = data.get_stats("CWE-89");
    assert_eq!(stats.total, 3);
    assert_eq!(stats.confirmed, 2);
    assert_eq!(stats.false_positives, 1);
}

#[test]
fn test_historical_data_get_stats_nonexistent() {
    let data = HistoricalData::new();

    let stats = data.get_stats("CWE-999");
    assert_eq!(stats.total, 0);
    assert_eq!(stats.confirmed, 0);
    assert_eq!(stats.false_positives, 0);
}

// ============================================================================
// ConfidenceRefinementPhase Tests
// ============================================================================

#[test]
fn test_confidence_phase_new() {
    let phase = ConfidenceRefinementPhase::new();

    // Just verify it creates without panic
    let _ = phase.historical_data();
}

#[test]
fn test_confidence_single_source() {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding = create_minimal_finding();
    finding.confidence_score = 0.5;
    finding.sources = vec!["semgrep".to_string()];

    let result = phase.refine_confidence(&finding, &Default::default());

    assert_eq!(result.original_score, 0.5);
    // Single source should not get multi-source boost
    assert!(!result
        .factors
        .contains(&ConfidenceFactor::MultiSourceConfirmation));
}

#[test]
fn test_confidence_multi_source() {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding = create_minimal_finding();
    finding.confidence_score = 0.5;
    finding.sources = vec!["semgrep".to_string(), "bandit".to_string()];

    let result = phase.refine_confidence(&finding, &Default::default());

    // Should get +0.1 for multi-source confirmation
    assert_eq!(result.refined_score, 0.6);
    assert!(result
        .factors
        .contains(&ConfidenceFactor::MultiSourceConfirmation));
}

#[test]
fn test_confidence_cross_file() {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding = create_minimal_finding();
    finding.confidence_score = 0.5;
    finding.cross_file_references = Some(vec!["other_file.rs".to_string()]);

    let result = phase.refine_confidence(&finding, &Default::default());

    // Should get +0.08 for cross-file reachability
    assert_eq!(result.refined_score, 0.58);
    assert!(result
        .factors
        .contains(&ConfidenceFactor::CrossFileReachability));
}

#[test]
fn test_confidence_clamped_max() {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding = create_minimal_finding();
    finding.confidence_score = 0.95;
    finding.sources = vec!["semgrep".to_string(), "bandit".to_string()]; // +0.1
    finding.verification_status = Some(VerificationStatus::Confirmed); // +0.15

    let result = phase.refine_confidence(&finding, &Default::default());

    // Should be clamped to 1.0
    assert_eq!(result.refined_score, 1.0);
}

#[test]
fn test_confidence_clamped_min() {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding = create_minimal_finding();
    finding.confidence_score = 0.1;
    finding.verification_status = Some(VerificationStatus::FalsePositive); // -0.3

    let result = phase.refine_confidence(&finding, &Default::default());

    // Should be clamped to 0.0
    assert_eq!(result.refined_score, 0.0);
}

#[test]
fn test_confidence_false_positive_lowers() {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding = create_minimal_finding();
    finding.confidence_score = 0.8;
    finding.verification_status = Some(VerificationStatus::FalsePositive);

    let result = phase.refine_confidence(&finding, &Default::default());

    // Should be reduced by 0.3
    assert_eq!(result.refined_score, 0.5);
    assert!(result
        .factors
        .contains(&ConfidenceFactor::FalsePositiveDetected));
}

#[test]
fn test_confidence_confirmed_boosts() {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding = create_minimal_finding();
    finding.confidence_score = 0.5;
    finding.verification_status = Some(VerificationStatus::Confirmed);

    let result = phase.refine_confidence(&finding, &Default::default());

    // Should be increased by 0.15
    assert_eq!(result.refined_score, 0.65);
    assert!(result.factors.contains(&ConfidenceFactor::VerifiedByLlm));
}

#[test]
fn test_confidence_test_code_penalty() {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding = create_minimal_finding();
    finding.confidence_score = 0.7;
    finding.file_path = "src/auth_test.rs".to_string();

    let result = phase.refine_confidence(&finding, &Default::default());

    // Should be reduced by 0.1 for test code
    assert_eq!(result.refined_score, 0.6);
    assert!(result.factors.contains(&ConfidenceFactor::TestCodeRelated));
}

#[test]
fn test_confidence_third_party_penalty() {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding = create_minimal_finding();
    finding.confidence_score = 0.7;
    finding.file_path = "node_modules/package/file.js".to_string();

    let result = phase.refine_confidence(&finding, &Default::default());

    // Should be reduced by 0.15 for third-party code
    assert_eq!(result.refined_score, 0.55);
    assert!(result.factors.contains(&ConfidenceFactor::ThirdPartyCode));
}

#[test]
fn test_confidence_low_confidence_source_penalty() {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding = create_minimal_finding();
    finding.confidence_score = 0.7;
    finding.sources = vec!["bandit".to_string()];

    let result = phase.refine_confidence(&finding, &Default::default());

    // Should be reduced by 0.05 for low-confidence source
    assert_eq!(result.refined_score, 0.65);
    assert!(result
        .factors
        .contains(&ConfidenceFactor::LowConfidenceSource));
}

#[test]
fn test_confidence_triage_true_positive() {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding = create_minimal_finding();
    finding.confidence_score = 0.5;
    finding.verification_notes = Some("triage: true_positive confirmed".to_string());

    let result = phase.refine_confidence(&finding, &Default::default());

    // Should be increased by 0.10
    assert_eq!(result.refined_score, 0.6);
    assert!(result
        .factors
        .contains(&ConfidenceFactor::TriageTruePositive));
}

#[test]
fn test_confidence_triage_false_positive() {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding = create_minimal_finding();
    finding.confidence_score = 0.7;
    finding.verification_notes = Some("triage: false_positive identified".to_string());

    let result = phase.refine_confidence(&finding, &Default::default());

    // Should be reduced by 0.25
    assert_eq!(result.refined_score, 0.45);
    assert!(result
        .factors
        .contains(&ConfidenceFactor::TriageFalsePositive));
}

#[test]
fn test_confidence_rationale_validated() {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding = create_minimal_finding();
    finding.confidence_score = 0.5;
    finding.verification_notes = Some("rationale: sound validated by LLM".to_string());

    let result = phase.refine_confidence(&finding, &Default::default());

    // Should be increased by 0.10
    assert_eq!(result.refined_score, 0.6);
    assert!(result
        .factors
        .contains(&ConfidenceFactor::RationaleValidated));
}

#[test]
fn test_confidence_rationale_flawed() {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding = create_minimal_finding();
    finding.confidence_score = 0.7;
    finding.verification_notes = Some("rationale: flawed invalid analysis".to_string());

    let result = phase.refine_confidence(&finding, &Default::default());

    // Should be reduced by 0.20
    assert_eq!(result.refined_score, 0.5);
    assert!(result
        .factors
        .contains(&ConfidenceFactor::RationaleValidated));
}

#[test]
fn test_confidence_never_submit_penalty() {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding = create_minimal_finding();
    finding.confidence_score = 0.8;
    finding.title = "Missing Header".to_string();
    finding.description = "Content-Security-Policy header not set".to_string();
    finding.cwe_id = Some("CWE-693".to_string());

    let result = phase.refine_confidence(&finding, &Default::default());

    // Should be heavily penalized (multiplied by 0.1)
    assert_eq!(result.refined_score, 0.08);
    assert!(result
        .factors
        .iter()
        .any(|f| matches!(f, ConfidenceFactor::NeverSubmitMatch { .. })));
}

#[test]
fn test_confidence_severity_downgrade() {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding = create_minimal_finding();
    finding.confidence_score = 0.7;
    finding.triage_verdict = Some(TriageVerdict::Downgrade {
        original: Severity::High,
        reason: "Theoretical impact".to_string(),
    });

    let result = phase.refine_confidence(&finding, &Default::default());

    // Should be reduced by 0.15
    assert_eq!(result.refined_score, 0.55);
}

// ============================================================================
// apply_refinements Tests
// ============================================================================

#[test]
fn test_apply_refinements_single_finding() {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding = create_minimal_finding();
    finding.confidence_score = 0.5;

    let mut findings = vec![finding];
    let mut refinements = std::collections::HashMap::new();
    refinements.insert(
        findings[0].id.clone(),
        RefinedConfidence {
            original_score: 0.5,
            refined_score: 0.75,
            explanation: vec!["Test refinement".to_string()],
            factors: vec![],
        },
    );

    phase.apply_refinements(&mut findings, &refinements);

    assert_eq!(findings[0].confidence_score, 0.75);
}

#[test]
fn test_apply_refinements_multiple_findings() {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding1 = create_minimal_finding();
    finding1.id = "finding-1".to_string();
    finding1.confidence_score = 0.5;

    let mut finding2 = create_minimal_finding();
    finding2.id = "finding-2".to_string();
    finding2.confidence_score = 0.6;

    let mut findings = vec![finding1, finding2];

    let mut refinements = std::collections::HashMap::new();
    refinements.insert(
        "finding-1".to_string(),
        RefinedConfidence {
            original_score: 0.5,
            refined_score: 0.7,
            explanation: vec![],
            factors: vec![],
        },
    );
    refinements.insert(
        "finding-2".to_string(),
        RefinedConfidence {
            original_score: 0.6,
            refined_score: 0.8,
            explanation: vec![],
            factors: vec![],
        },
    );

    phase.apply_refinements(&mut findings, &refinements);

    assert_eq!(findings[0].confidence_score, 0.7);
    assert_eq!(findings[1].confidence_score, 0.8);
}

#[test]
fn test_apply_refinements_missing_refinement() {
    let phase = ConfidenceRefinementPhase::new();
    let mut finding = create_minimal_finding();
    finding.id = "finding-1".to_string();
    finding.confidence_score = 0.5;

    let mut findings = vec![finding];
    let refinements = std::collections::HashMap::new(); // Empty - no refinements

    phase.apply_refinements(&mut findings, &refinements);

    // Should remain unchanged
    assert_eq!(findings[0].confidence_score, 0.5);
}

// ============================================================================
// analyze_code_context Tests
// ============================================================================

#[test]
fn test_analyze_code_context_empty() {
    let phase = ConfidenceRefinementPhase::new();
    let result = phase.analyze_code_context("");

    // Empty code should not support or contradict
    assert!(!result.supports);
    assert!(!result.contradicts);
}

#[test]
fn test_analyze_code_context_sanitization() {
    let phase = ConfidenceRefinementPhase::new();
    let code = "sanitize(input); escape_html(data);";
    let result = phase.analyze_code_context(code);

    // Sanitization should contradict vulnerability
    assert!(result.contradicts);
}

#[test]
fn test_analyze_code_context_vulnerable_pattern() {
    let phase = ConfidenceRefinementPhase::new();
    let code = "execute(query + userInput);";
    let result = phase.analyze_code_context(code);

    // Direct concatenation should support vulnerability
    assert!(result.supports);
}
