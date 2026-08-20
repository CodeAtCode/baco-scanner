//! Unit tests for src/scanner/phases/other_phases/confidence_aggregation.rs
//!
//! Tests cover confidence scoring phase functionality and confidence refinement.

use baco::analysis_context::AnalysisContext;
use baco::confidence_refinement::{
    normalize_confidence, ConfidenceFactor, ConfidenceRefinementPhase, HistoricalData,
    ProjectBaseline,
};
use baco::config::{NormalizationConfig, NormalizationTier};
use baco::findings::{Severity, TriageVerdict, VerificationStatus, VulnerabilityFinding};
use tempfile::TempDir;

use crate::fixtures::make_aggregation_finding;

// ============================================================================
// Helper Functions
// ============================================================================

fn create_test_finding(
    id: &str,
    title: &str,
    file_path: &str,
    line: u32,
    severity: Severity,
    confidence: f32,
) -> VulnerabilityFinding {
    let mut finding = make_aggregation_finding(
        id,
        severity,
        confidence,
        file_path,
        Some(line),
        Some("CWE-79"),
        None,
    );
    finding.description = format!("Test finding: {}", title);
    finding.title = title.to_string();
    finding.sources = vec!["test".to_string()];
    finding
}

// ============================================================================
// ConfidenceRefinementPhase::new() Tests
// ============================================================================

#[test]
fn test_confidence_refinement_phase_new() {
    let phase = ConfidenceRefinementPhase::new();

    // Just verify it creates successfully
    assert!(phase
        .historical_data()
        .matches_false_positive_pattern("CWE-79", "html_escape"));
}

#[test]
fn test_confidence_refinement_phase_default() {
    let phase = ConfidenceRefinementPhase::default();

    assert!(phase
        .historical_data()
        .matches_false_positive_pattern("CWE-79", "html_escape"));
}

// ============================================================================
// ConfidenceRefinementPhase::run() Tests
// ============================================================================

#[test]
fn test_run_with_empty_findings() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();
    let findings: Vec<VulnerabilityFinding> = vec![];

    let results = phase.run(findings, &context);

    assert!(results.is_empty());
}

#[test]
fn test_run_with_single_finding() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();
    let findings = vec![create_test_finding(
        "f1",
        "Test",
        "test.rs",
        10,
        Severity::Medium,
        0.5,
    )];

    let results = phase.run(findings, &context);

    assert_eq!(results.len(), 1);
    assert!(results.contains_key("f1"));
}

#[test]
fn test_run_preserves_all_finding_ids() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();
    let findings = vec![
        create_test_finding("f1", "Test 1", "test1.rs", 10, Severity::Medium, 0.5),
        create_test_finding("f2", "Test 2", "test2.rs", 20, Severity::High, 0.6),
        create_test_finding("f3", "Test 3", "test3.rs", 30, Severity::Low, 0.4),
    ];

    let results = phase.run(findings, &context);

    assert_eq!(results.len(), 3);
    assert!(results.contains_key("f1"));
    assert!(results.contains_key("f2"));
    assert!(results.contains_key("f3"));
}

// ============================================================================
// Confidence Refinement Factors Tests
// ============================================================================

#[test]
fn test_refinement_with_verified_status_increases_confidence() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_test_finding("f1", "Verified", "test.rs", 10, Severity::Medium, 0.5);
    finding.verification_status = Some(VerificationStatus::Confirmed);

    let results = phase.run(vec![finding], &context);
    let refinement = results.get("f1").unwrap();

    assert!(refinement.refined_score > refinement.original_score);
    assert!(refinement
        .factors
        .contains(&ConfidenceFactor::VerifiedByLlm));
}

#[test]
fn test_refinement_with_false_positive_status_decreases_confidence() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding =
        create_test_finding("f1", "False Positive", "test.rs", 10, Severity::Medium, 0.7);
    finding.verification_status = Some(VerificationStatus::FalsePositive);

    let results = phase.run(vec![finding], &context);
    let refinement = results.get("f1").unwrap();

    assert!(refinement.refined_score < refinement.original_score);
    assert!(refinement
        .factors
        .contains(&ConfidenceFactor::FalsePositiveDetected));
}

#[test]
fn test_refinement_with_multiple_sources_increases_confidence() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding =
        create_test_finding("f1", "Multi-source", "source.rs", 10, Severity::Medium, 0.5);
    finding.sources = vec![
        "semgrep".to_string(),
        "llm".to_string(),
        "manual".to_string(),
    ];

    let results = phase.run(vec![finding], &context);
    let refinement = results.get("f1").unwrap();

    assert!(refinement.refined_score > refinement.original_score);
    assert!(
        refinement
            .factors
            .contains(&ConfidenceFactor::MultiSourceConfirmation),
        "factors: {:?}",
        refinement.factors
    );
}

#[test]
fn test_refinement_with_cross_file_references_increases_confidence() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding =
        create_test_finding("f1", "Cross-file", "source.rs", 10, Severity::Medium, 0.5);
    finding.cross_file_references = Some(vec!["related finding".to_string()]);

    let results = phase.run(vec![finding], &context);
    let refinement = results.get("f1").unwrap();

    assert!(refinement.refined_score > refinement.original_score);
    assert!(refinement
        .factors
        .contains(&ConfidenceFactor::CrossFileReachability));
}

#[test]
fn test_refinement_with_test_file_decreases_confidence() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let finding = create_test_finding("f1", "Test code", "src/test.rs", 10, Severity::Medium, 0.7);

    let results = phase.run(vec![finding], &context);
    let refinement = results.get("f1").unwrap();

    assert!(refinement.refined_score < refinement.original_score);
    assert!(refinement
        .factors
        .contains(&ConfidenceFactor::TestCodeRelated));
}

#[test]
fn test_refinement_with_vendor_file_decreases_confidence() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let finding = create_test_finding(
        "f1",
        "Vendor code",
        "vendor/lib.rs",
        10,
        Severity::Medium,
        0.7,
    );

    let results = phase.run(vec![finding], &context);
    let refinement = results.get("f1").unwrap();

    assert!(refinement.refined_score < refinement.original_score);
    assert!(refinement
        .factors
        .contains(&ConfidenceFactor::ThirdPartyCode));
}

#[test]
fn test_refinement_with_high_severity_boost() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_test_finding(
        "f1",
        "High severity",
        "test.rs",
        10,
        Severity::Critical,
        0.8,
    );
    finding.verification_status = Some(VerificationStatus::Confirmed);

    let results = phase.run(vec![finding], &context);
    let refinement = results.get("f1").unwrap();

    // Should get both verified boost and severity boost
    assert!(refinement.refined_score > refinement.original_score);
}

// ============================================================================
// HistoricalData Tests
// ============================================================================

#[test]
fn test_historical_data_new_with_default_patterns() {
    let data = HistoricalData::new();

    // Should have false positive patterns for CWE-79
    assert!(data.matches_false_positive_pattern("CWE-79", "html_escape"));
    assert!(data.matches_false_positive_pattern("CWE-79", "escape_html"));

    // Should have high confidence patterns for CWE-79
    assert!(data.matches_high_confidence_pattern("CWE-79", "innerHTML"));
    assert!(data.matches_high_confidence_pattern("CWE-79", "dangerouslySetInnerHTML"));
}

#[test]
fn test_historical_data_matches_false_positive_pattern() {
    let data = HistoricalData::new();

    // XSS false positive patterns
    assert!(data.matches_false_positive_pattern("CWE-79", "html_escape(input)"));
    assert!(data.matches_false_positive_pattern("CWE-79", "sanitize_html(data)"));
    assert!(data.matches_false_positive_pattern("CWE-79", "element.textContent = value"));

    // SQL injection false positive patterns
    assert!(data.matches_false_positive_pattern("CWE-89", "ORM.find_by(id)"));
    assert!(data.matches_false_positive_pattern("CWE-89", "prepare_statement(sql)"));
}

#[test]
fn test_historical_data_matches_high_confidence_pattern() {
    let data = HistoricalData::new();

    // XSS high confidence patterns
    assert!(data.matches_high_confidence_pattern("CWE-79", "element.innerHTML = user_input"));
    assert!(data.matches_high_confidence_pattern("CWE-79", "document.write(input)"));

    // SQL injection high confidence patterns
    assert!(data.matches_high_confidence_pattern("CWE-89", "execute(query + param)"));
    assert!(data.matches_high_confidence_pattern("CWE-89", "raw_sql(query)"));
}

#[test]
fn test_historical_data_never_submit_patterns() {
    let data = HistoricalData::new();

    // Should match never-submit patterns
    assert!(data
        .check_never_submit_pattern(
            "Missing security header",
            "Content Security Policy not set",
            Some(&"CWE-693".to_string())
        )
        .is_some());

    assert!(data
        .check_never_submit_pattern(
            "Open redirect",
            "Potential open redirect vulnerability",
            Some(&"CWE-601".to_string())
        )
        .is_some());
}

#[test]
fn test_historical_data_record_verification() {
    let mut data = HistoricalData::new();

    data.record_verification("CWE-79", false); // confirmed
    data.record_verification("CWE-79", true); // false positive
    data.record_verification("CWE-79", false); // confirmed

    let stats = data.get_stats("CWE-79");
    assert_eq!(stats.total, 3);
    assert_eq!(stats.confirmed, 2);
    assert_eq!(stats.false_positives, 1);
}

#[test]
fn test_historical_data_unknown_cwe_returns_default_stats() {
    let data = HistoricalData::new();

    let stats = data.get_stats("CWE-999");
    assert_eq!(stats.total, 0);
    assert_eq!(stats.confirmed, 0);
    assert_eq!(stats.false_positives, 0);
}

// ============================================================================
// Context Analysis Tests
// ============================================================================

#[test]
fn test_analyze_code_context_supports_vulnerability() {
    let phase = ConfidenceRefinementPhase::new();

    let code = "let data = request.param('input'); unsafe_eval(data);";
    let analysis = phase.analyze_code_context(code);

    assert!(analysis.supports);
    assert!(!analysis.contradicts);
}

#[test]
fn test_analyze_code_context_contradicts_vulnerability() {
    let phase = ConfidenceRefinementPhase::new();

    let code = "validate_input(input); sanitize(data); check_auth(user);";
    let analysis = phase.analyze_code_context(code);

    assert!(!analysis.supports);
    assert!(analysis.contradicts);
}

#[test]
fn test_analyze_code_context_neutral() {
    let phase = ConfidenceRefinementPhase::new();

    let code = "let x = 5; let y = 10;";
    let analysis = phase.analyze_code_context(code);

    assert!(!analysis.supports);
    assert!(!analysis.contradicts);
}

// ============================================================================
// ProjectBaseline Tests
// ============================================================================

#[test]
fn test_project_baseline_empty() {
    let baseline = ProjectBaseline::empty();

    assert_eq!(baseline.total_findings, 0);
    assert_eq!(baseline.true_positives, 0);
    assert_eq!(baseline.false_positives, 0);
    assert_eq!(baseline.mean_confidence, 0.0);
    assert_eq!(baseline.false_positive_rate(), 0.0);
    assert_eq!(baseline.std_dev(), 0.0);
}

#[test]
fn test_project_baseline_update() {
    let mut baseline = ProjectBaseline::empty();

    baseline.update(0.8, true); // TP with high confidence
    baseline.update(0.3, false); // FP with low confidence
    baseline.update(0.9, true); // TP with high confidence

    assert_eq!(baseline.total_findings, 3);
    assert_eq!(baseline.true_positives, 2);
    assert_eq!(baseline.false_positives, 1);
    assert!(baseline.mean_confidence > 0.0);
}

#[test]
fn test_project_baseline_save_load() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("baseline.json");

    let mut baseline = ProjectBaseline::empty();
    baseline.update(0.8, true);
    baseline.update(0.3, false);

    baseline.save(&path).unwrap();

    let loaded = ProjectBaseline::load(&path);

    assert_eq!(loaded.total_findings, baseline.total_findings);
    assert_eq!(loaded.true_positives, baseline.true_positives);
    assert_eq!(loaded.false_positives, baseline.false_positives);
}

#[test]
fn test_project_baseline_load_nonexistent_file() {
    let path = std::path::PathBuf::from("/nonexistent/baseline.json");

    let baseline = ProjectBaseline::load(&path);

    assert!(baseline.total_findings == 0);
}

#[test]
fn test_project_baseline_load_invalid_json() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("invalid.json");

    std::fs::write(&path, "invalid json {{{{").unwrap();

    let baseline = ProjectBaseline::load(&path);

    // Should return empty baseline on invalid JSON
    assert_eq!(baseline.total_findings, 0);
}

// ============================================================================
// normalize_confidence Tests
// ============================================================================

#[test]
fn test_normalize_confidence_disabled() {
    let config = NormalizationConfig {
        enabled: false,
        normalization_tier: NormalizationTier::None,
        project_baseline_path: None,
    };
    let baseline = ProjectBaseline::empty();

    let result = normalize_confidence(0.8, &config, &baseline);

    assert_eq!(result, 0.8);
}

#[test]
fn test_normalize_confidence_none_tier() {
    let config = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::None,
        project_baseline_path: None,
    };
    let baseline = ProjectBaseline::empty();

    let result = normalize_confidence(0.8, &config, &baseline);

    assert_eq!(result, 0.8);
}

#[test]
fn test_normalize_confidence_project_relative_high_fp_rate() {
    let config = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::ProjectRelative,
        project_baseline_path: None,
    };

    let mut baseline = ProjectBaseline::empty();
    // Simulate 40% false positive rate
    baseline.update(0.5, true);
    baseline.update(0.3, false);
    baseline.update(0.4, false);
    baseline.update(0.6, false);
    baseline.update(0.7, true);

    let result = normalize_confidence(0.8, &config, &baseline);

    // Should be scaled down due to high FP rate
    assert!(result < 0.8);
}

#[test]
fn test_normalize_confidence_project_relative_low_fp_rate() {
    let config = NormalizationConfig {
        enabled: true,
        normalization_tier: NormalizationTier::ProjectRelative,
        project_baseline_path: None,
    };

    let mut baseline = ProjectBaseline::empty();
    // Simulate 5% false positive rate (5 TP, 0 FP)
    for _ in 0..5 {
        baseline.update(0.7, true);
    }

    let result = normalize_confidence(0.5, &config, &baseline);

    // Should be scaled up due to low FP rate
    assert!(result > 0.5);
    assert!(result <= 1.0);
}

// ============================================================================
// apply_refinements Tests
// ============================================================================

#[test]
fn test_apply_refinements_updates_findings() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_test_finding("f1", "Test", "test.rs", 10, Severity::Medium, 0.5);
    finding.verification_status = Some(VerificationStatus::Confirmed);

    let mut findings = vec![finding];
    let refinements = phase.run(findings.clone(), &context);

    phase.apply_refinements(&mut findings, &refinements);

    let refined = refinements.get("f1").unwrap();
    assert_eq!(findings[0].confidence_score, refined.refined_score);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_refinement_clamps_to_valid_range() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    // Very low initial confidence with FP status
    let mut finding = create_test_finding("f1", "Low", "test.rs", 10, Severity::Low, 0.1);
    finding.verification_status = Some(VerificationStatus::FalsePositive);

    let results = phase.run(vec![finding], &context);
    let refinement = results.get("f1").unwrap();

    assert!(refinement.refined_score >= 0.0);
    assert!(refinement.refined_score <= 1.0);
}

#[test]
fn test_refinement_with_never_submit_pattern_heavily_penalized() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding =
        create_test_finding("f1", "Missing header", "test.rs", 10, Severity::High, 0.9);
    finding.description = "Content Security Policy not configured".to_string();
    finding.cwe_id = Some("CWE-693".to_string());

    let results = phase.run(vec![finding], &context);
    let refinement = results.get("f1").unwrap();

    // Should be heavily penalized (multiplied by 0.1)
    assert!(refinement.refined_score < refinement.original_score * 0.2);
}

#[test]
fn test_refinement_with_triage_true_positive() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_test_finding("f1", "Triaged", "source.rs", 10, Severity::Medium, 0.5);
    finding.verification_notes = Some("triage: true_positive confirmed".to_string());

    let results = phase.run(vec![finding], &context);
    let refinement = results.get("f1").unwrap();

    assert!(refinement.refined_score > refinement.original_score);
    assert!(refinement
        .factors
        .contains(&ConfidenceFactor::TriageTruePositive));
}

#[test]
fn test_refinement_with_triage_false_positive() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_test_finding("f1", "Triaged FP", "test.rs", 10, Severity::Medium, 0.7);
    finding.verification_notes = Some("triage: false_positive identified".to_string());

    let results = phase.run(vec![finding], &context);
    let refinement = results.get("f1").unwrap();

    assert!(refinement.refined_score < refinement.original_score);
    assert!(refinement
        .factors
        .contains(&ConfidenceFactor::TriageFalsePositive));
}

#[test]
fn test_refinement_with_rationale_validated() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding =
        create_test_finding("f1", "Validated", "source.rs", 10, Severity::Medium, 0.5);
    finding.verification_notes = Some("rationale: validated as sound".to_string());

    let results = phase.run(vec![finding], &context);
    let refinement = results.get("f1").unwrap();

    assert!(refinement.refined_score > refinement.original_score);
    assert!(refinement
        .factors
        .contains(&ConfidenceFactor::RationaleValidated));
}

#[test]
fn test_refinement_with_downgrade_triage_verdict() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let mut finding = create_test_finding("f1", "Downgraded", "test.rs", 10, Severity::High, 0.7);
    finding.triage_verdict = Some(TriageVerdict::Downgrade {
        adjusted_severity: Severity::Medium,
    });

    let results = phase.run(vec![finding], &context);
    let refinement = results.get("f1").unwrap();

    assert!(refinement.refined_score < refinement.original_score);
    // Check that severity downgrade factor was applied
    let has_downgrade = refinement.factors.iter().any(|f| matches!(f, ConfidenceFactor::SeverityDowngrade { original_severity, reason: _ } if *original_severity == Severity::High));
    assert!(has_downgrade);
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_full_refinement_workflow() {
    let phase = ConfidenceRefinementPhase::new();
    let context = AnalysisContext::default();

    let findings = vec![
        // Verified finding - should increase
        {
            let mut f = create_test_finding("f1", "Verified", "test.rs", 10, Severity::Medium, 0.5);
            f.verification_status = Some(VerificationStatus::Confirmed);
            f
        },
        // False positive - should decrease
        {
            let mut f =
                create_test_finding("f2", "False Positive", "test.rs", 20, Severity::Medium, 0.7);
            f.verification_status = Some(VerificationStatus::FalsePositive);
            f
        },
        // Multi-source - should increase
        {
            let mut f =
                create_test_finding("f3", "Multi-source", "source.rs", 30, Severity::Medium, 0.5);
            f.sources = vec!["semgrep".to_string(), "llm".to_string()];
            f
        },
        // Test file - should decrease
        { create_test_finding("f4", "Test code", "src/test.rs", 40, Severity::Medium, 0.7) },
    ];

    let refinements = phase.run(findings.clone(), &context);

    // Verify all findings have refinements
    assert_eq!(refinements.len(), 4);

    // f1: Verified - should increase
    assert!(refinements.get("f1").unwrap().refined_score > 0.5);

    // f2: False positive - should decrease
    assert!(refinements.get("f2").unwrap().refined_score < 0.7);

    // f3: Multi-source - should increase
    assert!(refinements.get("f3").unwrap().refined_score > 0.5);

    // f4: Test file - should decrease
    assert!(refinements.get("f4").unwrap().refined_score < 0.7);
}

#[test]
fn test_record_verification_result_updates_history() {
    let mut phase = ConfidenceRefinementPhase::new();

    phase.record_verification_result("CWE-79", false); // confirmed
    phase.record_verification_result("CWE-79", true); // false positive
    phase.record_verification_result("CWE-79", false); // confirmed

    let data = phase.historical_data();
    let stats = data.get_stats("CWE-79");

    assert_eq!(stats.total, 3);
    assert_eq!(stats.confirmed, 2);
    assert_eq!(stats.false_positives, 1);
}
