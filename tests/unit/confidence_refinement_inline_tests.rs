//! Inline tests moved from src/confidence_refinement.rs (formerly the `#[cfg(test)] mod tests` block).
//!
//! These tests exercise the public API of the confidence refinement phase.
//! Tests that referenced private fields of `ContextAnalysis` are commented out
//! and noted in the report — they cannot be moved to an external test file
//! without making those fields `pub` in the source module.

#[cfg(test)]
mod tests {
    use baco::analysis_context::AnalysisContext;
    use baco::confidence_refinement::{
        ConfidenceFactor, ConfidenceRefinementPhase, HistoricalData,
    };
    use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
    use baco::phase::helpers::create_finding_with_params;

    #[test]
    fn test_refine_confidence_verified() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::High);
        finding.verification_status = Some(VerificationStatus::Confirmed);

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!(refined.refined_score > refined.original_score);
        assert!(refined.factors.contains(&ConfidenceFactor::VerifiedByLlm));
    }

    #[test]
    fn test_refine_confidence_false_positive() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::High);
        finding.verification_status = Some(VerificationStatus::FalsePositive);

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!(refined.refined_score < refined.original_score);
        assert!(refined
            .factors
            .contains(&ConfidenceFactor::FalsePositiveDetected));
    }

    #[test]
    fn test_refine_confidence_multi_source() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::Medium);
        finding.sources = vec!["semgrep".to_string(), "llm".to_string()];

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!(refined
            .factors
            .contains(&ConfidenceFactor::MultiSourceConfirmation));
    }

    #[test]
    fn test_refine_confidence_test_code() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let finding = create_finding_with_params("f1", "Test finding", Severity::High);

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!(refined.factors.contains(&ConfidenceFactor::TestCodeRelated));
    }

    #[test]
    fn test_refine_confidence_vendor_code() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::High);
        finding.file_path = "vendor/some-lib/lib.rs".to_string();

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!(refined.factors.contains(&ConfidenceFactor::ThirdPartyCode));
    }

    #[test]
    fn test_refine_confidence_cross_file() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::High);
        finding.cross_file_references = Some(vec!["src/util.rs".to_string()]);

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!(refined
            .factors
            .contains(&ConfidenceFactor::CrossFileReachability));
    }

    #[test]
    fn test_historical_false_positive_patterns() {
        let data = HistoricalData::new();

        assert!(data.matches_false_positive_pattern("CWE-79", "some_function(html_escape(x))"));
        assert!(data.matches_false_positive_pattern("CWE-89", "User.find_by(name: name)"));
    }

    #[test]
    fn test_historical_high_confidence_patterns() {
        let data = HistoricalData::new();

        assert!(data.matches_high_confidence_pattern("CWE-79", "element.innerHTML = userInput"));
    }

    #[test]
    fn test_confidence_clamped_to_range() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let finding = create_finding_with_params("f1", "Test finding", Severity::Critical);

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!(refined.refined_score <= 1.0);

        let finding2 = create_finding_with_params("f2", "Test finding", Severity::Low);

        let refinements2 = phase.run(vec![finding2], &context);
        let refined2 = refinements2.get("f2").unwrap();

        assert!(refined2.refined_score >= 0.0);
    }

    #[test]
    fn test_apply_refinements() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let finding = create_finding_with_params("f1", "Test finding", Severity::High);

        let mut findings = vec![finding];
        let refinements = phase.run(findings.clone(), &context);

        phase.apply_refinements(&mut findings, &refinements);

        assert_eq!(
            findings[0].confidence_score,
            refinements["f1"].refined_score
        );
    }

    // NOTE: `test_context_analysis_supports` is commented out because it reads the
    // private fields `ContextAnalysis.supports` / `ContextAnalysis.contradicts`,
    // which are not accessible from an external test file.
    //
    // #[test]
    // fn test_context_analysis_supports() {
    //     let phase = ConfidenceRefinementPhase::new();
    //     let code = "user_input = request.params.input; eval(user_input)";
    //
    //     let analysis = phase.analyze_code_context(code);
    //
    //     assert!(analysis.supports);
    //     assert!(!analysis.contradicts);
    // }

    // NOTE: `test_context_analysis_contradicts` is commented out for the same reason:
    // it reads private fields of `ContextAnalysis`.
    //
    // #[test]
    // fn test_context_analysis_contradicts() {
    //     let phase = ConfidenceRefinementPhase::new();
    //     let code = "user_input = sanitize(input); preparedStatement.execute(user_input)";
    //
    //     let analysis = phase.analyze_code_context(code);
    //
    //     assert!(!analysis.supports);
    //     assert!(analysis.contradicts);
    // }

    #[test]
    fn test_record_verification() {
        let mut phase = ConfidenceRefinementPhase::new();

        phase.record_verification_result("CWE-79", false);
        phase.record_verification_result("CWE-79", false);
        phase.record_verification_result("CWE-79", true);

        let stats = phase.historical_data().get_stats("CWE-79");
        assert_eq!(stats.total, 3);
        assert_eq!(stats.confirmed, 2);
        assert_eq!(stats.false_positives, 1);
    }

    #[test]
    fn test_multiple_findings_refinement() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut f3 = create_finding_with_params("f3", "Test finding", Severity::Critical);
        f3.file_path = "src/main.rs".to_string();

        let findings = vec![
            create_finding_with_params("f1", "Test finding", Severity::High),
            create_finding_with_params("f2", "Test finding", Severity::Medium),
            f3,
        ];

        let refinements = phase.run(findings, &context);

        assert_eq!(refinements.len(), 3);
        assert!(refinements["f3"].refined_score > refinements["f3"].original_score);
    }

    #[test]
    fn test_confidence_boost_calculation_exact_values() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let finding = create_finding_with_params("f1", "Test finding", Severity::Medium);
        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!((refined.original_score - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_multi_source_exact_boost() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::Medium);
        finding.file_path = "src/main.rs".to_string();
        finding.sources = vec!["semgrep".to_string(), "llm".to_string()];

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!((refined.refined_score - 0.9).abs() < 0.01);
        assert!(refined
            .factors
            .contains(&ConfidenceFactor::MultiSourceConfirmation));
    }

    #[test]
    fn test_cross_file_exact_boost() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::Medium);
        finding.file_path = "src/main.rs".to_string();
        finding.cross_file_references = Some(vec!["src/util.rs".to_string()]);

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!((refined.refined_score - 0.88).abs() < 0.001);
        assert!(refined
            .factors
            .contains(&ConfidenceFactor::CrossFileReachability));
    }

    #[test]
    fn test_multi_source_and_cross_file_combined() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::Medium);
        finding.file_path = "src/main.rs".to_string();
        finding.sources = vec!["semgrep".to_string(), "llm".to_string()];
        finding.cross_file_references = Some(vec!["src/util.rs".to_string()]);

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!((refined.refined_score - 0.98).abs() < 0.001);
        assert_eq!(refined.factors.len(), 2);
    }

    #[test]
    fn test_verification_status_confirmed_boost() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::Medium);
        finding.file_path = "src/main.rs".to_string();
        finding.verification_status = Some(VerificationStatus::Confirmed);

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!((refined.refined_score - 0.95).abs() < 0.001);
        assert!(refined.factors.contains(&ConfidenceFactor::VerifiedByLlm));
    }

    #[test]
    fn test_verification_status_false_positive_penalty() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::Medium);
        finding.file_path = "src/main.rs".to_string();
        finding.verification_status = Some(VerificationStatus::FalsePositive);

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!((refined.refined_score - 0.5).abs() < 0.001);
        assert!(refined
            .factors
            .contains(&ConfidenceFactor::FalsePositiveDetected));
    }

    #[test]
    fn test_verification_status_needs_review_no_change() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::Medium);
        finding.file_path = "src/main.rs".to_string();
        finding.verification_status = Some(VerificationStatus::NeedsReview);

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!((refined.refined_score - 0.8).abs() < 0.001);
        assert!(refined.explanation[0].contains("pending"));
    }

    #[test]
    fn test_verification_status_failed_penalty() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::Medium);
        finding.file_path = "src/main.rs".to_string();
        finding.verification_status = Some(VerificationStatus::Failed);

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!((refined.refined_score - 0.7).abs() < 0.001);
    }

    #[test]
    fn test_empty_findings_returns_empty_map() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let findings: Vec<VulnerabilityFinding> = vec![];
        let refinements = phase.run(findings, &context);

        assert!(refinements.is_empty());
    }

    #[test]
    fn test_confidence_at_max_clamped_correctly() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::Critical);
        finding.file_path = "src/main.rs".to_string();
        finding.confidence_score = 0.95;
        finding.sources = vec!["semgrep".to_string(), "llm".to_string()];
        finding.cross_file_references = Some(vec!["src/util.rs".to_string()]);
        finding.verification_status = Some(VerificationStatus::Confirmed);

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!((refined.refined_score - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_low_confidence_source_penalty() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::Medium);
        finding.file_path = "src/main.rs".to_string();
        finding.sources = vec!["bandit".to_string()];

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!((refined.refined_score - 0.75).abs() < 0.001);
        assert!(refined
            .factors
            .contains(&ConfidenceFactor::LowConfidenceSource));
    }

    #[test]
    fn test_severity_boost_for_high_severity() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::Critical);
        finding.file_path = "src/main.rs".to_string();
        finding.confidence_score = 0.85;

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!((refined.refined_score - 0.9).abs() < 0.001);
        assert!(refined.factors.contains(&ConfidenceFactor::SeverityBoost));
    }

    // NOTE: `test_neutral_code_context` is commented out because it reads the private
    // fields `ContextAnalysis.supports`, `.contradicts`, and `.explanation`, which
    // are not accessible from an external test file.
    //
    // #[test]
    // fn test_neutral_code_context() {
    //     let phase = ConfidenceRefinementPhase::new();
    //     let analysis = phase.analyze_code_context("regular function call here");
    //
    //     assert!(!analysis.supports);
    //     assert!(!analysis.contradicts);
    //     assert_eq!(analysis.explanation, "Code context is neutral");
    // }

    #[test]
    fn test_historical_data_record_verification_updates_stats() {
        let mut data = HistoricalData::new();

        data.record_verification("CWE-79", false);
        data.record_verification("CWE-79", false);
        data.record_verification("CWE-79", true);
        data.record_verification("CWE-89", false);

        let stats_79 = data.get_stats("CWE-79");
        assert_eq!(stats_79.total, 3);
        assert_eq!(stats_79.confirmed, 2);
        assert_eq!(stats_79.false_positives, 1);

        let stats_89 = data.get_stats("CWE-89");
        assert_eq!(stats_89.total, 1);
        assert_eq!(stats_89.confirmed, 1);
        assert_eq!(stats_89.false_positives, 0);
    }

    #[test]
    fn test_historical_data_unknown_cwe_returns_default() {
        let data = HistoricalData::new();

        let stats = data.get_stats("CWE-UNKNOWN");
        assert_eq!(stats.total, 0);
        assert_eq!(stats.confirmed, 0);
        assert_eq!(stats.false_positives, 0);
    }

    // NOTE: `test_context_analysis_with_only_support_patterns` is commented out —
    // reads private fields of `ContextAnalysis`.
    //
    // #[test]
    // fn test_context_analysis_with_only_support_patterns() {
    //     let phase = ConfidenceRefinementPhase::new();
    //     let code = "request.params.input";
    //
    //     let analysis = phase.analyze_code_context(code);
    //
    //     assert!(analysis.supports);
    //     assert!(!analysis.contradicts);
    // }

    // NOTE: `test_context_analysis_with_only_contradict_patterns` is commented out —
    // reads private fields of `ContextAnalysis`.
    //
    // #[test]
    // fn test_context_analysis_with_only_contradict_patterns() {
    //     let phase = ConfidenceRefinementPhase::new();
    //     let code = "validate(sanitize(escape(input)))";
    //
    //     let analysis = phase.analyze_code_context(code);
    //
    //     assert!(!analysis.supports);
    //     assert!(analysis.contradicts);
    // }

    #[test]
    fn test_third_party_code_node_modules() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::High);
        finding.file_path = "node_modules/express/lib/router.js".to_string();

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!(refined.factors.contains(&ConfidenceFactor::ThirdPartyCode));
        assert!(refined.refined_score < refined.original_score);
    }

    #[test]
    fn test_low_base_confidence_stays_non_negative() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::Low);
        finding.file_path = "src/main.rs".to_string();
        finding.confidence_score = 0.1;
        finding.verification_status = Some(VerificationStatus::FalsePositive);

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!((refined.refined_score - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_never_submit_pattern_cwe_693() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding =
            create_finding_with_params("f1", "Missing security headers", Severity::Medium);
        finding.file_path = "src/main.rs".to_string();
        finding.description = "Application is missing HSTS header".to_string();
        finding.cwe_id = Some("CWE-693".to_string());

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!((refined.refined_score - 0.08).abs() < 0.01);
        assert!(refined
            .factors
            .iter()
            .any(|f| matches!(f, ConfidenceFactor::NeverSubmitMatch { .. })));
    }

    #[test]
    fn test_never_submit_pattern_open_redirect() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding =
            create_finding_with_params("f2", "Open redirect vulnerability", Severity::Medium);
        finding.file_path = "src/main.rs".to_string();
        finding.description = "Potential open redirect without credential leak".to_string();
        finding.cwe_id = Some("CWE-601".to_string());

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f2").unwrap();

        assert!((refined.refined_score - 0.08).abs() < 0.01);
        assert!(refined
            .factors
            .iter()
            .any(|f| matches!(f, ConfidenceFactor::NeverSubmitMatch { .. })));
    }

    #[test]
    fn test_never_submit_pattern_self_xss() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f3", "Reflected XSS", Severity::Medium);
        finding.file_path = "src/main.rs".to_string();
        finding.description = "Reflected XSS on same origin - self-XSS".to_string();
        finding.cwe_id = Some("CWE-79".to_string());

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f3").unwrap();

        assert!((refined.refined_score - 0.08).abs() < 0.01);
        assert!(refined
            .factors
            .iter()
            .any(|f| matches!(f, ConfidenceFactor::NeverSubmitMatch { .. })));
    }

    #[test]
    fn test_never_submit_pattern_ssrf() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f4", "SSRF vulnerability", Severity::Medium);
        finding.file_path = "src/main.rs".to_string();
        finding.description = "SSRF via DNS callback without OOB confirmation".to_string();
        finding.cwe_id = Some("CWE-918".to_string());

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f4").unwrap();

        assert!((refined.refined_score - 0.08).abs() < 0.01);
        assert!(refined
            .factors
            .iter()
            .any(|f| matches!(f, ConfidenceFactor::NeverSubmitMatch { .. })));
    }

    #[test]
    fn test_never_submit_pattern_no_match() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f5", "SQL injection", Severity::High);
        finding.file_path = "src/main.rs".to_string();
        finding.description = "Direct SQL concatenation with user input".to_string();
        finding.cwe_id = Some("CWE-89".to_string());

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f5").unwrap();

        assert!(!refined
            .factors
            .iter()
            .any(|f| matches!(f, ConfidenceFactor::NeverSubmitMatch { .. })));
    }
}
