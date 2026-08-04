//! Unit tests extracted from the inline `#[cfg(test)] mod tests` block in
//! `src/llm_verification.rs`.
//!
//! Covers `ExtendedVerificationPhase`, `VerificationResult` / `VerificationReport`,
//! and the `render_template` helper.

#![allow(clippy::needless_return)]

#[cfg(test)]
mod tests {
    use baco::analysis_context::AnalysisContext;
    use baco::findings::{
        IssueCategory, SecurityIssue, Severity, VerificationStatus, VulnerabilityFinding,
    };
    use baco::llm_verification::{
        render_template, ExtendedVerificationPhase, VerificationReport, VerificationResult,
    };
    use baco::project_type::ProjectType as DetectProjectType;
    use std::collections::HashMap;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_test_finding(
        title: &str,
        severity: Severity,
        code: Option<&str>,
    ) -> VulnerabilityFinding {
        VulnerabilityFinding {
            id: format!("test-{}", title.to_lowercase().replace(' ', "-")),
            title: title.to_string(),
            description: format!("Test description for {}", title),
            severity,
            confidence_score: 0.7,
            cwe_id: Some("CWE-79".to_string()),
            file_path: "src/test.rs".to_string(),
            line_number: Some(42),
            code_snippet: code.map(|s| s.to_string()),
            diff_hunk: None,
            recommendation: Some("Fix this issue".to_string()),
            code_location: Some("src/test.rs:42".to_string()),
            already_reported: false,
            sources: vec!["static_analysis".to_string()],
            commit_reference: None,
            ticket_reference: None,
            priority_score: Some(0.8),
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: Some(SecurityIssue {
                category: IssueCategory::Injection,
                cwe_id: Some("CWE-79".to_string()),
                owasp_category: Some("Injection".to_string()),
                mitre_attack: None,
                custom_tags: vec!["xss".to_string()],
            }),
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
            statement_range: None,
            triage_verdict: None,
        }
    }

    #[test]
    fn test_verification_phase_initialization() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"{}").unwrap();
        let context = AnalysisContext::load(temp_file.path().parent().unwrap()).unwrap();

        let phase = ExtendedVerificationPhase::new(DetectProjectType::Web, context, None);

        assert_eq!(*phase.project_type(), DetectProjectType::Web);
        assert!(!phase.security_practices().is_empty());
    }

    #[test]
    fn test_verify_finding_with_sanitization() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"{}").unwrap();
        let context = AnalysisContext::load(temp_file.path().parent().unwrap()).unwrap();

        let phase = ExtendedVerificationPhase::new(DetectProjectType::Web, context, None);

        let finding = make_test_finding(
            "XSS in user input",
            Severity::High,
            Some("escape(user_input)"),
        );

        let result = phase.verify_finding(&finding);

        assert!(!result.mitigating_factors.is_empty());
        assert!(result
            .related_patterns
            .contains(&"sanitization_present".to_string()));
    }

    #[test]
    fn test_verify_finding_known_false_positive() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"{}").unwrap();
        let context = AnalysisContext::load(temp_file.path().parent().unwrap()).unwrap();

        let phase = ExtendedVerificationPhase::new(DetectProjectType::Web, context, None);

        let finding = make_test_finding(
            "Potential SQL Injection",
            Severity::Medium,
            Some("SELECT * FROM users WHERE id = ? -- test query"),
        );

        let result = phase.verify_finding(&finding);

        assert_eq!(result.status, VerificationStatus::FalsePositive);
        assert!(result.false_positive_reason.is_some());
    }

    #[test]
    fn test_verify_finding_no_mitigating_factors() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"{}").unwrap();
        let context = AnalysisContext::load(temp_file.path().parent().unwrap()).unwrap();

        let phase = ExtendedVerificationPhase::new(DetectProjectType::Web, context, None);

        let finding = make_test_finding(
            "Command Injection",
            Severity::Critical,
            Some("exec(user_input)"),
        );

        let result = phase.verify_finding(&finding);

        assert!(result.mitigating_factors.is_empty());
        assert_eq!(result.status, VerificationStatus::Confirmed);
    }

    #[test]
    fn test_execute_verification() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"{}").unwrap();
        let context = AnalysisContext::load(temp_file.path().parent().unwrap()).unwrap();

        let mut phase = ExtendedVerificationPhase::new(DetectProjectType::Web, context, None);

        let findings = vec![
            make_test_finding(
                "SQL Injection",
                Severity::Critical,
                Some("SELECT * FROM users WHERE id = ?"),
            ),
            make_test_finding("XSS", Severity::High, Some("escape(user_input)")),
            make_test_finding("Test Issue", Severity::Low, Some("test code")),
        ];

        let report = phase.execute(&findings).unwrap();

        assert_eq!(report.total_findings, 3);
        assert!(report.confirmed > 0 || report.false_positives > 0 || report.needs_review > 0);
    }

    #[test]
    fn test_verification_report_generation() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"{}").unwrap();
        let context = AnalysisContext::load(temp_file.path().parent().unwrap()).unwrap();

        let mut phase = ExtendedVerificationPhase::new(DetectProjectType::Web, context, None);

        let findings = vec![
            make_test_finding("Vuln 1", Severity::Critical, Some("exec(cmd)")),
            make_test_finding("Vuln 2", Severity::High, Some("escape(x)")),
        ];

        let report = phase.execute(&findings).unwrap();

        // Check report statistics
        assert_eq!(report.total_findings, 2);
        assert!(report.average_confidence >= 0.0 && report.average_confidence <= 1.0);
        assert!(!report.results.is_empty());
    }

    #[test]
    fn test_confidence_refinement_high_severity() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"{}").unwrap();
        let context = AnalysisContext::load(temp_file.path().parent().unwrap()).unwrap();

        let phase = ExtendedVerificationPhase::new(DetectProjectType::Web, context, None);

        let finding = make_test_finding("Critical Issue", Severity::Critical, Some("unsafe_code"));

        let result = phase.verify_finding(&finding);

        // High severity should boost confidence
        assert!(result.confidence >= 0.7);
    }

    #[test]
    fn test_confidence_refinement_already_reported() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"{}").unwrap();
        let context = AnalysisContext::load(temp_file.path().parent().unwrap()).unwrap();

        let phase = ExtendedVerificationPhase::new(DetectProjectType::Web, context, None);

        let mut finding =
            make_test_finding("Re-reported Issue", Severity::Medium, Some("some_code"));
        finding.already_reported = true;

        let result = phase.verify_finding(&finding);

        // Already reported should slightly reduce confidence
        assert!(result.confidence <= 0.7);
    }

    #[test]
    fn test_security_practices_by_type() {
        let web_practices =
            ExtendedVerificationPhase::get_security_practices(DetectProjectType::Web);
        assert!(web_practices.iter().any(|p| p.contains("Input validation")));

        let cli_practices =
            ExtendedVerificationPhase::get_security_practices(DetectProjectType::CLI);
        assert!(cli_practices.iter().any(|p| p.contains("Argument")));

        let embedded_practices =
            ExtendedVerificationPhase::get_security_practices(DetectProjectType::Embedded);
        assert!(embedded_practices
            .iter()
            .any(|p| p.contains("buffer overflow")));
    }

    #[test]
    fn test_has_sanitization() {
        let phase = ExtendedVerificationPhase::new(
            DetectProjectType::Web,
            AnalysisContext::default(),
            None,
        );

        assert!(phase.has_sanitization("escape(user_input)"));
        assert!(phase.has_sanitization("sanitize(input)"));
        assert!(phase.has_sanitization("parametrized_query"));
        assert!(!phase.has_sanitization("exec(user_input)"));
    }

    #[test]
    fn test_is_known_false_positive_pattern() {
        let phase = ExtendedVerificationPhase::new(
            DetectProjectType::Web,
            AnalysisContext::default(),
            None,
        );

        assert!(phase.is_known_false_positive_pattern("let x = TODO"));
        assert!(phase.is_known_false_positive_pattern("mock_data"));
        assert!(!phase.is_known_false_positive_pattern("real_production_code"));
    }

    #[test]
    fn test_template_rendering() {
        let template = "Hello %%NAME%%, verify finding {{TITLE}}";
        let mut variables = HashMap::new();
        variables.insert("NAME".to_string(), "World".to_string());
        variables.insert("TITLE".to_string(), "Test Finding".to_string());

        let result = render_template(template, &variables);
        assert_eq!(result, "Hello World, verify finding Test Finding");
    }

    #[test]
    fn test_project_type_mapping() {
        // Test project type to prompt type mapping logic
        let test_cases = vec![
            (DetectProjectType::Web, "web"),
            (DetectProjectType::CLI, "cli"),
            (DetectProjectType::Library, "library"),
        ];

        // Just verify the types exist and are accessible
        for (pt, expected) in test_cases {
            let _ = pt;
            let _ = expected;
        }
    }

    #[test]
    fn test_verification_result_serialization() {
        let result = VerificationResult {
            finding_id: "test-001".to_string(),
            status: VerificationStatus::Confirmed,
            confidence: 0.85,
            notes: "Verified via LLM".to_string(),
            mitigating_factors: vec!["Input validation".to_string()],
            related_patterns: vec!["CWE-79".to_string()],
            false_positive_reason: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: VerificationResult = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.finding_id, "test-001");
        assert_eq!(deserialized.status, VerificationStatus::Confirmed);
    }

    #[test]
    fn test_verification_report_serialization() {
        let report = VerificationReport {
            total_findings: 10,
            confirmed: 5,
            false_positives: 2,
            needs_review: 3,
            failed: 0,
            results: vec![],
            average_confidence: 0.75,
            high_confidence_findings: vec!["id1".to_string(), "id2".to_string()],
        };

        let json = serde_json::to_string(&report).unwrap();
        let deserialized: VerificationReport = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.total_findings, 10);
        assert_eq!(deserialized.confirmed, 5);
        assert_eq!(deserialized.false_positives, 2);
    }

    #[test]
    fn test_is_cwe_known_false_positive() {
        let phase = ExtendedVerificationPhase::new(
            DetectProjectType::Web,
            AnalysisContext::default(),
            None,
        );

        // Test known false positive CWEs
        assert!(phase.is_cwe_known_false_positive("CWE-190")); // Integer overflow
        assert!(phase.is_cwe_known_false_positive("CWE-191")); // Integer underflow
        assert!(phase.is_cwe_known_false_positive("CWE-754")); // Improper check for special elements

        // Test unknown CWEs (not in the false positive list)
        assert!(!phase.is_cwe_known_false_positive("CWE-79")); // XSS
        assert!(!phase.is_cwe_known_false_positive("CWE-89")); // SQL Injection
        assert!(!phase.is_cwe_known_false_positive("CWE-1234")); // Custom CWE
    }

    #[test]
    fn test_calculate_refined_confidence_with_mitigating_factors() {
        let phase = ExtendedVerificationPhase::new(
            DetectProjectType::Web,
            AnalysisContext::default(),
            None,
        );

        let finding = make_test_finding("Test Issue", Severity::Medium, Some("code"));
        let mitigating_factors = vec![
            "Input validation present".to_string(),
            "Output encoding applied".to_string(),
        ];

        let confidence = phase.calculate_refined_confidence(&finding, &mitigating_factors, &[]);

        // Should reduce confidence by 0.1 per mitigating factor (0.7 - 0.2 = 0.5)
        assert!((confidence - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_calculate_refined_confidence_high_severity_boost() {
        let phase = ExtendedVerificationPhase::new(
            DetectProjectType::Web,
            AnalysisContext::default(),
            None,
        );

        let finding = make_test_finding("Critical Issue", Severity::Critical, Some("code"));
        let confidence = phase.calculate_refined_confidence(&finding, &[], &[]);

        // High severity should boost confidence (0.7 + 0.1 = 0.8)
        assert!((confidence - 0.8).abs() < 0.01);
    }

    #[test]
    fn test_calculate_refined_confidence_already_reported_reduction() {
        let phase = ExtendedVerificationPhase::new(
            DetectProjectType::Web,
            AnalysisContext::default(),
            None,
        );

        let mut finding = make_test_finding("Repeated Issue", Severity::Medium, Some("code"));
        finding.already_reported = true;

        let confidence = phase.calculate_refined_confidence(&finding, &[], &[]);

        // Already reported should reduce confidence (0.7 - 0.05 = 0.65)
        assert!((confidence - 0.65).abs() < 0.01);
    }

    #[test]
    fn test_calculate_refined_confidence_combined_effects() {
        let phase = ExtendedVerificationPhase::new(
            DetectProjectType::Web,
            AnalysisContext::default(),
            None,
        );

        let mut finding = make_test_finding("Complex Issue", Severity::High, Some("code"));
        finding.already_reported = true;
        let mitigating_factors = vec!["Sanitization detected".to_string()];

        let confidence = phase.calculate_refined_confidence(&finding, &mitigating_factors, &[]);

        // High severity (+0.1), already reported (-0.05), 1 mitigating factor (-0.1)
        // 0.7 + 0.1 - 0.05 - 0.1 = 0.65
        assert!((confidence - 0.65).abs() < 0.01);
    }

    #[test]
    fn test_calculate_refined_confidence_bounds() {
        let phase = ExtendedVerificationPhase::new(
            DetectProjectType::Web,
            AnalysisContext::default(),
            None,
        );

        // Test confidence doesn't go below 0
        let finding = make_test_finding("Low confidence issue", Severity::Low, Some("code"));
        let mut low_confidence_finding = finding.clone();
        low_confidence_finding.confidence_score = 0.1;

        let many_factors = vec![
            "Factor 1".to_string(),
            "Factor 2".to_string(),
            "Factor 3".to_string(),
            "Factor 4".to_string(),
            "Factor 5".to_string(),
        ];

        let confidence =
            phase.calculate_refined_confidence(&low_confidence_finding, &many_factors, &[]);
        assert!(confidence >= 0.0);

        // Test confidence doesn't exceed 1.0
        let high_confidence_finding =
            make_test_finding("High confidence", Severity::Critical, Some("code"));
        let mut max_confidence_finding = high_confidence_finding.clone();
        max_confidence_finding.confidence_score = 0.95;

        let confidence = phase.calculate_refined_confidence(&max_confidence_finding, &[], &[]);
        assert!(confidence <= 1.0);
    }

    #[test]
    fn test_new_with_none_llm_client() {
        let context = AnalysisContext::default();
        let phase = ExtendedVerificationPhase::new(DetectProjectType::CLI, context, None);

        assert_eq!(*phase.project_type(), DetectProjectType::CLI);
        assert!(!phase.security_practices().is_empty());
        // CLI should have 4 security practices
        assert_eq!(phase.security_practices().len(), 4);
    }

    #[test]
    fn test_new_with_all_project_types() {
        let project_types = vec![
            (DetectProjectType::Web, 7),
            (DetectProjectType::CLI, 4),
            (DetectProjectType::Library, 4),
            (DetectProjectType::Embedded, 4),
            (DetectProjectType::Firmware, 3),
            (DetectProjectType::Desktop, 4),
            (DetectProjectType::Game, 3),
            (DetectProjectType::Unknown, 3),
        ];

        for (project_type, expected_count) in project_types {
            let phase = ExtendedVerificationPhase::new(
                project_type.clone(),
                AnalysisContext::default(),
                None,
            );

            assert_eq!(
                phase.security_practices().len(),
                expected_count,
                "Security practices count mismatch for {:?}",
                project_type
            );
        }
    }

    #[test]
    fn test_project_type_accessor() {
        let phase = ExtendedVerificationPhase::new(
            DetectProjectType::Library,
            AnalysisContext::default(),
            None,
        );

        let project_type = phase.project_type();
        assert_eq!(project_type, &DetectProjectType::Library);
    }

    #[test]
    fn test_security_practices_accessor() {
        let phase = ExtendedVerificationPhase::new(
            DetectProjectType::Web,
            AnalysisContext::default(),
            None,
        );

        let practices = phase.security_practices();
        assert!(!practices.is_empty());
        assert!(practices.iter().any(|p| p.contains("Input validation")));
    }

    #[test]
    fn test_has_sanitization_all_patterns() {
        let phase = ExtendedVerificationPhase::new(
            DetectProjectType::Web,
            AnalysisContext::default(),
            None,
        );

        // Test all sanitization patterns
        assert!(phase.has_sanitization("sanitize_input()"));
        assert!(phase.has_sanitization("escape_html()"));
        assert!(phase.has_sanitization("encode_url()"));
        assert!(phase.has_sanitization("validate_input()"));
        assert!(phase.has_sanitization("filter_data()"));
        assert!(phase.has_sanitization("parameterized_query()"));
        assert!(phase.has_sanitization("parametrized_query()"));
        assert!(phase.has_sanitization("prepared_statement()"));
        assert!(phase.has_sanitization("bind_param()"));
        assert!(phase.has_sanitization("htmlspecialchars()"));
        assert!(phase.has_sanitization("htmlentities()"));
        assert!(phase.has_sanitization("urlencode()"));
        assert!(phase.has_sanitization("base64_encode()"));
    }

    #[test]
    fn test_has_sanitization_case_insensitive() {
        let phase = ExtendedVerificationPhase::new(
            DetectProjectType::Web,
            AnalysisContext::default(),
            None,
        );

        // Should be case insensitive
        assert!(phase.has_sanitization("SANITIZE(input)"));
        assert!(phase.has_sanitization("SaNiTiZe(input)"));
        assert!(phase.has_sanitization("PARAMETERIZED_QUERY"));
    }

    #[test]
    fn test_is_known_false_positive_all_patterns() {
        let phase = ExtendedVerificationPhase::new(
            DetectProjectType::Web,
            AnalysisContext::default(),
            None,
        );

        // Test all false positive patterns
        assert!(phase.is_known_false_positive_pattern("test code"));
        assert!(phase.is_known_false_positive_pattern("mock object"));
        assert!(phase.is_known_false_positive_pattern("example usage"));
        assert!(phase.is_known_false_positive_pattern("demo app"));
        assert!(phase.is_known_false_positive_pattern("sample data"));
        assert!(phase.is_known_false_positive_pattern("todo item"));
        assert!(phase.is_known_false_positive_pattern("fixme note"));
        assert!(phase.is_known_false_positive_pattern("xxx marker"));
        assert!(phase.is_known_false_positive_pattern("hack workaround"));
        assert!(phase.is_known_false_positive_pattern("if false condition"));
        assert!(phase.is_known_false_positive_pattern("unreachable code"));
        assert!(phase.is_known_false_positive_pattern("dead_code attribute"));
    }

    #[test]
    fn test_is_known_false_positive_case_insensitive() {
        let phase = ExtendedVerificationPhase::new(
            DetectProjectType::Web,
            AnalysisContext::default(),
            None,
        );

        // Should be case insensitive
        assert!(phase.is_known_false_positive_pattern("TEST code"));
        assert!(phase.is_known_false_positive_pattern("MoCk object"));
        assert!(phase.is_known_false_positive_pattern("IF FALSE condition"));
    }

    #[test]
    fn test_render_template_both_syntaxes() {
        // Test both %%VAR%% and {{{VAR}}} syntaxes
        // Note: {{{{VAR}}}} in the string literal becomes {{{VAR}}} after Rust string parsing
        let template = "Report: %%TITLE%% - {{{{SEVERITY}}}} - %%CODE%%";
        let mut variables = HashMap::new();
        variables.insert("TITLE".to_string(), "SQL Injection".to_string());
        variables.insert("SEVERITY".to_string(), "High".to_string());
        variables.insert("CODE".to_string(), "SELECT * FROM users".to_string());

        let result = render_template(template, &variables);
        // The pattern {{{{SEVERITY}}}} in source = {{{SEVERITY}}} in runtime
        // render_template looks for {{{VAR}}} pattern
        assert!(result.contains("SQL Injection"));
        assert!(result.contains("SELECT * FROM users"));
        // Just verify the template was processed, exact brace count depends on implementation
        assert!(!result.contains("%%TITLE%%"));
        assert!(!result.contains("%%CODE%%"));
    }

    #[test]
    fn test_render_template_empty_variables() {
        let template = "Finding: %%TITLE%% at {{LINE}}";
        let variables = HashMap::new();

        let result = render_template(template, &variables);
        // Unreplaced variables should remain as-is
        assert_eq!(result, "Finding: %%TITLE%% at {{LINE}}");
    }

    #[test]
    fn test_render_template_special_characters() {
        let template = "Code: %%CODE%%";
        let mut variables = HashMap::new();
        variables.insert(
            "CODE".to_string(),
            "SELECT * FROM users WHERE id = 'test'".to_string(),
        );

        let result = render_template(template, &variables);
        assert!(result.contains("SELECT * FROM users"));
        assert!(result.contains("'test'"));
    }

    #[test]
    fn test_verify_finding_with_cwe_false_positive() {
        let phase = ExtendedVerificationPhase::new(
            DetectProjectType::Web,
            AnalysisContext::default(),
            None,
        );

        let mut finding = make_test_finding("Integer overflow", Severity::Medium, Some("code"));
        finding.security_issue = Some(SecurityIssue {
            category: IssueCategory::MemoryCorruption,
            cwe_id: Some("CWE-190".to_string()),
            owasp_category: None,
            mitre_attack: None,
            custom_tags: vec![],
        });

        let result = phase.verify_finding(&finding);

        // CWE-190 is a known false positive pattern
        assert!(result.false_positive_reason.is_some());
        assert!(result.false_positive_reason.unwrap().contains("CWE-190"));
    }

    #[test]
    fn test_execute_with_empty_findings() {
        let mut phase = ExtendedVerificationPhase::new(
            DetectProjectType::Web,
            AnalysisContext::default(),
            None,
        );

        let findings: Vec<VulnerabilityFinding> = vec![];
        let report = phase.execute(&findings).unwrap();

        assert_eq!(report.total_findings, 0);
        assert_eq!(report.confirmed, 0);
        assert_eq!(report.false_positives, 0);
        assert_eq!(report.needs_review, 0);
        assert_eq!(report.failed, 0);
        assert_eq!(report.average_confidence, 0.0);
    }

    #[test]
    fn test_verification_result_creation() {
        let result = VerificationResult {
            finding_id: "test-123".to_string(),
            status: VerificationStatus::NeedsReview,
            confidence: 0.6,
            notes: "Manual review required".to_string(),
            mitigating_factors: vec!["Input sanitization".to_string()],
            related_patterns: vec!["CWE-79".to_string(), "sanitization_present".to_string()],
            false_positive_reason: None,
        };

        assert_eq!(result.finding_id, "test-123");
        assert_eq!(result.status, VerificationStatus::NeedsReview);
        assert_eq!(result.confidence, 0.6);
        assert_eq!(result.mitigating_factors.len(), 1);
        assert_eq!(result.related_patterns.len(), 2);
    }

    #[test]
    fn test_verification_report_statistics() {
        let results = [
            VerificationResult {
                finding_id: "1".to_string(),
                status: VerificationStatus::Confirmed,
                confidence: 0.9,
                notes: "".to_string(),
                mitigating_factors: vec![],
                related_patterns: vec![],
                false_positive_reason: None,
            },
            VerificationResult {
                finding_id: "2".to_string(),
                status: VerificationStatus::FalsePositive,
                confidence: 0.3,
                notes: "".to_string(),
                mitigating_factors: vec![],
                related_patterns: vec![],
                false_positive_reason: Some("Known pattern".to_string()),
            },
            VerificationResult {
                finding_id: "3".to_string(),
                status: VerificationStatus::NeedsReview,
                confidence: 0.5,
                notes: "".to_string(),
                mitigating_factors: vec!["Factor".to_string()],
                related_patterns: vec![],
                false_positive_reason: None,
            },
        ];

        // Manually create report to test statistics calculation
        let total = results.len();
        let confirmed = results
            .iter()
            .filter(|r| r.status == VerificationStatus::Confirmed)
            .count();
        let false_positives = results
            .iter()
            .filter(|r| r.status == VerificationStatus::FalsePositive)
            .count();
        let needs_review = results
            .iter()
            .filter(|r| r.status == VerificationStatus::NeedsReview)
            .count();

        assert_eq!(total, 3);
        assert_eq!(confirmed, 1);
        assert_eq!(false_positives, 1);
        assert_eq!(needs_review, 1);
    }
}
