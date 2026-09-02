//! Tests for T15: discovery skip logic and T23: baseline persistence.

#[cfg(test)]
mod discovery_skip_tests {
    use baco::evidence::EvidenceSource;
    use baco::findings::{Severity, VulnerabilityFinding};

    /// Helper to create a finding with given evidence sources.
    fn make_finding(id: &str, evidence_sources: Vec<EvidenceSource>) -> VulnerabilityFinding {
        let mut finding = VulnerabilityFinding {
            id: id.to_string(),
            title: "Test Finding".to_string(),
            description: "Test description".to_string(),
            severity: Severity::High,
            confidence_score: 0.8,
            cwe_id: Some("CWE-79".to_string()),
            file_path: "test.rs".to_string(),
            line_number: Some(42),
            code_snippet: Some("let x = unsafe_code();".to_string()),
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["test".to_string()],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
            statement_range: None,
            triage_verdict: None,
            evidence: Vec::new(),
            verification_tier: None,
        };

        for source in evidence_sources {
            finding.add_evidence(source, 0.6, "test".to_string());
        }

        finding
    }

    #[test]
    fn test_llm_analysis_evidence_skips_discovery() {
        // Finding with LlmAnalysis evidence should be skipped
        let finding = make_finding(
            "test-1",
            vec![EvidenceSource::LlmAnalysis(
                "previous-discovery".to_string(),
            )],
        );

        let should_skip = finding
            .evidence
            .iter()
            .any(|e| matches!(e.source, EvidenceSource::LlmAnalysis(_)));

        assert!(should_skip, "LlmAnalysis evidence should trigger skip");
    }

    #[test]
    fn test_semgrep_evidence_needs_discovery() {
        // Finding with only Semgrep evidence should NOT be skipped
        let finding = make_finding(
            "test-2",
            vec![EvidenceSource::Semgrep("semgrep-rule-id".to_string())],
        );

        let should_skip = finding
            .evidence
            .iter()
            .any(|e| matches!(e.source, EvidenceSource::LlmAnalysis(_)));

        assert!(!should_skip, "Semgrep evidence should not trigger skip");
    }

    #[test]
    fn test_mixed_evidence_skips_if_llm_present() {
        // Finding with both Semgrep and LlmAnalysis should be skipped
        let finding = make_finding(
            "test-3",
            vec![
                EvidenceSource::Semgrep("semgrep-rule-id".to_string()),
                EvidenceSource::LlmAnalysis("previous-discovery".to_string()),
            ],
        );

        let should_skip = finding
            .evidence
            .iter()
            .any(|e| matches!(e.source, EvidenceSource::LlmAnalysis(_)));

        assert!(
            should_skip,
            "Mixed evidence with LlmAnalysis should trigger skip"
        );
    }

    #[test]
    fn test_partition_logic() {
        let mut findings = vec![
            make_finding("skip-1", vec![EvidenceSource::LlmAnalysis("prev".into())]),
            make_finding("process-1", vec![EvidenceSource::Semgrep("rule1".into())]),
            make_finding("skip-2", vec![EvidenceSource::LlmAnalysis("prev2".into())]),
            make_finding("process-2", vec![EvidenceSource::Semgrep("rule2".into())]),
        ];

        let (skipped, to_process): (Vec<_>, Vec<_>) = findings.drain(..).partition(|f| {
            f.evidence
                .iter()
                .any(|e| matches!(e.source, EvidenceSource::LlmAnalysis(_)))
        });

        assert_eq!(skipped.len(), 2, "Should skip 2 findings with LlmAnalysis");
        assert_eq!(
            to_process.len(),
            2,
            "Should process 2 findings with Semgrep"
        );

        assert!(skipped.iter().all(|f| f
            .evidence
            .iter()
            .any(|e| matches!(e.source, EvidenceSource::LlmAnalysis(_)))));
        assert!(to_process.iter().all(|f| !f
            .evidence
            .iter()
            .any(|e| matches!(e.source, EvidenceSource::LlmAnalysis(_)))));
    }
}

#[cfg(test)]
mod baseline_persistence_tests {
    use baco::confidence_refinement::ProjectBaseline;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_baseline_round_trip() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let baseline_path = temp_dir.path().join("project-baseline.json");

        let original = ProjectBaseline {
            total_findings: 100,
            true_positives: 85,
            false_positives: 15,
            mean_confidence: 0.75,
            sum_sq_dev: 12.5,
        };

        // Save
        original
            .save(&baseline_path)
            .expect("Failed to save baseline");

        // Load
        let loaded = ProjectBaseline::load(&baseline_path);

        assert_eq!(original, loaded, "Loaded baseline should match original");
        assert_eq!(loaded.false_positive_rate(), 0.15);
    }

    #[test]
    fn test_corrupt_baseline_file_returns_empty() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let baseline_path = temp_dir.path().join("project-baseline.json");

        // Write corrupt JSON
        let mut file = fs::File::create(&baseline_path).expect("Failed to create file");
        file.write_all(b"{ invalid json {{{")
            .expect("Failed to write");

        // Should return empty baseline without panicking
        let loaded = ProjectBaseline::load(&baseline_path);
        assert_eq!(
            loaded,
            ProjectBaseline::empty(),
            "Corrupt baseline should return empty"
        );
    }

    #[test]
    fn test_missing_baseline_file_returns_empty() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let baseline_path = temp_dir.path().join("nonexistent.json");

        let loaded = ProjectBaseline::load(&baseline_path);
        assert_eq!(
            loaded,
            ProjectBaseline::empty(),
            "Missing baseline should return empty"
        );
    }

    #[test]
    fn test_cwe_79_fp_pattern_in_baseline() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let baseline_path = temp_dir.path().join("project-baseline.json");

        let baseline = ProjectBaseline {
            total_findings: 50,
            true_positives: 40,
            false_positives: 10,
            mean_confidence: 0.70,
            sum_sq_dev: 8.0,
        };

        baseline
            .save(&baseline_path)
            .expect("Failed to save baseline");

        let loaded = ProjectBaseline::load(&baseline_path);
        assert_eq!(loaded.false_positives, 10);
        assert_eq!(loaded.total_findings, 50);
    }
}

#[cfg(test)]
mod confidence_scoring_baseline_integration_tests {
    use baco::confidence_refinement::ProjectBaseline;

    #[test]
    fn test_baseline_update_logic() {
        let mut baseline = ProjectBaseline::empty();

        // Add some findings
        baseline.update(0.8, true); // TP
        baseline.update(0.3, false); // FP
        baseline.update(0.9, true); // TP

        assert_eq!(baseline.total_findings, 3);
        assert_eq!(baseline.true_positives, 2);
        assert_eq!(baseline.false_positives, 1);
        assert!((baseline.mean_confidence - 0.67).abs() < 0.01);
    }

    #[test]
    fn test_empty_baseline_safe_operations() {
        let baseline = ProjectBaseline::empty();

        // Should not panic on empty baseline operations
        assert_eq!(baseline.false_positive_rate(), 0.0);
        assert_eq!(baseline.std_dev(), 0.0);
    }
}
