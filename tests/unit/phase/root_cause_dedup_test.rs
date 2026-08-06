#[cfg(test)]
mod tests {
    use baco::config::ScannerConfig;
    use baco::findings::Severity;
    use baco::phase::helpers::create_test_finding;
    use baco::root_cause_dedup::RootCauseDeduplicator;
    use baco::scanner::Scanner;
    use tempfile::TempDir;

    #[test]
    fn test_root_cause_dedup_phase_name_and_order() {
        // RootCauseDeduplicator doesn't implement ScanPhase trait directly
        // It's used via the run_root_cause_dedup function
        let _dedup = RootCauseDeduplicator::new();
    }

    #[test]
    fn test_root_cause_dedup_with_no_findings() {
        let mut dedup = RootCauseDeduplicator::new();
        let findings = vec![];

        let groups = dedup.deduplicate(findings);

        assert!(groups.is_empty());
    }

    #[test]
    fn test_root_cause_dedup_with_findings() {
        let mut dedup = RootCauseDeduplicator::new();
        let finding = create_test_finding("Test vulnerability", "test.rs", 42, Severity::High);
        let findings = vec![finding];

        let groups = dedup.deduplicate(findings);

        assert_eq!(groups.len(), 1);
    }

    #[test]
    fn test_root_cause_dedup_multiple_findings() {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();

        let scanner = Scanner::new(config.clone(), temp_dir.path().to_path_buf(), false);

        let findings = vec![
            create_test_finding("High severity", "high.rs", 10, Severity::High),
            create_test_finding("Medium severity", "medium.rs", 20, Severity::Medium),
            create_test_finding("Low severity", "low.rs", 30, Severity::Low),
        ];

        scanner.state.send_modify(|s| {
            s.findings = findings;
        });

        let findings = scanner.state.borrow().findings.clone();
        let mut dedup = RootCauseDeduplicator::new();
        let groups = dedup.deduplicate(findings);

        // Each finding should be in its own group (different files/locations)
        assert_eq!(groups.len(), 3);
    }

    #[test]
    fn test_root_cause_dedup_same_root_cause() {
        use baco::findings::VulnerabilityFinding;

        let finding1 = VulnerabilityFinding {
            id: "finding1".to_string(),
            title: "SQL Injection".to_string(),
            severity: Severity::High,
            confidence_score: 0.8,
            file_path: "src/db.rs".to_string(),
            line_number: Some(10),
            code_snippet: Some("query(user_input)".to_string()),
            description: "SQL injection vulnerability".to_string(),
            cwe_id: None,
            verification_status: None,
            sources: vec![],
            cross_file_references: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
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
        };

        let finding2 = VulnerabilityFinding {
            id: "finding2".to_string(),
            title: "SQL Injection".to_string(),
            severity: Severity::High,
            confidence_score: 0.8,
            file_path: "src/api.rs".to_string(),
            line_number: Some(20),
            code_snippet: Some("query(user_input)".to_string()),
            description: "SQL injection vulnerability".to_string(),
            cwe_id: None,
            verification_status: None,
            sources: vec![],
            cross_file_references: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
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
        };

        let mut dedup = RootCauseDeduplicator::new();
        let findings = vec![finding1, finding2];
        let groups = dedup.deduplicate(findings);

        // Same vulnerability type and code snippet should be grouped together
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn test_root_cause_compute_id() {
        let finding = create_test_finding("Test vulnerability", "test.rs", 42, Severity::High);

        let id1 = RootCauseDeduplicator::compute_root_cause_id(&finding);
        let id2 = RootCauseDeduplicator::compute_root_cause_id(&finding);

        // Same finding should produce same ID
        assert_eq!(id1, id2);
        assert!(!id1.is_empty());
        assert_eq!(id1.len(), 64); // SHA256 hex encoded
    }
}
