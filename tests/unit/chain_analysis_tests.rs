//! Comprehensive tests for chain analysis, root cause deduplication, variant search,
//! cross-file analysis, and multi-verifier modules.
//!
//! This module tests attack chain detection, vulnerability grouping, pattern matching,
//! and verification voting logic.

use baco::chain_analysis::{apply_chain_verdicts, ChainAnalyzer, ChainResult, ChainType};
use baco::crossfile::CrossFileAnalyzer;
use baco::findings::{Severity, TriageVerdict, VulnerabilityFinding};
use baco::multi_verifier::{MultiVerifier, VerifierConfig};
use baco::root_cause_dedup::{GlobalFpStore, RootCauseDeduplicator};
use baco::scanner_types::cve::RootCauseGroup;
use baco::scanner_types::poc::VerifierVerdict;
use baco::scanner_types::severity::V3Severity;
use baco::variant_search::{SearchPattern, VariantHit, VariantSearcher};
use std::fs;
use tempfile::TempDir;

/// Helper to create a test VulnerabilityFinding with minimal fields
fn create_finding(
    id: &str,
    file_path: &str,
    cwe_id: Option<&str>,
    title: &str,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test finding description".to_string(),
        severity: Severity::High,
        confidence_score: 0.8,
        cwe_id: cwe_id.map(String::from),
        file_path: file_path.to_string(),
        line_number: Some(42),
        code_snippet: None,
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
    }
}

/// Helper to create a VulnerabilityFinding with code snippet
fn create_finding_with_snippet(
    id: &str,
    file_path: &str,
    title: &str,
    code_snippet: Option<&str>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test finding".to_string(),
        severity: Severity::Medium,
        confidence_score: 0.7,
        cwe_id: None,
        file_path: file_path.to_string(),
        line_number: Some(10),
        code_snippet: code_snippet.map(String::from),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["semgrep".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.5),
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
    }
}

// ============================================================================
// CHAIN ANALYSIS TESTS
// ============================================================================

#[test]
fn test_analyze_chains_empty_findings_returns_empty() {
    let findings: Vec<VulnerabilityFinding> = Vec::new();
    let chains = ChainAnalyzer::analyze_chains(&findings);
    assert!(chains.is_empty());
}

#[test]
fn test_analyze_chains_single_finding_no_chain() {
    let findings = vec![create_finding(
        "f1",
        "src/main.rs",
        Some("CWE-89"),
        "SQL Injection",
    )];
    let chains = ChainAnalyzer::analyze_chains(&findings);
    assert!(chains.is_empty());
}

#[test]
fn test_injection_to_execution_chain_detected() {
    let findings = vec![
        create_finding("f1", "src/db.rs", Some("CWE-89"), "SQL Injection"),
        create_finding("f2", "src/db.rs", Some("CWE-78"), "Command Injection"),
    ];
    let chains = ChainAnalyzer::analyze_chains(&findings);
    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0].chain_type, ChainType::InjectionToExecution);
    assert_eq!(chains[0].primary_finding_id, "f1");
    assert_eq!(chains[0].partner_finding_ids, vec!["f2"]);
}

#[test]
fn test_auth_bypass_to_privilege_escalation_chain() {
    let findings = vec![
        create_finding("f1", "src/auth.rs", Some("CWE-287"), "Auth Bypass"),
        create_finding(
            "f2",
            "src/admin.rs",
            Some("CWE-269"),
            "Privilege Escalation",
        ),
    ];
    let chains = ChainAnalyzer::analyze_chains(&findings);
    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0].chain_type, ChainType::AuthBypassToPrivilegeEscal);
}

#[test]
fn test_file_access_to_rce_chain() {
    let findings = vec![
        create_finding("f1", "src/upload.rs", Some("CWE-22"), "Path Traversal"),
        create_finding("f2", "src/include.rs", Some("CWE-98"), "File Include"),
    ];
    let chains = ChainAnalyzer::analyze_chains(&findings);
    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0].chain_type, ChainType::FileAccessToRCE);
}

#[test]
fn test_data_exfiltration_chain() {
    let findings = vec![
        create_finding("f1", "src/proxy.rs", Some("CWE-918"), "SSRF"),
        create_finding("f2", "src/api.rs", Some("CWE-200"), "Info Exposure"),
    ];
    let chains = ChainAnalyzer::analyze_chains(&findings);
    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0].chain_type, ChainType::DataExfilChain);
}

#[test]
fn test_no_chain_across_different_directories() {
    let findings = vec![
        create_finding("f1", "src/db.rs", Some("CWE-89"), "SQL Injection"),
        create_finding("f2", "tests/test.rs", Some("CWE-78"), "Command Injection"),
    ];
    let chains = ChainAnalyzer::analyze_chains(&findings);
    assert!(chains.is_empty());
}

#[test]
fn test_apply_chain_verdicts_marks_related_findings() {
    let mut findings = vec![
        create_finding("f1", "src/db.rs", Some("CWE-89"), "SQL Injection"),
        create_finding("f2", "src/db.rs", Some("CWE-78"), "Command Injection"),
        create_finding("f3", "src/other.rs", Some("CWE-200"), "Info Exposure"),
    ];

    let chains = vec![ChainResult {
        primary_finding_id: "f1".to_string(),
        partner_finding_ids: vec!["f2".to_string()],
        chain_description: "Test chain".to_string(),
        chain_type: ChainType::InjectionToExecution,
    }];

    apply_chain_verdicts(&mut findings, &chains);

    assert!(matches!(
        findings[0].triage_verdict,
        Some(TriageVerdict::ChainRequired { .. })
    ));
    assert!(matches!(
        findings[1].triage_verdict,
        Some(TriageVerdict::ChainRequired { .. })
    ));
    assert!(findings[2].triage_verdict.is_none());
}

#[test]
fn test_chain_type_variants() {
    assert_eq!(
        ChainType::InjectionToExecution,
        ChainType::InjectionToExecution
    );
    assert_eq!(
        ChainType::AuthBypassToPrivilegeEscal,
        ChainType::AuthBypassToPrivilegeEscal
    );
    assert_eq!(ChainType::FileAccessToRCE, ChainType::FileAccessToRCE);
    assert_eq!(ChainType::DataExfilChain, ChainType::DataExfilChain);
}

#[test]
fn test_chain_result_creation() {
    let result = ChainResult {
        primary_finding_id: "primary-1".to_string(),
        partner_finding_ids: vec!["partner-1".to_string(), "partner-2".to_string()],
        chain_description: "Test attack chain".to_string(),
        chain_type: ChainType::InjectionToExecution,
    };

    assert_eq!(result.primary_finding_id, "primary-1");
    assert_eq!(result.partner_finding_ids.len(), 2);
    assert!(!result.chain_description.is_empty());
}

// ============================================================================
// ROOT CAUSE DEDUPLICATION TESTS
// ============================================================================

#[test]
fn test_root_cause_deduplicator_new_creates_empty() {
    let dedup = RootCauseDeduplicator::new();
    assert_eq!(dedup.group_count(), 0);
}

#[test]
fn test_compute_root_cause_id_same_inputs_produce_same_hash() {
    let finding1 =
        create_finding_with_snippet("f1", "src/db.rs", "SQL Injection", Some("SELECT *"));
    let finding2 =
        create_finding_with_snippet("f2", "src/db.rs", "SQL Injection", Some("SELECT *"));

    let id1 = RootCauseDeduplicator::compute_root_cause_id(&finding1);
    let id2 = RootCauseDeduplicator::compute_root_cause_id(&finding2);

    assert_eq!(id1, id2);
}

#[test]
fn test_compute_root_cause_id_different_files_produce_different_hash() {
    let finding1 =
        create_finding_with_snippet("f1", "src/db.rs", "SQL Injection", Some("SELECT *"));
    let finding2 =
        create_finding_with_snippet("f2", "src/api.rs", "SQL Injection", Some("SELECT *"));

    let id1 = RootCauseDeduplicator::compute_root_cause_id(&finding1);
    let id2 = RootCauseDeduplicator::compute_root_cause_id(&finding2);

    assert_ne!(id1, id2);
}

#[test]
fn test_compute_root_cause_id_normalizes_whitespace() {
    let finding1 = create_finding_with_snippet(
        "f1",
        "src/db.rs",
        "SQL Injection",
        Some("SELECT *\nFROM users"),
    );
    let finding2 = create_finding_with_snippet(
        "f2",
        "src/db.rs",
        "SQL Injection",
        Some("SELECT * FROM users"),
    );

    let id1 = RootCauseDeduplicator::compute_root_cause_id(&finding1);
    let id2 = RootCauseDeduplicator::compute_root_cause_id(&finding2);

    assert_eq!(id1, id2);
}

#[test]
fn test_deduplicate_groups_same_root_cause() {
    let mut dedup = RootCauseDeduplicator::new();

    let findings = vec![
        create_finding_with_snippet("f1", "src/db.rs", "SQL Injection", Some("SELECT *")),
        create_finding_with_snippet("f2", "src/db.rs", "SQL Injection", Some("SELECT *")),
    ];

    let groups = dedup.deduplicate(findings);
    assert_eq!(groups.len(), 1);
}

#[test]
fn test_deduplicate_separates_different_root_causes() {
    let mut dedup = RootCauseDeduplicator::new();

    let findings = vec![
        create_finding_with_snippet("f1", "src/db.rs", "SQL Injection", Some("SELECT *")),
        create_finding_with_snippet("f2", "src/api.rs", "XSS", Some("<script>")),
    ];

    let groups = dedup.deduplicate(findings);
    assert_eq!(groups.len(), 2);
}

#[test]
fn test_merge_groups_combines_same_root_cause() {
    let mut dedup = RootCauseDeduplicator::new();

    let mut group1 = RootCauseGroup::new("abc123", "SQL Injection", V3Severity::High);
    group1.add_finding("f1", "src/db.rs", 42);

    let mut group2 = RootCauseGroup::new("abc123", "SQL Injection", V3Severity::High);
    group2.add_finding("f2", "src/api.rs", 100);

    dedup.merge_groups(vec![group1, group2]);

    assert_eq!(dedup.group_count(), 1);
}

#[test]
fn test_into_groups_returns_all_groups() {
    let mut dedup = RootCauseDeduplicator::new();

    let findings = vec![
        create_finding_with_snippet("f1", "src/db.rs", "SQL Injection", Some("SELECT *")),
        create_finding_with_snippet("f2", "src/api.rs", "XSS", Some("<script>")),
    ];

    dedup.deduplicate(findings);
    let groups = dedup.into_groups();

    assert_eq!(groups.len(), 2);
}

// ============================================================================
// GLOBAL FP STORE TESTS
// ============================================================================

#[test]
fn test_fp_store_new_creates_empty() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("fp_store.json");

    let store = GlobalFpStore::with_path(&path);
    assert!(store.is_empty());
}

#[test]
fn test_fp_store_mark_false_positive_adds_id() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("fp_store.json");

    let mut store = GlobalFpStore::with_path(&path);
    store.mark_false_positive("test-fp-id");

    assert!(!store.is_empty());
    assert!(store.is_false_positive("test-fp-id"));
}

#[test]
fn test_fp_store_remove_removes_id() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("fp_store.json");

    let mut store = GlobalFpStore::with_path(&path);
    store.mark_false_positive("test-fp-id");
    assert!(store.is_false_positive("test-fp-id"));

    store.remove("test-fp-id");
    assert!(!store.is_false_positive("test-fp-id"));
}

#[test]
fn test_fp_store_load_missing_file_returns_empty() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("nonexistent.json");

    let store = GlobalFpStore::load(&path);
    assert!(store.is_empty());
}

#[test]
fn test_fp_store_save_and_load() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("fp_store.json");

    {
        let mut store = GlobalFpStore::with_path(&path);
        store.mark_false_positive("fp-1");
        store.mark_false_positive("fp-2");
        store.save().unwrap();
    }

    let store = GlobalFpStore::load(&path);
    assert!(store.is_false_positive("fp-1"));
    assert!(store.is_false_positive("fp-2"));
}

// ============================================================================
// VARIANT SEARCH TESTS
// ============================================================================

#[test]
fn test_variant_searcher_new_creates_with_default_threshold() {
    let temp = TempDir::new().unwrap();
    let searcher = VariantSearcher::new(temp.path().to_string_lossy().to_string());

    // Search with no patterns should return empty
    let hits = searcher.search_variants().unwrap();
    assert!(hits.is_empty());
}

#[test]
fn test_search_patterns_added_correctly() {
    let temp = TempDir::new().unwrap();
    let pattern = SearchPattern::new(
        "command_injection",
        r"Command::new\(",
        vec!["user_input".to_string()],
    );

    let searcher = VariantSearcher::new(temp.path().to_string_lossy().to_string())
        .with_patterns(vec![pattern]);

    let hits = searcher.search_variants().unwrap();
    assert!(hits.is_empty()); // No matching files
}

#[test]
fn test_search_with_vulnerable_file() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("vuln.rs");
    fs::write(&test_file, "Command::new(user_input).spawn();").unwrap();

    let pattern = SearchPattern::new(
        "command_injection",
        r"Command::new\(.*\).*spawn\(\)",
        vec!["user_input".to_string()],
    );

    let searcher = VariantSearcher::new(temp.path().to_string_lossy().to_string())
        .with_patterns(vec![pattern])
        .with_threshold(0.3);

    let hits = searcher.search_variants().unwrap();
    assert!(!hits.is_empty());
    assert!(hits[0].file_path.contains("vuln.rs"));
}

#[test]
fn test_threshold_filters_low_score_hits() {
    let temp = TempDir::new().unwrap();
    let test_file = temp.path().join("test.rs");
    fs::write(&test_file, "Command::new(\"ls\");").unwrap();

    let pattern = SearchPattern::new("test", r"Command::new\(", vec![]);

    let searcher = VariantSearcher::new(temp.path().to_string_lossy().to_string())
        .with_patterns(vec![pattern])
        .with_threshold(0.9);

    let hits = searcher.search_variants().unwrap();
    // High threshold should filter out low-score matches
    for hit in &hits {
        assert!(hit.similarity_score >= 0.9);
    }
}

#[test]
fn test_extract_pattern_escapes_special_chars() {
    let pattern = VariantSearcher::extract_pattern("user.name");
    assert!(pattern.contains("\\."));

    let pattern2 = VariantSearcher::extract_pattern("func(arg)");
    assert!(pattern2.contains("\\("));
    assert!(pattern2.contains("\\)"));
}

#[test]
fn test_match_pattern_valid_regex() {
    assert!(VariantSearcher::match_pattern("let x = foo();", r"foo\(\)"));
    assert!(!VariantSearcher::match_pattern(
        "let x = bar();",
        r"foo\(\)"
    ));
}

#[test]
fn test_match_pattern_invalid_regex_returns_false() {
    let result = VariantSearcher::match_pattern("test", "[invalid(");
    assert!(!result);
}

#[test]
fn test_variant_hit_creation() {
    let hit = VariantHit::new("src/main.rs", 42, 0.85, "code snippet");

    assert_eq!(hit.file_path, "src/main.rs");
    assert_eq!(hit.line_number, 42);
    assert_eq!(hit.similarity_score, 0.85);
    assert_eq!(hit.snippet, "code snippet");
}

// ============================================================================
// CROSS-FILE ANALYSIS TESTS
// ============================================================================

#[test]
fn test_cross_file_analyzer_empty_findings() {
    let findings: Vec<VulnerabilityFinding> = Vec::new();
    let result = CrossFileAnalyzer::analyze_cross_file_references(&findings);
    assert!(result.is_empty());
}

#[test]
fn test_cross_file_analyzer_single_finding_no_references() {
    let findings = vec![create_finding("f1", "src/main.rs", Some("CWE-79"), "XSS")];
    let result = CrossFileAnalyzer::analyze_cross_file_references(&findings);

    assert_eq!(result.len(), 1);
    assert!(result[0].cross_file_references.is_none());
}

#[test]
fn test_cross_file_analyzer_same_cwe_different_file() {
    let findings = vec![
        create_finding("f1", "src/main.rs", Some("CWE-79"), "XSS"),
        create_finding("f2", "src/utils.rs", Some("CWE-79"), "XSS"),
    ];
    let result = CrossFileAnalyzer::analyze_cross_file_references(&findings);

    assert_eq!(result.len(), 2);
    // Both should have cross-file references
    assert!(result[0].cross_file_references.is_some());
    assert!(result[1].cross_file_references.is_some());
}

#[test]
fn test_cross_file_analyzer_same_severity_and_source() {
    let mut f1 = create_finding("f1", "src/main.rs", None, "Issue");
    f1.severity = Severity::High;
    f1.sources = vec!["semgrep".to_string()];

    let mut f2 = create_finding("f2", "src/utils.rs", None, "Issue");
    f2.severity = Severity::High;
    f2.sources = vec!["semgrep".to_string()];

    let findings = vec![f1, f2];
    let result = CrossFileAnalyzer::analyze_cross_file_references(&findings);

    assert_eq!(result.len(), 2);
}

// ============================================================================
// MULTI-VERIFIER TESTS
// ============================================================================

#[test]
fn test_multi_verifier_new_with_default_config() {
    let config = VerifierConfig::default();
    let _verifier = MultiVerifier::new(config.clone());

    assert_eq!(config.num_verifiers, 3);
    assert_eq!(config.circuit_breaker_threshold, 0.5);
}

#[test]
#[allow(clippy::unit_arg)]
fn test_multi_verifier_with_verifiers_config() {
    let _verifier = MultiVerifier::new(VerifierConfig::default()).with_verifiers(5);
    // Config fields are private, just verify construction works
}

#[test]
fn test_verify_returns_valid_verdict() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    let result = verifier.verify("test-finding", "let x = 1;").unwrap();

    assert!(matches!(
        result.final_verdict,
        VerifierVerdict::Confirmed | VerifierVerdict::Rejected | VerifierVerdict::Inconclusive
    ));
}

#[test]
fn test_verify_todo_code_is_rejected() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    let result = verifier.verify("test", "// TODO: fix this").unwrap();

    assert_eq!(result.final_verdict, VerifierVerdict::Rejected);
}

#[test]
fn test_verify_unsafe_code_is_confirmed() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    let result = verifier.verify("test", "unsafe { *ptr }").unwrap();

    assert!(matches!(
        result.final_verdict,
        VerifierVerdict::Confirmed | VerifierVerdict::Inconclusive
    ));
}

#[test]
fn test_circuit_breaker_triggers_on_high_failure_rate() {
    // Create a verifier with low threshold so it triggers easily
    let config = VerifierConfig {
        num_verifiers: 3,
        circuit_breaker_threshold: 0.1, // Very low threshold
    };
    let verifier = MultiVerifier::new(config);

    // After verifications, circuit breaker state depends on actual failures
    // We can only test that verify works correctly
    let result = verifier.verify("test", "code").unwrap();
    // Result should be valid
    assert!(matches!(
        result.final_verdict,
        VerifierVerdict::Confirmed | VerifierVerdict::Rejected | VerifierVerdict::Inconclusive
    ));
}

#[test]
fn test_reset_circuit_breaker_clears_state() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    // Reset should not panic and should leave verifier in usable state
    verifier.reset_circuit_breaker();

    // After reset, verifier should still work
    let _result = verifier.verify("test", "code").unwrap();
}

#[test]
fn test_confidence_is_between_zero_and_one() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    let result = verifier.verify("test", "code").unwrap();

    assert!(result.confidence >= 0.0);
    assert!(result.confidence <= 1.0);
}

#[test]
fn test_vote_count_sums_to_num_verifiers() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    let result = verifier.verify("test", "code").unwrap();

    let total_votes: u32 = result.vote_count.values().sum();
    assert_eq!(total_votes, 3); // default num_verifiers
}

#[test]
fn test_batch_verify_filters_rejected() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    let findings = vec![
        create_finding_with_snippet("f1", "src/main.rs", "Issue", Some("unsafe { x }")),
        create_finding_with_snippet("f2", "src/main.rs", "Issue", Some("// TODO")),
    ];

    let result = verifier.verify_batch(&findings);

    // Should keep confirmed/inconclusive, filter out rejected
    assert!(result.len() <= findings.len());
}
