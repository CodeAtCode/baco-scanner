//! MultiVerifier phase tests
//!
//! These tests verify that the MultiVerifier phase correctly
//! processes findings through the verification pipeline.

use baco::findings::{Severity, VulnerabilityFinding};
use baco::multi_verifier::{MultiVerifier, VerifierConfig};
use baco::scanner_types::poc::VerifierVerdict;

/// Helper to create a VulnerabilityFinding for tests
fn make_finding(
    id: &str,
    title: &str,
    file_path: &str,
    line_number: Option<u32>,
    code_snippet: Option<&str>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test description".to_string(),
        severity: Severity::High,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: file_path.to_string(),
        line_number,
        code_snippet: code_snippet.map(String::from),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["test".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.9),
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

#[test]
fn test_multi_verifier_default_config() {
    let config = VerifierConfig::default();

    assert_eq!(config.num_verifiers, 3);
    assert_eq!(config.circuit_breaker_threshold, 0.5);
}

#[test]
fn test_multi_verifier_verify_batch_empty_findings() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    let findings: Vec<VulnerabilityFinding> = vec![];
    let result = verifier.verify_batch(&findings);

    assert!(result.is_empty());
}

#[test]
fn test_multi_verifier_verify_batch_single_finding_confirmed() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    let finding = make_finding(
        "f1",
        "Unsafe Code",
        "src/main.rs",
        Some(42),
        Some("unsafe { *ptr }"),
    );

    let findings = vec![finding];
    let result = verifier.verify_batch(&findings);

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].id, "f1");
}

#[test]
fn test_multi_verifier_verify_batch_single_finding_rejected() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    let finding = make_finding(
        "f2",
        "TODO Code",
        "src/lib.rs",
        Some(100),
        Some("// TODO: fix this later"),
    );

    let findings = vec![finding];
    let result = verifier.verify_batch(&findings);

    assert!(result.is_empty());
}

#[test]
fn test_multi_verifier_verify_batch_multiple_findings() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    let findings = vec![
        make_finding("f1", "Unsafe", "src/a.rs", Some(10), Some("unsafe { x }")),
        make_finding("f2", "TODO", "src/b.rs", Some(20), Some("// TODO")),
        make_finding(
            "f3",
            "Spawn",
            "src/c.rs",
            Some(30),
            Some("Command::new().spawn()"),
        ),
    ];

    let result = verifier.verify_batch(&findings);

    assert!(!result.is_empty());
}

#[test]
fn test_multi_verifier_verify_batch_mixed_results() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    let findings = vec![
        make_finding(
            "confirmed-1",
            "Unsafe Code",
            "src/unsafe.rs",
            Some(1),
            Some("unsafe { *ptr }"),
        ),
        make_finding(
            "rejected-1",
            "TODO Code",
            "src/todo.rs",
            Some(2),
            Some("// TODO: implement later"),
        ),
        make_finding(
            "confirmed-2",
            "Spawn",
            "src/spawn.rs",
            Some(3),
            Some("std::process::Command::new().spawn()"),
        ),
    ];

    let result = verifier.verify_batch(&findings);

    let confirmed_count = result
        .iter()
        .filter(|f| f.id.starts_with("confirmed"))
        .count();
    let rejected_count = result
        .iter()
        .filter(|f| f.id.starts_with("rejected"))
        .count();

    assert!(
        confirmed_count >= 1,
        "Should keep at least one confirmed finding"
    );
    assert_eq!(rejected_count, 0, "Should reject all TODO findings");
}

#[test]
fn test_multi_verifier_verify_batch_preserves_finding_data() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    let finding = make_finding(
        "preserve-test",
        "SQL Injection",
        "src/db.rs",
        Some(42),
        Some("SELECT * FROM users"),
    );

    let findings = vec![finding.clone()];
    let result = verifier.verify_batch(&findings);

    if !result.is_empty() {
        assert_eq!(result[0].id, "preserve-test");
        assert_eq!(result[0].title, "SQL Injection");
        assert_eq!(result[0].file_path, "src/db.rs");
        assert_eq!(result[0].line_number, Some(42));
        assert_eq!(result[0].severity, Severity::High);
    }
}

#[test]
fn test_multi_verifier_verify_batch_no_code_snippet() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    let finding = make_finding("no-code", "No Code", "src/empty.rs", Some(1), None);

    let findings = vec![finding];
    let result = verifier.verify_batch(&findings);

    assert!(!result.is_empty());
}

#[test]
fn test_multi_verifier_verify_batch_custom_verifier_count() {
    let verifier = MultiVerifier::new(VerifierConfig {
        num_verifiers: 5,
        circuit_breaker_threshold: 0.5,
    });

    let finding = make_finding(
        "f1",
        "Unsafe",
        "src/main.rs",
        Some(42),
        Some("unsafe { *ptr }"),
    );

    let findings = vec![finding];
    let result = verifier.verify_batch(&findings);

    assert!(!result.is_empty());
}

#[test]
fn test_multi_verifier_majority_vote_logic() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    let finding_id = "test-majority";
    let code_snippet = "unsafe { *ptr }";

    let result = verifier.verify(finding_id, code_snippet).unwrap();

    assert!(matches!(
        result.final_verdict,
        VerifierVerdict::Confirmed | VerifierVerdict::Inconclusive
    ));
    assert!(result.confidence >= 0.0);
    assert!(result.confidence <= 1.0);
    assert_eq!(result.verdicts.len(), 3);
}

#[test]
fn test_multi_verifier_tie_breaker() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    let finding_id = "tie-test";
    let code_snippet = "println!(\"hello\")";

    let mut has_tie = false;

    for _ in 0..20 {
        let result = verifier.verify(finding_id, code_snippet).unwrap();

        if result.final_verdict == VerifierVerdict::Inconclusive {
            has_tie = true;
            break;
        }
    }

    assert!(has_tie, "Should produce inconclusive verdict on tied votes");
}
