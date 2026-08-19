//! MultiVerifier phase tests
//!
//! These tests verify that the MultiVerifier phase correctly
//! processes findings through the verification pipeline.

use crate::fixtures::make_finding_phase as make_finding;
use baco::findings::{Severity, VulnerabilityFinding};
use baco::multi_verifier::{MultiVerifier, VerifierConfig};
use baco::scanner_types::poc::VerifierVerdict;

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
#[test]
fn test_rejected_for_todo_code() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    let finding_id = "finding-456";
    let code_snippet = "// TODO: fix this later";

    let result = verifier.verify(finding_id, code_snippet).unwrap();

    assert_eq!(result.final_verdict, VerifierVerdict::Rejected);
}

#[test]
fn test_circuit_breaker_triggers() {
    let config = VerifierConfig {
        num_verifiers: 5,
        ..Default::default()
    };

    let verifier = MultiVerifier::new(config);

    // Force circuit breaker by having too many failures
    verifier
        .api_failure_count
        .store(10, std::sync::atomic::Ordering::SeqCst);
    verifier
        .total_verifications
        .store(15, std::sync::atomic::Ordering::SeqCst);

    let result = verifier.verify("finding", "code").unwrap();

    assert_eq!(result.final_verdict, VerifierVerdict::Inconclusive);
    assert!(verifier.is_circuit_broken());
}

#[test]
fn test_configurable_verifier_count() {
    let verifier = MultiVerifier::new(VerifierConfig::default()).with_verifiers(5);

    let result = verifier.verify("find", "code").unwrap();

    assert_eq!(result.verdicts.len(), 5);
}

#[test]
fn test_reset_circuit_breaker() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    verifier
        .api_failure_count
        .store(10, std::sync::atomic::Ordering::SeqCst);
    verifier
        .total_verifications
        .store(15, std::sync::atomic::Ordering::SeqCst);

    assert!(verifier.is_circuit_broken());

    verifier.reset_circuit_breaker();

    assert!(!verifier.is_circuit_broken());
}

#[test]
fn test_confidence_calculation() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    // Use code that triggers consistent verdicts
    let code = "unsafe { *ptr }";
    let result = verifier.verify("id", code).unwrap();

    // Confidence should be between 0 and 1
    assert!(result.confidence >= 0.0);
    assert!(result.confidence <= 1.0);

    // Check vote counts sum to number of verifiers
    let total_votes: u32 = result.vote_count.values().sum();
    assert_eq!(total_votes, 3); // default num_verifiers
}

#[test]
fn test_vote_count_tracking() {
    let verifier = MultiVerifier::new(VerifierConfig::default());

    let result = verifier.verify("test-id", "code").unwrap();

    // Vote count should have at least one entry
    assert!(
        !result.vote_count.is_empty(),
        "vote_count should not be empty"
    );

    // Sum of all votes should equal number of verifiers
    let total_votes: u32 = result.vote_count.values().sum();
    assert_eq!(total_votes, 3); // default num_verifiers
}

#[test]
fn test_verifiers_produces_valid_output() {
    let config = VerifierConfig {
        num_verifiers: 5,
        circuit_breaker_threshold: 0.3,
    };

    let verifier = MultiVerifier::new(config);

    let result = verifier
        .verify("vuln-find", "let x = unsafe { *ptr }; spawn();")
        .unwrap();

    // All verifiers should return valid verdicts
    for v in &result.verdicts {
        assert!(matches!(
            v,
            VerifierVerdict::Confirmed | VerifierVerdict::Rejected | VerifierVerdict::Inconclusive
        ));
    }
}
