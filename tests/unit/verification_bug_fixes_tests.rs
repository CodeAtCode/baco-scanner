//! Regression tests for verification phase Bug H and Bug I fixes.
//!
//! Bug H: Persist seven-question gate answers on the finding.
//! Bug I: Preserve a pre-existing Confirmed status on agent error.
//!
//! Each test must fail when its fix is reverted and pass when the fix is applied.

use baco::error::ScanError;
use baco::findings::{VerificationStatus, VulnerabilityFinding};
use baco::llm::{ChatMessage, ChatResponseWithModel, LlmChatClient};
use baco::scanner::phases::llm_phases::verification::{
    parse_batch_verification_verdict, verify_findings_batched,
};
use std::collections::HashMap;

// ============================================================================
// Bug H Tests: Gate answer persistence
// ============================================================================

#[test]
fn test_bug_h_gate_answers_persisted_on_parse() {
    // Bug H regression: verify that seven-question gate answers are captured
    // in the parse output, not discarded.
    //
    // Before the fix: parse_batch_verification_verdict returned (status, notes)
    // and the gate answers were computed but discarded.
    // After the fix: it returns (status, notes, gate_answers) with the actual answers.

    let verdict_json = r#"[{
        "index": 0,
        "verification_status": "confirmed",
        "verification_notes": "the handler has no nonce check",
        "seven_question_gate": {
            "reachability": "yes",
            "controllability": "yes",
            "preconditions": "no",
            "impact": "yes",
            "context": "yes",
            "evidence": "yes",
            "confidence": "yes"
        },
        "concrete_impact_proof": {
            "attack_vector": "POST action=pay reaches handler",
            "consequence": "order marked paid without payment",
            "is_theoretical": false
        }
    }]"#;

    let results = parse_batch_verification_verdict(verdict_json, 1);

    // Assert the result has gate answers (third element of tuple)
    assert!(
        results[0].2.is_some(),
        "Bug H: gate answers must be persisted, got None"
    );

    let gate_answers = results[0].2.as_ref().unwrap();

    // Assert the gate answers are the actual answers, not placeholders
    let reachability = gate_answers
        .iter()
        .find(|(q, _)| q == "reachability")
        .unwrap();
    assert!(
        reachability.1,
        "Bug H: reachability should be true (yes), got {}",
        reachability.1
    );

    let controllability = gate_answers
        .iter()
        .find(|(q, _)| q == "controllability")
        .unwrap();
    assert!(
        controllability.1,
        "Bug H: controllability should be true (yes), got {}",
        controllability.1
    );

    let preconditions = gate_answers
        .iter()
        .find(|(q, _)| q == "preconditions")
        .unwrap();
    assert!(
        !preconditions.1,
        "Bug H: preconditions should be false (no), got {}",
        preconditions.1
    );
}

#[test]
fn test_bug_h_gate_answers_none_when_gate_missing() {
    // Bug H regression: when the gate is missing from the verdict, gate_answers should be None.

    let verdict_json = r#"[{
        "index": 0,
        "verification_status": "confirmed",
        "verification_notes": "looks real but no gate"
    }]"#;

    let results = parse_batch_verification_verdict(verdict_json, 1);

    // Assert gate answers are None when gate is missing
    assert!(
        results[0].2.is_none(),
        "Bug H: gate answers should be None when gate is missing"
    );
}

#[test]
fn test_bug_h_gate_answers_are_actual_values_not_placeholders() {
    // Bug H regression: verify that gate answers reflect the actual gate values,
    // not hardcoded placeholders.

    // All "no" answers
    let verdict_json = r#"[{
        "index": 0,
        "verification_status": "confirmed",
        "verification_notes": "test",
        "seven_question_gate": {
            "reachability": "no",
            "controllability": "no",
            "preconditions": "yes",
            "impact": "no",
            "context": "no",
            "evidence": "no",
            "confidence": "no"
        },
        "concrete_impact_proof": {
            "attack_vector": "test",
            "consequence": "test",
            "is_theoretical": false
        }
    }]"#;

    let results = parse_batch_verification_verdict(verdict_json, 1);

    assert!(
        results[0].2.is_some(),
        "Bug H: gate answers must be persisted"
    );

    let gate_answers = results[0].2.as_ref().unwrap();

    // Check that "no" answers are false
    let reachability = gate_answers
        .iter()
        .find(|(q, _)| q == "reachability")
        .unwrap();
    assert!(
        !reachability.1,
        "Bug H: reachability=no should be false, got {}",
        reachability.1
    );

    // Check that "yes" answers are true
    let preconditions = gate_answers
        .iter()
        .find(|(q, _)| q == "preconditions")
        .unwrap();
    assert!(
        preconditions.1,
        "Bug H: preconditions=yes should be true, got {}",
        preconditions.1
    );
}

#[test]
fn test_bug_h_gate_answers_with_unknown_values() {
    // Bug H regression: verify that "unknown" values become false (None from answered_yes).

    let verdict_json = r#"[{
        "index": 0,
        "verification_status": "confirmed",
        "verification_notes": "test",
        "seven_question_gate": {
            "reachability": "unknown",
            "controllability": "unknown",
            "preconditions": "unknown",
            "impact": "unknown",
            "context": "unknown",
            "evidence": "unknown",
            "confidence": "unknown"
        },
        "concrete_impact_proof": {
            "attack_vector": "test",
            "consequence": "test",
            "is_theoretical": false
        }
    }]"#;

    let results = parse_batch_verification_verdict(verdict_json, 1);

    assert!(
        results[0].2.is_some(),
        "Bug H: gate answers must be persisted even for unknown values"
    );

    let gate_answers = results[0].2.as_ref().unwrap();

    // Check that "unknown" answers become false (as per answered_yes returning None, then unwrap_or(false))
    let reachability = gate_answers
        .iter()
        .find(|(q, _)| q == "reachability")
        .unwrap();
    assert!(
        !reachability.1,
        "Bug H: reachability=unknown should be false, got {}",
        reachability.1
    );
}

// ============================================================================
// Bug I Tests: Preserve Confirmed status on agent error
// ============================================================================
//
// These tests call verify_findings_batched with a mock LLM client that always
// returns an error, exercising the production error path. Before the fix, all
// findings in an error batch were downgraded to NeedsReview. After the fix,
// pre-existing Confirmed findings retain their status.
//
// Teeth: reverting the Bug I guard (removing the matches!(...Confirmed) check)
// causes test_bug_i_confirmed_preserved_on_llm_error to fail.

/// Mock LLM client that always returns a Network error.
struct ErrorClient;

impl LlmChatClient for ErrorClient {
    async fn chat(&self, _messages: &[ChatMessage]) -> Result<ChatResponseWithModel, ScanError> {
        Err(ScanError::Network {
            message: "simulated LLM failure".to_string(),
            source: None,
        })
    }
}

fn finding_with_status(status: Option<VerificationStatus>) -> VulnerabilityFinding {
    VulnerabilityFinding {
        title: "test finding".to_string(),
        file_path: "src/test.rs".to_string(),
        code_snippet: Some("let x = 1;".to_string()),
        verification_status: status,
        ..Default::default()
    }
}

#[tokio::test]
async fn test_bug_i_confirmed_preserved_on_llm_error() {
    let client = ErrorClient;
    let prompts: HashMap<String, String> = HashMap::new();
    let primitives: HashMap<String, Vec<String>> = HashMap::new();
    let findings = vec![finding_with_status(Some(VerificationStatus::Confirmed))];

    let (results, _fallback) = verify_findings_batched(
        &client,
        &findings,
        2,
        &prompts,
        &primitives,
        &std::env::temp_dir(),
        0,
    )
    .await;

    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].0,
        VerificationStatus::Confirmed,
        "Bug I: Confirmed status must be preserved when the LLM returns an error"
    );
}

#[tokio::test]
async fn test_bug_i_false_positive_downgraded_on_llm_error() {
    let client = ErrorClient;
    let prompts: HashMap<String, String> = HashMap::new();
    let primitives: HashMap<String, Vec<String>> = HashMap::new();
    let findings = vec![finding_with_status(Some(VerificationStatus::FalsePositive))];

    let (results, _fallback) = verify_findings_batched(
        &client,
        &findings,
        2,
        &prompts,
        &primitives,
        &std::env::temp_dir(),
        0,
    )
    .await;

    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].0,
        VerificationStatus::NeedsReview,
        "Bug I: FalsePositive must be downgraded to NeedsReview on LLM error"
    );
}

// ============================================================================
// Integration tests: verify the full flow
// ============================================================================

#[test]
fn test_bug_h_full_parse_with_all_gate_answers() {
    // Full integration test: parse a complete verdict and verify all gate answers are captured.

    let verdict_json = r#"[{
        "index": 0,
        "verification_status": "confirmed",
        "verification_notes": "all checks pass",
        "seven_question_gate": {
            "reachability": "yes",
            "controllability": "yes",
            "preconditions": "no",
            "impact": "yes",
            "context": "yes",
            "evidence": "yes",
            "confidence": "yes"
        },
        "concrete_impact_proof": {
            "attack_vector": "user input reaches sink",
            "consequence": "arbitrary code execution",
            "is_theoretical": false
        }
    }]"#;

    let results = parse_batch_verification_verdict(verdict_json, 1);

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, VerificationStatus::Confirmed);
    assert!(results[0].2.is_some());

    let gate = results[0].2.as_ref().unwrap();
    assert_eq!(gate.len(), 7);

    // Verify each gate answer
    let expected = [
        ("reachability", true),
        ("controllability", true),
        ("preconditions", false),
        ("context", true),
        ("impact", true),
        ("evidence", true),
        ("confidence", true),
    ];

    for (name, expected_val) in expected {
        let actual = gate.iter().find(|(q, _)| q == name).unwrap();
        assert_eq!(actual.1, expected_val, "Gate answer for {}", name);
    }
}
