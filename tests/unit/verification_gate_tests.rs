//! The seven-question gate is enforced, not decorative.
//!
//! The verification prompt asks for seven gate answers and a concrete impact
//! scenario, and the parser used to read `verification_status` and drop all of
//! it. `confirmed` was therefore the model's word with nothing behind it -- the
//! single largest source of false positives, since a finding the judge cannot
//! locate in the code it was shown still came back confirmed.

use baco::findings::VerificationStatus;
use baco::scanner::phases::llm_phases::verification::parse_batch_verification_verdict;

const ALL_YES: &str = r#"[{
  "index": 0,
  "verification_status": "confirmed",
  "verification_notes": "the handler writes to the orders table with no nonce check",
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
    "attack_vector": "POST action=pay4payment_rated reaches the handler at line 4",
    "consequence": "order marked paid without payment",
    "is_theoretical": false
  }
}]"#;

fn verdict_with(gate: &str, proof: &str) -> String {
    format!(
        r#"[{{
  "index": 0,
  "verification_status": "confirmed",
  "verification_notes": "looks real",
  "seven_question_gate": {gate},
  "concrete_impact_proof": {proof}
}}]"#
    )
}

const GOOD_PROOF: &str = r#"{
    "attack_vector": "POST reaches the handler at line 4",
    "consequence": "order marked paid without payment",
    "is_theoretical": false
  }"#;

#[test]
fn test_a_full_pass_stays_confirmed() {
    // The control: if this ever downgrades, the gate is too strict and every
    // real finding needs review.
    let out = parse_batch_verification_verdict(ALL_YES, 1);
    assert_eq!(out[0].0, VerificationStatus::Confirmed);
}

#[test]
fn test_not_reachable_kills_the_finding() {
    let body = verdict_with(
        r#"{"reachability":"no","controllability":"yes","preconditions":"no","impact":"yes","context":"yes","evidence":"yes","confidence":"yes"}"#,
        GOOD_PROOF,
    );
    let out = parse_batch_verification_verdict(&body, 1);
    assert_eq!(out[0].0, VerificationStatus::FalsePositive);
    assert!(
        out[0].1.contains("not reachable"),
        "the reason must say which gate answer killed it, got {:?}",
        out[0].1
    );
}

#[test]
fn test_uncontrollable_input_kills_the_finding() {
    let body = verdict_with(
        r#"{"reachability":"yes","controllability":"no","preconditions":"no","impact":"yes","context":"yes","evidence":"yes","confidence":"yes"}"#,
        GOOD_PROOF,
    );
    let out = parse_batch_verification_verdict(&body, 1);
    assert_eq!(out[0].0, VerificationStatus::FalsePositive);
    assert!(out[0].1.contains("does not control"));
}

#[test]
fn test_an_existing_guard_kills_the_finding() {
    // preconditions=YES means the code IS protected, which the prompt defines
    // as a kill. It is the answer most likely to be ignored by a judge that
    // wants to confirm.
    let body = verdict_with(
        r#"{"reachability":"yes","controllability":"yes","preconditions":"yes","impact":"yes","context":"yes","evidence":"yes","confidence":"yes"}"#,
        GOOD_PROOF,
    );
    let out = parse_batch_verification_verdict(&body, 1);
    assert_eq!(out[0].0, VerificationStatus::FalsePositive);
    assert!(out[0].1.contains("validation"));
}

#[test]
fn test_no_code_evidence_demotes_to_needs_review() {
    // Not a false positive claim -- the judge simply could not find the code.
    let body = verdict_with(
        r#"{"reachability":"yes","controllability":"yes","preconditions":"no","impact":"yes","context":"yes","evidence":"no","confidence":"yes"}"#,
        GOOD_PROOF,
    );
    let out = parse_batch_verification_verdict(&body, 1);
    assert_eq!(out[0].0, VerificationStatus::NeedsReview);
    assert!(out[0].1.contains("no code evidence"));
}

#[test]
fn test_a_theoretical_impact_demotes_to_needs_review() {
    // The prompt requires a concrete scenario and says to downgrade a
    // theoretical one. "could potentially lead to" is the tell.
    let body = verdict_with(
        r#"{"reachability":"yes","controllability":"yes","preconditions":"no","impact":"yes","context":"yes","evidence":"yes","confidence":"yes"}"#,
        r#"{"attack_vector":"could potentially lead to data exposure","consequence":"unclear","is_theoretical":true}"#,
    );
    let out = parse_batch_verification_verdict(&body, 1);
    assert_eq!(out[0].0, VerificationStatus::NeedsReview);
    assert!(out[0].1.contains("theoretical"));
}

#[test]
fn test_a_missing_impact_scenario_demotes_to_needs_review() {
    let body = verdict_with(
        r#"{"reachability":"yes","controllability":"yes","preconditions":"no","impact":"yes","context":"yes","evidence":"yes","confidence":"yes"}"#,
        r#"{"attack_vector":"","consequence":"","is_theoretical":false}"#,
    );
    let out = parse_batch_verification_verdict(&body, 1);
    assert_eq!(out[0].0, VerificationStatus::NeedsReview);
}

#[test]
fn test_case_and_spacing_in_answers_do_not_matter() {
    // " YES " and "Yes" are yes; "NO" on preconditions means the code is NOT
    // protected, which is the passing answer for that question.
    let body = verdict_with(
        r#"{"reachability":" YES ","controllability":"Yes","preconditions":"NO","impact":"yes","context":"yes","evidence":"yes","confidence":"yes"}"#,
        GOOD_PROOF,
    );
    let out = parse_batch_verification_verdict(&body, 1);
    assert_eq!(
        out[0].0,
        VerificationStatus::Confirmed,
        "all gate answers pass"
    );
}

#[test]
fn test_no_concrete_impact_kills_the_finding() {
    let body = verdict_with(
        r#"{"reachability":"yes","controllability":"yes","preconditions":"no","impact":"no","context":"yes","evidence":"yes","confidence":"yes"}"#,
        GOOD_PROOF,
    );
    let out = parse_batch_verification_verdict(&body, 1);
    assert_eq!(out[0].0, VerificationStatus::FalsePositive);
}

#[test]
fn test_a_response_without_the_gate_is_left_to_the_model() {
    // A model that omits the gate is not second-guessed here: there is nothing
    // to enforce, and inventing a downgrade would be a guess. The honest
    // outcome is the status the model gave.
    let body =
        r#"[{"index":0,"verification_status":"confirmed","verification_notes":"legacy shape"}]"#;
    let out = parse_batch_verification_verdict(body, 1);
    assert_eq!(out[0].0, VerificationStatus::Confirmed);
}

#[test]
fn test_an_unknown_answer_is_not_read_as_a_yes_or_a_no() {
    // "unknown" must not trip a kill, and must not count as the affirmative the
    // prompt's PASS rule needs.
    let body = verdict_with(
        r#"{"reachability":"unknown","controllability":"unknown","preconditions":"unknown","impact":"unknown","context":"unknown","evidence":"unknown","confidence":"unknown"}"#,
        GOOD_PROOF,
    );
    let out = parse_batch_verification_verdict(&body, 1);
    assert_eq!(
        out[0].0,
        VerificationStatus::Confirmed,
        "an unparsed answer must not be turned into a verdict"
    );
}

#[test]
fn test_a_non_confirmed_verdict_is_never_overridden() {
    // The gate only ever downgrades. A model that already said false_positive
    // must not have that rewritten.
    let body = r#"[{
      "index": 0,
      "verification_status": "false_positive",
      "verification_notes": "protected by check_admin_referer",
      "seven_question_gate": {"reachability":"yes","controllability":"yes","preconditions":"no","impact":"yes","context":"yes","evidence":"yes","confidence":"yes"}
    }]"#;
    let out = parse_batch_verification_verdict(body, 1);
    assert_eq!(out[0].0, VerificationStatus::FalsePositive);
    assert!(
        out[0].1.contains("check_admin_referer"),
        "the model's reason survives"
    );
}
