//! Tests for the strict-JSON verification verdict parser
//! (`parse_verification_verdict` in `src/scanner/phases/llm_phases/verification.rs`).

use baco::findings::VerificationStatus;
use baco::scanner::phases::llm_phases::parse_verification_verdict;

#[test]
fn test_parse_confirmed_valid_json() {
    let input = r#"{
        "verification_status": "confirmed",
        "verification_notes": "This is a genuine vulnerability"
    }"#;

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::Confirmed);
    assert_eq!(notes, "This is a genuine vulnerability");
}

#[test]
fn test_parse_false_positive_valid_json() {
    let input = r#"{
        "verification_status": "false_positive",
        "verification_notes": "Input is sanitized before use"
    }"#;

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::FalsePositive);
    assert_eq!(notes, "Input is sanitized before use");
}

#[test]
fn test_parse_needs_review_valid_json() {
    let input = r#"{
        "verification_status": "needs_review",
        "verification_notes": "Insufficient context to determine"
    }"#;

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::NeedsReview);
    assert_eq!(notes, "Insufficient context to determine");
}

#[test]
fn test_parse_fenced_json() {
    let input = r#"```json
    {
        "verification_status": "confirmed",
        "verification_notes": "Verified exploit path"
    }
    ```"#;

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::Confirmed);
    assert_eq!(notes, "Verified exploit path");
}

#[test]
fn test_parse_garbage_returns_needs_review_with_raw_text() {
    let input = "This is completely invalid garbage text that is not JSON at all";

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::NeedsReview);
    assert_eq!(notes, input);
}

#[test]
fn test_parse_unknown_status_returns_needs_review() {
    let input = r#"{
        "verification_status": "unknown_status",
        "verification_notes": "Something weird"
    }"#;

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::NeedsReview);
    assert_eq!(notes, "Something weird");
}

#[test]
fn test_parse_missing_notes_field() {
    let input = r#"{
        "verification_status": "confirmed"
    }"#;

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::Confirmed);
    assert_eq!(notes, "");
}

#[test]
fn test_parse_unrecognized_field_names_are_ignored() {
    // Only the renamed keys `verification_status`/`verification_notes` are
    // read; other keys are ignored by serde, so the verdict still parses.
    let input = r#"{
        "verification_status": "confirmed",
        "notes": "different key name"
    }"#;

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::Confirmed);
    assert_eq!(notes, "");
}

#[test]
fn test_parse_prose_wrapping_json_degrades_to_needs_review() {
    // Strict contract: prose outside the JSON object fails the whole-string
    // parse, so the verdict degrades to needs_review with the raw response.
    let input = r#"This is NOT confirmed. Here's my analysis:
    {
        "verification_status": "false_positive",
        "verification_notes": "The code has proper bounds checking"
    }"#;

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::NeedsReview);
    assert_eq!(notes, input);
}

#[test]
fn test_parse_array_shaped_json_salvages_first_element() {
    // LLM sometimes returns array of objects - salvage path should extract first element
    let input = r#"[
        {
            "seven_question_gate": {
                "reachability": "yes",
                "controllability": "no"
            },
            "triage_verdict": "needs_review",
            "verification_status": "needs_review",
            "verification_notes": "Input is not fully controlled by attacker",
            "confidence": 0.3
        }
    ]"#;

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::NeedsReview);
    // Should extract human notes, not raw JSON
    assert_eq!(notes, "Input is not fully controlled by attacker");
    // Notes should NOT contain '{' character (no raw JSON)
    assert!(!notes.contains('{'));
}

#[test]
fn test_parse_array_with_triage_verdict_field() {
    // Array with triage_verdict instead of verification_status
    let input = r#"[
        {
            "triage_verdict": "needs_review",
            "verification_notes": "Insufficient evidence to confirm"
        }
    ]"#;

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::NeedsReview);
    assert_eq!(notes, "Insufficient evidence to confirm");
}

#[test]
fn test_parse_array_confirmed_status() {
    // Array with confirmed status
    let input = r#"[
        {
            "verification_status": "confirmed",
            "verification_notes": "Exploit path demonstrated",
            "confidence": 0.95
        }
    ]"#;

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::Confirmed);
    assert_eq!(notes, "Exploit path demonstrated");
    assert!(!notes.contains('{'));
}

#[test]
fn test_parse_array_false_positive_status() {
    // Array with false_positive status
    let input = r#"[
        {
            "verification_status": "false_positive",
            "verification_notes": "Input is sanitized at boundary"
        }
    ]"#;

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::FalsePositive);
    assert_eq!(notes, "Input is sanitized at boundary");
}

#[test]
fn test_parse_array_missing_notes_returns_empty() {
    // Array without verification_notes field
    let input = r#"[
        {
            "verification_status": "confirmed"
        }
    ]"#;

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::Confirmed);
    assert_eq!(notes, "");
}

#[test]
fn test_parse_array_empty_array_falls_back_to_raw() {
    // Empty array - salvage fails, falls back to raw content
    let input = "[]";

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::NeedsReview);
    assert_eq!(notes, input);
}

#[test]
fn test_parse_array_non_array_object_falls_back_to_raw() {
    // Not an array, not a valid verdict object - falls back to raw
    let input = r#"{"some_other_key": "value"}"#;

    let (status, notes) = parse_verification_verdict(input);
    assert_eq!(status, VerificationStatus::NeedsReview);
    assert_eq!(notes, input);
}
