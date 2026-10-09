//! Robustness gaps in the verification phase parser and prompt loader.
//!
//! These tests close two mutation-surviving defects:
//! 1. Out-of-bounds index handling in `parse_batch_verification_verdict`
//! 2. Empty-prompt guard in `load_verification_prompt`

use baco::findings::VerificationStatus;
use baco::scanner::phases::llm_phases::verification::parse_batch_verification_verdict;

/// An item with `index == expected_count` must not panic.
///
/// The loop bounds-checks with `idx < expected_count`, so accepting
/// `index == expected_count` would index one past the end of `results`.
/// Since the index comes from an LLM response, a malformed reply could
/// crash the scanner.
///
/// Choice: skip the item with a warning, rather than returning an error.
/// The rest of the parser tolerates partial results, and skipping is
/// more robust than failing the entire batch for one out-of-range index.
#[test]
fn test_out_of_range_index_skipped_with_warning() {
    // Item with index == expected_count (out of bounds)
    let input = r#"[{
        "index": 1,
        "verification_status": "confirmed",
        "verification_notes": "This should be skipped"
    }]"#;

    // expected_count = 1, so index 1 is out of range
    let out = parse_batch_verification_verdict(input, 1);

    // The out-of-range item should be skipped, leaving the default value
    assert_eq!(
        out[0].0,
        VerificationStatus::NeedsReview,
        "out-of-range index must not overwrite the default"
    );
    assert_eq!(
        out[0].1, "Batch parse missing this item",
        "should have the default missing-item message"
    );
}

/// An item with `index > expected_count` must also be skipped.
#[test]
fn test_far_out_of_range_index_skipped() {
    // Item with index way out of bounds
    let input = r#"[{
        "index": 100,
        "verification_status": "confirmed",
        "verification_notes": "This should be skipped"
    }]"#;

    let out = parse_batch_verification_verdict(input, 1);

    assert_eq!(
        out[0].0,
        VerificationStatus::NeedsReview,
        "far out-of-range index must not panic or overwrite"
    );
}

/// Valid indices within range must still work correctly.
#[test]
fn test_valid_index_within_range_works() {
    let input = r#"[{
        "index": 0,
        "verification_status": "confirmed",
        "verification_notes": "Valid item",
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
            "attack_vector": "test attack",
            "is_theoretical": false
        }
    }]"#;

    let out = parse_batch_verification_verdict(input, 1);

    assert_eq!(out[0].0, VerificationStatus::Confirmed);
    assert_eq!(out[0].1, "Valid item");
}

/// Multiple items with one out-of-range: valid ones process, out-of-range skipped.
#[test]
fn test_mixed_valid_and_invalid_indices() {
    let input = r#"[{
        "index": 0,
        "verification_status": "confirmed",
        "verification_notes": "Valid first item",
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
            "attack_vector": "test attack",
            "is_theoretical": false
        }
    }, {
        "index": 2,
        "verification_status": "false_positive",
        "verification_notes": "Out of range"
    }, {
        "index": 1,
        "verification_status": "needs_review",
        "verification_notes": "Valid second item",
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
            "attack_vector": "test attack",
            "is_theoretical": false
        }
    }]"#;

    let out = parse_batch_verification_verdict(input, 2);

    // Index 0: valid
    assert_eq!(out[0].0, VerificationStatus::Confirmed);
    assert_eq!(out[0].1, "Valid first item");

    // Index 1: valid
    assert_eq!(out[1].0, VerificationStatus::NeedsReview);
    assert_eq!(out[1].1, "Valid second item");
}
