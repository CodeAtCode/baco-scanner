//! The triage discard-rate fallback.
//!
//! Triage is a cost filter, so dropping files is its job. These tests cover the
//! boundary where dropping stops being a saving and becomes the whole result: a
//! scan that analyses almost nothing is indistinguishable from a clean target.

use baco::scanner::phases::llm_phases::static_analysis::{
    TRIAGE_MAX_DISCARD_RATIO, should_distrust_triage,
};

#[test]
fn test_discard_limit_is_strictly_above_half() {
    // Stated as a constant so the number is visible wherever it is argued
    // about. 0.5 means "at most half the batch may be dropped".
    assert_eq!(TRIAGE_MAX_DISCARD_RATIO, 0.5);
}

#[test]
fn test_healthy_triage_stays_a_filter() {
    // The common case must not be disturbed by the fallback, otherwise every
    // scan pays full cost and the triage phase does nothing.
    // (classified, submitted) semantics: 8 classified out of 10 submitted = 20% unclassified
    assert!(
        !should_distrust_triage(8, 10),
        "20% unclassified stays a filter"
    );
    // 9 classified out of 10 submitted = 10% unclassified
    assert!(
        !should_distrust_triage(9, 10),
        "10% unclassified stays a filter"
    );
}

#[test]
fn test_exactly_half_is_allowed() {
    // The comparison is `>`, so a batch split exactly in half still trusts the
    // triage result. This is the case that decides between `>` and `>=`.
    // 5 classified out of 10 submitted = 50% unclassified
    assert!(
        !should_distrust_triage(5, 10),
        "exactly 50% must not trip the fallback"
    );
}

#[test]
fn test_more_than_half_is_distrusted() {
    // The case that motivated the fallback: ten files submitted, only four classified.
    // 4 classified out of 10 submitted = 60% unclassified
    assert!(
        should_distrust_triage(4, 10),
        "60% unclassified must trip the fallback"
    );
    // 1 classified out of 3 submitted = 66.7% unclassified
    assert!(
        should_distrust_triage(1, 3),
        "a third classified is already the problem"
    );
}

#[test]
fn test_empty_llm_response_is_distrusted() {
    // The core bug scenario: LLM returned valid JSON but classified nothing.
    // 0 classified out of 10 submitted = 100% unclassified
    assert!(
        should_distrust_triage(0, 10),
        "100% unclassified must trip the fallback"
    );
    // 0 classified out of 1 submitted = 100% unclassified
    assert!(
        should_distrust_triage(0, 1),
        "a single dropped file is also total wipeout"
    );
}

#[test]
fn test_empty_batch_is_not_distrusted() {
    // submitted == 0 would be a division by zero. It must be a plain "no", not a
    // NaN that compares false against everything and silently skips the
    // fallback for a batch that was never triaged.
    assert!(!should_distrust_triage(0, 0));
}

#[test]
fn test_nothing_skipped_is_never_distrusted() {
    // 10 classified out of 10 submitted = 0% unclassified
    assert!(!should_distrust_triage(10, 10));
}
