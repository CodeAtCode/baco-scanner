//! The warning that a scan looked at nothing.
//!
//! The zero-LLM-call check is satisfied by a single triage call, so it stays
//! silent through the failure it should catch: files indexed, nothing analysed.

use baco::scan_health::scan_analysed_nothing;

#[test]
fn test_files_indexed_and_none_analysed_is_the_symptom() {
    assert!(scan_analysed_nothing(6, 0));
}

#[test]
fn test_the_reported_case_six_indexed_zero_analysed() {
    // Exactly what the log showed: 6 indexed, 0 analyzed, llm: 1/0. A triage
    // call made the call count non-zero, so the old warning did not fire.
    assert!(scan_analysed_nothing(6, 0));
}

#[test]
fn test_some_analysed_is_not_the_symptom() {
    assert!(!scan_analysed_nothing(6, 1));
    assert!(!scan_analysed_nothing(6, 6));
}

#[test]
fn test_nothing_indexed_is_not_the_symptom() {
    // An empty project analysed nothing because there was nothing to analyse.
    // Warning about it trains people to ignore the warning.
    assert!(!scan_analysed_nothing(0, 0));
}

#[test]
fn test_the_condition_ignores_the_llm_call_count_entirely() {
    // It takes only the two file counts, which is the point: no LLM call count
    // can suppress it, and none is needed to trigger it.
    let indexed = 1u64;
    let analyzed = 0u64;
    for _llm_calls in [0u64, 1, 18, 1000] {
        assert!(
            scan_analysed_nothing(indexed, analyzed),
            "an LLM call count of {_llm_calls} must not change the verdict"
        );
    }
}
