//! Progress bar math tests
//!
//! Verify that progress bar calculations are correct and do not overshoot.

use baco::scanner::phase_spec::PhaseSpec;
use baco::scanner::progress::progress_position;

#[test]
fn test_phase_spec_counts() {
    // Guard against the hardcoded-24 regression
    assert_eq!(PhaseSpec::total(), 23);
    assert_eq!(PhaseSpec::parallel().len(), 4);
    assert_eq!(PhaseSpec::sequential().len(), 19);
}

#[test]
fn test_progress_bar_loop_math() {
    // Test the fixed advance formula: base + ((i + 1) * 100 / total)
    // After the loop completes, position should be exactly base + 100
    let test_cases = vec![1, 5, 50, 200];

    for n in test_cases {
        let base = 1000u64;
        let total = n;

        // Simulate the loop
        let mut position = base;
        for i in 0..total {
            position = base + ((i as u64 + 1) * 100 / total.max(1) as u64);
        }

        // After loop, position should be exactly base + 100
        assert_eq!(
            position,
            base + 100,
            "For n={}, expected position {} but got {}",
            n,
            base + 100,
            position
        );

        // Verify we never exceed base + 100
        assert!(
            position <= base + 100,
            "For n={}, position {} exceeded base + 100",
            n,
            position
        );
    }
}

#[test]
fn test_bar_total_consistency() {
    // Verify that the bar total (23 * 100 = 2300) is sufficient for all phases
    // parallel block = 4 * 100 = 400
    // sequential block = 19 phases, last pre-phase set = 400 + 18*100 = 2200
    // final phase ends at 2300 = bar total

    let total_units = PhaseSpec::total() as u64 * 100;
    let parallel_units = PhaseSpec::parallel().len() as u64 * 100;
    let sequential_units = PhaseSpec::sequential().len() as u64;

    // The bar total must be >= parallel + (sequential - 1) * 100 + 100
    // i.e., start + phases*100 fits the bar
    let required = parallel_units + (sequential_units - 1) * 100 + 100;

    assert!(
        total_units >= required,
        "Bar total {} < required {}",
        total_units,
        required
    );

    // Specific values
    assert_eq!(total_units, 2300);
    assert_eq!(parallel_units, 400);
    assert_eq!(sequential_units, 19);
}

#[test]
fn test_progress_position_matches_original_formula() {
    // Test the progress_position helper with float semantics
    // These are the exact cases from the task specification:

    // progress_position(0, 1, 3) == 33 — the exact case that distinguishes float from integer arithmetic
    assert_eq!(progress_position(0, 1, 3), 33);

    // progress_position(1000, 9, 10) == 1090 — last item at 90% (formula uses 0-indexed i)
    assert_eq!(progress_position(1000, 9, 10), 1090);

    // progress_position(1000, 0, 0) == 1000 — zero total does not divide by zero or advance
    assert_eq!(progress_position(1000, 0, 0), 1000);

    // progress_position(500, 0, 1) == 500 — first (and only) item at 0%
    assert_eq!(progress_position(500, 0, 1), 500);

    // progress_position(0, 99, 100) == 99 — integer truncation at a non-round boundary
    assert_eq!(progress_position(0, 99, 100), 99);
}
