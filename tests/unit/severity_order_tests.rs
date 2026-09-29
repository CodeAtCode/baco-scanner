//! Regression tests for Severity ordering invariants.
//!
//! These tests lock the ordering behavior of the Severity enum to prevent
//! accidental changes that would break sorting logic in report rendering.

use baco::findings::Severity;

#[test]
fn test_severity_order_critical_highest() {
    // Critical must be greater than all other severities when using Reverse sort
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::Critical > Severity::Medium);
    assert!(Severity::Critical > Severity::Low);
    assert!(Severity::Critical > Severity::Info);
}

#[test]
fn test_severity_order_high_above_medium() {
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::High > Severity::Low);
    assert!(Severity::High > Severity::Info);
}

#[test]
fn test_severity_order_medium_above_low() {
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Medium > Severity::Info);
}

#[test]
fn test_severity_order_low_above_info() {
    assert!(Severity::Low > Severity::Info);
}

#[test]
fn test_severity_sort_consistency_with_reverse() {
    let mut severities = [
        Severity::Low,
        Severity::Critical,
        Severity::Medium,
        Severity::Info,
        Severity::High,
    ];

    severities.sort_by_key(|s| std::cmp::Reverse(*s));

    assert_eq!(severities[0], Severity::Critical);
    assert_eq!(severities[1], Severity::High);
    assert_eq!(severities[2], Severity::Medium);
    assert_eq!(severities[3], Severity::Low);
    assert_eq!(severities[4], Severity::Info);
}

#[test]
fn test_severity_copy_and_debug_derives() {
    let s: Severity = Severity::Critical;
    let _copy1 = s;
    let _copy2 = s; // Should compile if Copy is derived
    let _debug_str = format!("{:?}", s); // Should compile if Debug is derived

    assert_eq!(
        format!("{:?}", s),
        "Critical",
        "Debug output is relied on by logs and by serde round-trips"
    );
    assert_eq!(_copy1, s, "Copy must yield an equal value, not a move");
    assert_eq!(_copy2, s);
}
