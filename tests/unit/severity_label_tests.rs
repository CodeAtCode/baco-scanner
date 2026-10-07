//! Severity labels are parsed, not validated.
//!
//! A mutation run over `src/findings.rs` found all seven mutants in this crate's
//! verdict modules alive in `Severity::from_label` and nowhere else: deleting any
//! of the five match arms, or replacing the whole function with `None` or
//! `Some(Default::default())`, left the suite green. No test called the function
//! at all.
//!
//! That matters because severity is not cosmetic. It decides which findings a
//! report shows and which ones gate a scan, so a label that silently parses as
//! `None` becomes a finding that silently disappears.

use baco::findings::Severity;

#[test]
fn every_label_maps_to_its_own_severity() {
    for (label, expected) in [
        ("critical", Severity::Critical),
        ("high", Severity::High),
        ("medium", Severity::Medium),
        ("low", Severity::Low),
        ("info", Severity::Info),
        // "informational" shares the info arm, so it must map to the same value.
        ("informational", Severity::Info),
    ] {
        assert_eq!(
            Severity::from_label(label),
            Some(expected),
            "{label:?} must parse to {expected:?}"
        );
    }
}

/// The doc comment promises case-insensitivity, so a parser that only accepted
/// lowercase would pass every test above and still reject real model output.
#[test]
fn labels_parse_case_insensitively() {
    for label in ["CRITICAL", "Critical", "cRiTiCaL", "HIGH", "Medium", "LOW"] {
        assert!(
            Severity::from_label(label).is_some(),
            "{label:?} must parse: the function lowercases its input"
        );
    }
    assert_eq!(Severity::from_label("HiGh"), Some(Severity::High));
}

/// An unrecognised label must be None, not a default. Falling back to a default
/// is the mutation `Some(Default::default())` that this file exists to catch.
#[test]
fn an_unrecognised_label_is_none_and_not_a_default() {
    for label in ["", "unknown", "severe", "inform", "crit", "med"] {
        assert_eq!(
            Severity::from_label(label),
            None,
            "{label:?} is not a severity label and must not parse to one"
        );
    }
}
