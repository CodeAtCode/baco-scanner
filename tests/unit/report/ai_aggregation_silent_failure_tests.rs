//! Tests for three silent-failure defects in AI aggregation and HTML rendering.
//!
//! Each test calls the production function it covers. An earlier version of this
//! file re-implemented the merge comparator inline and asserted
//! `calculate_severity_stats` against a list the test itself had filtered — a
//! copy of the code under test, or a helper tested against itself. Neither could
//! fail when the production code regressed, and both passed with the fixes
//! disabled. Do not add tests here that re-derive the logic they claim to check.

use crate::fixtures::make_aggregation_finding;
use baco::config::ScannerConfig;
use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::report::ai_aggregation::deduplication::dedup_merge_comparator;
use baco::report::html::renderer::generate_html_report;

fn finding(
    id: &str,
    severity: Severity,
    confidence: f32,
    status: Option<VerificationStatus>,
) -> VulnerabilityFinding {
    let mut f = make_aggregation_finding(
        id,
        severity,
        confidence,
        "src/test.rs",
        Some(42),
        Some("CWE-79"),
        status,
    );
    // A unique title so the rendered report can be searched for this finding.
    f.title = format!("UNIQUE_TITLE_{id}");
    // Control the verification tier from `confidence` alone. classify_finding
    // promotes to Supported on either two evidence items or confidence > 0.8, so
    // leaving the fixture's evidence in place would make every finding survive
    // the gate and the filtering assertions would prove nothing.
    f.evidence.clear();
    f
}

/// The number the report headline claims is being shown.
fn reported_total(html: &str) -> usize {
    let marker = "Showing ";
    let start = html
        .find(marker)
        .unwrap_or_else(|| panic!("no finding-count line in the report"))
        + marker.len();
    let rest = &html[start..];
    let end = rest
        .find(" findings")
        .unwrap_or_else(|| panic!("finding-count line is malformed: {rest:?}"));
    rest[..end].trim().parse().expect("numeric finding count")
}

#[test]
fn test_deduplication_prefers_confirmed_over_false_positive() {
    // A Confirmed finding (Medium, 0.6) and a FalsePositive one (High, 0.8) at
    // the same location. Severity and confidence both favour the false
    // positive; only verification_status separates them.
    let confirmed = finding(
        "a",
        Severity::Medium,
        0.6,
        Some(VerificationStatus::Confirmed),
    );
    let false_positive = finding(
        "b",
        Severity::High,
        0.8,
        Some(VerificationStatus::FalsePositive),
    );

    assert_eq!(
        dedup_merge_comparator(&confirmed, &false_positive),
        std::cmp::Ordering::Greater,
        "the verified finding must be preferred"
    );
    assert_eq!(
        dedup_merge_comparator(&false_positive, &confirmed),
        std::cmp::Ordering::Less,
        "and the ordering must be symmetric"
    );
}

#[test]
fn test_deduplication_still_prefers_severity_when_status_matches() {
    // The fix must not have replaced the existing ordering, only prepended a
    // status check. Both are unverified here, so severity decides.
    let low = finding("a", Severity::Low, 0.9, None);
    let high = finding("b", Severity::High, 0.1, None);

    assert_eq!(
        dedup_merge_comparator(&low, &high),
        std::cmp::Ordering::Less,
        "with equal status, the more severe finding still wins"
    );
}

#[test]
fn test_deduplication_falls_back_to_confidence_when_severity_ties() {
    let timid = finding("a", Severity::Medium, 0.3, None);
    let certain = finding("b", Severity::Medium, 0.7, None);

    assert_eq!(
        dedup_merge_comparator(&timid, &certain),
        std::cmp::Ordering::Less
    );
    assert_eq!(
        dedup_merge_comparator(&certain, &timid),
        std::cmp::Ordering::Greater
    );
}

#[test]
fn test_two_unverified_findings_are_ordered_by_confidence() {
    // Confirmed-vs-FalsePositive is the case that was broken. Two findings with
    // no verdict at all must fall through to severity and confidence untouched.
    let a = finding("a", Severity::High, 0.4, None);
    let b = finding("b", Severity::High, 0.9, None);

    assert_eq!(dedup_merge_comparator(&a, &b), std::cmp::Ordering::Less);
    assert_eq!(dedup_merge_comparator(&b, &a), std::cmp::Ordering::Greater);
}

#[test]
fn test_needs_review_is_treated_as_no_verdict() {
    // NeedsReview is an absence of a verdict, not a rival to Confirmed. Both
    // findings are Low severity with equal confidence, so the comparator must not
    // invent a preference between them.
    let confirmed = finding("a", Severity::Low, 0.2, Some(VerificationStatus::Confirmed));
    let review = finding(
        "b",
        Severity::Low,
        0.2,
        Some(VerificationStatus::NeedsReview),
    );

    assert_eq!(
        dedup_merge_comparator(&confirmed, &review),
        std::cmp::Ordering::Equal
    );
}

#[test]
fn test_html_headline_matches_the_findings_actually_rendered() {
    // With the evidence gate on, findings without enough evidence are filtered
    // out. The headline count must describe the rendered list, not the input.
    let dir = tempfile::tempdir().expect("tmpdir");
    let out = dir.path().join("report.html");

    // confidence 0.9 with no evidence classifies as Supported and survives;
    // 0.8 and below with no evidence classify as Unverified and are dropped.
    let findings = vec![
        finding(
            "kept",
            Severity::High,
            0.9,
            Some(VerificationStatus::Confirmed),
        ),
        finding(
            "dropped_a",
            Severity::High,
            0.8,
            Some(VerificationStatus::Confirmed),
        ),
        finding(
            "dropped_b",
            Severity::Medium,
            0.5,
            Some(VerificationStatus::Confirmed),
        ),
    ];

    let mut config = ScannerConfig::default();
    config.output.evidence_gate = true;

    generate_html_report(&findings, out.to_str().expect("path"), Some(&config), None)
        .expect("report generated");
    let html = std::fs::read_to_string(&out).expect("report read");

    assert_eq!(
        reported_total(&html),
        1,
        "the headline must count the main list, not every finding passed in"
    );
    assert!(
        html.contains("UNIQUE_TITLE_kept"),
        "the surviving finding must be in the main list"
    );
    // Filtered findings are not hidden: the renderer moves them into a separate
    // appendix. Asserting they vanish from the HTML would be asserting a bug.
    assert!(
        html.contains("UNIQUE_TITLE_dropped_a"),
        "a filtered finding is relocated to the unverified appendix, not deleted"
    );
    assert!(html.contains("UNIQUE_TITLE_dropped_b"));

    let appendix = html
        .find("unverified-appendix")
        .expect("the report has an unverified appendix");
    assert!(
        html[appendix..].contains("UNIQUE_TITLE_dropped_a"),
        "the filtered finding must appear after the appendix opens"
    );
    assert!(
        !html[..appendix].contains("UNIQUE_TITLE_dropped_a"),
        "and must not also appear in the main list above it"
    );

    // The severity breakdown is the number that was wrong. It is rendered into
    // the filter buttons, and it must describe the same set as the list: one High
    // finding survives, so the button must read High (1) and not High (2).
    assert!(
        html.contains("High (1)"),
        "the severity breakdown must count the filtered set, got no 'High (1)'"
    );
    assert!(
        !html.contains("High (2)"),
        "the breakdown counted filtered-out findings"
    );
    assert!(
        !html.contains("Medium (1)"),
        "the breakdown counted a filtered-out Medium finding"
    );
}

#[test]
fn test_html_headline_counts_everything_when_the_gate_is_off() {
    // The other direction: with the gate off nothing is filtered, so the headline
    // must equal the input. Guards against a fix that always filters.
    let dir = tempfile::tempdir().expect("tmpdir");
    let out = dir.path().join("report.html");

    let findings = vec![
        finding(
            "a",
            Severity::High,
            0.9,
            Some(VerificationStatus::Confirmed),
        ),
        finding(
            "b",
            Severity::Medium,
            0.5,
            Some(VerificationStatus::Confirmed),
        ),
        finding("c", Severity::Low, 0.2, None),
    ];

    let mut config = ScannerConfig::default();
    config.output.evidence_gate = false;

    generate_html_report(&findings, out.to_str().expect("path"), Some(&config), None)
        .expect("report generated");
    let html = std::fs::read_to_string(&out).expect("report read");

    assert_eq!(reported_total(&html), 3);
    for id in ["a", "b", "c"] {
        assert!(
            html.contains(&format!("UNIQUE_TITLE_{id}")),
            "finding {id} must be rendered when the gate is off"
        );
    }
}
