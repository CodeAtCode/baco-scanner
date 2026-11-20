//! RootCauseDedup phase tests
//!
//! These tests verify that the root cause deduplication phase correctly
//! collapses duplicate findings when enabled.

use crate::fixtures::make_finding_phase as make_finding;
use baco::findings::VulnerabilityFinding;
use baco::root_cause_dedup::RootCauseDeduplicator;
use baco::scanner_types::severity::V3Severity;

#[test]
fn test_root_cause_dedup_collapses_identical_findings() {
    // Build 3 identical findings and verify they collapse into 1 group
    let mut dedup = RootCauseDeduplicator::new();

    let findings = vec![
        make_finding(
            "f1",
            "SQL Injection",
            "src/db.rs",
            Some(42),
            Some("SELECT * FROM users"),
        ),
        make_finding(
            "f2",
            "SQL Injection",
            "src/db.rs",
            Some(100),
            Some("SELECT * FROM users"),
        ),
        make_finding(
            "f3",
            "SQL Injection",
            "src/db.rs",
            Some(200),
            Some("SELECT * FROM users"),
        ),
    ];

    let groups = dedup.deduplicate(findings);

    assert_eq!(
        groups.len(),
        1,
        "Should have exactly 1 group for identical findings"
    );

    // Verify all 3 finding IDs are in the group
    let total_findings: usize = groups.iter().map(|g| g.findings.len()).sum();
    assert_eq!(total_findings, 3, "Group should contain all 3 finding IDs");
}

#[test]
fn test_root_cause_dedup_keeps_distinct_findings_separate() {
    // Build 2 findings with different titles/files and verify they stay separate
    let mut dedup = RootCauseDeduplicator::new();

    let findings = vec![
        make_finding(
            "f1",
            "SQL Injection",
            "src/db.rs",
            Some(42),
            Some("SELECT * FROM users"),
        ),
        make_finding(
            "f2",
            "XSS Vulnerability",
            "src/api.rs",
            Some(100),
            Some("<script>alert(1)</script>"),
        ),
    ];

    let groups = dedup.deduplicate(findings);

    assert_eq!(
        groups.len(),
        2,
        "Should have 2 groups for different root causes"
    );
}

#[test]
fn root_cause_dedup_groups_findings_sharing_a_root_cause() {
    // The "keep one per group" rule lives in the dedup phase. What the
    // deduplicator owns is the grouping, so assert that exactly instead of
    // replaying the phase's keep-one loop here.
    let mut dedup = RootCauseDeduplicator::new();

    let findings = vec![
        make_finding(
            "f1",
            "SQL Injection",
            "src/db.rs",
            Some(42),
            Some("SELECT * FROM users"),
        ),
        make_finding(
            "f2",
            "SQL Injection",
            "src/db.rs",
            Some(100),
            Some("SELECT * FROM users"),
        ),
        make_finding(
            "f3",
            "SQL Injection",
            "src/db.rs",
            Some(200),
            Some("SELECT * FROM users"),
        ),
    ];

    let groups = dedup.deduplicate(findings);

    assert_eq!(groups.len(), 1, "one root cause, so one group");
    assert_eq!(
        groups[0].findings,
        vec!["f1".to_string(), "f2".to_string(), "f3".to_string()],
        "every finding with that root cause belongs to the group"
    );
}

#[test]
fn test_root_cause_dedup_handles_empty_findings() {
    // Call dedup with empty Vec and verify result is empty
    let mut dedup = RootCauseDeduplicator::new();

    let findings: Vec<VulnerabilityFinding> = vec![];

    let groups = dedup.deduplicate(findings);

    assert_eq!(groups.len(), 0, "Should have 0 groups for empty input");
}

#[test]
fn test_root_cause_dedup_groups_by_normalized_snippet() {
    // Build 2 findings with the same title/file but code snippets differing only in whitespace.
    // Assert they produce the same root cause id.
    let finding1 = make_finding(
        "f1",
        "SQL Injection",
        "src/db.rs",
        Some(42),
        Some("SELECT *\nFROM users"),
    );
    let finding2 = make_finding(
        "f2",
        "SQL Injection",
        "src/db.rs",
        Some(42),
        Some("SELECT * FROM users"),
    );

    let id1 = RootCauseDeduplicator::compute_root_cause_id(&finding1);
    let id2 = RootCauseDeduplicator::compute_root_cause_id(&finding2);

    assert_eq!(
        id1, id2,
        "Whitespace-different snippets should produce same root cause ID after normalization"
    );
}
#[test]
fn test_compute_root_cause_id_same_inputs() {
    let finding1 = make_finding(
        "f1",
        "SQL Injection",
        "src/db.rs",
        Some(42),
        Some("SELECT * FROM users"),
    );
    let finding2 = make_finding(
        "f2",
        "SQL Injection",
        "src/db.rs",
        Some(42),
        Some("SELECT * FROM users"),
    );

    let id1 = RootCauseDeduplicator::compute_root_cause_id(&finding1);
    let id2 = RootCauseDeduplicator::compute_root_cause_id(&finding2);

    assert_eq!(id1, id2, "Same inputs should produce same root cause ID");
}

#[test]
fn test_compute_root_cause_id_different_files() {
    let finding1 = make_finding(
        "f1",
        "SQL Injection",
        "src/db.rs",
        Some(42),
        Some("SELECT * FROM users"),
    );
    let finding2 = make_finding(
        "f2",
        "SQL Injection",
        "src/api.rs",
        Some(42),
        Some("SELECT * FROM users"),
    );

    let id1 = RootCauseDeduplicator::compute_root_cause_id(&finding1);
    let id2 = RootCauseDeduplicator::compute_root_cause_id(&finding2);

    assert_ne!(
        id1, id2,
        "Different files should produce different root cause IDs"
    );
}

#[test]
fn test_compute_root_cause_id_different_snippets() {
    let finding1 = make_finding(
        "f1",
        "SQL Injection",
        "src/db.rs",
        Some(42),
        Some("SELECT * FROM users"),
    );
    let finding2 = make_finding(
        "f2",
        "SQL Injection",
        "src/db.rs",
        Some(42),
        Some("SELECT * FROM admin"),
    );

    let id1 = RootCauseDeduplicator::compute_root_cause_id(&finding1);
    let id2 = RootCauseDeduplicator::compute_root_cause_id(&finding2);

    assert_ne!(
        id1, id2,
        "Different code snippets should produce different root cause IDs"
    );
}

#[test]
fn test_deduplicate_preserves_locations() {
    let mut dedup = RootCauseDeduplicator::new();

    // Same file path, different line numbers - should group together
    let findings = vec![
        make_finding(
            "f1",
            "SQL Injection",
            "src/db.rs",
            Some(42),
            Some("SELECT * FROM users"),
        ),
        make_finding(
            "f2",
            "SQL Injection",
            "src/db.rs",
            Some(100),
            Some("SELECT * FROM users"),
        ),
    ];

    let groups = dedup.deduplicate(findings);

    assert_eq!(groups.len(), 1);
    let group = &groups[0];
    assert_eq!(group.all_locations.len(), 2);
    assert!(group.all_locations.contains(&("src/db.rs".to_string(), 42)));
    assert!(
        group
            .all_locations
            .contains(&("src/db.rs".to_string(), 100))
    );
}

#[test]
fn test_merge_groups() {
    use baco::scanner_types::cve::RootCauseGroup;

    let mut dedup = RootCauseDeduplicator::new();

    let group1 = RootCauseGroup::new("abc123", "SQL Injection", V3Severity::High);
    let mut group1 = group1;
    group1.add_finding("f1", "src/db.rs", 42);

    let group2 = RootCauseGroup::new(
        "abc123", // Same ID - should merge
        "SQL Injection",
        V3Severity::High,
    );
    let mut group2 = group2;
    group2.add_finding("f2", "src/api.rs", 100);

    dedup.merge_groups(vec![group1, group2]);

    assert_eq!(dedup.group_count(), 1);
    let groups = dedup.into_groups();
    let total_findings: usize = groups.iter().map(|g| g.findings.len()).sum();
    assert_eq!(total_findings, 2);
}

#[test]
fn test_deduplicate_with_no_code_snippet() {
    let mut dedup = RootCauseDeduplicator::new();

    let findings = vec![
        make_finding("f1", "SQL Injection", "src/db.rs", Some(42), None),
        make_finding("f2", "SQL Injection", "src/db.rs", Some(100), None),
    ];

    let groups = dedup.deduplicate(findings);

    assert_eq!(
        groups.len(),
        1,
        "Should group findings even without code snippet"
    );
}

#[test]
fn test_deduplicate_case_insensitive_title() {
    let finding1 = make_finding(
        "f1",
        "sql injection",
        "src/db.rs",
        Some(42),
        Some("SELECT *"),
    );
    let finding2 = make_finding(
        "f2",
        "SQL Injection",
        "src/db.rs",
        Some(42),
        Some("SELECT *"),
    );

    let id1 = RootCauseDeduplicator::compute_root_cause_id(&finding1);
    let id2 = RootCauseDeduplicator::compute_root_cause_id(&finding2);

    assert_eq!(id1, id2, "Case-insensitive title should produce same ID");
}
