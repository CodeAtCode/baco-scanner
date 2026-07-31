//! RootCauseDedup phase tests
//!
//! These tests verify that the root cause deduplication phase correctly
//! collapses duplicate findings when enabled.

use baco::findings::{Severity, VulnerabilityFinding};
use baco::root_cause_dedup::RootCauseDeduplicator;

/// Helper to create a VulnerabilityFinding for tests
fn make_finding(
    id: &str,
    title: &str,
    file_path: &str,
    line_number: Option<u32>,
    code_snippet: Option<&str>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test description".to_string(),
        severity: Severity::High,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: file_path.to_string(),
        line_number,
        code_snippet: code_snippet.map(String::from),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec!["test".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.9),
        cross_file_references: None,
        verification_status: None,
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
        statement_range: None,
        triage_verdict: None,
    }
}

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
fn test_root_cause_dedup_preserves_one_finding_per_group() {
    // Mirror the phase logic: create dedup, call deduplicate, then for each group
    // pick group.findings.first() and find the matching finding in the original list.
    // Assert the result has exactly 1 finding after dedup.
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

    let deduped_groups = dedup.deduplicate(findings.clone());

    // Keep one finding per group (the first one encountered) - mirroring phases.rs:1084-1092
    let mut kept_findings = Vec::new();
    for group in deduped_groups {
        if let Some(finding_id) = group.findings.first() {
            // Find the original finding by ID
            if let Some(finding) = findings.iter().find(|f| f.id == *finding_id) {
                kept_findings.push(finding.clone());
            }
        }
    }

    assert_eq!(
        kept_findings.len(),
        1,
        "Should preserve exactly 1 finding after dedup"
    );
    assert_eq!(
        kept_findings[0].id, "f1",
        "Should keep the first finding encountered"
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
