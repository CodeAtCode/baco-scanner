//! Integration tests for cross-scan merge functionality

use baco::findings::{FindingsMerger, Severity, VulnerabilityFinding};

fn create_finding(id: &str, title: &str, file_path: &str, line: u32) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test finding".to_string(),
        severity: Severity::High,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: file_path.to_string(),
        line_number: Some(line),
        code_snippet: Some("test code".to_string()),
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: vec![],
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
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
    }
}

#[test]
fn test_cross_scan_merge_preserves_unique_findings() {
    // Scan A: Findings from first scan
    let scan_a = vec![
        create_finding("a1", "SQL Injection", "src/db.rs", 42),
        create_finding("a2", "XSS", "src/api.rs", 100),
        create_finding("a3", "CSRF", "src/auth.rs", 200),
    ];

    // Scan B: Findings from second scan with some overlap
    let scan_b = vec![
        create_finding("b1", "Path Traversal", "src/fs.rs", 15), // New
        create_finding("a2", "XSS", "src/api.rs", 100),          // Duplicate (same ID)
        create_finding("b2", "RCE", "src/exec.rs", 88),          // New
    ];

    let merged = FindingsMerger::merge_scans(vec![scan_a, scan_b]);

    // Should preserve all unique findings: a1, a2, a3, b1, b2 = 5 total
    assert_eq!(merged.len(), 5, "Merged scan should have 5 unique findings");

    // Collect IDs for easier checking
    let ids: Vec<String> = merged.iter().map(|f| f.id.clone()).collect();

    assert!(ids.contains(&"a1".to_string()), "Should preserve a1");
    assert!(
        ids.contains(&"a2".to_string()),
        "Should preserve a2 (deduplicated)"
    );
    assert!(ids.contains(&"a3".to_string()), "Should preserve a3");
    assert!(ids.contains(&"b1".to_string()), "Should preserve b1");
    assert!(ids.contains(&"b2".to_string()), "Should preserve b2");
}

#[test]
fn test_cross_scan_merge_different_root_cause_ids_preserved() {
    // Findings with different IDs should all be preserved
    let scan_a = vec![
        create_finding("rc1", "Memory Corruption", "src/mem.rs", 10),
        create_finding("rc2", "Integer Overflow", "src/math.rs", 25),
    ];

    let scan_b = vec![
        create_finding("rc3", "Use After Free", "src/heap.rs", 50),
        create_finding("rc4", "Double Free", "src/heap.rs", 75),
    ];

    let merged = FindingsMerger::merge_scans(vec![scan_a, scan_b]);

    // All 4 findings should be preserved (all have different IDs)
    assert_eq!(
        merged.len(),
        4,
        "All findings with different RootCauseIds should be preserved"
    );
}

#[test]
fn test_cross_scan_merge_same_root_cause_deduplicated() {
    // Same ID across scans should be deduplicated
    let scan_a = vec![create_finding("same-id", "SQL Injection", "src/db.rs", 42)];

    let scan_b = vec![
        create_finding("same-id", "SQL Injection", "src/db.rs", 42),
        create_finding("same-id", "SQL Injection", "src/db.rs", 42),
    ];

    let scan_c = vec![create_finding("same-id", "SQL Injection", "src/db.rs", 42)];

    let merged = FindingsMerger::merge_scans(vec![scan_a, scan_b, scan_c]);

    // Should have exactly 1 finding (all were duplicates)
    assert_eq!(
        merged.len(),
        1,
        "Findings with same RootCauseId should be deduplicated to one"
    );
    assert_eq!(merged[0].id, "same-id");
}

#[test]
fn test_cross_scan_merge_empty_scans() {
    let scan_a: Vec<VulnerabilityFinding> = vec![];
    let scan_b = vec![create_finding("f1", "Test", "src/test.rs", 1)];
    let scan_c: Vec<VulnerabilityFinding> = vec![];

    let merged = FindingsMerger::merge_scans(vec![scan_a, scan_b, scan_c]);

    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].id, "f1");
}

#[test]
fn test_cross_scan_merge_multiple_overlaps() {
    // Complex scenario with multiple overlapping findings
    let scan_a = vec![
        create_finding("f1", "Vuln 1", "src/a.rs", 10),
        create_finding("f2", "Vuln 2", "src/b.rs", 20),
        create_finding("f3", "Vuln 3", "src/c.rs", 30),
    ];

    let scan_b = vec![
        create_finding("f2", "Vuln 2", "src/b.rs", 20), // Overlap with scan_a
        create_finding("f4", "Vuln 4", "src/d.rs", 40),
        create_finding("f5", "Vuln 5", "src/e.rs", 50),
    ];

    let scan_c = vec![
        create_finding("f3", "Vuln 3", "src/c.rs", 30), // Overlap with scan_a
        create_finding("f5", "Vuln 5", "src/e.rs", 50), // Overlap with scan_b
        create_finding("f6", "Vuln 6", "src/f.rs", 60),
    ];

    let merged = FindingsMerger::merge_scans(vec![scan_a, scan_b, scan_c]);

    // Should have 6 unique findings (f1-f6)
    assert_eq!(merged.len(), 6);

    let ids: Vec<String> = merged.iter().map(|f| f.id.clone()).collect();
    for i in 1..=6 {
        assert!(
            ids.contains(&format!("f{}", i)),
            "Should preserve finding f{}",
            i
        );
    }
}

#[test]
fn test_cross_scan_merge_preserves_finding_data() {
    // Verify that merged findings preserve their original data
    let scan_a = vec![create_finding("f1", "SQL Injection", "src/db.rs", 42)];

    let scan_b = vec![create_finding("f2", "XSS", "src/api.rs", 100)];

    let merged = FindingsMerger::merge_scans(vec![scan_a, scan_b]);

    assert_eq!(merged.len(), 2);

    // Find f1 and verify its data
    let f1 = merged.iter().find(|f| f.id == "f1").unwrap();
    assert_eq!(f1.title, "SQL Injection");
    assert_eq!(f1.file_path, "src/db.rs");
    assert_eq!(f1.line_number, Some(42));

    // Find f2 and verify its data
    let f2 = merged.iter().find(|f| f.id == "f2").unwrap();
    assert_eq!(f2.title, "XSS");
    assert_eq!(f2.file_path, "src/api.rs");
    assert_eq!(f2.line_number, Some(100));
}
