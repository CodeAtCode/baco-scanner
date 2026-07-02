//! Deduplication edge case tests for report aggregation
//!
//! Tests cover various edge cases in the deduplicate_findings function:
//! - Same file/line but different CWE
//! - Missing line numbers
//! - Identical IDs but different metadata
//! - Overlapping code snippets
//! - Different tools on same location
//! - Case-insensitive file path matching
//! - Relative vs absolute path deduplication
//! - Empty findings list handling

use baco::context::AnalysisContext;
use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::report::aggregation::ReportAggregationPhase;

fn create_finding(
    id: &str,
    title: &str,
    severity: Severity,
    file: &str,
    line: Option<u32>,
    cwe: Option<&str>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test finding".to_string(),
        severity,
        confidence_score: 0.8,
        cwe_id: cwe.map(String::from),
        file_path: file.to_string(),
        line_number: line,
        code_snippet: Some("test code".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this".to_string()),
        code_location: None,
        already_reported: false,
        sources: vec!["test".to_string()],
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

/// Test 1: Findings with same file/line but different CWE should NOT be deduplicated
#[test]
fn test_same_location_different_cwe() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "SQL Injection", Severity::High, "src/auth.rs", Some(42), Some("CWE-89")),
        create_finding("f2", "XSS Vulnerability", Severity::High, "src/auth.rs", Some(42), Some("CWE-79")),
        create_finding("f3", "Command Injection", Severity::Critical, "src/auth.rs", Some(42), Some("CWE-78")),
    ];

    let unique = phase.deduplicate_findings(findings);

    // Different CWEs at same location should all be kept
    assert_eq!(unique.len(), 3, "Findings with same location but different CWE should not be deduplicated");
    
    // Verify all CWEs are preserved
    let cwe_ids: Vec<_> = unique.iter().filter_map(|f| f.cwe_id.as_ref()).collect();
    assert!(cwe_ids.contains(&&"CWE-89".to_string()));
    assert!(cwe_ids.contains(&&"CWE-79".to_string()));
    assert!(cwe_ids.contains(&&"CWE-78".to_string()));
}

/// Test 2: Findings with missing line numbers
#[test]
fn test_missing_line_numbers() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Issue in file", Severity::Medium, "src/utils.rs", None, Some("CWE-22")),
        create_finding("f2", "Another issue", Severity::High, "src/utils.rs", None, Some("CWE-22")),
        create_finding("f3", "Different CWE", Severity::Low, "src/utils.rs", None, Some("CWE-23")),
    ];

    let unique = phase.deduplicate_findings(findings);

    // Same file, no line number, same CWE -> should deduplicate to 1
    assert_eq!(unique.len(), 1, "Findings with missing line numbers and same CWE should be deduplicated");

    // Different CWE with missing line number -> should keep both
    let findings_diff_cwe = vec![
        create_finding("f1", "Issue 1", Severity::Medium, "src/lib.rs", None, Some("CWE-22")),
        create_finding("f2", "Issue 2", Severity::High, "src/lib.rs", None, Some("CWE-23")),
    ];
    let unique_diff = phase.deduplicate_findings(findings_diff_cwe);
    assert_eq!(unique_diff.len(), 2, "Findings with missing line numbers but different CWE should be kept");
}

/// Test 3: Findings with identical IDs but different metadata
#[test]
fn test_identical_ids_different_metadata() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "First occurrence", Severity::High, "src/main.rs", Some(100), Some("CWE-79")),
        create_finding("f1", "Second occurrence", Severity::Critical, "src/main.rs", Some(100), Some("CWE-79")),
    ];

    let unique = phase.deduplicate_findings(findings);

    // Same file/line/CWE (id doesn't affect dedup key) -> should deduplicate to 1
    assert_eq!(unique.len(), 1, "Findings with same location should be deduplicated regardless of ID");

    // But different locations with same ID should be kept
    let findings_diff_loc = vec![
        create_finding("f1", "In file A", Severity::High, "src/a.rs", Some(10), Some("CWE-79")),
        create_finding("f1", "In file B", Severity::High, "src/b.rs", Some(20), Some("CWE-79")),
    ];
    let unique_diff = phase.deduplicate_findings(findings_diff_loc);
    assert_eq!(unique_diff.len(), 2, "Findings with same ID but different locations should be kept");
}

/// Test 4: Findings with overlapping code snippets
#[test]
fn test_overlapping_code_snippets() {
    let phase = ReportAggregationPhase::new();

    let mut finding1 = create_finding("f1", "Snippet A", Severity::High, "src/parser.rs", Some(50), Some("CWE-119"));
    finding1.code_snippet = Some("buffer.copy(input)".to_string());

    let mut finding2 = create_finding("f2", "Snippet B", Severity::Critical, "src/parser.rs", Some(50), Some("CWE-119"));
    finding2.code_snippet = Some("buffer.copy(input_data)".to_string());

    let findings = vec![finding1, finding2];
    let unique = phase.deduplicate_findings(findings);

    // Code snippet doesn't affect dedup key -> should deduplicate
    assert_eq!(unique.len(), 1, "Findings with same location should be deduplicated regardless of snippet");

    // Different locations with similar snippets should be kept
    let mut finding3 = create_finding("f3", "Snippet in A", Severity::High, "src/a.rs", Some(10), Some("CWE-119"));
    finding3.code_snippet = Some("buffer.copy(input)".to_string());

    let mut finding4 = create_finding("f4", "Snippet in B", Severity::High, "src/b.rs", Some(10), Some("CWE-119"));
    finding4.code_snippet = Some("buffer.copy(input)".to_string());

    let findings_similar = vec![finding3, finding4];
    let unique_similar = phase.deduplicate_findings(findings_similar);
    assert_eq!(unique_similar.len(), 2, "Findings with same snippet but different locations should be kept");
}

/// Test 5: Findings from different tools on same location
#[test]
fn test_different_tools_same_location() {
    let phase = ReportAggregationPhase::new();

    // Simulate findings from different security scanners
    let mut finding_sonar = create_finding("sonar-123", "Null pointer", Severity::High, "src/service.rs", Some(75), Some("CWE-476"));
    finding_sonar.sources = vec!["sonarqube".to_string()];

    let mut finding_github = create_finding("GHSA-abc", "Null pointer deref", Severity::Critical, "src/service.rs", Some(75), Some("CWE-476"));
    github_sources = vec!["github-code-scanning".to_string()];

    let mut finding_deps = create_finding("dep-check-456", "Null dereference", Severity::Medium, "src/service.rs", Some(75), Some("CWE-476"));
    finding_deps.sources = vec!["dependabot".to_string()];

    let findings = vec![finding_sonar, finding_github, finding_deps];
    let unique = phase.deduplicate_findings(findings);

    // Same location, same CWE from different tools -> should deduplicate to 1
    assert_eq!(unique.len(), 1, "Findings from different tools at same location should be deduplicated");

    // Different tools, different locations -> should keep all
    let mut finding_sonar2 = create_finding("sonar-789", "Issue in A", Severity::High, "src/a.rs", Some(10), Some("CWE-476"));
    finding_sonar2.sources = vec!["sonarqube".to_string()];

    let mut finding_github2 = create_finding("GHSA-def", "Issue in B", Severity::High, "src/b.rs", Some(20), Some("CWE-476"));
    finding_github2.sources = vec!["github-code-scanning".to_string()];

    let findings_multi = vec![finding_sonar2, finding_github2];
    let unique_multi = phase.deduplicate_findings(findings_multi);
    assert_eq!(unique_multi.len(), 2, "Findings from different tools at different locations should be kept");
}

/// Test 6: Case-insensitive file path matching
#[test]
fn test_case_insensitive_file_paths() {
    let phase = ReportAggregationPhase::new();

    // Note: The current implementation uses exact string matching,
    // so these will NOT be deduplicated (which is the expected behavior)
    let findings = vec![
        create_finding("f1", "In src", Severity::High, "src/auth.rs", Some(10), Some("CWE-79")),
        create_finding("f2", "In SRC", Severity::High, "SRC/auth.rs", Some(10), Some("CWE-79")),
        create_finding("f3", "In Src", Severity::High, "Src/Auth.rs", Some(10), Some("CWE-79")),
    ];

    let unique = phase.deduplicate_findings(findings);

    // Current implementation does case-sensitive matching
    assert_eq!(unique.len(), 3, "Current implementation uses case-sensitive path matching");
}

/// Test 7: Relative vs absolute path deduplication
#[test]
fn test_relative_vs_absolute_paths() {
    let phase = ReportAggregationPhase::new();

    // Note: The current implementation does not normalize paths,
    // so these will NOT be deduplicated (which is the expected behavior)
    let findings = vec![
        create_finding("f1", "Relative path", Severity::High, "src/auth.rs", Some(10), Some("CWE-79")),
        create_finding("f2", "Absolute path", Severity::High, "/home/user/project/src/auth.rs", Some(10), Some("CWE-79")),
        create_finding("f3", "Relative with ./", Severity::High, "./src/auth.rs", Some(10), Some("CWE-79")),
    ];

    let unique = phase.deduplicate_findings(findings);

    // Current implementation does not normalize paths
    assert_eq!(unique.len(), 3, "Current implementation does not normalize relative vs absolute paths");

    // Same path format should still deduplicate
    let findings_same = vec![
        create_finding("f1", "First", Severity::High, "src/auth.rs", Some(10), Some("CWE-79")),
        create_finding("f2", "Second", Severity::High, "src/auth.rs", Some(10), Some("CWE-79")),
    ];
    let unique_same = phase.deduplicate_findings(findings_same);
    assert_eq!(unique_same.len(), 1, "Same path format should still deduplicate correctly");
}

/// Test 8: Empty findings list handling
#[test]
fn test_empty_findings_list() {
    let phase = ReportAggregationPhase::new();

    let findings: Vec<VulnerabilityFinding> = vec![];
    let unique = phase.deduplicate_findings(findings);

    assert_eq!(unique.len(), 0, "Empty findings list should return empty result");
}

/// Additional edge case: Single finding
#[test]
fn test_single_finding() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Single issue", Severity::Medium, "src/single.rs", Some(42), Some("CWE-20")),
    ];

    let unique = phase.deduplicate_findings(findings);

    assert_eq!(unique.len(), 1, "Single finding should be returned as-is");
}

/// Additional edge case: All findings are duplicates
#[test]
fn test_all_duplicates() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Dup 1", Severity::High, "src/dup.rs", Some(1), Some("CWE-79")),
        create_finding("f2", "Dup 2", Severity::Critical, "src/dup.rs", Some(1), Some("CWE-79")),
        create_finding("f3", "Dup 3", Severity::Low, "src/dup.rs", Some(1), Some("CWE-79")),
        create_finding("f4", "Dup 4", Severity::Medium, "src/dup.rs", Some(1), Some("CWE-79")),
    ];

    let unique = phase.deduplicate_findings(findings);

    assert_eq!(unique.len(), 1, "All duplicates should reduce to single finding");
}

/// Additional edge case: Mixed duplicates and unique findings
#[test]
fn test_mixed_duplicates_and_unique() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        // Two duplicates at same location
        create_finding("f1", "Dup A1", Severity::High, "src/mixed.rs", Some(10), Some("CWE-79")),
        create_finding("f2", "Dup A2", Severity::Critical, "src/mixed.rs", Some(10), Some("CWE-79")),
        // Unique finding at different line
        create_finding("f3", "Unique B", Severity::Medium, "src/mixed.rs", Some(20), Some("CWE-79")),
        // Unique finding in different file
        create_finding("f4", "Unique C", Severity::Low, "src/other.rs", Some(10), Some("CWE-79")),
        // Duplicate of f3
        create_finding("f5", "Dup B1", Severity::High, "src/mixed.rs", Some(20), Some("CWE-79")),
    ];

    let unique = phase.deduplicate_findings(findings);

    // Should have: 1 from A, 1 from B, 1 from C = 3 total
    assert_eq!(unique.len(), 3, "Mixed duplicates and unique should be handled correctly");
}
