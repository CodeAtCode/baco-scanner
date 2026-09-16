//! Tests for structural deduplication in scanner orchestrator

use baco::findings::VulnerabilityFinding;
use baco::scanner::structural_dedup;

use crate::fixtures::make_aggregation_finding;

fn make_finding(
    id: &str,
    file: &str,
    line: Option<u32>,
    cwe: Option<&str>,
    sources: Vec<&str>,
    confidence: f32,
) -> VulnerabilityFinding {
    let mut f = make_aggregation_finding(
        id,
        baco::findings::Severity::High,
        confidence,
        file,
        line,
        cwe,
        None,
    );
    f.sources = sources.into_iter().map(String::from).collect();
    f
}

#[test]
fn test_dedup_same_file_lines_within_tolerance_same_cwe() {
    // Same file, lines within ±2, same CWE → should merge
    // Chained clustering: consecutive lines 10,11,12 stay within ±2 of each other
    let mut findings = vec![
        make_finding(
            "1",
            "src/main.rs",
            Some(10),
            Some("CWE-79"),
            vec!["semgrep"],
            0.7,
        ),
        make_finding(
            "2",
            "src/main.rs",
            Some(11),
            Some("CWE-79"),
            vec!["llm"],
            0.8,
        ),
        make_finding(
            "3",
            "src/main.rs",
            Some(12),
            Some("CWE-79"),
            vec!["manual"],
            0.6,
        ),
    ];

    let merged = structural_dedup(&mut findings);

    // All three should merge into one (highest confidence is 0.8)
    assert_eq!(findings.len(), 1);
    assert_eq!(merged, 2); // 2 findings merged
                           // The keeper should have all sources combined
    assert_eq!(findings[0].sources.len(), 3);
    assert!(findings[0].sources.contains(&"semgrep".to_string()));
    assert!(findings[0].sources.contains(&"llm".to_string()));
    assert!(findings[0].sources.contains(&"manual".to_string()));
}

#[test]
fn test_dedup_same_file_different_cwe() {
    // Same file/line, different CWE → both kept
    let mut findings = vec![
        make_finding(
            "1",
            "src/main.rs",
            Some(10),
            Some("CWE-79"),
            vec!["semgrep"],
            0.7,
        ),
        make_finding(
            "2",
            "src/main.rs",
            Some(10),
            Some("CWE-89"),
            vec!["llm"],
            0.8,
        ),
    ];

    let merged = structural_dedup(&mut findings);

    // Different CWE means different groups, so both should be kept
    assert_eq!(findings.len(), 2);
    assert_eq!(merged, 0);
}

#[test]
fn test_dedup_same_file_lines_far_apart() {
    // Same file, lines far apart (>±2) → both kept
    // Line 10 and 20 differ by 10, far beyond the ±2 chain tolerance
    let mut findings = vec![
        make_finding(
            "1",
            "src/main.rs",
            Some(10),
            Some("CWE-79"),
            vec!["semgrep"],
            0.7,
        ),
        make_finding(
            "2",
            "src/main.rs",
            Some(20),
            Some("CWE-79"),
            vec!["llm"],
            0.8,
        ),
    ];

    let merged = structural_dedup(&mut findings);

    // Lines far apart mean different groups, so both should be kept
    assert_eq!(findings.len(), 2);
    assert_eq!(merged, 0);
}

#[test]
fn test_dedup_different_files() {
    // Different files → both kept
    let mut findings = vec![
        make_finding(
            "1",
            "src/main.rs",
            Some(10),
            Some("CWE-79"),
            vec!["semgrep"],
            0.7,
        ),
        make_finding(
            "2",
            "src/lib.rs",
            Some(10),
            Some("CWE-79"),
            vec!["llm"],
            0.8,
        ),
    ];

    let merged = structural_dedup(&mut findings);

    // Different files mean different groups, so both should be kept
    assert_eq!(findings.len(), 2);
    assert_eq!(merged, 0);
}

#[test]
fn test_dedup_empty_input() {
    // Empty input → 0 merged, no panic
    let mut findings: Vec<VulnerabilityFinding> = vec![];

    let merged = structural_dedup(&mut findings);

    assert_eq!(findings.len(), 0);
    assert_eq!(merged, 0);
}

#[test]
fn test_dedup_confidence_tiebreaker() {
    // Same sources count, higher confidence wins
    let mut findings = vec![
        make_finding(
            "1",
            "src/main.rs",
            Some(10),
            Some("CWE-79"),
            vec!["semgrep"],
            0.7,
        ),
        make_finding(
            "2",
            "src/main.rs",
            Some(11),
            Some("CWE-79"),
            vec!["llm"],
            0.9,
        ),
    ];

    let merged = structural_dedup(&mut findings);

    // Both have 1 source, so higher confidence (0.9) wins
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].confidence_score, 0.9);
    assert_eq!(merged, 1);
}
