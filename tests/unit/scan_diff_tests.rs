//! Tests for T29: scan-to-scan diff engine (src/scan_diff.rs)

use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::run_store::stable_finding_key;
use baco::scan_diff::{
    diff_scans, format_diff_markdown, load_previous_findings, DiffStatus, LoadFindingsError,
};
use std::io::Write;

fn create_finding(
    key_seed: &str,
    file_path: &str,
    severity: Severity,
    snippet: &str,
) -> VulnerabilityFinding {
    let mut finding = crate::fixtures::create_test_finding(
        &format!("finding-{}", key_seed),
        &format!("Finding {}", key_seed),
        file_path,
        10,
    );
    finding.description = format!("Description for {}", key_seed);
    finding.severity = severity;
    finding.cwe_id = Some("CWE-79".to_string());
    finding.code_snippet = Some(snippet.to_string());
    finding.verification_status = Some(VerificationStatus::NeedsReview);
    finding.verification_tier = Some(baco::evidence::VerificationTier::Verified);
    finding
}

#[test]
fn test_diff_scans_new_and_persisted() {
    // prev=[A], cur=[A,B] → A Persisted, B New
    let prev = vec![create_finding("A", "src/a.rs", Severity::Medium, "code A")];
    let cur = vec![
        create_finding("A", "src/a.rs", Severity::Medium, "code A"),
        create_finding("B", "src/b.rs", Severity::High, "code B"),
    ];

    let diff = diff_scans(&prev, &cur);

    assert_eq!(diff.len(), 2);

    let persisted = diff
        .iter()
        .find(|d| d.status == DiffStatus::Persisted)
        .unwrap();
    assert_eq!(persisted.key, stable_finding_key(&prev[0]));
    assert_eq!(persisted.title, "Finding A");
    assert!(persisted.previous.is_some());
    assert!(persisted.current.is_some());
    assert!(!persisted.severity_changed);

    let new_finding = diff.iter().find(|d| d.status == DiffStatus::New).unwrap();
    assert_eq!(new_finding.title, "Finding B");
    assert!(new_finding.previous.is_none());
    assert!(new_finding.current.is_some());
}

#[test]
fn test_diff_scans_fixed() {
    // prev=[A,B], cur=[A] → B Fixed
    let prev = vec![
        create_finding("A", "src/a.rs", Severity::Medium, "code A"),
        create_finding("B", "src/b.rs", Severity::High, "code B"),
    ];
    let cur = vec![create_finding("A", "src/a.rs", Severity::Medium, "code A")];

    let diff = diff_scans(&prev, &cur);

    assert_eq!(diff.len(), 2);

    let persisted = diff
        .iter()
        .find(|d| d.status == DiffStatus::Persisted)
        .unwrap();
    assert_eq!(persisted.title, "Finding A");

    let fixed = diff.iter().find(|d| d.status == DiffStatus::Fixed).unwrap();
    assert_eq!(fixed.title, "Finding B");
    assert!(fixed.previous.is_some());
    assert!(fixed.current.is_none());
}

#[test]
fn test_diff_scans_severity_change_flagged() {
    let prev = vec![create_finding("A", "src/a.rs", Severity::Low, "code A")];
    let cur = vec![create_finding("A", "src/a.rs", Severity::Medium, "code A")];

    let diff = diff_scans(&prev, &cur);

    assert_eq!(diff.len(), 1);
    let persisted = &diff[0];
    assert_eq!(persisted.status, DiffStatus::Persisted);
    assert!(persisted.severity_changed);
}

#[test]
fn test_format_diff_markdown_sections_and_counts() {
    let prev = vec![
        create_finding("A", "src/a.rs", Severity::Medium, "code A"),
        create_finding("B", "src/b.rs", Severity::High, "code B"),
    ];
    let cur = vec![
        create_finding("A", "src/a.rs", Severity::Medium, "code A"),
        create_finding("C", "src/c.rs", Severity::Low, "code C"),
    ];

    let diff = diff_scans(&prev, &cur);
    let markdown = format_diff_markdown(&diff);

    assert!(markdown.contains("New: 1, Fixed: 1, Persisted: 1"));
    assert!(markdown.contains("## New"));
    assert!(markdown.contains("## Fixed"));
    assert!(markdown.contains("## Persisted"));
    assert!(markdown.contains("Finding A"));
    assert!(markdown.contains("Finding B"));
    assert!(markdown.contains("Finding C"));
}

#[test]
fn test_load_previous_findings_roundtrip() {
    let temp_dir = tempfile::tempdir().unwrap();
    let findings_path = temp_dir.path().join("findings.json");

    let findings = vec![
        create_finding("A", "src/a.rs", Severity::Medium, "code A"),
        create_finding("B", "src/b.rs", Severity::High, "code B"),
    ];

    let json = serde_json::to_string_pretty(&findings).unwrap();
    let mut file = std::fs::File::create(&findings_path).unwrap();
    file.write_all(json.as_bytes()).unwrap();

    let loaded = load_previous_findings(temp_dir.path()).unwrap();

    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[0].title, "Finding A");
    assert_eq!(loaded[1].title, "Finding B");
}

#[test]
fn test_load_previous_findings_file_not_found() {
    let temp_dir = tempfile::tempdir().unwrap();
    let result = load_previous_findings(temp_dir.path());

    assert!(result.is_err());
    match result.unwrap_err() {
        LoadFindingsError::FileNotFound(path) => {
            assert!(path.ends_with("findings.json"));
        }
        _ => panic!("Expected FileNotFound error"),
    }
}
