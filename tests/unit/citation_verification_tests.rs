//! Citation verification unit tests.

use baco::citation_verification::verify_citations;
use baco::findings::VulnerabilityFinding;
use std::fs;
use std::fs::File;
use std::io::Write;
use tempfile::TempDir;

use crate::fixtures::create_test_finding;

fn make_finding(file_path: String, line_number: Option<u32>) -> VulnerabilityFinding {
    let mut f = create_test_finding("test-finding-001", "Test Finding", &file_path, 1);
    f.description = "A test vulnerability".to_string();
    f.line_number = line_number;
    f
}

#[test]
fn test_valid_file_and_line() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.rs");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "line 1").unwrap();
    writeln!(file, "line 2").unwrap();
    writeln!(file, "line 3").unwrap();

    let finding = make_finding("test.rs".to_string(), Some(2));
    let original_confidence = finding.confidence_score;

    let mut findings = vec![finding];
    let report = verify_citations(&mut findings, temp_dir.path());

    assert_eq!(report.checked, 1);
    assert_eq!(report.passed, 1);
    assert_eq!(report.failed, 0);
    assert_eq!(findings[0].confidence_score, original_confidence);
    assert!(findings[0].verification_notes.is_none());
}

#[test]
fn test_missing_file() {
    let temp_dir = TempDir::new().unwrap();

    let finding = make_finding("nonexistent.rs".to_string(), Some(1));
    let original_confidence = finding.confidence_score;

    let mut findings = vec![finding];
    let report = verify_citations(&mut findings, temp_dir.path());

    assert_eq!(report.checked, 1);
    assert_eq!(report.passed, 0);
    assert_eq!(report.failed, 1);
    assert_eq!(findings[0].confidence_score, original_confidence * 0.5);
    assert!(findings[0].verification_notes.is_some());
    assert!(
        findings[0]
            .verification_notes
            .as_ref()
            .unwrap()
            .contains("citation verification failed")
    );
}

#[test]
fn test_line_beyond_eof() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.rs");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "line 1").unwrap();
    writeln!(file, "line 2").unwrap();

    let finding = make_finding("test.rs".to_string(), Some(10)); // Beyond the 2 lines in file
    let original_confidence = finding.confidence_score;

    let mut findings = vec![finding];
    let report = verify_citations(&mut findings, temp_dir.path());

    assert_eq!(report.checked, 1);
    assert_eq!(report.passed, 0);
    assert_eq!(report.failed, 1);
    assert_eq!(findings[0].confidence_score, original_confidence * 0.5);
    assert!(findings[0].verification_notes.is_some());
    assert!(
        findings[0]
            .verification_notes
            .as_ref()
            .unwrap()
            .contains("citation verification failed")
    );
}

#[test]
fn test_no_line_number_with_existing_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.rs");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "line 1").unwrap();

    let finding = make_finding("test.rs".to_string(), None); // No line number specified
    let original_confidence = finding.confidence_score;

    let mut findings = vec![finding];
    let report = verify_citations(&mut findings, temp_dir.path());

    assert_eq!(report.checked, 1);
    assert_eq!(report.passed, 1);
    assert_eq!(report.failed, 0);
    assert_eq!(findings[0].confidence_score, original_confidence);
    assert!(findings[0].verification_notes.is_none());
}

#[test]
fn test_empty_findings_slice() {
    let temp_dir = TempDir::new().unwrap();

    let mut findings: Vec<VulnerabilityFinding> = vec![];
    let report = verify_citations(&mut findings, temp_dir.path());

    assert_eq!(report.checked, 0);
    assert_eq!(report.passed, 0);
    assert_eq!(report.failed, 0);
}

#[test]
fn test_multiple_files_sentinel_skipped_without_penalty() {
    // Finding with "multiple_files" sentinel path should be skipped
    // without halving confidence or adding failure note
    let temp_dir = TempDir::new().unwrap();

    let finding = make_finding("multiple_files".to_string(), Some(1));
    let original_confidence = finding.confidence_score;

    let mut findings = vec![finding];
    let report = verify_citations(&mut findings, temp_dir.path());

    // Counted as checked but neither passed nor failed
    assert_eq!(report.checked, 1);
    assert_eq!(report.passed, 0);
    assert_eq!(report.failed, 0);

    // Confidence unchanged
    assert_eq!(findings[0].confidence_score, original_confidence);

    // No failure note added
    assert!(findings[0].verification_notes.is_none());
}

#[test]
fn test_empty_file_path_skipped_without_penalty() {
    // Finding with empty file_path should also be skipped
    let temp_dir = TempDir::new().unwrap();

    let finding = make_finding("".to_string(), Some(1));
    let original_confidence = finding.confidence_score;

    let mut findings = vec![finding];
    let report = verify_citations(&mut findings, temp_dir.path());

    assert_eq!(report.checked, 1);
    assert_eq!(report.passed, 0);
    assert_eq!(report.failed, 0);
    assert_eq!(findings[0].confidence_score, original_confidence);
    assert!(findings[0].verification_notes.is_none());
}

#[test]
fn test_mixed_findings_sentinel_and_real() {
    // Mix of sentinel path and real file - sentinel skipped, real verified
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("real.rs");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "line 1").unwrap();
    writeln!(file, "line 2").unwrap();

    let finding_sentinel = make_finding("multiple_files".to_string(), Some(1));
    let finding_real = make_finding("real.rs".to_string(), Some(2));

    let mut findings = vec![finding_sentinel, finding_real];
    let report = verify_citations(&mut findings, temp_dir.path());

    // Both checked, only real one passed
    assert_eq!(report.checked, 2);
    assert_eq!(report.passed, 1);
    assert_eq!(report.failed, 0);

    // Sentinel: confidence unchanged, no note
    assert_eq!(findings[0].confidence_score, 0.8);
    assert!(findings[0].verification_notes.is_none());

    // Real file: confidence unchanged, no note (valid citation)
    assert_eq!(findings[1].confidence_score, 0.8);
    assert!(findings[1].verification_notes.is_none());
}
#[test]
fn test_path_traversal_rejection() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.rs");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "line 1").unwrap();

    // Try path traversal attack
    let finding = make_finding("../evil.rs".to_string(), Some(1));
    let original_confidence = finding.confidence_score;

    let mut findings = vec![finding];
    let report = verify_citations(&mut findings, temp_dir.path());

    // Should fail - path traversal is not allowed
    assert_eq!(report.checked, 1);
    assert_eq!(report.passed, 0);
    assert_eq!(report.failed, 1);
    assert_eq!(findings[0].confidence_score, original_confidence * 0.5);
    assert!(findings[0].verification_notes.is_some());
}

#[test]
fn test_absolute_path_rejection() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.rs");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "line 1").unwrap();

    // Try absolute path
    let finding = "/etc/passwd".to_string();
    let finding = make_finding(finding.to_string(), Some(1));
    let original_confidence = finding.confidence_score;

    let mut findings = vec![finding];
    let report = verify_citations(&mut findings, temp_dir.path());

    // Should fail - absolute path outside project
    assert_eq!(report.checked, 1);
    assert_eq!(report.passed, 0);
    assert_eq!(report.failed, 1);
    assert_eq!(findings[0].confidence_score, original_confidence * 0.5);
}

#[test]
fn test_valid_subdirectory_path() {
    let temp_dir = TempDir::new().unwrap();
    let subdir = temp_dir.path().join("src");
    fs::create_dir_all(&subdir).unwrap();
    let file_path = subdir.join("test.rs");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "line 1").unwrap();
    writeln!(file, "line 2").unwrap();

    let finding = make_finding("src/test.rs".to_string(), Some(2));
    let original_confidence = finding.confidence_score;

    let mut findings = vec![finding];
    let report = verify_citations(&mut findings, temp_dir.path());

    assert_eq!(report.checked, 1);
    assert_eq!(report.passed, 1);
    assert_eq!(report.failed, 0);
    assert_eq!(findings[0].confidence_score, original_confidence);
}

#[test]
fn test_deeply_nested_path() {
    let temp_dir = TempDir::new().unwrap();
    let nested = temp_dir.path().join("a/b/c/d");
    fs::create_dir_all(&nested).unwrap();
    let file_path = nested.join("test.rs");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "line 1").unwrap();

    let finding = make_finding("a/b/c/d/test.rs".to_string(), Some(1));
    let original_confidence = finding.confidence_score;

    let mut findings = vec![finding];
    let report = verify_citations(&mut findings, temp_dir.path());

    assert_eq!(report.checked, 1);
    assert_eq!(report.passed, 1);
    assert_eq!(report.failed, 0);
    assert_eq!(findings[0].confidence_score, original_confidence);
}

#[test]
fn test_multiple_failures_accumulate_notes() {
    let temp_dir = TempDir::new().unwrap();

    let finding1 = make_finding("missing1.rs".to_string(), Some(1));
    let finding2 = make_finding("missing2.rs".to_string(), Some(1));

    let mut findings = vec![finding1, finding2];
    let report = verify_citations(&mut findings, temp_dir.path());

    assert_eq!(report.checked, 2);
    assert_eq!(report.passed, 0);
    assert_eq!(report.failed, 2);

    // Both should have verification notes
    assert!(findings[0].verification_notes.is_some());
    assert!(findings[1].verification_notes.is_some());
}

#[test]
fn test_line_number_zero() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.rs");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "line 1").unwrap();

    let finding = make_finding("test.rs".to_string(), Some(0));
    let original_confidence = finding.confidence_score;

    let mut findings = vec![finding];
    let report = verify_citations(&mut findings, temp_dir.path());

    // Line 0 is invalid (1-indexed)
    assert_eq!(report.checked, 1);
    assert_eq!(report.passed, 0);
    assert_eq!(report.failed, 1);
    assert_eq!(findings[0].confidence_score, original_confidence * 0.5);
}

#[test]
fn test_exact_line_match() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.rs");
    let mut file = File::create(&file_path).unwrap();
    for i in 1..=100 {
        writeln!(file, "line {}", i).unwrap();
    }

    let finding = make_finding("test.rs".to_string(), Some(100));
    let original_confidence = finding.confidence_score;

    let mut findings = vec![finding];
    let report = verify_citations(&mut findings, temp_dir.path());

    // Line 100 should pass (file has exactly 100 lines)
    assert_eq!(report.checked, 1);
    assert_eq!(report.passed, 1);
    assert_eq!(report.failed, 0);
    assert_eq!(findings[0].confidence_score, original_confidence);
}

#[test]
fn test_line_one_beyond_eof() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.rs");
    let mut file = File::create(&file_path).unwrap();
    for i in 1..=100 {
        writeln!(file, "line {}", i).unwrap();
    }

    let finding = make_finding("test.rs".to_string(), Some(101));
    let original_confidence = finding.confidence_score;

    let mut findings = vec![finding];
    let report = verify_citations(&mut findings, temp_dir.path());

    // Line 101 should fail (file has 100 lines)
    assert_eq!(report.checked, 1);
    assert_eq!(report.passed, 0);
    assert_eq!(report.failed, 1);
    assert_eq!(findings[0].confidence_score, original_confidence * 0.5);
    assert!(
        findings[0]
            .verification_notes
            .as_ref()
            .unwrap()
            .contains("line 101 out of range")
    );
}
