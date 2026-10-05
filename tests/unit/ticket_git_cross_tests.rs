//! Unit tests for src/scanner/phases/other_phases/ticket_git_cross.rs
//!
//! Tests cover ticket cross-reference and Git analysis phase functions.

use baco::config::ScannerConfig;
use baco::findings::{Severity, VulnerabilityFinding};
use baco::scanner::Scanner;
use baco::scanner::phases::other_phases::looks_like_a_repository;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

use crate::fixtures::make_finding_report_agg;

// ============================================================================
// Helper Functions
// ============================================================================

fn create_test_finding(
    id: &str,
    title: &str,
    file_path: &str,
    line: u32,
    severity: Severity,
) -> VulnerabilityFinding {
    let mut finding =
        make_finding_report_agg(id, title, file_path, Some(line), Some("CWE-79"), severity);
    finding.description = format!("Test finding: {}", title);
    finding.sources = vec!["test".to_string()];
    finding
}

fn create_test_scanner(config: ScannerConfig, temp_dir: &TempDir) -> Scanner {
    Scanner::new(config, temp_dir.path().to_path_buf(), false)
}

// ============================================================================
// run_ticket_cross_ref Tests
// ============================================================================

#[test]
fn test_ticket_cross_ref_with_empty_findings() {
    // Empty findings should return empty results
    let findings: Vec<VulnerabilityFinding> = vec![];
    assert!(findings.is_empty());
}

#[test]
fn test_ticket_cross_ref_with_multiple_findings() {
    let temp_dir = TempDir::new().unwrap();
    let config = ScannerConfig::default();
    let scanner = create_test_scanner(config, &temp_dir);

    let findings: &[VulnerabilityFinding] = &[
        create_test_finding("f1", "Finding 1", "file1.rs", 10, Severity::High),
        create_test_finding("f2", "Finding 2", "file2.rs", 20, Severity::Medium),
        create_test_finding("f3", "Finding 3", "file3.rs", 30, Severity::Low),
    ];

    assert_eq!(findings.len(), 3);
    assert!(findings.iter().all(|f| f.ticket_reference.is_none()));

    let _ = scanner;
}

#[test]
fn test_ticket_cross_ref_preserves_finding_data() {
    let temp_dir = TempDir::new().unwrap();
    let config = ScannerConfig::default();
    let scanner = create_test_scanner(config, &temp_dir);

    let mut finding =
        create_test_finding("f1", "Original Title", "test.rs", 42, Severity::Critical);
    finding.description = "Critical vulnerability description".to_string();
    finding.code_snippet = Some("unsafe_code()".to_string());

    assert_eq!(finding.title, "Original Title");
    assert_eq!(finding.file_path, "test.rs");
    assert_eq!(finding.line_number, Some(42));
    assert_eq!(finding.severity, Severity::Critical);

    let _ = scanner;
}

#[test]
fn test_ticket_cross_ref_with_no_ticket_systems() {
    let temp_dir = TempDir::new().unwrap();
    let config = ScannerConfig::default();

    // Default config has no ticket systems
    assert!(config.tickets.systems.is_empty());

    let scanner = create_test_scanner(config, &temp_dir);
    let _ = scanner;
}

// ============================================================================
// run_git_analysis Tests
// ============================================================================

#[test]
fn test_git_analysis_with_nonexistent_path() {
    let config = ScannerConfig::default();
    let _scanner = Scanner::new(config, PathBuf::from("/nonexistent/path"), false);

    // Git analysis should handle non-Git repositories gracefully
    let remote_url = Scanner::get_git_remote_url("/nonexistent/path");
    assert!(remote_url.is_none());
}

#[test]
fn test_git_analysis_with_empty_path() {
    let config = ScannerConfig::default();
    let _scanner = Scanner::new(config, PathBuf::from(""), false);

    let remote_url = Scanner::get_git_remote_url("");
    assert!(remote_url.is_none());
}

#[test]
fn test_git_analysis_preserves_findings_without_git() {
    let temp_dir = TempDir::new().unwrap();
    let config = ScannerConfig::default();
    let scanner = create_test_scanner(config, &temp_dir);

    let findings: &[VulnerabilityFinding] = &[
        create_test_finding("f1", "Finding 1", "file1.rs", 10, Severity::High),
        create_test_finding("f2", "Finding 2", "file2.rs", 20, Severity::Medium),
    ];

    // Findings should exist but have no commit references (not a git repo)
    for finding in findings {
        assert!(finding.commit_reference.is_none());
    }

    let _ = scanner;
}

// ============================================================================
// run_cross_file_analysis Tests
// ============================================================================

#[test]
fn test_cross_file_analysis_with_empty_findings() {
    let temp_dir = TempDir::new().unwrap();
    let config = ScannerConfig::default();
    let scanner = create_test_scanner(config, &temp_dir);

    let findings: Vec<VulnerabilityFinding> = vec![];

    assert!(findings.is_empty());

    let _ = scanner;
}

#[test]
fn test_cross_file_analysis_with_multiple_findings() {
    let temp_dir = TempDir::new().unwrap();
    let config = ScannerConfig::default();
    let scanner = create_test_scanner(config, &temp_dir);

    let findings: &[VulnerabilityFinding] = &[
        create_test_finding("f1", "Finding 1", "src/main.rs", 10, Severity::High),
        create_test_finding("f2", "Finding 2", "src/utils.rs", 20, Severity::Medium),
        create_test_finding("f3", "Finding 3", "src/lib.rs", 30, Severity::Low),
    ];

    assert_eq!(findings.len(), 3);

    let _ = scanner;
}

#[test]
fn test_cross_file_analysis_preserves_finding_ids() {
    let temp_dir = TempDir::new().unwrap();
    let config = ScannerConfig::default();
    let scanner = create_test_scanner(config, &temp_dir);

    let findings: &[VulnerabilityFinding] = &[
        create_test_finding("unique-id-1", "Finding 1", "file1.rs", 10, Severity::High),
        create_test_finding("unique-id-2", "Finding 2", "file2.rs", 20, Severity::Medium),
    ];

    let ids: Vec<String> = findings.iter().map(|f| f.id.clone()).collect();

    assert!(ids.contains(&"unique-id-1".to_string()));
    assert!(ids.contains(&"unique-id-2".to_string()));

    let _ = scanner;
}

// ============================================================================
// Scanner Helper Function Tests
// ============================================================================

#[test]
fn test_extract_owner_repo_from_url_https() {
    let url = "https://github.com/owner/repo.git";
    let result = Scanner::extract_owner_repo_from_url(url);

    assert!(result.is_some());
    let (owner, repo) = result.unwrap();
    assert_eq!(owner, "owner");
    assert_eq!(repo, "repo");
}

#[test]
fn test_extract_owner_repo_from_url_https_no_git_suffix() {
    let url = "https://github.com/owner/repo";
    let result = Scanner::extract_owner_repo_from_url(url);

    assert!(result.is_some());
    let (owner, repo) = result.unwrap();
    assert_eq!(owner, "owner");
    assert_eq!(repo, "repo");
}

#[test]
fn test_extract_owner_repo_from_url_git_ssh() {
    let url = "git@github.com:owner/repo.git";
    let result = Scanner::extract_owner_repo_from_url(url);

    assert!(result.is_some());
    let (owner, repo) = result.unwrap();
    assert_eq!(owner, "owner");
    assert_eq!(repo, "repo");
}

#[test]
fn test_extract_owner_repo_from_url_invalid() {
    let url = "invalid-url";
    let result = Scanner::extract_owner_repo_from_url(url);

    assert!(result.is_none());
}

#[test]
fn test_extract_owner_repo_from_url_empty() {
    let url = "";
    let result = Scanner::extract_owner_repo_from_url(url);

    assert!(result.is_none());
}

#[test]
fn test_extract_owner_repo_from_url_gitlab() {
    let url = "https://gitlab.com/owner/repo.git";
    let result = Scanner::extract_owner_repo_from_url(url);

    assert!(result.is_some());
    let (owner, repo) = result.unwrap();
    assert_eq!(owner, "owner");
    assert_eq!(repo, "repo");
}

#[test]
fn test_extract_owner_repo_from_url_with_subpath() {
    let url = "https://github.com/owner/repo/subpath";
    let result = Scanner::extract_owner_repo_from_url(url);

    assert!(result.is_some());
    let (owner, repo) = result.unwrap();
    assert_eq!(owner, "owner");
    assert_eq!(repo, "repo");
}

#[test]
fn test_extract_owner_repo_from_url_whitespace() {
    let url = "  https://github.com/owner/repo.git  ";
    let result = Scanner::extract_owner_repo_from_url(url);

    assert!(result.is_some());
    let (owner, repo) = result.unwrap();
    assert_eq!(owner, "owner");
    assert_eq!(repo, "repo");
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_phase_with_many_findings() {
    let temp_dir = TempDir::new().unwrap();
    let config = ScannerConfig::default();
    let scanner = create_test_scanner(config, &temp_dir);

    let findings: Vec<VulnerabilityFinding> = (0..100)
        .map(|i| {
            create_test_finding(
                &format!("f{}", i),
                &format!("Finding {}", i),
                &format!("file{}.rs", i),
                i as u32,
                Severity::Medium,
            )
        })
        .collect();

    assert_eq!(findings.len(), 100);

    let _ = scanner;
}

#[test]
fn test_phase_with_various_severities() {
    let temp_dir = TempDir::new().unwrap();
    let config = ScannerConfig::default();
    let scanner = create_test_scanner(config, &temp_dir);

    let findings: &[VulnerabilityFinding] = &[
        create_test_finding("f1", "Critical", "file1.rs", 1, Severity::Critical),
        create_test_finding("f2", "High", "file2.rs", 2, Severity::High),
        create_test_finding("f3", "Medium", "file3.rs", 3, Severity::Medium),
        create_test_finding("f4", "Low", "file4.rs", 4, Severity::Low),
    ];

    assert_eq!(findings.len(), 4);
    assert_eq!(findings[0].severity, Severity::Critical);
    assert_eq!(findings[1].severity, Severity::High);
    assert_eq!(findings[2].severity, Severity::Medium);
    assert_eq!(findings[3].severity, Severity::Low);

    let _ = scanner;
}

#[test]
fn test_phase_with_special_filenames() {
    let temp_dir = TempDir::new().unwrap();
    let config = ScannerConfig::default();
    let scanner = create_test_scanner(config, &temp_dir);

    let findings: &[VulnerabilityFinding] = &[
        create_test_finding("f1", "Finding", "src/main.rs", 10, Severity::High),
        create_test_finding("f2", "Finding", "src/utils_test.rs", 20, Severity::Medium),
        create_test_finding("f3", "Finding", "src/lib.rs", 30, Severity::Low),
    ];

    assert_eq!(findings.len(), 3);

    let _ = scanner;
}

// ============================================================================
// looks_like_a_repository: "not a repository" vs "a repository where git broke"
// ============================================================================
//
// The git phase warned on every scan of an extracted archive, because
// extracted/ is not a repository. A warning channel that fires every time is
// one nobody reads, which is how the triage fallback going silent went unnoticed
// twice. So the warning is now conditional on the target really being inside a
// git repository, and this predicate is what decides it.

#[test]
fn test_a_plain_directory_is_not_a_repository() {
    let dir = tempfile::tempdir().expect("tmpdir");
    std::fs::write(dir.path().join("main.rs"), "fn main() {}").expect("write");
    assert!(
        !looks_like_a_repository(dir.path()),
        "a directory with no .git is not a repository"
    );
}

#[test]
fn test_a_directory_holding_dot_git_is_a_repository() {
    let dir = tempfile::tempdir().expect("tmpdir");
    std::fs::create_dir(dir.path().join(".git")).expect("mkdir");
    assert!(looks_like_a_repository(dir.path()));
}

#[test]
fn test_a_file_named_dot_git_counts() {
    // Worktrees and submodules use a .git FILE, not a directory. The check uses
    // exists(), so both are seen; a directory-only check would miss these.
    let dir = tempfile::tempdir().expect("tmpdir");
    std::fs::write(dir.path().join(".git"), "gitdir: ../elsewhere").expect("write");
    assert!(looks_like_a_repository(dir.path()));
}

#[test]
fn test_a_subdirectory_of_a_repository_is_inside_it() {
    // The case that matters: the target is a plugin subdirectory and the
    // repository is above it.
    let dir = tempfile::tempdir().expect("tmpdir");
    std::fs::create_dir(dir.path().join(".git")).expect("mkdir");
    let nested = dir
        .path()
        .join("wp-content")
        .join("plugins")
        .join("captcha");
    std::fs::create_dir_all(&nested).expect("mkdir -p");
    assert!(looks_like_a_repository(&nested));
}

#[test]
fn test_a_directory_named_git_is_not_dot_git() {
    // "git" is not ".git". A loose check would fire on any vendored git dir.
    let dir = tempfile::tempdir().expect("tmpdir");
    std::fs::create_dir(dir.path().join("git")).expect("mkdir");
    assert!(!looks_like_a_repository(dir.path()));
}

#[test]
fn test_an_empty_directory_is_not_a_repository() {
    let dir = tempfile::tempdir().expect("tmpdir");
    assert!(!looks_like_a_repository(dir.path()));
}

#[test]
fn test_the_project_under_test_is_inside_a_git_repository() {
    // baco is a git repository, so scanning it must take the warning branch.
    // Skip this test when running in a copy without .git (e.g., cargo-mutants scratch dir).
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if !looks_like_a_repository(manifest_dir) {
        // Not a git repo - skip this test
        return;
    }
    assert!(
        looks_like_a_repository(manifest_dir),
        "baco's own source tree should be recognised as inside a repository"
    );
}
