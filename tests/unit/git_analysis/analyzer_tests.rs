//! Tests for GitHistoryAnalyzer

use baco::git_analysis::GitHistoryAnalyzer;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Setup a minimal git repository for testing
fn setup_test_repo() -> TempDir {
    let tmp_dir = TempDir::new().expect("Failed to create temp dir");
    let repo_path = tmp_dir.path();

    // Initialize git repo
    let _repo = git2::Repository::init(repo_path).expect("Failed to init repo");

    // Create a test file
    let test_file = repo_path.join("test.txt");
    fs::write(&test_file, "initial content\n").expect("Failed to write test file");

    // Add and commit
    let mut index = _repo.index().expect("Failed to get index");
    index.add_path(Path::new("test.txt")).expect("Failed to add file");
    index.write().expect("Failed to write index");

    let tree_id = index.write_tree().expect("Failed to write tree");
    let tree = _repo.find_tree(tree_id).expect("Failed to find tree");

    let signature =
        git2::Signature::now("Test User", "test@example.com").expect("Failed to create signature");

    _repo
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            "Initial commit with test file",
            &tree,
            &[],
        )
        .expect("Failed to create commit");

    tmp_dir
}

#[test]
fn test_analyzer_initialization_success() {
    let tmp_dir = setup_test_repo();
    let repo_path = tmp_dir.path().to_string_lossy().to_string();

    let analyzer = GitHistoryAnalyzer::new(&repo_path);

    assert!(analyzer.is_ok(), "Analyzer should initialize successfully");
}

#[test]
fn test_analyzer_initialization_invalid_path() {
    let analyzer = GitHistoryAnalyzer::new("/nonexistent/path");

    assert!(
        analyzer.is_err(),
        "Analyzer should fail with invalid path"
    );
    let err = analyzer.unwrap_err().to_string();
    assert!(
        err.contains("failed to resolve path") || err.contains("does not exist"),
        "Error should mention path issue: {}",
        err
    );
}

#[test]
fn test_find_related_commits_file_level() {
    let tmp_dir = setup_test_repo();
    let repo_path = tmp_dir.path().to_string_lossy().to_string();

    let analyzer = GitHistoryAnalyzer::new(&repo_path).expect("Failed to create analyzer");

    let commits = analyzer
        .find_related_commits("test.txt", None, 10)
        .expect("Failed to find commits");

    assert!(
        !commits.is_empty(),
        "Should find at least one commit for the file"
    );
    assert_eq!(commits[0].modified_files.len(), 1);
    assert!(commits[0].commit_message.contains("Initial commit"));
}

#[test]
fn test_find_related_commits_with_line_number() {
    let tmp_dir = setup_test_repo();
    let repo_path = tmp_dir.path().to_string_lossy().to_string();

    let analyzer = GitHistoryAnalyzer::new(&repo_path).expect("Failed to create analyzer");

    // Test with a valid line number
    let commits = analyzer
        .find_related_commits("test.txt", Some(1), 10)
        .expect("Failed to find commits for line");

    assert_eq!(commits.len(), 1, "Should return single commit for specific line");
    assert!(commits[0].commit_hash.len() == 8, "Commit hash should be abbreviated to 8 chars");
}

#[test]
fn test_find_related_commits_invalid_file() {
    let tmp_dir = setup_test_repo();
    let repo_path = tmp_dir.path().to_string_lossy().to_string();

    let analyzer = GitHistoryAnalyzer::new(&repo_path).expect("Failed to create analyzer");

    let result = analyzer.find_related_commits("nonexistent.txt", None, 10);

    // Should return empty list rather than error for file not in history
    assert!(
        result.is_ok(),
        "Should handle nonexistent file gracefully"
    );
    let commits = result.unwrap();
    assert!(commits.is_empty(), "Should return empty list for nonexistent file");
}

#[test]
fn test_analyze_vulnerability_patterns() {
    let tmp_dir = setup_test_repo();
    let repo_path = tmp_dir.path().to_string_lossy().to_string();

    let analyzer = GitHistoryAnalyzer::new(&repo_path).expect("Failed to create analyzer");

    let patterns = analyzer.analyze_vulnerability_patterns("test.txt");

    // Should not panic and return a vector
    assert!(patterns.is_ok());
}

#[test]
fn test_identify_risky_patterns() {
    let tmp_dir = setup_test_repo();
    let repo_path = tmp_dir.path().to_string_lossy().to_string();

    let analyzer = GitHistoryAnalyzer::new(&repo_path).expect("Failed to create analyzer");

    let patterns = analyzer.identify_risky_patterns("test.txt");

    // Should not panic and return a vector
    assert!(patterns.is_ok());
}

#[test]
fn test_generate_confidence_scores_empty_history() {
    let tmp_dir = TempDir::new().expect("Failed to create temp dir");
    let repo_path = tmp_dir.path().to_string_lossy().to_string();

    // Create repo without any commits
    let _repo = git2::Repository::init(&repo_path).expect("Failed to init repo");

    let analyzer = GitHistoryAnalyzer::new(&repo_path).expect("Failed to create analyzer");

    let modifiers = analyzer
        .generate_confidence_scores("test.txt")
        .expect("Failed to generate confidence scores");

    assert!(
        !modifiers.is_empty(),
        "Should return at least one modifier for empty history"
    );
    assert_eq!(modifiers[0].source, "git_history");
    assert_eq!(modifiers[0].modifier, -0.1);
}

#[test]
fn test_generate_confidence_scores_with_security_commits() {
    let tmp_dir = setup_test_repo();
    let repo_path = tmp_dir.path().to_string_lossy().to_string();

    let analyzer = GitHistoryAnalyzer::new(&repo_path).expect("Failed to create analyzer");

    let modifiers = analyzer
        .generate_confidence_scores("test.txt")
        .expect("Failed to generate confidence scores");

    // The initial commit doesn't have security keywords, so we should get the base modifiers
    assert!(!modifiers.is_empty());
}

#[test]
fn test_analyze_full_result() {
    let tmp_dir = setup_test_repo();
    let repo_path = tmp_dir.path().to_string_lossy().to_string();

    let analyzer = GitHistoryAnalyzer::new(&repo_path).expect("Failed to create analyzer");

    let result = analyzer.analyze("test.txt").expect("Failed to run full analysis");

    assert!(
        !result.related_commits.is_empty(),
        "Should have related commits"
    );
    assert!(
        result.git_confidence_score >= 0.0 && result.git_confidence_score <= 1.0,
        "Confidence score should be between 0 and 1"
    );
}

#[test]
fn test_get_remote_url_no_remote() {
    let tmp_dir = setup_test_repo();
    let repo_path = tmp_dir.path().to_string_lossy().to_string();

    let analyzer = GitHistoryAnalyzer::new(&repo_path).expect("Failed to create analyzer");

    let remote_url = analyzer.get_remote_url();

    assert!(
        remote_url.is_none(),
        "Should return None when no remote is configured"
    );
}

#[test]
fn test_max_commits_limit() {
    let tmp_dir = setup_test_repo();
    let repo_path = tmp_dir.path().to_string_lossy().to_string();

    let analyzer = GitHistoryAnalyzer::new(&repo_path).expect("Failed to create analyzer");

    // Request only 1 commit
    let commits = analyzer
        .find_related_commits("test.txt", None, 1)
        .expect("Failed to find commits");

    assert_eq!(
        commits.len(),
        1,
        "Should respect max_commits limit"
    );
}

#[test]
fn test_commit_reference_fields() {
    let tmp_dir = setup_test_repo();
    let repo_path = tmp_dir.path().to_string_lossy().to_string();

    let analyzer = GitHistoryAnalyzer::new(&repo_path).expect("Failed to create analyzer");

    let commits = analyzer
        .find_related_commits("test.txt", None, 1)
        .expect("Failed to find commits");

    let commit = &commits[0];

    assert_eq!(commit.commit_hash.len(), 8);
    assert!(!commit.commit_message.is_empty());
    assert_eq!(commit.author, "Test User");
    assert_eq!(commit.author_email, "test@example.com");
    assert!(commit.timestamp > 0);
    assert!(!commit.modified_files.is_empty());
    assert!(commit.lines_added >= 0);
    assert!(commit.lines_deleted >= 0);
}
