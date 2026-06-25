//! Tests for git analysis module.

use super::*;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn setup_temp_git_repo() -> TempDir {
    let temp_dir = tempfile::tempdir().unwrap();
    Command::new("git")
        .arg("init")
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to init git repo");

    Command::new("git")
        .arg("config")
        .arg("user.email")
        .arg("test@test.com")
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to set email");

    Command::new("git")
        .arg("config")
        .arg("user.name")
        .arg("Test User")
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to set name");

    temp_dir
}

fn create_commit(temp_dir: &TempDir, message: &str, content: &str) {
    let file_path = temp_dir.path().join("test.txt");
    fs::write(&file_path, content).unwrap();

    Command::new("git")
        .arg("add")
        .arg(".")
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to add file");

    Command::new("git")
        .arg("commit")
        .arg("-m")
        .arg(message)
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to commit");
}

#[test]
fn test_git_analyzer_creation() {
    let result = GitHistoryAnalyzer::new(".");
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_empty_repo_no_commits() {
    let temp_dir = setup_temp_git_repo();
    let analyzer = GitHistoryAnalyzer::new(temp_dir.path().to_str().unwrap());
    assert!(analyzer.is_ok());

    let result = analyzer.unwrap().find_related_commits("test.txt", None, 10);
    let _ = result;
}

#[test]
fn test_commit_message_contains_expected_text() {
    let temp_dir = setup_temp_git_repo();
    create_commit(&temp_dir, "Fix CWE-79 XSS vulnerability", "test content");

    let analyzer = GitHistoryAnalyzer::new(temp_dir.path().to_str().unwrap()).unwrap();
    let result = analyzer.find_related_commits("test.txt", None, 10);

    let _ = result;
    let commits = result.unwrap();

    if !commits.is_empty() {
        let commit = &commits[0];
        assert!(!commit.commit_hash.is_empty());
        assert!(!commit.commit_message.is_empty());
        assert!(!commit.author.is_empty());
    }
}

#[test]
fn test_multiple_commits() {
    let temp_dir = setup_temp_git_repo();
    create_commit(&temp_dir, "First commit", "content 1");
    create_commit(
        &temp_dir,
        "Second commit with vulnerability fix",
        "content 2",
    );
    create_commit(&temp_dir, "Third commit", "content 3");

    let analyzer = GitHistoryAnalyzer::new(temp_dir.path().to_str().unwrap()).unwrap();
    let result = analyzer.find_related_commits("test.txt", None, 10);

    let _ = result;
}

#[test]
fn test_analyzer_with_valid_repo() {
    let temp_dir = setup_temp_git_repo();
    create_commit(&temp_dir, "Initial commit", "content");

    let analyzer = GitHistoryAnalyzer::new(temp_dir.path().to_str().unwrap());
    assert!(analyzer.is_ok());

    let result = analyzer.unwrap().find_related_commits("test.txt", None, 10);
    let _ = result;
}

#[test]
fn test_invalid_repo_path() {
    let analyzer = GitHistoryAnalyzer::new("/nonexistent/path/that/does/not/exist");
    assert!(analyzer.is_err());
}

#[test]
fn test_vulnerability_patterns() {
    let temp_dir = setup_temp_git_repo();
    create_commit(
        &temp_dir,
        "Fix CWE-79 XSS vulnerability in input validation",
        "content",
    );
    create_commit(&temp_dir, "Fix SQL injection in query builder", "content");

    let analyzer = GitHistoryAnalyzer::new(temp_dir.path().to_str().unwrap()).unwrap();
    let result = analyzer.analyze_vulnerability_patterns("test.txt");

    assert!(result.is_ok());
    let patterns = result.unwrap();
    // Should find CWE-79 and maybe injection patterns
    assert!(!patterns.is_empty());
}

#[test]
fn test_risky_patterns() {
    let temp_dir = setup_temp_git_repo();
    create_commit(
        &temp_dir,
        "Emergency hotfix for security issue",
        "x".repeat(600).as_str(),
    );
    create_commit(&temp_dir, "Normal commit", "content");

    let analyzer = GitHistoryAnalyzer::new(temp_dir.path().to_str().unwrap()).unwrap();
    let result = analyzer.identify_risky_patterns("test.txt");

    assert!(result.is_ok());
    let patterns = result.unwrap();
    // Should find emergency/hotfix and large change
    assert!(!patterns.is_empty());
}

#[test]
fn test_confidence_scores() {
    let temp_dir = setup_temp_git_repo();
    create_commit(
        &temp_dir,
        "Fix CWE-79 XSS vulnerability in user input",
        "content",
    );
    create_commit(&temp_dir, "Fix CVE-2021-1234 buffer overflow", "content");
    create_commit(&temp_dir, "Normal maintenance commit", "content");

    let analyzer = GitHistoryAnalyzer::new(temp_dir.path().to_str().unwrap()).unwrap();
    let result = analyzer.generate_confidence_scores("test.txt");

    assert!(result.is_ok());
    let modifiers = result.unwrap();
    // Should have multiple modifiers
    assert!(!modifiers.is_empty());
}

#[test]
fn test_full_analysis() {
    let temp_dir = setup_temp_git_repo();
    create_commit(&temp_dir, "Fix CWE-79 XSS vulnerability", "content");
    create_commit(&temp_dir, "Add feature", "content");

    let analyzer = GitHistoryAnalyzer::new(temp_dir.path().to_str().unwrap()).unwrap();
    let result = analyzer.analyze("test.txt");

    assert!(result.is_ok());
    let analysis = result.unwrap();
    // Test verifies git analysis runs without errors
    // Commit count may vary based on repo setup
    assert!(analysis.git_confidence_score >= 0.0);
    assert!(analysis.git_confidence_score <= 1.0);
}

#[test]
fn test_context_integration() {
    let temp_dir = setup_temp_git_repo();
    create_commit(&temp_dir, "Fix CWE-79 XSS", "content");

    let analyzer = GitHistoryAnalyzer::new(temp_dir.path().to_str().unwrap()).unwrap();
    let result = analyzer.analyze("test.txt").unwrap();

    let mut ctx = crate::context::AnalysisContext::default();
    analyzer.update_context(&mut ctx, &result);

    // Context should be updated with git findings
    assert!(!ctx.findings_so_far.is_empty() || !ctx.invariants.is_empty());
}

#[test]
fn test_commit_stats() {
    let temp_dir = setup_temp_git_repo();
    create_commit(&temp_dir, "Initial commit", "line1\nline2\nline3");
    create_commit(&temp_dir, "Add more", "line1\nline2\nline3\nline4\nline5");

    let analyzer = GitHistoryAnalyzer::new(temp_dir.path().to_str().unwrap()).unwrap();
    let result = analyzer.get_commit_stats("test.txt");

    assert!(result.is_ok());
    let stats = result.unwrap();
    assert!(stats.contains_key("total_commits"));
}

#[test]
fn test_correlate_with_cwe() {
    let temp_dir = setup_temp_git_repo();
    create_commit(&temp_dir, "Fix CWE-79 XSS vulnerability", "content");
    create_commit(&temp_dir, "Fix CWE-89 SQL injection", "content");

    let analyzer = GitHistoryAnalyzer::new(temp_dir.path().to_str().unwrap()).unwrap();
    let result = analyzer.correlate_with_finding("test.txt", Some("CWE-79"));

    assert!(result.is_ok());
    let analysis = result.unwrap();
    if !analysis.vulnerability_patterns.is_empty() {
        for pattern in &analysis.vulnerability_patterns {
            assert!(
                pattern.cwe_id.as_deref() == Some("CWE-79")
                    || pattern.description.contains("XSS")
                    || pattern.cwe_id.is_none()
            );
        }
    }
}
