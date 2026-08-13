//! Tests for git_analysis helpers

use baco::analysis_context::AnalysisContext;
use baco::git_analysis::helpers::{
    calculate_overall_confidence, get_commit_stats, get_remote_url, update_context,
};
use baco::git_analysis::models::{
    CommitReference, GitAnalysisResult, GitConfidenceModifier, RiskyCommitPattern,
    RiskyPatternType, VulnerabilityPattern, VulnerabilityPatternType,
};
use git2::Repository;
use std::process::Command;
use tempfile::TempDir;

/// Setup a minimal git repository for testing
fn setup_test_repo() -> TempDir {
    let tmp_dir = TempDir::new().expect("Failed to create temp dir");
    let repo_path = tmp_dir.path();

    // Initialize git repo
    let _repo = git2::Repository::init(repo_path).expect("Failed to init repo");

    // Create a test file
    let test_file = repo_path.join("test.txt");
    std::fs::write(&test_file, "initial content\n").expect("Failed to write test file");

    // Add and commit
    let mut index = _repo.index().expect("Failed to get index");
    index
        .add_path(std::path::Path::new("test.txt"))
        .expect("Failed to add file");
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
fn test_get_remote_url_no_remote() {
    let tmp_dir = setup_test_repo();
    let repo = Repository::open(tmp_dir.path()).unwrap();

    let remote = get_remote_url(&repo);
    assert!(remote.is_none());
}

#[test]
fn test_get_remote_url_with_remote() {
    let tmp_dir = setup_test_repo();
    let repo = Repository::open(tmp_dir.path()).unwrap();

    // Add a remote
    Command::new("git")
        .arg("remote")
        .arg("add")
        .arg("origin")
        .arg("https://github.com/test/test.git")
        .current_dir(tmp_dir.path())
        .output()
        .expect("Failed to add remote");

    let remote = get_remote_url(&repo);
    assert!(remote.is_some());
    assert_eq!(remote.unwrap(), "https://github.com/test/test.git");
}

#[test]
fn test_calculate_overall_confidence_empty_commits() {
    let commits: Vec<CommitReference> = vec![];
    let patterns: Vec<VulnerabilityPattern> = vec![];
    let risky: Vec<RiskyCommitPattern> = vec![];

    let score = calculate_overall_confidence(&commits, &patterns, &risky);
    assert_eq!(score, 0.3); // No history available
}

#[test]
fn test_calculate_overall_confidence_with_security_commits() {
    let commits = vec![CommitReference {
        commit_hash: "abc123".to_string(),
        commit_message: "Fix security issue".to_string(),
        author: "Test".to_string(),
        author_email: "test@example.com".to_string(),
        timestamp: 1234567890,
        modified_files: vec!["test.txt".to_string()],
        lines_added: 10,
        lines_deleted: 5,
        is_security_fix: true,
        cwe_references: vec![],
    }];
    let patterns: Vec<VulnerabilityPattern> = vec![];
    let risky: Vec<RiskyCommitPattern> = vec![];

    let score = calculate_overall_confidence(&commits, &patterns, &risky);
    assert!(score > 0.5); // Should be boosted by security commit
}

#[test]
fn test_calculate_overall_confidence_with_cwe_refs() {
    let commits = vec![CommitReference {
        commit_hash: "abc123".to_string(),
        commit_message: "Fix CWE-79".to_string(),
        author: "Test".to_string(),
        author_email: "test@example.com".to_string(),
        timestamp: 1234567890,
        modified_files: vec!["test.txt".to_string()],
        lines_added: 10,
        lines_deleted: 5,
        is_security_fix: false,
        cwe_references: vec!["CWE-79".to_string()],
    }];
    let patterns: Vec<VulnerabilityPattern> = vec![];
    let risky: Vec<RiskyCommitPattern> = vec![];

    let score = calculate_overall_confidence(&commits, &patterns, &risky);
    assert!(score > 0.5); // Should be boosted by CWE reference
}

#[test]
fn test_calculate_overall_confidence_with_risky_patterns() {
    let commits = vec![CommitReference {
        commit_hash: "abc123".to_string(),
        commit_message: "Normal commit".to_string(),
        author: "Test".to_string(),
        author_email: "test@example.com".to_string(),
        timestamp: 1234567890,
        modified_files: vec!["test.txt".to_string()],
        lines_added: 10,
        lines_deleted: 5,
        is_security_fix: false,
        cwe_references: vec![],
    }];
    let patterns: Vec<VulnerabilityPattern> = vec![];
    let risky = vec![RiskyCommitPattern {
        pattern_type: RiskyPatternType::SecurityBypass,
        description: "Security bypass".to_string(),
        commit: "abc123".to_string(),
        risk_score: 0.5,
    }];

    let score = calculate_overall_confidence(&commits, &patterns, &risky);
    assert!(score < 0.5); // Should be reduced by risky pattern
}

#[test]
fn test_calculate_overall_confidence_clamped() {
    // Many security commits should be clamped
    let commits: Vec<CommitReference> = (0..20)
        .map(|i| CommitReference {
            commit_hash: format!("abc{}", i),
            commit_message: "Security fix".to_string(),
            author: "Test".to_string(),
            author_email: "test@example.com".to_string(),
            timestamp: 1234567890,
            modified_files: vec!["test.txt".to_string()],
            lines_added: 10,
            lines_deleted: 5,
            is_security_fix: true,
            cwe_references: vec![],
        })
        .collect();
    let patterns: Vec<VulnerabilityPattern> = vec![];
    let risky: Vec<RiskyCommitPattern> = vec![];

    let score = calculate_overall_confidence(&commits, &patterns, &risky);
    assert!(score <= 1.0); // Should be clamped to max 1.0
}

#[test]
fn test_update_context_with_vulnerability_patterns() {
    let mut ctx = AnalysisContext::default();
    let result = GitAnalysisResult {
        related_commits: vec![],
        vulnerability_patterns: vec![VulnerabilityPattern {
            pattern_type: VulnerabilityPatternType::SecurityFix,
            description: "Test vulnerability".to_string(),
            cwe_id: None,
            commit: "abc123".to_string(),
            confidence: 0.8,
        }],
        risky_patterns: vec![],
        confidence_modifiers: vec![],
        git_confidence_score: 0.5,
    };

    update_context(&mut ctx, &result);

    assert!(!ctx.findings_so_far.is_empty());
    assert!(ctx.findings_so_far[0].contains("[git]"));
}

#[test]
fn test_update_context_with_security_commits() {
    let mut ctx = AnalysisContext::default();
    let result = GitAnalysisResult {
        related_commits: vec![CommitReference {
            commit_hash: "abc123".to_string(),
            commit_message: "Security fix".to_string(),
            author: "Test".to_string(),
            author_email: "test@example.com".to_string(),
            timestamp: 1234567890,
            modified_files: vec!["test.txt".to_string()],
            lines_added: 10,
            lines_deleted: 5,
            is_security_fix: true,
            cwe_references: vec![],
        }],
        vulnerability_patterns: vec![],
        risky_patterns: vec![],
        confidence_modifiers: vec![GitConfidenceModifier {
            source: "security_commits".to_string(),
            modifier: 0.1,
            reason: "Security commits found".to_string(),
        }],
        git_confidence_score: 0.5,
    };

    update_context(&mut ctx, &result);

    assert!(!ctx.invariants.is_empty());
    assert!(ctx.invariants[0].contains("security fixes"));
}

#[test]
fn test_get_commit_stats() {
    let commits = vec![
        CommitReference {
            commit_hash: "abc123".to_string(),
            commit_message: "Add feature".to_string(),
            author: "Test".to_string(),
            author_email: "test@example.com".to_string(),
            timestamp: 1234567890,
            modified_files: vec!["test.txt".to_string()],
            lines_added: 10,
            lines_deleted: 5,
            is_security_fix: false,
            cwe_references: vec![],
        },
        CommitReference {
            commit_hash: "def456".to_string(),
            commit_message: "Security fix".to_string(),
            author: "Test".to_string(),
            author_email: "test@example.com".to_string(),
            timestamp: 1234567890,
            modified_files: vec!["sec.txt".to_string()],
            lines_added: 3,
            lines_deleted: 2,
            is_security_fix: true,
            cwe_references: vec!["CWE-79".to_string()],
        },
    ];

    let stats = get_commit_stats(&commits);

    assert_eq!(stats.get("total_commits"), Some(&2));
    assert_eq!(stats.get("security_commits"), Some(&1));
    assert_eq!(stats.get("total_additions"), Some(&13));
    assert_eq!(stats.get("total_deletions"), Some(&7));
}
