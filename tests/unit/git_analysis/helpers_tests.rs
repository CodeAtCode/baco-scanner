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
// ============================================================================
// Diff Hunk Parsing Tests
// ============================================================================

#[test]
fn test_hunk_header_parsing_simple() {
    // @@ -10,5 +10,7 @@ function main()
    let header = "@@ -10,5 +10,7 @@ function main()";

    // Extract old start line
    let parts: Vec<&str> = header.split(" @@").next().unwrap().split(' ').collect();
    assert_eq!(parts.len(), 3);

    let old_range = parts[1].trim_start_matches('-');
    let old_start: i32 = old_range.split(',').next().unwrap().parse().unwrap();
    assert_eq!(old_start, 10);
}

#[test]
fn test_hunk_header_parsing_no_count() {
    // @@ -10 +10,7 @@ (old count omitted means 1)
    let header = "@@ -10 +10,7 @@";

    let parts: Vec<&str> = header.split(" @@").next().unwrap().split(' ').collect();
    let old_range = parts[1].trim_start_matches('-');
    let old_start: i32 = old_range.split(',').next().unwrap().parse().unwrap();
    assert_eq!(old_start, 10);
}

#[test]
fn test_path_extraction_from_diff() {
    // diff --git a/src/main.c b/src/main.c
    let diff_line = "diff --git a/src/main.c b/src/main.c";

    // Extract path after "b/"
    if let Some(start) = diff_line.find("b/") {
        let path = &diff_line[start + 2..];
        // Path should be "src/main.c"
        assert_eq!(path, "src/main.c");
    }
}

#[test]
fn test_rename_detection_in_diff() {
    // rename from a/old/path.c
    // rename to b/new/path.c
    let rename_from = "rename from a/old/path.c";
    let rename_to = "rename to b/new/path.c";

    assert!(rename_from.contains("rename from"));
    assert!(rename_to.contains("rename to"));

    let old_path = rename_from.trim_start_matches("rename from a/");
    let new_path = rename_to.trim_start_matches("rename to b/");

    assert_eq!(old_path, "old/path.c");
    assert_eq!(new_path, "new/path.c");
}

// ============================================================================
// Commit Reference Field Tests
// ============================================================================

#[test]
fn test_commit_reference_security_keyword_detection() {
    let commit_messages = vec![
        ("Fix security vulnerability in auth", true),
        ("Security patch for CVE-2024-1234", true),
        ("Fix CWE-79 XSS issue", true),
        ("Update dependencies", false),
        ("Add new feature", false),
        ("Refactor code structure", false),
    ];

    for (msg, should_be_security) in commit_messages {
        let is_security = msg.to_lowercase().contains("security")
            || msg.to_lowercase().contains("vulnerability")
            || msg.to_lowercase().contains("cve-")
            || msg.to_lowercase().contains("cwe-");

        assert_eq!(is_security, should_be_security, "Message: {}", msg);
    }
}

#[test]
fn test_commit_reference_cwe_extraction() {
    let msg = "Fix XSS vulnerability (CWE-79) in input handling";

    let has_cwe = msg.contains("CWE-");
    assert!(has_cwe);

    // Extract CWE ID
    if let Some(start) = msg.find("CWE-") {
        let cwe_part = &msg[start..];
        let cwe_id: String = cwe_part
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '-')
            .collect();
        assert_eq!(cwe_id, "CWE-79");
    }
}

// ============================================================================
// Confidence Modifier Tests
// ============================================================================

#[test]
fn test_confidence_modifier_accumulation() {
    let modifiers = [
        GitConfidenceModifier {
            source: "security_commits".to_string(),
            modifier: 0.1,
            reason: "Security fix in history".to_string(),
        },
        GitConfidenceModifier {
            source: "cwe_references".to_string(),
            modifier: 0.05,
            reason: "CWE mentioned".to_string(),
        },
        GitConfidenceModifier {
            source: "risky_pattern".to_string(),
            modifier: -0.15,
            reason: "Security bypass detected".to_string(),
        },
    ];

    let total_modifier: f32 = modifiers.iter().map(|m| m.modifier).sum();
    assert_eq!(total_modifier, 0.0); // 0.1 + 0.05 - 0.15 = 0.0
}

#[test]
fn test_confidence_modifier_clamping() {
    let base_score = 0.5;
    let modifiers = [0.3, 0.2, 0.1]; // Total +0.6

    let new_score = base_score + modifiers.iter().sum::<f32>();
    let clamped = new_score.clamp(0.0, 1.0);

    assert_eq!(clamped, 1.0); // Should be clamped to max
}

// ============================================================================
// GitAnalysisResult Construction Tests
// ============================================================================

#[test]
fn test_git_analysis_result_default_values() {
    let result = GitAnalysisResult {
        related_commits: vec![],
        vulnerability_patterns: vec![],
        risky_patterns: vec![],
        confidence_modifiers: vec![],
        git_confidence_score: 0.5,
    };

    assert!(result.related_commits.is_empty());
    assert!(result.vulnerability_patterns.is_empty());
    assert!(result.risky_patterns.is_empty());
    assert!(result.confidence_modifiers.is_empty());
    assert_eq!(result.git_confidence_score, 0.5);
}

#[test]
fn test_risky_pattern_type_coverage() {
    // Verify all risky pattern types are covered
    let _large_change = RiskyPatternType::LargeChange;
    let _hotfix = RiskyPatternType::Hotfix;
    let _revert = RiskyPatternType::Revert;
    let _merge_with_conflicts = RiskyPatternType::MergeWithConflicts;
    let _new_author = RiskyPatternType::NewAuthor;
    let _emergency = RiskyPatternType::EmergencyCommit;
    let _security_bypass = RiskyPatternType::SecurityBypass;

    // Just verify they compile - actual usage tested elsewhere
}

#[test]
fn test_vulnerability_pattern_type_coverage() {
    // Verify all vulnerability pattern types are covered
    let _security_vulnerability = VulnerabilityPatternType::SecurityVulnerability;
    let _security_fix = VulnerabilityPatternType::SecurityFix;
    let _security_todo = VulnerabilityPatternType::SecurityTodo;
    let _security_deprecation = VulnerabilityPatternType::SecurityDeprecation;
    let _vulnerable_dependency = VulnerabilityPatternType::VulnerableDependency;
    let _injection_risk = VulnerabilityPatternType::InjectionRisk;
    let _auth_issue = VulnerabilityPatternType::AuthIssue;
    let _crypto_misuse = VulnerabilityPatternType::CryptoMisuse;
    let _custom = VulnerabilityPatternType::Custom("test".to_string());

    // Just verify they compile
}
