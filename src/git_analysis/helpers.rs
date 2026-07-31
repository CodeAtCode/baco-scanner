//! Helper functions for git operations and analysis.

use git2::Repository;
use std::collections::HashMap;

use crate::analysis_context::AnalysisContext;
use crate::git_analysis::models::{
    CommitReference, GitAnalysisResult, RiskyCommitPattern, VulnerabilityPattern,
};

/// Get the remote URL for a repository
pub fn get_remote_url(repo: &Repository) -> Option<String> {
    repo.remotes().ok().and_then(|remotes| {
        let iter = remotes.iter();
        for name in iter.flatten() {
            if let Ok(remote) = repo.find_remote(name) {
                if let Some(url) = remote.url() {
                    return Some(url.to_string());
                }
            }
        }
        None
    })
}

/// Calculate overall git-based confidence score
pub fn calculate_overall_confidence(
    commits: &[CommitReference],
    patterns: &[VulnerabilityPattern],
    risky: &[RiskyCommitPattern],
) -> f32 {
    let mut score = 0.5; // Base score

    // No history available
    if commits.is_empty() {
        return 0.3;
    }

    // Positive modifiers
    let security_commits = commits.iter().filter(|c| c.is_security_fix).count();
    score += (security_commits as f32 * 0.05).min(0.2);

    let cwe_refs = commits
        .iter()
        .filter(|c| !c.cwe_references.is_empty())
        .count();
    score += (cwe_refs as f32 * 0.05).min(0.15);

    // Vulnerability patterns add confidence
    score += (patterns.len() as f32 * 0.03).min(0.15);

    // Negative modifiers from risky patterns
    let risk_penalty: f32 = risky.iter().map(|r| r.risk_score).sum::<f32>() * 0.1;
    score -= risk_penalty.min(0.3);

    score.clamp(0.0, 1.0)
}

/// Update AnalysisContext with git analysis results
pub fn update_context(ctx: &mut AnalysisContext, result: &GitAnalysisResult) {
    // Add git-based findings to context
    for pattern in &result.vulnerability_patterns {
        if !ctx.findings_so_far.contains(&pattern.description) {
            ctx.findings_so_far.push(format!(
                "[git] {}: {} (confidence: {:.2})",
                pattern.pattern_type_to_string(),
                pattern.description,
                pattern.confidence
            ));
        }
    }

    // Update invariants based on security commits
    if result
        .confidence_modifiers
        .iter()
        .any(|m| m.source == "security_commits")
    {
        ctx.invariants
            .push("Code has security fixes in git history - review related patterns".to_string());
    }
}

/// Get commit statistics for a file
#[allow(dead_code)]
pub fn get_commit_stats(commits: &[CommitReference]) -> HashMap<String, i32> {
    let mut stats = HashMap::new();
    stats.insert("total_commits".to_string(), commits.len() as i32);

    let security_commits = commits.iter().filter(|c| c.is_security_fix).count();
    stats.insert("security_commits".to_string(), security_commits as i32);

    let total_additions: i32 = commits.iter().map(|c| c.lines_added).sum();
    let total_deletions: i32 = commits.iter().map(|c| c.lines_deleted).sum();
    stats.insert("total_additions".to_string(), total_additions);
    stats.insert("total_deletions".to_string(), total_deletions);

    stats
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_analysis::test_utils::setup_test_repo;
    use crate::git_analysis::{GitConfidenceModifier, RiskyPatternType, VulnerabilityPatternType};
    use std::process::Command;

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
}
