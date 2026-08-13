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
