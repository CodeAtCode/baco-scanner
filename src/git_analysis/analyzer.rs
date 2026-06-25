//! Git history analyzer implementation.

use git2::Repository;
use std::path::Path;

use crate::context::AnalysisContext;
use crate::git_analysis::helpers::{calculate_overall_confidence, get_remote_url, update_context};
use crate::git_analysis::models::{
    CommitReference, GitAnalysisResult, GitConfidenceModifier, RiskyCommitPattern,
    RiskyPatternType, VulnerabilityPattern, VulnerabilityPatternType,
};
use crate::git_analysis::patterns::{
    analyze_commit_message, calculate_pattern_confidence, compile_risky_patterns,
    compile_vulnerability_patterns, get_security_keywords,
};
use regex::Regex;

/// Git history analyzer for security analysis
pub struct GitHistoryAnalyzer {
    repo: Repository,
    /// Compiled regex patterns for vulnerability detection
    vulnerability_patterns: Vec<(Regex, VulnerabilityPatternType, &'static str)>,
    /// Compiled regex patterns for risky commit detection
    risky_patterns: Vec<(Regex, RiskyPatternType, f32)>,
    /// Security-related keywords
    security_keywords: Vec<&'static str>,
}

impl GitHistoryAnalyzer {
    /// Create a new analyzer for the given repository path
    pub fn new(repo_path: &str) -> Result<Self, git2::Error> {
        let repo = Repository::open(repo_path)?;

        let vulnerability_patterns = compile_vulnerability_patterns();
        let risky_patterns = compile_risky_patterns();
        let security_keywords = get_security_keywords();

        Ok(Self {
            repo,
            vulnerability_patterns,
            risky_patterns,
            security_keywords,
        })
    }

    /// Find commits related to a specific file and optionally a specific line
    pub fn find_related_commits(
        &self,
        file_path: &str,
        line_number: Option<u32>,
        max_commits: usize,
    ) -> Result<Vec<CommitReference>, String> {
        // If a line number is provided, try to use blame to find the specific commit
        if let Some(lineno) = line_number {
            if let Ok(commit) = self.find_commit_for_line(file_path, lineno) {
                return Ok(vec![commit]);
            }
            // If blame fails, fall back to file-level search
        }

        // Fallback: file-level commit search (original behavior)
        self.find_related_commits_file_level(file_path, max_commits)
    }

    /// Find the commit that last modified a specific line using git blame
    fn find_commit_for_line(
        &self,
        file_path: &str,
        line_number: u32,
    ) -> Result<CommitReference, String> {
        let path = Path::new(file_path);

        let blame = self
            .repo
            .blame_file(path, None)
            .map_err(|e| format!("blame failed: {}", e))?;

        let hunk = blame
            .get_line(line_number as usize)
            .ok_or_else(|| format!("no blame hunk found for line {}", line_number))?;

        let commit_oid = hunk.final_commit_id();
        let commit = self
            .repo
            .find_commit(commit_oid)
            .map_err(|e| format!("failed to find commit: {}", e))?;

        let message = commit.message().unwrap_or("");
        let (is_security_fix, cwe_references) =
            analyze_commit_message(message, &self.security_keywords);

        let author_name = commit.author().name().unwrap_or("").to_string();
        let author_email = commit.author().email().unwrap_or("").to_string();
        let timestamp = commit.time().seconds();

        Ok(CommitReference {
            commit_hash: commit_oid.to_string()[..8].to_string(),
            commit_message: message.to_string(),
            author: author_name,
            author_email,
            timestamp,
            modified_files: vec![file_path.to_string()],
            lines_added: 0,
            lines_deleted: 0,
            is_security_fix,
            cwe_references,
        })
    }

    /// Find commits related to a specific file (file-level search)
    fn find_related_commits_file_level(
        &self,
        file_path: &str,
        max_commits: usize,
    ) -> Result<Vec<CommitReference>, String> {
        let mut commits = Vec::new();

        let mut revwalk = self.repo.revwalk().map_err(|e| e.to_string())?;
        revwalk.push_head().map_err(|e| e.to_string())?;
        revwalk
            .set_sorting(git2::Sort::TIME)
            .map_err(|e| e.to_string())?;

        for oid in revwalk {
            let oid = oid.map_err(|e| e.to_string())?;
            let commit = self.repo.find_commit(oid).map_err(|e| e.to_string())?;

            let parent_tree = commit.parent(0).ok().and_then(|p| p.tree().ok());
            let tree = commit.tree().map_err(|e| e.to_string())?;

            let mut lines_added: i32 = 0;
            let mut lines_deleted: i32 = 0;
            let mut modified_files = Vec::new();

            if let Ok(diff) = self.repo.diff_tree_to_tree(
                parent_tree.as_ref(),
                Some(&tree),
                Some(&mut git2::DiffOptions::new().context_lines(0)),
            ) {
                diff.foreach(
                    &mut |delta, _hunk| {
                        if let Some(path) = delta.new_file().path() {
                            let path_str = path.to_string_lossy().to_string();
                            if path_str == file_path || path_str.ends_with(file_path) {
                                modified_files.push(path_str);
                            }
                        }
                        true
                    },
                    None,
                    None,
                    Some(&mut |_delta, _hunk, line| {
                        match line.origin() {
                            '+' => lines_added += 1,
                            '-' => lines_deleted += 1,
                            _ => {}
                        }
                        true
                    }),
                )
                .unwrap_or_default();
            }

            if modified_files.is_empty() {
                continue;
            }

            let message = commit.message().unwrap_or("");
            let (is_security_fix, cwe_references) =
                analyze_commit_message(message, &self.security_keywords);

            commits.push(CommitReference {
                commit_hash: oid.to_string()[..8].to_string(),
                commit_message: message.to_string(),
                author: commit.author().name().unwrap_or("").to_string(),
                author_email: commit.author().email().unwrap_or("").to_string(),
                timestamp: commit.time().seconds(),
                modified_files,
                lines_added,
                lines_deleted,
                is_security_fix,
                cwe_references,
            });

            if commits.len() >= max_commits {
                break;
            }
        }

        Ok(commits)
    }

    /// Analyze git history for vulnerability patterns in a file
    pub fn analyze_vulnerability_patterns(
        &self,
        file_path: &str,
    ) -> Result<Vec<VulnerabilityPattern>, String> {
        let commits = self.find_related_commits(file_path, None, 50)?;
        let mut patterns = Vec::new();

        for commit in commits {
            let message = commit.commit_message.to_lowercase();

            // Check against vulnerability patterns
            for (regex, pattern_type, description) in &self.vulnerability_patterns {
                if regex.is_match(&message) {
                    let confidence = calculate_pattern_confidence(
                        commit.timestamp,
                        commit.is_security_fix,
                        commit.cwe_references.len(),
                        pattern_type,
                    );
                    let cwe_id = commit.cwe_references.first().cloned();

                    patterns.push(VulnerabilityPattern {
                        pattern_type: pattern_type.clone(),
                        description: description.to_string(),
                        cwe_id,
                        commit: commit.commit_hash.clone(),
                        confidence,
                    });
                }
            }
        }

        Ok(patterns)
    }

    pub fn get_remote_url(&self) -> Option<String> {
        get_remote_url(&self.repo)
    }

    /// Identify risky commit patterns in history
    pub fn identify_risky_patterns(
        &self,
        file_path: &str,
    ) -> Result<Vec<RiskyCommitPattern>, String> {
        let commits = self.find_related_commits(file_path, None, 50)?;
        let mut patterns = Vec::new();

        for commit in commits {
            let message = commit.commit_message.to_lowercase();

            // Check for large changes
            let change_size = commit.lines_added + commit.lines_deleted;
            if change_size > 500 {
                patterns.push(RiskyCommitPattern {
                    pattern_type: RiskyPatternType::LargeChange,
                    description: format!(
                        "Large change: +{} -{} lines",
                        commit.lines_added, commit.lines_deleted
                    ),
                    commit: commit.commit_hash.clone(),
                    risk_score: (change_size as f32 / 2000.0).min(0.8),
                });
            }

            // Check for risky patterns
            for (regex, pattern_type, risk_score) in &self.risky_patterns {
                if regex.is_match(&message) {
                    patterns.push(RiskyCommitPattern {
                        pattern_type: pattern_type.clone(),
                        description: format!("Risky pattern: {}", commit.commit_message),
                        commit: commit.commit_hash.clone(),
                        risk_score: *risk_score,
                    });
                }
            }
        }

        Ok(patterns)
    }

    /// Generate git-based confidence scores
    pub fn generate_confidence_scores(
        &self,
        file_path: &str,
    ) -> Result<Vec<GitConfidenceModifier>, String> {
        let commits = self.find_related_commits(file_path, None, 20)?;
        let mut modifiers = Vec::new();

        if commits.is_empty() {
            modifiers.push(GitConfidenceModifier {
                source: "git_history".to_string(),
                modifier: -0.1,
                reason: "No git history available".to_string(),
            });
            return Ok(modifiers);
        }

        // Check for security-related commits
        let security_commits: Vec<_> = commits.iter().filter(|c| c.is_security_fix).collect();

        if !security_commits.is_empty() {
            let modifier = (security_commits.len() as f32 * 0.05).min(0.2);
            modifiers.push(GitConfidenceModifier {
                source: "security_commits".to_string(),
                modifier,
                reason: format!("Found {} security-related commits", security_commits.len()),
            });
        }

        // Check for recent fixes
        let recent_fixes: Vec<_> = commits
            .iter()
            .filter(|c| {
                let age_days = (chrono::Utc::now().timestamp() - c.timestamp) / 86400;
                age_days < 30 && c.is_security_fix
            })
            .collect();

        if !recent_fixes.is_empty() {
            modifiers.push(GitConfidenceModifier {
                source: "recent_security_fixes".to_string(),
                modifier: 0.1,
                reason: "Recent security fixes indicate active security maintenance".to_string(),
            });
        }

        // Check for patterns with CWE references
        let cwe_commits: Vec<_> = commits
            .iter()
            .filter(|c| !c.cwe_references.is_empty())
            .collect();

        if !cwe_commits.is_empty() {
            modifiers.push(GitConfidenceModifier {
                source: "cwe_references".to_string(),
                modifier: 0.15,
                reason: "Commits reference CWE vulnerabilities".to_string(),
            });
        }

        // Large number of commits can indicate active development
        if commits.len() > 10 {
            modifiers.push(GitConfidenceModifier {
                source: "active_development".to_string(),
                modifier: 0.05,
                reason: "Active development history (good for finding related fixes)".to_string(),
            });
        }

        Ok(modifiers)
    }

    /// Perform full git analysis and return all results
    pub fn analyze(&self, file_path: &str) -> Result<GitAnalysisResult, String> {
        let related_commits = self.find_related_commits(file_path, None, 20)?;
        let vulnerability_patterns = self.analyze_vulnerability_patterns(file_path)?;
        let risky_patterns = self.identify_risky_patterns(file_path)?;
        let confidence_modifiers = self.generate_confidence_scores(file_path)?;

        // Calculate overall git confidence score
        let git_confidence_score = calculate_overall_confidence(
            &related_commits,
            &vulnerability_patterns,
            &risky_patterns,
        );

        Ok(GitAnalysisResult {
            related_commits,
            vulnerability_patterns,
            risky_patterns,
            confidence_modifiers,
            git_confidence_score,
        })
    }

    /// Correlate findings with git history
    pub fn correlate_with_finding(
        &self,
        file_path: &str,
        cwe_id: Option<&str>,
    ) -> Result<GitAnalysisResult, String> {
        let mut result = self.analyze(file_path)?;

        // If looking for specific CWE, filter patterns
        if let Some(cwe) = cwe_id {
            result
                .vulnerability_patterns
                .retain(|p| p.cwe_id.as_deref() == Some(cwe));
        }

        Ok(result)
    }

    /// Update AnalysisContext with git analysis results
    pub fn update_context(&self, ctx: &mut AnalysisContext, result: &GitAnalysisResult) {
        update_context(ctx, result);
    }

    /// Get commit statistics for a file
    pub fn get_commit_stats(
        &self,
        file_path: &str,
    ) -> Result<std::collections::HashMap<String, i32>, String> {
        let commits = self.find_related_commits(file_path, None, 100)?;
        Ok(crate::git_analysis::helpers::get_commit_stats(&commits))
    }
}

/// Backward compatibility alias
pub struct GitAnalyzer {
    repo: Repository,
}

impl GitAnalyzer {
    pub fn new(repo_path: &str) -> Result<Self, git2::Error> {
        let repo = Repository::open(repo_path)?;
        Ok(Self { repo })
    }

    #[deprecated(since = "0.1.0", note = "Use GitHistoryAnalyzer instead")]
    pub fn find_related_commits(
        &self,
        file_path: &str,
        line_number: Option<u32>,
    ) -> Result<Vec<CommitReference>, String> {
        let path = self
            .repo
            .workdir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let analyzer = GitHistoryAnalyzer::new(&path).map_err(|e| e.to_string())?;
        analyzer.find_related_commits(file_path, line_number, 10)
    }
}
