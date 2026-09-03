//! Environment and utility functions for scanner

/// Extract owner and repository name from a Git URL
///
/// Supports both HTTPS and SSH URL formats:
/// - HTTPS: https://github.com/owner/repo-name.git
/// - SSH: git@github.com:owner/repo-name.git
///
/// Returns None if the URL format is not recognized
pub fn extract_owner_repo_from_url(url: &str) -> Option<(String, String)> {
    let url = url.trim();
    if url.starts_with("git@") {
        let without_git = url.trim_start_matches("git@");
        if let Some((_host, rest)) = without_git.split_once(':') {
            if let Some((owner, repo)) = rest.split_once('/') {
                let repo = repo.trim_end_matches(".git");
                return Some((owner.to_string(), repo.to_string()));
            }
        }
    } else if url.starts_with("https://") || url.starts_with("http://") {
        let without_scheme = url
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        if let Some((_host, rest)) = without_scheme.split_once('/') {
            let parts: Vec<&str> = rest.split('/').collect();
            if parts.len() >= 2 {
                let repo = parts[1].trim_end_matches(".git");
                return Some((parts[0].to_string(), repo.to_string()));
            }
        }
    }
    None
}

/// Get Git remote URL from a repository path
///
/// Uses the GitHistoryAnalyzer to extract the remote URL
pub fn get_git_remote_url(repo_path: &str) -> Option<String> {
    use crate::git_analysis::GitHistoryAnalyzer;
    GitHistoryAnalyzer::new(repo_path)
        .ok()
        .and_then(|a| a.get_remote_url())
}
