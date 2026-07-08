//! Environment and utility functions for scanner

use std::path::Path;

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

/// Compute checkpoint path from output directory
pub fn compute_checkpoint_path(output_dir: &Path) -> std::path::PathBuf {
    output_dir.join("checkpoint.json")
}

/// Compute findings JSON path from output directory
pub fn compute_findings_json_path(output_dir: &Path) -> std::path::PathBuf {
    output_dir.join("findings.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_owner_repo_from_url_https() {
        let url = "https://github.com/owner/repo-name";
        let result = extract_owner_repo_from_url(url);
        assert_eq!(result, Some(("owner".to_string(), "repo-name".to_string())));
    }

    #[test]
    fn test_extract_owner_repo_from_url_https_with_git_suffix() {
        let url = "https://github.com/owner/repo-name.git";
        let result = extract_owner_repo_from_url(url);
        assert_eq!(result, Some(("owner".to_string(), "repo-name".to_string())));
    }

    #[test]
    fn test_extract_owner_repo_from_url_ssh() {
        let url = "git@github.com:owner/repo-name";
        let result = extract_owner_repo_from_url(url);
        assert_eq!(result, Some(("owner".to_string(), "repo-name".to_string())));
    }

    #[test]
    fn test_extract_owner_repo_from_url_ssh_with_git_suffix() {
        let url = "git@github.com:owner/repo-name.git";
        let result = extract_owner_repo_from_url(url);
        assert_eq!(result, Some(("owner".to_string(), "repo-name".to_string())));
    }

    #[test]
    fn test_extract_owner_repo_from_url_invalid() {
        let url = "invalid-url";
        let result = extract_owner_repo_from_url(url);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_owner_repo_from_url_empty() {
        let url = "";
        let result = extract_owner_repo_from_url(url);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_owner_repo_from_url_with_port() {
        let url = "https://gitlab.example.com:8080/owner/repo";
        let result = extract_owner_repo_from_url(url);
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[test]
    fn test_extract_owner_repo_from_url_http() {
        let url = "http://bitbucket.org/owner/repo";
        let result = extract_owner_repo_from_url(url);
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[test]
    fn test_extract_owner_repo_from_url_trailing_whitespace() {
        let url = "  https://github.com/owner/repo  ";
        let result = extract_owner_repo_from_url(url);
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[test]
    fn test_extract_owner_repo_from_various_git_hosts() {
        // GitHub
        assert_eq!(
            extract_owner_repo_from_url("https://github.com/rust-lang/rust"),
            Some(("rust-lang".to_string(), "rust".to_string()))
        );

        // GitLab
        assert_eq!(
            extract_owner_repo_from_url("https://gitlab.com/gitlab-org/gitlab"),
            Some(("gitlab-org".to_string(), "gitlab".to_string()))
        );

        // Bitbucket SSH
        assert_eq!(
            extract_owner_repo_from_url("git@bitbucket.org:team/project.git"),
            Some(("team".to_string(), "project".to_string()))
        );
    }

    #[test]
    fn test_extract_owner_repo_from_url_with_subpath() {
        // URLs with organization subpaths
        assert_eq!(
            extract_owner_repo_from_url("https://github.com/vercel/next.js"),
            Some(("vercel".to_string(), "next.js".to_string()))
        );
    }

    #[test]
    fn test_compute_checkpoint_path() {
        let output_dir = std::path::Path::new("/tmp/output");
        let checkpoint_path = compute_checkpoint_path(output_dir);
        assert_eq!(
            checkpoint_path,
            std::path::Path::new("/tmp/output/checkpoint.json")
        );
    }

    #[test]
    fn test_compute_findings_json_path() {
        let output_dir = std::path::Path::new("/tmp/output");
        let json_path = compute_findings_json_path(output_dir);
        assert_eq!(json_path, std::path::Path::new("/tmp/output/findings.json"));
    }
}
