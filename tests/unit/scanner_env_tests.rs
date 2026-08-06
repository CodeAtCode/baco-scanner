//! Unit tests for scanner/env.rs standalone functions
//!
//! Covers:
//! - get_git_remote_url happy path
//! - get_git_remote_url with no remote configured
//! - get_git_remote_url with nonexistent path

use baco::scanner::get_git_remote_url;
use std::process::Command;
use tempfile::tempdir;

// ============================================================================
// TEST FIXTURES
// ============================================================================

/// Create a minimal git repository with optional remote
fn create_git_repo_with_remote(remote_url: Option<&str>) -> tempfile::TempDir {
    let tmp_dir = tempdir().expect("Failed to create temp dir");
    let repo_path = tmp_dir.path();

    // Initialize git repo
    Command::new("git")
        .arg("init")
        .current_dir(repo_path)
        .output()
        .expect("Failed to init git repo");

    // Configure git user (required for commits)
    Command::new("git")
        .arg("config")
        .arg("user.name")
        .arg("Test User")
        .current_dir(repo_path)
        .output()
        .expect("Failed to config git user name");

    Command::new("git")
        .arg("config")
        .arg("user.email")
        .arg("test@example.com")
        .current_dir(repo_path)
        .output()
        .expect("Failed to config git user email");

    // Create an initial commit (required for a valid repo)
    let test_file = repo_path.join("README.md");
    std::fs::write(&test_file, "# Test Repo").expect("Failed to write test file");

    Command::new("git")
        .arg("add")
        .arg(".")
        .current_dir(repo_path)
        .output()
        .expect("Failed to add file");

    Command::new("git")
        .arg("commit")
        .arg("-m")
        .arg("Initial commit")
        .current_dir(repo_path)
        .output()
        .expect("Failed to create initial commit");

    // Add remote if specified
    if let Some(url) = remote_url {
        Command::new("git")
            .arg("remote")
            .arg("add")
            .arg("origin")
            .arg(url)
            .current_dir(repo_path)
            .output()
            .expect("Failed to add remote");
    }

    tmp_dir
}

// ============================================================================
// HAPPY PATH TESTS
// ============================================================================

#[test]
fn test_get_git_remote_url_https() {
    let tmp_dir = create_git_repo_with_remote(Some("https://github.com/owner/repo.git"));
    let repo_path = tmp_dir.path().to_string_lossy().to_string();

    let result = get_git_remote_url(&repo_path);

    assert!(result.is_some());
    assert_eq!(result.unwrap(), "https://github.com/owner/repo.git");
}

#[test]
fn test_get_git_remote_url_ssh() {
    let tmp_dir = create_git_repo_with_remote(Some("git@github.com:owner/repo.git"));
    let repo_path = tmp_dir.path().to_string_lossy().to_string();

    let result = get_git_remote_url(&repo_path);

    assert!(result.is_some());
    assert_eq!(result.unwrap(), "git@github.com:owner/repo.git");
}

#[test]
fn test_get_git_remote_url_gitlab_https() {
    let tmp_dir =
        create_git_repo_with_remote(Some("https://gitlab.com/group/subgroup/project.git"));
    let repo_path = tmp_dir.path().to_string_lossy().to_string();

    let result = get_git_remote_url(&repo_path);

    assert!(result.is_some());
    assert_eq!(
        result.unwrap(),
        "https://gitlab.com/group/subgroup/project.git"
    );
}

#[test]
fn test_get_git_remote_url_bitbucket_ssh() {
    let tmp_dir = create_git_repo_with_remote(Some("git@bitbucket.org:team/project.git"));
    let repo_path = tmp_dir.path().to_string_lossy().to_string();

    let result = get_git_remote_url(&repo_path);

    assert!(result.is_some());
    assert_eq!(result.unwrap(), "git@bitbucket.org:team/project.git");
}

// ============================================================================
// NO REMOTE CONFIGURED TESTS
// ============================================================================

#[test]
fn test_get_git_remote_url_no_remote() {
    let tmp_dir = create_git_repo_with_remote(None);
    let repo_path = tmp_dir.path().to_string_lossy().to_string();

    let result = get_git_remote_url(&repo_path);

    assert!(result.is_none());
}

#[test]
fn test_get_git_remote_url_remote_removed() {
    let tmp_dir = create_git_repo_with_remote(Some("https://github.com/owner/repo.git"));
    let repo_path = tmp_dir.path();

    // Remove the remote
    Command::new("git")
        .arg("remote")
        .arg("remove")
        .arg("origin")
        .current_dir(repo_path)
        .output()
        .expect("Failed to remove remote");

    let result = get_git_remote_url(repo_path.to_string_lossy().as_ref());

    assert!(result.is_none());
}

// ============================================================================
// ERROR HANDLING TESTS
// ============================================================================

#[test]
fn test_get_git_remote_url_nonexistent_path() {
    let result = get_git_remote_url("/nonexistent/path/12345");

    assert!(result.is_none());
}

#[test]
fn test_get_git_remote_url_empty_path() {
    let result = get_git_remote_url("");

    assert!(result.is_none());
}

#[test]
fn test_get_git_remote_url_not_a_git_repo() {
    let tmp_dir = tempdir().expect("Failed to create temp dir");
    let repo_path = tmp_dir.path().to_string_lossy().to_string();

    // Don't initialize git repo - just a plain directory

    let result = get_git_remote_url(&repo_path);

    assert!(result.is_none());
}

#[test]
fn test_get_git_remote_url_bare_repo() {
    let tmp_dir = tempdir().expect("Failed to create temp dir");
    let repo_path = tmp_dir.path();

    // Create a bare git repo
    Command::new("git")
        .arg("init")
        .arg("--bare")
        .current_dir(repo_path)
        .output()
        .expect("Failed to init bare git repo");

    let result = get_git_remote_url(repo_path.to_string_lossy().as_ref());

    // Bare repos typically don't have worktrees, so this should return None
    assert!(result.is_none());
}

// ============================================================================
// EDGE CASES
// ============================================================================

#[test]
fn test_get_git_remote_url_multiple_remotes_returns_first() {
    let tmp_dir = create_git_repo_with_remote(Some("https://github.com/owner/repo.git"));
    let repo_path = tmp_dir.path();

    // Add another remote
    Command::new("git")
        .arg("remote")
        .arg("add")
        .arg("upstream")
        .arg("https://github.com/upstream/repo.git")
        .current_dir(repo_path)
        .output()
        .expect("Failed to add upstream remote");

    let result = get_git_remote_url(repo_path.to_string_lossy().as_ref());

    // Should return one of the remotes (implementation-dependent which one)
    assert!(result.is_some());
    let url = result.unwrap();
    assert!(
        url == "https://github.com/owner/repo.git" || url == "https://github.com/upstream/repo.git"
    );
}

#[test]
fn test_get_git_remote_url_remote_without_git_suffix() {
    let tmp_dir = create_git_repo_with_remote(Some("https://github.com/owner/repo"));
    let repo_path = tmp_dir.path().to_string_lossy().to_string();

    let result = get_git_remote_url(&repo_path);

    assert!(result.is_some());
    assert_eq!(result.unwrap(), "https://github.com/owner/repo");
}
