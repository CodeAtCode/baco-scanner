//! Shared test utilities for git_analysis module.

#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::process::Command;
#[cfg(test)]
use tempfile::TempDir;

/// Set up a test git repository with initial commit
#[cfg(test)]
#[allow(dead_code)]
pub fn setup_test_repo() -> TempDir {
    let tmp_dir = TempDir::new().expect("Failed to create temp dir");
    let repo_path = tmp_dir.path();

    // Initialize git repo
    Command::new("git")
        .arg("init")
        .current_dir(repo_path)
        .output()
        .expect("Failed to init git repo");

    // Configure git
    Command::new("git")
        .arg("config")
        .arg("user.name")
        .arg("Test User")
        .current_dir(repo_path)
        .output()
        .expect("Failed to configure git user");

    Command::new("git")
        .arg("config")
        .arg("user.email")
        .arg("test@example.com")
        .current_dir(repo_path)
        .output()
        .expect("Failed to configure git email");

    // Create a test file
    fs::write(repo_path.join("test.txt"), "Hello World").expect("Failed to write test file");

    // Add and commit
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
        .expect("Failed to commit");

    tmp_dir
}
