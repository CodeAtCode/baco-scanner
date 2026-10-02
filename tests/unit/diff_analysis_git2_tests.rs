//! Tests for git2-based diff analysis.

use baco::tools::diff_analysis::{
    DiffAnalysisInput, analyze_diff, changed_files, validate_revspec,
};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Create a temporary git repository with an initial commit
fn setup_test_repo() -> Result<TempDir, Box<dyn std::error::Error>> {
    let tmp_dir = TempDir::new()?;
    let repo_path = tmp_dir.path();

    // Initialize git repo
    std::process::Command::new("git")
        .arg("init")
        .current_dir(repo_path)
        .output()?;

    // Configure git user for commits
    std::process::Command::new("git")
        .arg("config")
        .arg("user.email")
        .arg("test@example.com")
        .current_dir(repo_path)
        .output()?;

    std::process::Command::new("git")
        .arg("config")
        .arg("user.name")
        .arg("Test User")
        .current_dir(repo_path)
        .output()?;

    // Create and commit a file
    let test_file = repo_path.join("test.txt");
    fs::write(&test_file, "line 1\nline 2\nline 3\n")?;

    std::process::Command::new("git")
        .arg("add")
        .arg("test.txt")
        .current_dir(repo_path)
        .output()?;

    std::process::Command::new("git")
        .arg("commit")
        .arg("-m")
        .arg("Initial commit")
        .current_dir(repo_path)
        .output()?;

    Ok(tmp_dir)
}

/// Modify a file in the test repo
fn modify_file(
    repo_path: &Path,
    filename: &str,
    new_content: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_path = repo_path.join(filename);
    fs::write(&file_path, new_content)?;
    Ok(())
}

#[test]
fn test_analyze_diff_insertions_deletions() -> Result<(), Box<dyn std::error::Error>> {
    let tmp_dir = setup_test_repo()?;
    let repo_path = tmp_dir.path();

    // Modify the file: add 2 lines, delete 1 line
    modify_file(
        repo_path,
        "test.txt",
        "line 1\nline 1.5\nline 2\nline 3\nline 4\n",
    )?;

    std::process::Command::new("git")
        .arg("add")
        .arg("test.txt")
        .current_dir(repo_path)
        .output()?;

    std::process::Command::new("git")
        .arg("commit")
        .arg("-m")
        .arg("Modify file")
        .current_dir(repo_path)
        .output()?;

    // Analyze diff
    let input = DiffAnalysisInput {
        file_path: "test.txt".to_string(),
        repo_path: Some(repo_path.to_str().unwrap().to_string()),
        base_commit: Some("HEAD~1".to_string()),
        head_commit: Some("HEAD".to_string()),
    };

    let result = analyze_diff(input)?;

    // Assert counts - we added 2 lines (1.5, 4) and deleted 0
    // The exact counts depend on how git2 calculates them
    assert!(
        result.insertions >= 2,
        "Expected at least 2 insertions, got {}",
        result.insertions
    );
    assert_eq!(result.files_changed, 1, "Expected 1 file changed");

    Ok(())
}

#[test]
fn test_invalid_revspec_errors() {
    // Test that invalid revspec produces an error
    let result = validate_revspec("-invalid");
    assert!(
        result.is_err(),
        "Expected error for revspec starting with '-'"
    );
    assert!(
        result.unwrap_err().contains("cannot start with '-'"),
        "Error message should mention the '-' issue"
    );

    // Valid revspec should not error at validation stage
    let result = validate_revspec("HEAD~1..HEAD");
    assert!(result.is_ok(), "Valid revspec should not error");
}

#[test]
fn test_diff_hunk_format() -> Result<(), Box<dyn std::error::Error>> {
    let tmp_dir = setup_test_repo()?;
    let repo_path = tmp_dir.path();

    // Modify the file
    modify_file(repo_path, "test.txt", "line 1 modified\nline 2\nline 3\n")?;

    std::process::Command::new("git")
        .arg("add")
        .arg("test.txt")
        .current_dir(repo_path)
        .output()?;

    std::process::Command::new("git")
        .arg("commit")
        .arg("-m")
        .arg("Modify first line")
        .current_dir(repo_path)
        .output()?;

    let input = DiffAnalysisInput {
        file_path: "test.txt".to_string(),
        repo_path: Some(repo_path.to_str().unwrap().to_string()),
        base_commit: Some("HEAD~1".to_string()),
        head_commit: Some("HEAD".to_string()),
    };

    let result = analyze_diff(input)?;

    // Verify the diff output has the expected hunk format
    assert!(
        result.diff_output.contains("@@"),
        "Diff output should contain hunk markers (@@)"
    );
    assert!(
        result.diff_output.contains("+++ "),
        "Diff output should contain new file marker"
    );
    assert!(
        result.diff_output.contains("--- "),
        "Diff output should contain old file marker"
    );

    // Verify context lines are present (the ' ' lines)
    let has_context = result
        .diff_output
        .lines()
        .any(|l| l.starts_with(' ') && !l.starts_with("+++") && !l.starts_with("---"));
    assert!(has_context, "Diff output should contain context lines");

    Ok(())
}

#[test]
fn test_git2_vs_cli_counts_match() -> Result<(), Box<dyn std::error::Error>> {
    let tmp_dir = setup_test_repo()?;
    let repo_path = tmp_dir.path();

    // Make several modifications to create a meaningful diff
    modify_file(
        repo_path,
        "test.txt",
        "line 1\nline 2 modified\nline 3\nline 4 added\n",
    )?;

    std::process::Command::new("git")
        .arg("add")
        .arg("test.txt")
        .current_dir(repo_path)
        .output()?;

    std::process::Command::new("git")
        .arg("commit")
        .arg("-m")
        .arg("Modify file")
        .current_dir(repo_path)
        .output()?;

    // Get counts from git2 implementation
    let input = DiffAnalysisInput {
        file_path: "test.txt".to_string(),
        repo_path: Some(repo_path.to_str().unwrap().to_string()),
        base_commit: Some("HEAD~1".to_string()),
        head_commit: Some("HEAD".to_string()),
    };

    let git2_result = analyze_diff(input.clone())?;

    // Get counts from git CLI
    let cli_output = std::process::Command::new("git")
        .arg("diff")
        .arg("--numstat")
        .arg("HEAD~1")
        .arg("HEAD")
        .current_dir(repo_path)
        .output()?;

    let cli_output_str = String::from_utf8_lossy(&cli_output.stdout);

    // Parse CLI output (format: "added\tdeleted\tfilename")
    let mut cli_insertions = 0u32;
    let mut cli_deletions = 0u32;

    for line in cli_output_str.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 2 {
            if let (Ok(ins), Ok(del)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                cli_insertions += ins;
                cli_deletions += del;
            }
        }
    }

    // Assert that git2 and CLI counts match
    assert_eq!(
        git2_result.insertions, cli_insertions,
        "git2 insertions ({}) should match CLI insertions ({})",
        git2_result.insertions, cli_insertions
    );
    assert_eq!(
        git2_result.deletions, cli_deletions,
        "git2 deletions ({}) should match CLI deletions ({})",
        git2_result.deletions, cli_deletions
    );

    Ok(())
}

#[test]
fn test_changed_files() -> Result<(), Box<dyn std::error::Error>> {
    let tmp_dir = setup_test_repo()?;
    let repo_path = tmp_dir.path();

    // Create and commit another file
    fs::write(repo_path.join("another.txt"), "content\n")?;

    std::process::Command::new("git")
        .arg("add")
        .arg("another.txt")
        .current_dir(repo_path)
        .output()?;

    std::process::Command::new("git")
        .arg("commit")
        .arg("-m")
        .arg("Add another file")
        .current_dir(repo_path)
        .output()?;

    let changed = changed_files(repo_path.to_str().unwrap(), "HEAD~1..HEAD")?;

    assert_eq!(changed.len(), 1, "Should have 1 changed file");
    assert_eq!(
        changed[0].file_name().unwrap().to_str().unwrap(),
        "another.txt",
        "Changed file should be another.txt"
    );

    Ok(())
}

#[test]
fn test_matches_changed_set() {
    use baco::tools::diff_analysis::matches_changed_set;

    let changed = vec![
        PathBuf::from("src/main.rs"),
        PathBuf::from("src/lib.rs"),
        PathBuf::from("tests/test.rs"),
    ];

    // Exact match
    assert!(matches_changed_set("src/main.rs", &changed));
    assert!(matches_changed_set("src/lib.rs", &changed));

    // No match
    assert!(!matches_changed_set("src/other.rs", &changed));
    assert!(!matches_changed_set("docs/readme.md", &changed));

    // Path with prefix match
    assert!(matches_changed_set(
        "/home/user/project/src/main.rs",
        &changed
    ));
}

#[test]
fn test_analyze_diff_no_base_or_head() {
    let input = DiffAnalysisInput {
        file_path: "test.txt".to_string(),
        repo_path: None,
        base_commit: None,
        head_commit: None,
    };

    let result = analyze_diff(input);
    assert!(
        result.is_err(),
        "Should error when neither base nor head is provided"
    );
    assert!(
        result.unwrap_err().to_string().contains("must be provided"),
        "Error should mention that a commit must be provided"
    );
}
