//! Unit tests for baco::tools module
//!
//! Tests cover diff_analysis functionality including analyze_diff and parse_diff.

use baco::tools::diff_analysis::{
    DiffAnalysisInput, DiffAnalysisOutput, analyze_diff, changed_files, matches_changed_set,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    // ============================================================================
    // analyze_diff() - Happy Path Tests
    // ============================================================================

    #[test]
    fn test_analyze_diff_both_commits_provided() {
        // Happy path: both base and head commits specified
        let input = DiffAnalysisInput {
            file_path: "README.md".to_string(),
            repo_path: None,
            base_commit: Some("v1.0.0".to_string()),
            head_commit: Some("v1.0.1".to_string()),
        };

        let result = analyze_diff(input);
        // These revspecs do not resolve in this repository (no tags, single commit), so
        // analyze_diff must reject them rather than report an empty diff as success.
        assert!(result.is_err(), "unresolvable revspec should be rejected");
    }

    #[test]
    fn test_analyze_diff_only_base_commit() {
        // Happy path: only base commit provided, head defaults to HEAD
        let input = DiffAnalysisInput {
            file_path: "README.md".to_string(),
            repo_path: None,
            base_commit: Some("v1.0.0".to_string()),
            head_commit: None,
        };

        let result = analyze_diff(input);
        // These revspecs do not resolve in this repository (no tags, single commit), so
        // analyze_diff must reject them rather than report an empty diff as success.
        assert!(result.is_err(), "unresolvable revspec should be rejected");
    }

    #[test]
    fn test_analyze_diff_only_head_commit() {
        // Happy path: only head commit provided, base defaults to HEAD~1
        let input = DiffAnalysisInput {
            file_path: "README.md".to_string(),
            repo_path: None,
            base_commit: None,
            head_commit: Some("v1.0.1".to_string()),
        };

        let result = analyze_diff(input);
        // These revspecs do not resolve in this repository (no tags, single commit), so
        // analyze_diff must reject them rather than report an empty diff as success.
        assert!(result.is_err(), "unresolvable revspec should be rejected");
    }

    // ============================================================================
    // analyze_diff() - Error Path Tests
    // ============================================================================

    #[test]
    fn test_analyze_diff_no_commits_provided() {
        // Error path: neither base nor head commit provided
        let input = DiffAnalysisInput {
            file_path: "README.md".to_string(),
            repo_path: None,
            base_commit: None,
            head_commit: None,
        };

        let result = analyze_diff(input);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("base_commit") || err_msg.contains("head_commit"));
    }

    #[test]
    fn test_analyze_diff_nonexistent_file() {
        // A file that doesn't exist in the repo or has no changes
        let input = DiffAnalysisInput {
            file_path: "nonexistent_file_xyz123.txt".to_string(),
            repo_path: None,
            base_commit: Some("HEAD~1".to_string()),
            head_commit: Some("HEAD".to_string()),
        };

        let result = analyze_diff(input);
        // The file doesn't exist, so we get an empty diff (Ok with zero stats)
        // This is valid behavior - no error for a file with no changes
        match result {
            Ok(output) => {
                // Valid case: file has no changes (or doesn't exist)
                assert_eq!(output.files_changed, 0);
                assert_eq!(output.insertions, 0);
                assert_eq!(output.deletions, 0);
            }
            Err(e) => {
                // Also acceptable: error if file truly doesn't exist
                let err = e.to_string();
                assert!(
                    err.contains("revspec")
                        || err.contains("not found")
                        || err.contains("Failed to open"),
                    "error should be meaningful: {}",
                    err
                );
            }
        }
    }

    // ============================================================================
    // parse_diff() - Happy Path Tests
    // ============================================================================

    // ============================================================================
    // DiffAnalysisInput - Struct Tests
    // ============================================================================

    #[test]
    fn test_diff_analysis_input_all_fields() {
        // Verify struct can be created with all fields
        let input = DiffAnalysisInput {
            file_path: "src/main.rs".to_string(),
            repo_path: None,
            base_commit: Some("abc123".to_string()),
            head_commit: Some("def456".to_string()),
        };

        assert_eq!(input.file_path, "src/main.rs");
        assert_eq!(input.base_commit, Some("abc123".to_string()));
        assert_eq!(input.head_commit, Some("def456".to_string()));
    }

    #[test]
    fn test_diff_analysis_input_minimal() {
        // Verify struct works with only head_commit
        let input = DiffAnalysisInput {
            file_path: "test.txt".to_string(),
            repo_path: None,
            base_commit: None,
            head_commit: Some("HEAD".to_string()),
        };

        assert!(input.base_commit.is_none());
        assert!(input.head_commit.is_some());
    }

    // ============================================================================
    // DiffAnalysisOutput - Struct Tests
    // ============================================================================

    #[test]
    fn test_diff_analysis_output_zero_stats() {
        // Verify struct with zero stats
        let output = DiffAnalysisOutput {
            diff_output: "".to_string(),
            files_changed: 0,
            insertions: 0,
            deletions: 0,
        };

        assert_eq!(output.files_changed, 0);
        assert_eq!(output.insertions, 0);
        assert_eq!(output.deletions, 0);
        assert!(output.diff_output.is_empty());
    }

    #[test]
    fn test_diff_analysis_output_with_stats() {
        // Verify struct with non-zero stats
        let output = DiffAnalysisOutput {
            diff_output: "+added\n-removed".to_string(),
            files_changed: 3,
            insertions: 10,
            deletions: 5,
        };

        assert_eq!(output.files_changed, 3);
        assert_eq!(output.insertions, 10);
        assert_eq!(output.deletions, 5);
        assert!(!output.diff_output.is_empty());
    }

    // ============================================================================
    // Integration Tests - Hermetic Temp Git Repos
    // ============================================================================

    #[test]
    fn test_analyze_diff_on_real_repo_head() {
        // Create a temporary git repo with deterministic two-commit history
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let repo_path = temp_dir.path();

        Command::new("git")
            .args(["init", "-q"])
            .current_dir(repo_path)
            .output()
            .expect("failed to init git repo");

        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(repo_path)
            .output()
            .expect("failed to set email");
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(repo_path)
            .output()
            .expect("failed to set name");

        let file_path = repo_path.join("lib.rs");
        std::fs::write(&file_path, "fn initial() {}\n").expect("failed to write file");

        Command::new("git")
            .args(["add", "."])
            .current_dir(repo_path)
            .output()
            .expect("failed to add");
        Command::new("git")
            .args(["commit", "-q", "-m", "first"])
            .current_dir(repo_path)
            .output()
            .expect("failed to commit");

        std::fs::write(&file_path, "fn initial() {}\nfn added() {}\n")
            .expect("failed to write file");

        Command::new("git")
            .args(["add", "."])
            .current_dir(repo_path)
            .output()
            .expect("failed to add");
        Command::new("git")
            .args(["commit", "-q", "-m", "second"])
            .current_dir(repo_path)
            .output()
            .expect("failed to commit");

        // Test with base_commit None and head_commit Some("HEAD")
        let input = DiffAnalysisInput {
            file_path: file_path.to_string_lossy().to_string(),
            repo_path: Some(repo_path.to_str().unwrap().to_string()),
            base_commit: None,
            head_commit: Some("HEAD".to_string()),
        };

        let result = analyze_diff(input);
        assert!(
            result.is_ok(),
            "analyze_diff should succeed: {:?}",
            result.err()
        );

        let output = result.unwrap();
        // New git2 implementation correctly counts actual files changed
        assert_eq!(output.files_changed, 1, "expected files_changed to be 1");
        assert_eq!(output.insertions, 1, "expected exactly one insertion");
        assert_eq!(output.deletions, 0, "expected no deletions");
    }

    #[test]
    fn test_analyze_diff_on_real_repo_compare() {
        // Create a temporary git repo with deterministic two-commit history
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let repo_path = temp_dir.path();

        Command::new("git")
            .args(["init", "-q"])
            .current_dir(repo_path)
            .output()
            .expect("failed to init git repo");

        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(repo_path)
            .output()
            .expect("failed to set email");
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(repo_path)
            .output()
            .expect("failed to set name");

        let file_path = repo_path.join("config.toml");
        std::fs::write(&file_path, "version = \"1.0\"\n").expect("failed to write file");

        Command::new("git")
            .args(["add", "."])
            .current_dir(repo_path)
            .output()
            .expect("failed to add");
        Command::new("git")
            .args(["commit", "-q", "-m", "first"])
            .current_dir(repo_path)
            .output()
            .expect("failed to commit");

        std::fs::write(&file_path, "version = \"1.1\"\nfeature = true\n")
            .expect("failed to write file");

        Command::new("git")
            .args(["add", "."])
            .current_dir(repo_path)
            .output()
            .expect("failed to add");
        Command::new("git")
            .args(["commit", "-q", "-m", "second"])
            .current_dir(repo_path)
            .output()
            .expect("failed to commit");

        // Test comparing HEAD~1 to HEAD
        let input = DiffAnalysisInput {
            file_path: file_path.to_string_lossy().to_string(),
            repo_path: Some(repo_path.to_str().unwrap().to_string()),
            base_commit: Some("HEAD~1".to_string()),
            head_commit: Some("HEAD".to_string()),
        };

        let result = analyze_diff(input);
        assert!(
            result.is_ok(),
            "analyze_diff should succeed: {:?}",
            result.err()
        );

        let output = result.unwrap();
        // New git2 implementation correctly counts actual files changed
        assert_eq!(output.files_changed, 1, "expected files_changed to be 1");
        assert_eq!(output.insertions, 2, "expected exactly two insertions");
        assert_eq!(output.deletions, 1, "expected exactly one deletion");
    }

    #[test]
    fn test_analyze_diff_nonexistent_revspec_returns_error() {
        // Create a temporary git repo
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let repo_path = temp_dir.path();

        Command::new("git")
            .args(["init", "-q"])
            .current_dir(repo_path)
            .output()
            .expect("failed to init git repo");

        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(repo_path)
            .output()
            .expect("failed to set email");
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(repo_path)
            .output()
            .expect("failed to set name");

        let file_path = repo_path.join("test.txt");
        std::fs::write(&file_path, "content\n").expect("failed to write file");

        Command::new("git")
            .args(["add", "."])
            .current_dir(repo_path)
            .output()
            .expect("failed to add");
        Command::new("git")
            .args(["commit", "-q", "-m", "first"])
            .current_dir(repo_path)
            .output()
            .expect("failed to commit");

        // Test with a nonexistent revspec - should return Err
        let input = DiffAnalysisInput {
            file_path: file_path.to_string_lossy().to_string(),
            repo_path: Some(repo_path.to_str().unwrap().to_string()),
            base_commit: Some("nonexistent-ref-xyz123".to_string()),
            head_commit: Some("HEAD".to_string()),
        };

        let result = analyze_diff(input);
        assert!(
            result.is_err(),
            "analyze_diff should return Err for nonexistent revspec, got: {:?}",
            result
        );
        let err = result.unwrap_err().to_string();
        // git2 reports revspec errors with a specific format
        assert!(
            err.contains("revspec")
                || err.contains("not found")
                || err.contains("Failed to execute"),
            "error should mention revspec failure: {}",
            err
        );
    }
}
#[test]
fn matches_changed_set_exact_suffix_and_miss() {
    use std::path::PathBuf;
    let changed = vec![PathBuf::from("src/vuln.rs"), PathBuf::from("web/app.js")];
    assert!(matches_changed_set("src/vuln.rs", &changed));
    assert!(matches_changed_set("/repo/src/vuln.rs", &changed));
    assert!(matches_changed_set("src\\vuln.rs", &changed));
    assert!(!matches_changed_set("src/clean.rs", &changed));
    assert!(!matches_changed_set("other/vuln.rs.bak", &changed));
}

#[test]
fn changed_files_missing_repo_errors() {
    let result = changed_files("/nonexistent-dir-baco-probe-xyz", "HEAD");
    assert!(result.is_err());
}

#[test]
fn changed_files_lists_modified_file() {
    if std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }
    let dir = std::env::temp_dir().join(format!("baco-diff-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let run = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .current_dir(&dir)
            .output()
            .unwrap()
    };
    run(&["init"]);
    run(&["config", "user.email", "t@t"]);
    run(&["config", "user.name", "t"]);
    std::fs::write(dir.join("a.rs"), "fn a() {}\n").unwrap();
    run(&["add", "."]);
    run(&["commit", "-m", "base"]);
    std::fs::write(dir.join("a.rs"), "fn a() {}\nfn b() {}\n").unwrap();
    let files = changed_files(dir.to_str().unwrap(), "HEAD").unwrap();
    assert_eq!(files, vec![std::path::PathBuf::from("a.rs")]);
    let _ = std::fs::remove_dir_all(&dir);
}
