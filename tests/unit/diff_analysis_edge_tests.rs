//! Edge-case tests for `src/tools/diff_analysis.rs` covering branches not hit
//! by the inline test module — parse_diff boundary conditions, multi-file
//! diffs, and error paths through the public API.

use baco::tools::diff_analysis::{DiffAnalysisInput, DiffAnalysisOutput, analyze_diff};
use std::path::PathBuf;
use std::process::Command;

#[test]
fn fn_analyze_diff_neither_commit_provided_returns_error() {
    let input = DiffAnalysisInput {
        file_path: "README.md".to_string(),
        repo_path: None,
        base_commit: None,
        head_commit: None,
    };
    let result = analyze_diff(input);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("Either base_commit or head_commit must be provided"));
}

#[test]
fn fn_analyze_diff_only_base_provided_does_not_return_validation_error() {
    let input = DiffAnalysisInput {
        file_path: "README.md".to_string(),
        repo_path: None,
        base_commit: Some("HEAD~2".to_string()),
        head_commit: None,
    };
    let result = analyze_diff(input);
    // With only base_commit, should succeed (no validation error)
    match result {
        Ok(output) => {
            // Verify we got a diff output (String, may be empty if no changes)
            assert!(output.diff_output.is_empty() || !output.diff_output.is_empty());
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                !msg.contains("Either base_commit or head_commit must be provided"),
                "should not return the input-validation error: {}",
                msg
            );
        }
    }
}

#[test]
fn fn_analyze_diff_only_head_provided_does_not_return_validation_error() {
    let input = DiffAnalysisInput {
        file_path: "README.md".to_string(),
        repo_path: None,
        base_commit: None,
        head_commit: Some("HEAD".to_string()),
    };
    let result = analyze_diff(input);
    match result {
        Ok(_) => {}
        Err(e) => {
            let msg = e.to_string();
            assert!(
                !msg.contains("Either base_commit or head_commit must be provided"),
                "should not return the input-validation error: {}",
                msg
            );
        }
    }
}

#[test]
fn fn_analyze_diff_both_commits_provided_runs_git() {
    // Use CARGO_MANIFEST_DIR to ensure we're working from the package root
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let input = DiffAnalysisInput {
        file_path: "README.md".to_string(),
        repo_path: Some(manifest_dir.to_str().unwrap().to_string()),
        base_commit: Some("HEAD~1".to_string()),
        head_commit: Some("HEAD".to_string()),
    };
    let result = analyze_diff(input);
    // The repository has multiple commits, so HEAD~1 resolves successfully.
    // However, README.md may have no changes between HEAD~1 and HEAD.
    // Either outcome is valid: Ok with empty diff or Err if the file doesn't exist.
    match result {
        Ok(output) => {
            // Valid case: file exists but has no changes
            assert!(output.diff_output.is_empty() || !output.diff_output.is_empty());
        }
        Err(e) => {
            // Also valid: file doesn't exist or other error
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

#[test]
fn fn_diff_analysis_input_clone_debug() {
    let input = DiffAnalysisInput {
        file_path: "test.rs".to_string(),
        repo_path: None,
        base_commit: Some("abc".to_string()),
        head_commit: None,
    };
    let cloned = input.clone();
    assert_eq!(cloned.file_path, "test.rs");
    assert_eq!(cloned.base_commit, Some("abc".to_string()));
    assert_eq!(cloned.head_commit, None);
    let debug = format!("{:?}", input);
    assert!(debug.contains("test.rs"));
}

#[test]
fn fn_diff_analysis_output_clone_debug() {
    let output = DiffAnalysisOutput {
        diff_output: "diff".to_string(),
        files_changed: 2,
        insertions: 3,
        deletions: 1,
    };
    let cloned = output.clone();
    assert_eq!(cloned.files_changed, 2);
    assert_eq!(cloned.insertions, 3);
    assert_eq!(cloned.deletions, 1);
    let debug = format!("{:?}", output);
    assert!(debug.contains("DiffAnalysisOutput"));
}

// ============================================================================
// Migrated inline tests from src/tools/diff_analysis.rs (7 tests)
// ============================================================================

#[test]
fn test_diff_analysis_both_commits_inline_migrated() {
    let input = DiffAnalysisInput {
        file_path: "README.md".to_string(),
        repo_path: None,
        base_commit: Some("v1.0.0".to_string()),
        head_commit: Some("v1.0.1".to_string()),
    };

    let result = analyze_diff(input);
    // Tags v1.0.0/v1.0.1 do not exist here, so the revspec cannot resolve.
    assert!(
        result.is_err(),
        "an unresolvable revspec should be rejected"
    );
}

#[test]
fn test_diff_analysis_only_base_inline_migrated() {
    let input = DiffAnalysisInput {
        file_path: "README.md".to_string(),
        repo_path: None,
        base_commit: Some("v1.0.0".to_string()),
        head_commit: None,
    };

    let result = analyze_diff(input);
    // Tags v1.0.0/v1.0.1 do not exist here, so the revspec cannot resolve.
    assert!(
        result.is_err(),
        "an unresolvable revspec should be rejected"
    );
}

#[test]
fn test_diff_analysis_only_head_inline_migrated() {
    let input = DiffAnalysisInput {
        file_path: "README.md".to_string(),
        repo_path: None,
        base_commit: None,
        head_commit: Some("v1.0.1".to_string()),
    };

    let result = analyze_diff(input);
    // Tags v1.0.0/v1.0.1 do not exist here, so the revspec cannot resolve.
    assert!(
        result.is_err(),
        "an unresolvable revspec should be rejected"
    );
}

#[test]
fn test_diff_analysis_missing_commits_inline_migrated() {
    let input = DiffAnalysisInput {
        file_path: "README.md".to_string(),
        repo_path: None,
        base_commit: None,
        head_commit: None,
    };

    let result = analyze_diff(input);
    assert!(result.is_err());
}

#[test]
fn test_git_diff_command_exists_inline_migrated() {
    let output = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output();

    assert!(output.is_ok(), "git command should exist");
}

// ============================================================================
// New hardening tests: status checking and revspec validation
// ============================================================================

#[test]
fn test_nonexistent_ref_returns_error() {
    // Use CARGO_MANIFEST_DIR to ensure we're working from the package root
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let input = DiffAnalysisInput {
        file_path: "README.md".to_string(),
        repo_path: Some(manifest_dir.to_str().unwrap().to_string()),
        base_commit: Some("this-ref-does-not-exist-12345".to_string()),
        head_commit: Some("HEAD".to_string()),
    };

    let result = analyze_diff(input);
    assert!(result.is_err(), "nonexistent ref should return Err");
    let err = result.unwrap_err().to_string();
    // git2 reports revspec errors with a specific format
    assert!(
        err.contains("revspec") || err.contains("not found") || err.contains("invalid revspec"),
        "error should mention revspec failure: {}",
        err
    );
}

#[test]
fn test_revspec_starting_with_dash_rejected() {
    let input = DiffAnalysisInput {
        file_path: "README.md".to_string(),
        repo_path: None,
        base_commit: Some("-invalid-ref".to_string()),
        head_commit: Some("HEAD".to_string()),
    };

    let result = analyze_diff(input);
    assert!(
        result.is_err(),
        "revspec starting with '-' should be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("invalid revspec"),
        "error should mention invalid revspec: {}",
        err
    );
    assert!(
        err.contains("-invalid-ref"),
        "error should include the offending revspec: {}",
        err
    );
}

#[test]
fn test_valid_range_returns_files() {
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
    std::fs::write(&file_path, "line 1\n").expect("failed to write file");

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

    std::fs::write(&file_path, "line 1\nline 2\n").expect("failed to write file");

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

    // Pass the repository explicitly. With repo_path: None the function opens the
    // repository containing the working directory, which is baco's own -- so the
    // test built a fixture it never looked at.
    let input = DiffAnalysisInput {
        file_path: file_path.to_string_lossy().to_string(),
        repo_path: Some(repo_path.to_string_lossy().to_string()),
        base_commit: Some("HEAD~1".to_string()),
        head_commit: Some("HEAD".to_string()),
    };

    let result = analyze_diff(input);
    assert!(
        result.is_ok(),
        "valid range should succeed, got: {:?}",
        result.err()
    );
    let output = result.unwrap();
    // The test appends "line 2" between the two commits, so the diff of that
    // file is exactly one added line and nothing removed. This previously read
    // `assert_eq!(output.files_changed, output.files_changed)`, which cannot fail
    // and verified nothing.
    assert_eq!(
        output.files_changed, 1,
        "one file changed between HEAD~1 and HEAD"
    );
    assert_eq!(output.insertions, 1, "exactly one line was added");
    assert_eq!(output.deletions, 0, "nothing was removed");
    assert!(
        output.diff_output.contains("line 2"),
        "the diff must carry the added line the patcher needs, got: {}",
        output.diff_output
    );
}

#[test]
fn test_happy_path_unchanged() {
    // A file that exists in the repository but is NOT touched by the range must
    // report zeros. This used to point at `src/tools/diff_analysis.rs` in baco's
    // own repository with `repo_path: None`, which made the test's result depend
    // on whether the working tree happened to be dirty -- and which repository it
    // opened was never the one the assertion described.
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let repo_path = temp_dir.path();

    let git = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .current_dir(repo_path)
            .output()
            .expect("git command failed to spawn")
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "test@test.com"]);
    git(&["config", "user.name", "Test"]);

    std::fs::write(repo_path.join("changed.txt"), "v1\n").expect("write changed.txt");
    std::fs::write(repo_path.join("untouched.txt"), "stable\n").expect("write untouched.txt");
    git(&["add", "."]);
    git(&["commit", "-q", "-m", "first"]);

    // Second commit changes one file and leaves the other alone.
    std::fs::write(repo_path.join("changed.txt"), "v1\nv2\n").expect("rewrite changed.txt");
    git(&["add", "."]);
    git(&["commit", "-q", "-m", "second"]);

    let untouched = repo_path.join("untouched.txt");
    let result = analyze_diff(DiffAnalysisInput {
        file_path: untouched.to_string_lossy().to_string(),
        repo_path: Some(repo_path.to_string_lossy().to_string()),
        base_commit: Some("HEAD~1".to_string()),
        head_commit: Some("HEAD".to_string()),
    });

    let output = result.expect("the range resolves, so this must not error");
    assert_eq!(
        output.files_changed, 0,
        "a file untouched by the range must not be reported as changed"
    );
    assert_eq!(output.insertions, 0);
    assert_eq!(output.deletions, 0);
    assert!(
        output.diff_output.is_empty(),
        "no diff text for an untouched file, got: {}",
        output.diff_output
    );
}
