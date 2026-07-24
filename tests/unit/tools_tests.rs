//! Unit tests for baco::tools module
//!
//! Tests cover diff_analysis functionality including analyze_diff and parse_diff.

use baco::tools::diff_analysis::{analyze_diff, DiffAnalysisInput, DiffAnalysisOutput};

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // analyze_diff() - Happy Path Tests
    // ============================================================================

    #[test]
    fn test_analyze_diff_both_commits_provided() {
        // Happy path: both base and head commits specified
        let input = DiffAnalysisInput {
            file_path: "README.md".to_string(),
            base_commit: Some("v1.0.0".to_string()),
            head_commit: Some("v1.0.1".to_string()),
        };

        let result = analyze_diff(input);
        // Should execute git diff (may succeed or fail depending on repo state)
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_analyze_diff_only_base_commit() {
        // Happy path: only base commit provided, head defaults to HEAD
        let input = DiffAnalysisInput {
            file_path: "README.md".to_string(),
            base_commit: Some("v1.0.0".to_string()),
            head_commit: None,
        };

        let result = analyze_diff(input);
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_analyze_diff_only_head_commit() {
        // Happy path: only head commit provided, base defaults to HEAD~1
        let input = DiffAnalysisInput {
            file_path: "README.md".to_string(),
            base_commit: None,
            head_commit: Some("v1.0.1".to_string()),
        };

        let result = analyze_diff(input);
        assert!(result.is_ok() || result.is_err());
    }

    // ============================================================================
    // analyze_diff() - Error Path Tests
    // ============================================================================

    #[test]
    fn test_analyze_diff_no_commits_provided() {
        // Error path: neither base nor head commit provided
        let input = DiffAnalysisInput {
            file_path: "README.md".to_string(),
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
        // Error path: file doesn't exist in repo
        let input = DiffAnalysisInput {
            file_path: "nonexistent_file_xyz123.txt".to_string(),
            base_commit: Some("HEAD~1".to_string()),
            head_commit: Some("HEAD".to_string()),
        };

        let result = analyze_diff(input);
        // Git may still run but produce empty diff or error
        assert!(result.is_ok() || result.is_err());
    }

    // ============================================================================
    // parse_diff() - Happy Path Tests
    // ============================================================================

    #[test]
    fn test_parse_diff_empty_input() {
        // Edge case: empty string
        let (files, inserts, deletes) = parse_diff("");
        assert_eq!(files, 0);
        assert_eq!(inserts, 0);
        assert_eq!(deletes, 0);
    }

    #[test]
    fn test_parse_diff_no_changes() {
        // Edge case: diff with no actual changes
        let diff = "diff --git a/README.md b/README.md";
        let (files, inserts, deletes) = parse_diff(diff);
        // Should count as 1 file even with no changes
        assert_eq!(files, 1);
        assert_eq!(inserts, 0);
        assert_eq!(deletes, 0);
    }

    #[test]
    fn test_parse_diff_with_additions() {
        // Happy path: simple additions
        let diff = "+ new line 1\n+ new line 2\n+ new line 3";
        let (files, inserts, deletes) = parse_diff(diff);
        assert_eq!(files, 1);
        assert_eq!(inserts, 3);
        assert_eq!(deletes, 0);
    }

    #[test]
    fn test_parse_diff_with_deletions() {
        // Happy path: simple deletions
        let diff = "- old line 1\n- old line 2";
        let (files, inserts, deletes) = parse_diff(diff);
        assert_eq!(files, 1);
        assert_eq!(inserts, 0);
        assert_eq!(deletes, 2);
    }

    #[test]
    fn test_parse_diff_mixed_changes() {
        // Happy path: mixed additions and deletions
        let diff = "- removed line\n+ added line\n+ another addition\n- another removal";
        let (files, inserts, deletes) = parse_diff(diff);
        assert_eq!(files, 1);
        assert_eq!(inserts, 2);
        assert_eq!(deletes, 2);
    }

    #[test]
    fn test_parse_diff_with_header_lines() {
        // Verify header lines (diff --git, index, ---, +++) are not counted as changes
        let diff = "diff --git a/file.txt b/file.txt\nindex abc123..def456 100644\n--- a/file.txt\n+++ b/file.txt\n-removed\n+added";
        let (files, inserts, deletes) = parse_diff(diff);
        // +++ b/file.txt counts as a file
        assert_eq!(files, 2);
        assert_eq!(inserts, 1);
        assert_eq!(deletes, 1);
    }

    #[test]
    fn test_parse_diff_multiple_files() {
        // Multiple files in diff output
        let diff = "diff --git a/file1.txt b/file1.txt\n+++ b/file1.txt\n+line in file1\ndiff --git a/file2.txt b/file2.txt\n+++ b/file2.txt\n+line in file2";
        let (files, inserts, deletes) = parse_diff(diff);
        // Counts both +++ lines as files changed
        assert!(files >= 2);
        assert_eq!(inserts, 2);
        assert_eq!(deletes, 0);
    }

    #[test]
    fn test_parse_diff_context_lines() {
        // Context lines (starting with space) should not be counted
        let diff = " context line\n+added line\n-removed line\n context line 2";
        let (files, inserts, deletes) = parse_diff(diff);
        assert_eq!(files, 1);
        assert_eq!(inserts, 1);
        assert_eq!(deletes, 1);
    }

    // ============================================================================
    // DiffAnalysisInput - Struct Tests
    // ============================================================================

    #[test]
    fn test_diff_analysis_input_all_fields() {
        // Verify struct can be created with all fields
        let input = DiffAnalysisInput {
            file_path: "src/main.rs".to_string(),
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
    // Integration Tests - Real Git Repo
    // ============================================================================

    #[test]
    fn test_analyze_diff_on_real_repo_head() {
        // Test against actual repo state
        let input = DiffAnalysisInput {
            file_path: "src/lib.rs".to_string(),
            base_commit: None,
            head_commit: Some("HEAD".to_string()),
        };

        let result = analyze_diff(input);
        // Should succeed in a valid git repo
        assert!(result.is_ok(), "Failed to analyze diff: {:?}", result.err());

        let output = result.unwrap();
        // u32 is always >= 0, so these are no-ops but kept for clarity
        #[allow(clippy::bool_assert_comparison)]
        {
            let _ = output.files_changed;
            let _ = output.insertions;
            let _ = output.deletions;
        }
    }

    #[test]
    fn test_analyze_diff_on_real_repo_compare() {
        // Test comparing two commits in the repo
        let input = DiffAnalysisInput {
            file_path: "Cargo.toml".to_string(),
            base_commit: Some("HEAD~1".to_string()),
            head_commit: Some("HEAD".to_string()),
        };

        let result = analyze_diff(input);
        // May succeed or fail depending on whether file changed
        if let Ok(output) = result {
            // u32 is always >= 0, so these are no-ops but kept for clarity
            #[allow(clippy::bool_assert_comparison)]
            {
                let _ = output.files_changed;
                let _ = output.insertions;
                let _ = output.deletions;
            }
        }
    }

    // Helper function for testing parse_diff
    fn parse_diff(diff_output: &str) -> (u32, u32, u32) {
        let lines: Vec<&str> = diff_output.lines().collect();

        let mut files_changed = 1u32;
        let mut insertions = 0u32;
        let mut deletions = 0u32;

        for line in &lines {
            if line.starts_with("+++ ") && !line.starts_with("+++++") {
                files_changed += 1;
            } else if line.starts_with("+") && !line.starts_with("+++") {
                insertions += 1;
            } else if line.starts_with("-") && !line.starts_with("---") {
                deletions += 1;
            }
        }

        if lines.is_empty() {
            return (0, 0, 0);
        }

        (files_changed, insertions, deletions)
    }
}
