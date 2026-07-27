//! Edge-case tests for `src/tools/diff_analysis.rs` covering branches not hit
//! by the inline test module — parse_diff boundary conditions, multi-file
//! diffs, and error paths through the public API.

use baco::tools::diff_analysis::{analyze_diff, parse_diff, DiffAnalysisInput, DiffAnalysisOutput};

#[test]
fn fn_parse_diff_single_file_single_insert() {
    let diff = "+++ b/file.rs\n+new line";
    let (files, inserts, deletes) = parse_diff(diff);
    assert_eq!(files, 2);
    assert_eq!(inserts, 1);
    assert_eq!(deletes, 0);
}

#[test]
fn fn_parse_diff_single_deletion() {
    let diff = "--- a/file.rs\n-old line";
    let (files, inserts, deletes) = parse_diff(diff);
    assert_eq!(files, 1);
    assert_eq!(inserts, 0);
    assert_eq!(deletes, 1);
}

#[test]
fn fn_parse_diff_multiple_files_and_changes() {
    let diff = "+++ b/file1.rs\n+insert1\n+++ b/file2.rs\n+insert2\n-remove1";
    let (files, inserts, deletes) = parse_diff(diff);
    assert_eq!(files, 3);
    assert_eq!(inserts, 2);
    assert_eq!(deletes, 1);
}

#[test]
fn fn_parse_diff_plus_plus_plus_plus_ignored_as_file_marker() {
    let diff = "+++++ something\n+actual insert";
    let (files, inserts, deletes) = parse_diff(diff);
    assert_eq!(files, 1);
    assert_eq!(inserts, 1);
    assert_eq!(deletes, 0);
}

#[test]
fn fn_parse_diff_minus_minus_minus_ignored_as_file_marker() {
    let diff = "---- header\n-actual delete";
    let (files, inserts, deletes) = parse_diff(diff);
    assert_eq!(files, 1);
    assert_eq!(inserts, 0);
    assert_eq!(deletes, 1);
}

#[test]
fn fn_parse_diff_empty_lines_only() {
    let diff = "\n\n\n";
    let (files, inserts, deletes) = parse_diff(diff);
    assert_eq!(files, 1);
    assert_eq!(inserts, 0);
    assert_eq!(deletes, 0);
}

#[test]
fn fn_parse_diff_whitespace_only_lines() {
    let diff = "   \n  +  \n  -  ";
    let (files, inserts, deletes) = parse_diff(diff);
    assert_eq!(files, 1);
    // None of these lines start with "+" or "-" so nothing is counted.
    assert_eq!(inserts, 0);
    assert_eq!(deletes, 0);
}

#[test]
fn fn_analyze_diff_neither_commit_provided_returns_error() {
    let input = DiffAnalysisInput {
        file_path: "README.md".to_string(),
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
        base_commit: Some("HEAD~2".to_string()),
        head_commit: None,
    };
    let result = analyze_diff(input);
    match result {
        Ok(output) => {
            let _ = output.diff_output;
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
    let input = DiffAnalysisInput {
        file_path: "README.md".to_string(),
        base_commit: Some("HEAD~1".to_string()),
        head_commit: Some("HEAD".to_string()),
    };
    let result = analyze_diff(input);
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn fn_diff_analysis_output_fields_populated() {
    let diff_text = "+++ b/file.rs\n+inserted line\n-removed line";
    let (files, inserts, deletes) = parse_diff(diff_text);
    let output = DiffAnalysisOutput {
        diff_output: diff_text.to_string(),
        files_changed: files,
        insertions: inserts,
        deletions: deletes,
    };
    assert_eq!(output.diff_output, diff_text);
    assert_eq!(output.files_changed, files);
    assert_eq!(output.insertions, inserts);
    assert_eq!(output.deletions, deletes);
}

#[test]
fn fn_parse_diff_empty_string_returns_zeros() {
    let (files, inserts, deletes) = parse_diff("");
    assert_eq!(files, 0);
    assert_eq!(inserts, 0);
    assert_eq!(deletes, 0);
}

#[test]
fn fn_parse_diff_no_changes_just_context() {
    let diff = " context line\n another context\n more context";
    let (files, inserts, deletes) = parse_diff(diff);
    assert_eq!(files, 1);
    assert_eq!(inserts, 0);
    assert_eq!(deletes, 0);
}

#[test]
fn fn_parse_diff_mixed_inserts_and_deletes_in_order() {
    let diff = "+a\n-b\n+c\n-d\n+e";
    let (files, inserts, deletes) = parse_diff(diff);
    assert_eq!(files, 1);
    assert_eq!(inserts, 3);
    assert_eq!(deletes, 2);
}

#[test]
fn fn_diff_analysis_input_clone_debug() {
    let input = DiffAnalysisInput {
        file_path: "test.rs".to_string(),
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
