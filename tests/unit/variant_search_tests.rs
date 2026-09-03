//! Unit tests for variant search module.

use baco::variant_search::*;
use std::fs;
use tempfile::TempDir;

fn create_test_files() -> TempDir {
    let temp = TempDir::new().unwrap();

    fs::write(
        temp.path().join("main.rs"),
        r#"
fn vulnerable_func() {
    let cmd = user_input();
    std::process::Command::new(cmd).spawn();
}
"#,
    )
    .unwrap();

    fs::write(
        temp.path().join("utils.rs"),
        r#"
fn safe_function() {

}
"#,
    )
    .unwrap();

    fs::write(
        temp.path().join("test.py"),
        r#"
import os
os.system(user_input)
"#,
    )
    .unwrap();

    temp
}

// ============================================================================
// Migrated inline tests from src/variant_search.rs (9 tests)
// ============================================================================

#[test]
fn test_search_finds_vulnerable_pattern_inline_migrated() {
    let temp = create_test_files();

    let searcher = VariantSearcher::new(temp.path().to_str().unwrap().to_string())
        .with_patterns(vec![SearchPattern::new(
            "command_injection",
            r"Command::new\(.*\).*spawn\(\)",
            vec!["user_input".to_string(), "process".to_string()],
        )])
        .with_threshold(0.3);

    let hits = searcher.search_variants().unwrap();

    assert!(!hits.is_empty());

    let has_command_injection = hits.iter().any(|h| h.file_path.contains("main.rs"));
    assert!(has_command_injection);

    drop(temp);
}

#[test]
fn test_binary_files_skipped_inline_migrated() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&vec![0u8; 100]).unwrap();

    let searcher = VariantSearcher::new(
        temp_file
            .path()
            .parent()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string(),
    );

    // Should not crash on binary files
    let result = searcher.search_variants();
    assert!(result.is_ok());
}

#[test]
fn test_node_modules_skipped_inline_migrated() {
    let temp = TempDir::new().unwrap();

    let node_modules = temp.path().join("node_modules");
    fs::create_dir_all(&node_modules).unwrap();
    fs::write(node_modules.join("evil.js"), "malicious code").unwrap();

    let searcher = VariantSearcher::new(temp.path().to_str().unwrap().to_string())
        .with_patterns(vec![SearchPattern::new("test", ".*", vec![])]);

    let hits = searcher.search_variants().unwrap();

    // node_modules should be skipped

    // Should not find anything in node_modules
    let from_node_modules = hits.iter().any(|h| h.file_path.contains("node_modules"));
    assert!(!from_node_modules);

    drop(temp);
}

#[test]
fn test_threshold_filters_results_inline_migrated() {
    let temp = create_test_files();

    let searcher = VariantSearcher::new(temp.path().to_str().unwrap().to_string())
        .with_patterns(vec![SearchPattern::new(
            "test",
            ".*",
            vec!["test".to_string()],
        )])
        .with_threshold(0.9);

    let hits = searcher.search_variants().unwrap();

    for hit in &hits {
        assert!(hit.similarity_score >= 0.9);
    }

    drop(temp);
}

#[test]
fn test_extract_pattern_inline_migrated() {
    let pattern = VariantSearcher::extract_pattern("user.name");
    assert!(pattern.contains("\\."));

    let pattern2 = VariantSearcher::extract_pattern("func(arg)");
    assert!(pattern2.contains("\\("));
    assert!(pattern2.contains("\\)"));
}

#[test]
fn test_match_pattern_inline_migrated() {
    assert!(VariantSearcher::match_pattern("let x = foo();", r"foo\(\)"));
    assert!(!VariantSearcher::match_pattern(
        "let x = bar();",
        r"foo\(\)"
    ));
}

#[test]
fn test_invalid_regex_handled_inline_migrated() {
    let result = VariantSearcher::match_pattern("test", "[invalid(");
    assert!(!result);
}

#[test]
fn test_snippet_extraction_inline_migrated() {
    let content = "line1\nline2\nline3\nline4\nline5";

    let snippet = VariantSearcher::extract_snippet(content, 1);
    assert!(snippet.contains("line2"));
}

#[test]
fn test_similarity_scoring_inline_migrated() {
    use tempfile::NamedTempFile;
    let temp_file = NamedTempFile::new().unwrap();

    let searcher = VariantSearcher::new(
        temp_file
            .path()
            .parent()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string(),
    );

    let pattern = SearchPattern::new(
        "command_injection",
        r"Command::new\(",
        vec!["user_input".to_string(), "spawn".to_string()],
    );

    let line1 = "let cmd = Command::new(user_input).spawn()";
    let score1 = searcher.calculate_similarity(line1, &pattern);

    let line2 = "let cmd = Command::new(\"ls\")";
    let score2 = searcher.calculate_similarity(line2, &pattern);

    assert!(score1 > score2);
}