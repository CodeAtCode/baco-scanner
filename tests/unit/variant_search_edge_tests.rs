//! Edge-case tests for `src/variant_search.rs` covering branches not hit by
//! the inline test module — binary file skipping, snippet boundary conditions,
//! similarity scoring corners, and directory-walk error handling.

use baco::variant_search::{SearchPattern, VariantHit, VariantSearchError, VariantSearcher};
use std::fs;
use tempfile::TempDir;

#[test]
fn fn_should_skip_file_returns_true_for_binary_extensions() {
    use std::path::Path;
    for ext in &[
        "bin", "so", "dll", "dylib", "exe", "png", "jpg", "jpeg", "gif", "ico", "pdf", "zip",
        "tar", "gz", "rar", "lock", "sum", "md5", "sha",
    ] {
        let path_str = format!("file.{}", ext);
        let path = Path::new(&path_str);
        assert!(
            VariantSearcher::should_skip_file(path),
            "extension `{}` should be skipped",
            ext
        );
    }
}

#[test]
fn fn_should_skip_file_returns_false_for_source_extensions() {
    use std::path::Path;
    for ext in &["rs", "py", "js", "ts", "go", "c", "cpp", "java", "txt"] {
        let path_str = format!("file.{}", ext);
        let path = Path::new(&path_str);
        assert!(
            !VariantSearcher::should_skip_file(path),
            "extension `{}` should NOT be skipped",
            ext
        );
    }
}

#[test]
fn fn_should_skip_file_returns_false_for_no_extension() {
    use std::path::Path;
    let path = Path::new("README");
    assert!(!VariantSearcher::should_skip_file(path));
}

#[test]
fn fn_extract_snippet_at_line_zero() {
    let content = "line1\nline2\nline3";
    let snippet = VariantSearcher::extract_snippet(content, 0);
    assert!(snippet.contains("line1"));
    assert!(snippet.contains("line2"));
}

#[test]
fn fn_extract_snippet_at_last_line() {
    let content = "line1\nline2\nline3";
    let snippet = VariantSearcher::extract_snippet(content, 2);
    assert!(snippet.contains("line3"));
}

#[test]
fn fn_extract_snippet_out_of_bounds_uses_saturating_sub() {
    let content = "only";
    let snippet = VariantSearcher::extract_snippet(content, 10);
    assert_eq!(snippet, "only");
}

#[test]
fn fn_extract_snippet_empty_content() {
    let snippet = VariantSearcher::extract_snippet("", 5);
    assert_eq!(snippet, "");
}

#[test]
fn fn_calculate_similarity_empty_pattern_keywords() {
    let searcher = VariantSearcher::new("/tmp".to_string());
    let pattern = SearchPattern::new("vuln", r"pat", vec![]);
    let score = searcher.calculate_similarity("line without matches", &pattern);
    // Empty pattern string still contributes via the non-empty code_pattern branch.
    assert!((score - 0.3).abs() < f32::EPSILON, "score = {}", score);
}

#[test]
fn fn_calculate_similarity_with_vulnerability_type_match() {
    let searcher = VariantSearcher::new("/tmp".to_string());
    let pattern = SearchPattern::new("command_injection", r"pat", vec![]);
    let line = "command_injection detected here";
    let score = searcher.calculate_similarity(line, &pattern);
    assert!((score - 0.7).abs() < f32::EPSILON, "score = {}", score);
}

#[test]
fn fn_calculate_similarity_with_keyword_match_case_insensitive() {
    let searcher = VariantSearcher::new("/tmp".to_string());
    let pattern = SearchPattern::new("vuln", r"pat", vec!["INPUT".to_string()]);
    let line = "uses input from user";
    let score = searcher.calculate_similarity(line, &pattern);
    // 0.3 (code_pattern non-empty) + 0.15 (keyword match) = 0.45
    assert!((score - 0.45).abs() < f32::EPSILON, "score = {}", score);
}

#[test]
fn fn_calculate_similarity_capped_at_one() {
    let searcher = VariantSearcher::new("/tmp".to_string());
    let pattern = SearchPattern::new(
        "vuln",
        r"pat",
        vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ],
    );
    let line = "vuln a b c d";
    let score = searcher.calculate_similarity(line, &pattern);
    assert!((score - 1.0).abs() < f32::EPSILON, "score = {}", score);
}

#[test]
fn fn_calculate_similarity_empty_code_pattern_does_not_add_score() {
    let searcher = VariantSearcher::new("/tmp".to_string());
    let pattern = SearchPattern::new("vuln", "", vec![]);
    let line = "vuln";
    let score = searcher.calculate_similarity(line, &pattern);
    // Only vulnerability_type match (0.4); empty code_pattern adds nothing.
    assert!((score - 0.4).abs() < f32::EPSILON, "score = {}", score);
}

#[test]
fn fn_search_variants_returns_empty_for_nonexistent_root() {
    let searcher = VariantSearcher::new("/nonexistent/path/that/does/not/exist".to_string())
        .with_patterns(vec![SearchPattern::new("vuln", r"pat", vec![])]);
    let result = searcher.search_variants();
    assert!(matches!(result, Err(VariantSearchError::IoError(_))));
}

#[test]
fn fn_search_variants_empty_patterns_returns_empty_vec() {
    let temp = TempDir::new().unwrap();
    let searcher = VariantSearcher::new(temp.path().to_str().unwrap().to_string());
    let hits = searcher.search_variants().unwrap();
    assert!(hits.is_empty());
}

#[test]
fn fn_search_variants_invalid_regex_returns_pattern_error() {
    let temp = TempDir::new().unwrap();
    let searcher = VariantSearcher::new(temp.path().to_str().unwrap().to_string())
        .with_patterns(vec![SearchPattern::new("vuln", "[invalid(", vec![])]);
    let result = searcher.search_variants();
    assert!(matches!(result, Err(VariantSearchError::PatternError(_))));
}

#[test]
fn fn_search_variants_skips_target_directory() {
    let temp = TempDir::new().unwrap();
    let target_dir = temp.path().join("target");
    fs::create_dir_all(&target_dir).unwrap();
    fs::write(target_dir.join("evil.rs"), "vuln match here").unwrap();

    let searcher = VariantSearcher::new(temp.path().to_str().unwrap().to_string())
        .with_patterns(vec![SearchPattern::new("vuln", r"vuln", vec![])])
        .with_threshold(0.0);

    let hits = searcher.search_variants().unwrap();
    assert!(
        !hits.iter().any(|h| h.file_path.contains("target")),
        "target dir must be skipped"
    );
}

#[test]
fn fn_search_variants_skips_git_directory() {
    let temp = TempDir::new().unwrap();
    let git_dir = temp.path().join(".git");
    fs::create_dir_all(&git_dir).unwrap();
    fs::write(git_dir.join("config"), "vuln").unwrap();

    let searcher = VariantSearcher::new(temp.path().to_str().unwrap().to_string())
        .with_patterns(vec![SearchPattern::new("vuln", r"vuln", vec![])])
        .with_threshold(0.0);

    let hits = searcher.search_variants().unwrap();
    assert!(!hits.iter().any(|h| h.file_path.contains(".git")));
}

#[test]
fn fn_search_variants_skips_build_and_dist_directories() {
    let temp = TempDir::new().unwrap();
    for dir_name in &["build", "dist", "node_modules"] {
        let dir = temp.path().join(dir_name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("evil.rs"), "vuln").unwrap();
    }

    let searcher = VariantSearcher::new(temp.path().to_str().unwrap().to_string())
        .with_patterns(vec![SearchPattern::new("vuln", r"vuln", vec![])])
        .with_threshold(0.0);

    let hits = searcher.search_variants().unwrap();
    for dir_name in &["build", "dist", "node_modules"] {
        assert!(
            !hits.iter().any(|h| h.file_path.contains(dir_name)),
            "{} should be skipped",
            dir_name
        );
    }
}

#[test]
fn fn_variant_hit_new_populates_fields() {
    let hit = VariantHit::new("/path/file.rs", 42, 0.75, "snippet");
    assert_eq!(hit.file_path, "/path/file.rs");
    assert_eq!(hit.line_number, 42);
    assert!((hit.similarity_score - 0.75).abs() < f32::EPSILON);
    assert_eq!(hit.snippet, "snippet");
}

#[test]
fn fn_search_pattern_new_populates_fields() {
    let pattern = SearchPattern::new(
        "sqli",
        r"union\s+select",
        vec!["db".to_string(), "query".to_string()],
    );
    assert_eq!(pattern.vulnerability_type, "sqli");
    assert_eq!(pattern.code_pattern, r"union\s+select");
    assert_eq!(pattern.context_keywords, vec!["db", "query"]);
}

#[test]
fn fn_with_threshold_builder_sets_threshold() {
    // Cannot inspect private field `threshold`; verify behavior by confirming
    // that a high threshold filters out low-similarity hits.
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("a.rs"), "vuln").unwrap();

    let low = VariantSearcher::new(temp.path().to_str().unwrap().to_string())
        .with_patterns(vec![SearchPattern::new("vuln", r"vuln", vec![])])
        .with_threshold(0.99);
    assert!(low.search_variants().unwrap().is_empty());

    let high = VariantSearcher::new(temp.path().to_str().unwrap().to_string())
        .with_patterns(vec![SearchPattern::new("vuln", r"vuln", vec![])])
        .with_threshold(0.0);
    assert!(!high.search_variants().unwrap().is_empty());
}

#[test]
fn fn_with_patterns_builder_replaces_patterns() {
    // Cannot inspect private field `patterns` directly; verify behavior by
    // confirming that only the last set of patterns is used.
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("a.rs"), "vulna").unwrap();
    fs::write(temp.path().join("b.rs"), "vulnb").unwrap();

    let searcher = VariantSearcher::new(temp.path().to_str().unwrap().to_string())
        .with_patterns(vec![SearchPattern::new("vulna", r"vulna", vec![])])
        .with_patterns(vec![SearchPattern::new("vulnb", r"vulnb", vec![])])
        .with_threshold(0.0);

    let hits = searcher.search_variants().unwrap();
    // Only vulnb should match (last with_patterns call wins).
    assert!(hits.iter().any(|h| h.file_path.contains("b.rs")));
    assert!(!hits.iter().any(|h| h.file_path.contains("a.rs")));
}

#[test]
fn fn_match_pattern_invalid_regex_returns_false() {
    assert!(!VariantSearcher::match_pattern("anything", "[unclosed"));
}

#[test]
fn fn_match_pattern_valid_regex_no_match_returns_false() {
    assert!(!VariantSearcher::match_pattern("hello world", r"xyz\d+"));
}

#[test]
fn fn_extract_pattern_escapes_all_special_chars() {
    let escaped = VariantSearcher::extract_pattern("a.b*c+d?e(f)g[h]i");
    assert!(escaped.contains("\\."));
    assert!(escaped.contains(".*"));
    assert!(escaped.contains("\\+"));
    assert!(escaped.contains("\\?"));
    assert!(escaped.contains("\\("));
    assert!(escaped.contains("\\)"));
    assert!(escaped.contains("\\["));
    assert!(escaped.contains("\\]"));
}

#[test]
fn fn_search_variants_recurses_into_subdirectories() {
    let temp = TempDir::new().unwrap();
    let sub = temp.path().join("src").join("nested");
    fs::create_dir_all(&sub).unwrap();
    fs::write(sub.join("vuln.rs"), "vuln pattern here").unwrap();

    let searcher = VariantSearcher::new(temp.path().to_str().unwrap().to_string())
        .with_patterns(vec![SearchPattern::new("vuln", r"vuln", vec![])])
        .with_threshold(0.0);

    let hits = searcher.search_variants().unwrap();
    assert!(hits.iter().any(|h| h.file_path.contains("nested")));
}
