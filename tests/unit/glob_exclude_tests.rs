//! Unit tests for glob-based path exclusion (ExcludeMatcher)
//!
//! These tests verify the correct behavior of glob pattern matching for excludes.

use baco::indexer::ExcludeMatcher;
use std::fs;
use tempfile::TempDir;

/// Helper to create a temp directory with a test file tree
fn create_test_tree() -> TempDir {
    let tmp = TempDir::new().expect("Failed to create temp dir");

    // Create src/foo.rs
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    fs::write(tmp.path().join("src/foo.rs"), "fn main() {}").unwrap();

    // Create src/nested/x.rs
    fs::create_dir_all(tmp.path().join("src/nested")).unwrap();
    fs::write(tmp.path().join("src/nested/x.rs"), "fn x() {}").unwrap();

    // Create assets/src/x.rs (should NOT be excluded by "src" pattern)
    fs::create_dir_all(tmp.path().join("assets/src")).unwrap();
    fs::write(tmp.path().join("assets/src/x.rs"), "fn y() {}").unwrap();

    // Create docs/readme.md
    fs::create_dir_all(tmp.path().join("docs")).unwrap();
    fs::write(tmp.path().join("docs/readme.md"), "# Docs").unwrap();

    // Create docs/sub/file.md (should NOT be excluded by "docs/*" pattern)
    fs::create_dir_all(tmp.path().join("docs/sub")).unwrap();
    fs::write(tmp.path().join("docs/sub/file.md"), "content").unwrap();

    // Create assets/app.min.js
    fs::create_dir_all(tmp.path().join("assets")).unwrap();
    fs::write(tmp.path().join("assets/app.min.js"), "minified").unwrap();

    // Create nested/path/to/lib.min.js
    fs::create_dir_all(tmp.path().join("nested/path/to")).unwrap();
    fs::write(tmp.path().join("nested/path/to/lib.min.js"), "minified").unwrap();

    tmp
}

#[test]
fn test_bare_pattern_excludes_directory_and_children() {
    // Pattern "src" should match src/ and everything under it
    // but NOT assets/src/ (different directory)
    let matcher = ExcludeMatcher::new(&["src".to_string()]).expect("Valid pattern");

    let tmp = create_test_tree();
    let root = tmp.path();

    // src/foo.rs should be excluded
    let src_foo = root.join("src/foo.rs");
    let rel_src_foo = src_foo.strip_prefix(root).unwrap();
    assert!(
        matcher.is_excluded(&src_foo, Some(rel_src_foo)),
        "src/foo.rs should be excluded by 'src' pattern"
    );

    // src/nested/x.rs should be excluded
    let src_nested = root.join("src/nested/x.rs");
    let rel_src_nested = src_nested.strip_prefix(root).unwrap();
    assert!(
        matcher.is_excluded(&src_nested, Some(rel_src_nested)),
        "src/nested/x.rs should be excluded by 'src' pattern"
    );

    // assets/src/x.rs should NOT be excluded
    let assets_src = root.join("assets/src/x.rs");
    let rel_assets_src = assets_src.strip_prefix(root).unwrap();
    assert!(
        !matcher.is_excluded(&assets_src, Some(rel_assets_src)),
        "assets/src/x.rs should NOT be excluded by 'src' pattern"
    );
}

#[test]
fn test_single_star_matches_any_depth() {
    // Pattern "docs/*" in globset matches any path under docs/ (single * crosses /)
    // This is globset's default behavior with LiteralSeparator = false
    let matcher = ExcludeMatcher::new(&["docs/*".to_string()]).expect("Valid pattern");

    let tmp = create_test_tree();
    let root = tmp.path();

    // docs/readme.md should be excluded (direct child)
    let docs_readme = root.join("docs/readme.md");
    let rel_docs_readme = docs_readme.strip_prefix(root).unwrap();
    assert!(
        matcher.is_excluded(&docs_readme, Some(rel_docs_readme)),
        "docs/readme.md should be excluded by 'docs/*' pattern"
    );

    // docs/sub/file.md IS also excluded (globset * crosses / by default)
    let docs_sub = root.join("docs/sub/file.md");
    let rel_docs_sub = docs_sub.strip_prefix(root).unwrap();
    assert!(
        matcher.is_excluded(&docs_sub, Some(rel_docs_sub)),
        "docs/sub/file.md IS excluded by 'docs/*' pattern (globset * crosses / by default)"
    );
}

#[test]
fn test_wildcard_in_filename_matches_any_depth() {
    // Pattern "*.min.js" matches any file ending in .min.js at any depth
    // (globset * crosses / by default)
    let matcher = ExcludeMatcher::new(&["*.min.js".to_string()]).expect("Valid pattern");

    let tmp = create_test_tree();
    let root = tmp.path();

    // assets/app.min.js should be excluded
    let app_min = root.join("assets/app.min.js");
    let rel_app_min = app_min.strip_prefix(root).unwrap();
    assert!(
        matcher.is_excluded(&app_min, Some(rel_app_min)),
        "assets/app.min.js should be excluded by '*.min.js' pattern"
    );

    // nested/path/to/lib.min.js should be excluded (any depth)
    let lib_min = root.join("nested/path/to/lib.min.js");
    let rel_lib_min = lib_min.strip_prefix(root).unwrap();
    assert!(
        matcher.is_excluded(&lib_min, Some(rel_lib_min)),
        "nested/path/to/lib.min.js should be excluded by '*.min.js' pattern"
    );
}

#[test]
fn test_invalid_pattern_warns_but_continues() {
    // Invalid pattern should be skipped with warning, valid patterns still work
    let matcher = ExcludeMatcher::new(&[
        "invalid[[[".to_string(), // Invalid glob
        "src".to_string(),        // Valid pattern
    ])
    .expect("Should succeed despite invalid pattern");

    let tmp = create_test_tree();
    let root = tmp.path();

    // src/foo.rs should still be excluded by the valid pattern
    let src_foo = root.join("src/foo.rs");
    let rel_src_foo = src_foo.strip_prefix(root).unwrap();
    assert!(
        matcher.is_excluded(&src_foo, Some(rel_src_foo)),
        "src/foo.rs should be excluded by valid 'src' pattern"
    );

    // docs/readme.md should NOT be excluded (no matching pattern)
    let docs_readme = root.join("docs/readme.md");
    let rel_docs_readme = docs_readme.strip_prefix(root).unwrap();
    assert!(
        !matcher.is_excluded(&docs_readme, Some(rel_docs_readme)),
        "docs/readme.md should NOT be excluded"
    );
}

#[test]
fn test_no_patterns_excludes_nothing() {
    // Empty pattern list should exclude nothing
    let matcher = ExcludeMatcher::new(&[]).expect("Empty patterns should work");

    let tmp = create_test_tree();
    let root = tmp.path();

    let src_foo = root.join("src/foo.rs");
    let rel_src_foo = src_foo.strip_prefix(root).unwrap();
    assert!(
        !matcher.is_excluded(&src_foo, Some(rel_src_foo)),
        "Nothing should be excluded with empty pattern list"
    );
}

#[test]
fn test_multiple_patterns() {
    // Multiple patterns should all be applied
    let matcher = ExcludeMatcher::new(&[
        "src".to_string(),
        "docs/*".to_string(),
        "*.min.js".to_string(),
    ])
    .expect("Valid patterns");

    let tmp = create_test_tree();
    let root = tmp.path();

    // src/foo.rs should be excluded
    let src_foo = root.join("src/foo.rs");
    let rel_src_foo = src_foo.strip_prefix(root).unwrap();
    assert!(matcher.is_excluded(&src_foo, Some(rel_src_foo)));

    // docs/readme.md should be excluded
    let docs_readme = root.join("docs/readme.md");
    let rel_docs_readme = docs_readme.strip_prefix(root).unwrap();
    assert!(matcher.is_excluded(&docs_readme, Some(rel_docs_readme)));

    // assets/app.min.js should be excluded
    let app_min = root.join("assets/app.min.js");
    let rel_app_min = app_min.strip_prefix(root).unwrap();
    assert!(matcher.is_excluded(&app_min, Some(rel_app_min)));

    // assets/src/x.rs should NOT be excluded
    let assets_src = root.join("assets/src/x.rs");
    let rel_assets_src = assets_src.strip_prefix(root).unwrap();
    assert!(!matcher.is_excluded(&assets_src, Some(rel_assets_src)));

    // docs/sub/file.md IS excluded because globset default literal_separator=false
    // means * crosses directory separators, so "docs/*" matches "docs/sub/file.md"
    let docs_sub = root.join("docs/sub/file.md");
    let rel_docs_sub = docs_sub.strip_prefix(root).unwrap();
    assert!(matcher.is_excluded(&docs_sub, Some(rel_docs_sub)));
}

#[test]
fn test_matches_absolute_path_when_no_relative_provided() {
    // When relative_path is None, matcher uses the full absolute path
    // Bare "tmp" does NOT match an absolute path like "/tmp/.../tmp_file.rs"
    let matcher_bare = ExcludeMatcher::new(&["tmp".to_string()]).expect("Valid pattern");

    let tmp = TempDir::new().expect("Failed to create temp dir");
    let tmp_path = tmp.path().join("tmp_file.rs");
    fs::write(&tmp_path, "fn x() {}").unwrap();

    // Bare "tmp" does NOT match absolute path (glob is root-anchored, not substring)
    assert!(
        !matcher_bare.is_excluded(&tmp_path, None),
        "Bare pattern 'tmp' should NOT match absolute path"
    );

    // A pattern like "**/tmp_file.rs" DOES match the absolute path
    let matcher_glob = ExcludeMatcher::new(&["**/tmp_file.rs".to_string()]).expect("Valid pattern");
    assert!(
        matcher_glob.is_excluded(&tmp_path, None),
        "Glob pattern '**/tmp_file.rs' should match absolute path"
    );
}
