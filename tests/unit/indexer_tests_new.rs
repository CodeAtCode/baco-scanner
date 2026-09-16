//! Additional unit tests for `baco::indexer` module
//!
//! Covers: extension map completeness, case-insensitive matching, size boundaries,
//! glob excludes, incremental hash-change selection, should-analyze decisions

use baco::indexer::FileIndex;
use std::fs::File;
use std::io::Write;
use tempfile::TempDir;

// ============================================================================
// Extension Map Completeness Tests
// ============================================================================

#[test]
fn test_extension_map_includes_csharp_ruby_go_java() {
    let temp_dir = TempDir::new().unwrap();

    // Create files for all required languages
    File::create(temp_dir.path().join("test.cs")).unwrap(); // C#
    File::create(temp_dir.path().join("test.rb")).unwrap(); // Ruby
    File::create(temp_dir.path().join("test.go")).unwrap(); // Go
    File::create(temp_dir.path().join("test.java")).unwrap(); // Java

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &[
            "csharp".to_string(),
            "ruby".to_string(),
            "go".to_string(),
            "java".to_string(),
        ],
        1024 * 1024,
        &[],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 4);
}

#[test]
fn test_case_insensitive_extension_matching() {
    let temp_dir = TempDir::new().unwrap();

    // Create files with mixed case extensions
    File::create(temp_dir.path().join("test.C")).unwrap();
    File::create(temp_dir.path().join("test.RS")).unwrap();
    File::create(temp_dir.path().join("test.PY")).unwrap();
    File::create(temp_dir.path().join("test.CPP")).unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &[
            "c".to_string(),
            "rust".to_string(),
            "python".to_string(),
            "cpp".to_string(),
        ],
        1024 * 1024,
        &[],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 4);
}

// ============================================================================
// Size Boundary Tests
// ============================================================================

#[test]
fn test_size_boundary_exact_limit() {
    let temp_dir = TempDir::new().unwrap();

    // Create file exactly at size limit
    let test_file = temp_dir.path().join("test.c");
    let content = "x".repeat(1000);
    File::create(&test_file)
        .unwrap()
        .write_all(content.as_bytes())
        .unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1000, // Exact limit
        &[],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 1);
}

#[test]
fn test_size_boundary_one_byte_over() {
    let temp_dir = TempDir::new().unwrap();

    // Create file one byte over limit
    let test_file = temp_dir.path().join("test.c");
    let content = "x".repeat(1001);
    File::create(&test_file)
        .unwrap()
        .write_all(content.as_bytes())
        .unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1000, // Limit
        &[],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 0);
}

#[test]
fn test_size_boundary_zero_limit() {
    let temp_dir = TempDir::new().unwrap();

    File::create(temp_dir.path().join("test.c"))
        .unwrap()
        .write_all(b"int main() { return 0; }")
        .unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        0, // Zero limit excludes any file with content
        &[],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 0);
}

// ============================================================================
// Glob Exclude Pattern Tests
// ============================================================================

#[test]
fn test_glob_exclude_star_pattern() {
    let temp_dir = TempDir::new().unwrap();

    std::fs::create_dir_all(temp_dir.path().join("src")).unwrap();
    std::fs::create_dir_all(temp_dir.path().join("tests")).unwrap();
    File::create(temp_dir.path().join("src/main.c")).unwrap();
    File::create(temp_dir.path().join("tests/test.c")).unwrap();
    File::create(temp_dir.path().join("test_helper.c")).unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &["tests/*".to_string()],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 2);
}

#[test]
fn test_glob_exclude_directory_trailing_slash() {
    let temp_dir = TempDir::new().unwrap();

    std::fs::create_dir_all(temp_dir.path().join("src")).unwrap();
    File::create(temp_dir.path().join("src/main.c")).unwrap();
    let vendor_dir = temp_dir.path().join("vendor");
    std::fs::create_dir(&vendor_dir).unwrap();
    File::create(vendor_dir.join("lib.c")).unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &["vendor/".to_string()],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 1);
}

#[test]
fn test_glob_exclude_nested_directories() {
    let temp_dir = TempDir::new().unwrap();

    std::fs::create_dir_all(temp_dir.path().join("a/b/c")).unwrap();
    File::create(temp_dir.path().join("a/b/c/test.c")).unwrap();
    File::create(temp_dir.path().join("a/test.c")).unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &["a/b/".to_string()],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 1);
}

// ============================================================================
// Incremental Hash-Change Selection Tests
// ============================================================================

#[test]
fn test_incremental_select_unchanged_files() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.c");
    let content = b"int main() { return 0; }";
    File::create(&test_file)
        .unwrap()
        .write_all(content)
        .unwrap();

    // First index with hash store
    let index1 = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &[],
        true, // Enable hash store
    )
    .unwrap();

    assert_eq!(index1.files.len(), 1);

    // Second index - unchanged file should still be selected
    let (index2, _hash2) = FileIndex::index_project_incremental(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &[],
        None,
        true,
    )
    .unwrap();

    assert_eq!(index2.files.len(), 1);
}

#[test]
fn test_incremental_select_changed_files() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.c");
    File::create(&test_file)
        .unwrap()
        .write_all(b"int main() {}")
        .unwrap();

    // First index
    let _index1 = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &[],
        true,
    )
    .unwrap();

    // Modify file
    File::create(&test_file)
        .unwrap()
        .write_all(b"int main() { return 1; }")
        .unwrap();

    // Incremental index - should detect change
    let (index2, _hash2) = FileIndex::index_project_incremental(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &[],
        None,
        true,
    )
    .unwrap();

    assert_eq!(index2.files.len(), 1);
}

#[test]
fn test_incremental_select_new_files() {
    let temp_dir = TempDir::new().unwrap();
    File::create(temp_dir.path().join("test1.c")).unwrap();

    // First index
    let _index1 = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &[],
        true,
    )
    .unwrap();

    // Add new file
    File::create(temp_dir.path().join("test2.c")).unwrap();

    // Incremental index - should include new file
    let (index2, _hash2) = FileIndex::index_project_incremental(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &[],
        None,
        true,
    )
    .unwrap();

    assert_eq!(index2.files.len(), 2);
}

#[test]
fn test_incremental_select_removed_files() {
    let temp_dir = TempDir::new().unwrap();
    File::create(temp_dir.path().join("test1.c")).unwrap();
    File::create(temp_dir.path().join("test2.c")).unwrap();

    // First index
    let _index1 = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &[],
        true,
    )
    .unwrap();

    // Remove a file
    std::fs::remove_file(temp_dir.path().join("test2.c")).unwrap();

    // Incremental index - should not include removed file
    let (index2, _hash2) = FileIndex::index_project_incremental(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &[],
        None,
        true,
    )
    .unwrap();

    assert_eq!(index2.files.len(), 1);
    assert_eq!(index2.files[0].path.file_name().unwrap(), "test1.c");
}

// ============================================================================
// Should-Analyze Decision Tests
// ============================================================================

#[test]
fn test_should_analyze_binary_file_excluded() {
    let temp_dir = TempDir::new().unwrap();

    // Create a file with binary content
    let test_file = temp_dir.path().join("test.dat");
    let binary_content = vec![0x00, 0x01, 0x02, 0xFF, 0xFE];
    File::create(&test_file)
        .unwrap()
        .write_all(&binary_content)
        .unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &[],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 0);
}

#[test]
fn test_should_analyze_symlink_skipped() {
    let temp_dir = TempDir::new().unwrap();

    // Create a real file
    let real_file = temp_dir.path().join("real.c");
    File::create(&real_file).unwrap();

    // Try to create symlink (may fail on some systems)
    let symlink_path = temp_dir.path().join("link.c");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_file, &symlink_path).ok();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &[],
        false,
    )
    .unwrap();

    // Should only include the real file
    assert_eq!(index.files.len(), 1);
}

#[test]
fn test_should_analyze_hidden_files_excluded() {
    let temp_dir = TempDir::new().unwrap();

    File::create(temp_dir.path().join("test.c")).unwrap();
    File::create(temp_dir.path().join(".hidden.c")).unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &[],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 1);
    assert_eq!(index.files[0].path.file_name().unwrap(), "test.c");
}
