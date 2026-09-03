//! Unit tests for `baco::indexer` module
//!
//! Covers: FileInfo, FileIndex structs and their methods

use baco::indexer::{FileIndex, FileInfo};
use baco::indexer::get_language_extensions;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use tempfile::TempDir;

// ============================================================================
// FileInfo Tests
// ============================================================================

#[test]
fn test_file_info_construction() {
    let info = FileInfo {
        path: PathBuf::from("test.rs"),
        size: 100,
        language: "rust".to_string(),
        hash: Some("abc123".to_string()),
    };

    assert_eq!(info.path, PathBuf::from("test.rs"));
    assert_eq!(info.size, 100);
    assert_eq!(info.language, "rust");
    assert_eq!(info.hash, Some("abc123".to_string()));
}

#[test]
fn test_file_info_without_hash() {
    let info = FileInfo {
        path: PathBuf::from("main.c"),
        size: 256,
        language: "c".to_string(),
        hash: None,
    };

    assert_eq!(info.hash, None);
}

// ============================================================================
// FileIndex Tests - index_project
// ============================================================================

#[test]
fn test_index_project_single_file() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.c");
    let mut file = File::create(&test_file).unwrap();
    file.write_all(b"int main() { return 0; }").unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &[],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 1);
    assert_eq!(index.files[0].language, "c");
    assert!(index.files[0].size > 0);
}

#[test]
fn test_index_project_empty_directory() {
    let temp_dir = TempDir::new().unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &[],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 0);
    assert_eq!(index.total_size, 0);
}

#[test]
fn test_index_project_multiple_languages() {
    let temp_dir = TempDir::new().unwrap();

    File::create(temp_dir.path().join("test.c")).unwrap();
    File::create(temp_dir.path().join("test.rs")).unwrap();
    File::create(temp_dir.path().join("test.py")).unwrap();
    File::create(temp_dir.path().join("test.js")).unwrap();
    File::create(temp_dir.path().join("test.go")).unwrap();
    File::create(temp_dir.path().join("test.java")).unwrap();
    File::create(temp_dir.path().join("test.cs")).unwrap();
    File::create(temp_dir.path().join("test.rb")).unwrap();
    File::create(temp_dir.path().join("test.php")).unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &[
            "c".to_string(),
            "rust".to_string(),
            "python".to_string(),
            "javascript".to_string(),
            "go".to_string(),
            "java".to_string(),
            "csharp".to_string(),
            "ruby".to_string(),
            "php".to_string(),
        ],
        1024 * 1024,
        &[],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 9);
}

#[test]
fn test_index_project_excludes_non_matching_extensions() {
    let temp_dir = TempDir::new().unwrap();

    File::create(temp_dir.path().join("test.c")).unwrap();
    File::create(temp_dir.path().join("test.txt")).unwrap();
    File::create(temp_dir.path().join("test.md")).unwrap();

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

#[test]
fn test_index_project_with_excludes() {
    let temp_dir = TempDir::new().unwrap();

    File::create(temp_dir.path().join("test.c")).unwrap();
    let subdir = temp_dir.path().join("tests");
    std::fs::create_dir(&subdir).unwrap();
    File::create(subdir.join("test2.c")).unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &["tests/".to_string()],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 1);
}

#[test]
fn test_index_project_over_size_limit() {
    let temp_dir = TempDir::new().unwrap();

    let large_file = temp_dir.path().join("large.c");
    let mut file = File::create(&large_file).unwrap();
    file.write_all(&"0".repeat(2000).into_bytes()).unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1000,
        &[],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 0);
}

#[test]
fn test_index_project_invalid_path() {
    let result = FileIndex::index_project(
        "/nonexistent/path/that/does/not/exist",
        &["c".to_string()],
        1024 * 1024,
        &[],
        false,
    );

    assert!(result.is_err());
}

#[test]
fn test_index_project_subdirectories() {
    let temp_dir = TempDir::new().unwrap();

    let src_dir = temp_dir.path().join("src");
    std::fs::create_dir(&src_dir).unwrap();
    File::create(src_dir.join("main.c")).unwrap();
    let subdir = temp_dir.path().join("lib");
    std::fs::create_dir(&subdir).unwrap();
    File::create(subdir.join("utils.c")).unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &[],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 2);
}

// ============================================================================
// FileIndex Tests - index_project_incremental
// ============================================================================

#[test]
fn test_index_project_incremental_basic() {
    let temp_dir = TempDir::new().unwrap();

    File::create(temp_dir.path().join("test.c")).unwrap();
    File::create(temp_dir.path().join("test.rs")).unwrap();

    let (index, hash_store) = FileIndex::index_project_incremental(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string(), "rust".to_string()],
        1024 * 1024,
        &[],
        None,
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 2);
    assert!(index.hash_store.is_some());
    assert!(hash_store.get_last_scan().is_some());
}

#[test]
fn test_index_project_incremental_invalid_path() {
    let result = FileIndex::index_project_incremental(
        "/nonexistent/path",
        &["c".to_string()],
        1024 * 1024,
        &[],
        None,
        false,
    );

    assert!(result.is_err());
}

// ============================================================================
// FileIndex Tests - get_files
// ============================================================================

#[test]
fn test_get_files_returns_empty_slice() {
    let index = FileIndex {
        files: Vec::new(),
        total_size: 0,
        hash_store: None,
    };

    assert!(index.get_files().is_empty());
    assert_eq!(index.get_files().len(), 0);
}

#[test]
fn test_get_files_returns_all_files() {
    let files = vec![
        FileInfo {
            path: PathBuf::from("test1.c"),
            size: 100,
            language: "c".to_string(),
            hash: None,
        },
        FileInfo {
            path: PathBuf::from("test2.rs"),
            size: 200,
            language: "rust".to_string(),
            hash: None,
        },
    ];

    let index = FileIndex {
        files: files.clone(),
        total_size: 300,
        hash_store: None,
    };

    let result = index.get_files();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].path, PathBuf::from("test1.c"));
    assert_eq!(result[1].path, PathBuf::from("test2.rs"));
}

// ============================================================================
// FileIndex Tests - iter
// ============================================================================

#[test]
fn test_iter_returns_correct_iterator() {
    let files = vec![
        FileInfo {
            path: PathBuf::from("test1.c"),
            size: 100,
            language: "c".to_string(),
            hash: None,
        },
        FileInfo {
            path: PathBuf::from("test2.rs"),
            size: 200,
            language: "rust".to_string(),
            hash: None,
        },
    ];

    let index = FileIndex {
        files: files.clone(),
        total_size: 300,
        hash_store: None,
    };

    let collected: Vec<&FileInfo> = index.iter().collect();
    assert_eq!(collected.len(), 2);
    assert_eq!(collected[0].path, PathBuf::from("test1.c"));
    assert_eq!(collected[1].path, PathBuf::from("test2.rs"));
}

#[test]
fn test_iter_with_empty_index() {
    let index = FileIndex {
        files: Vec::new(),
        total_size: 0,
        hash_store: None,
    };

    let collected: Vec<&FileInfo> = index.iter().collect();
    assert!(collected.is_empty());
}

// ============================================================================
// FileIndex Tests - get_hash_store
// ============================================================================

#[test]
fn test_get_hash_store_returns_none_when_not_set() {
    let index = FileIndex {
        files: Vec::new(),
        total_size: 0,
        hash_store: None,
    };

    assert!(index.get_hash_store().is_none());
}

#[test]
fn test_get_hash_store_returns_some_when_set() {
    use baco::indexer::FileHashStore;

    let hash_store = FileHashStore::new();
    let index = FileIndex {
        files: Vec::new(),
        total_size: 0,
        hash_store: Some(hash_store.clone()),
    };

    let result = index.get_hash_store();
    assert!(result.is_some());
}

// ============================================================================
// FileIndex Tests - total_size calculation
// ============================================================================

#[test]
fn test_total_size_calculated_correctly() {
    let temp_dir = TempDir::new().unwrap();

    let file1 = temp_dir.path().join("small.c");
    let mut f1 = File::create(&file1).unwrap();
    f1.write_all(b"abc").unwrap();

    let file2 = temp_dir.path().join("medium.c");
    let mut f2 = File::create(&file2).unwrap();
    f2.write_all(b"12345").unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &[],
        false,
    )
    .unwrap();

    assert_eq!(index.total_size, 8); // 3 + 5 bytes
}

// ============================================================================
// FileIndex Tests - C++ extensions
// ============================================================================

#[test]
fn test_index_cpp_extensions() {
    let temp_dir = TempDir::new().unwrap();

    File::create(temp_dir.path().join("test.cpp")).unwrap();
    File::create(temp_dir.path().join("test.hpp")).unwrap();
    File::create(temp_dir.path().join("test.cc")).unwrap();
    File::create(temp_dir.path().join("test.hh")).unwrap();
    File::create(temp_dir.path().join("test.cxx")).unwrap();
    File::create(temp_dir.path().join("test.hxx")).unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["cpp".to_string()],
        1024 * 1024,
        &[],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 6);
    for file in &index.files {
        assert_eq!(file.language, "cpp");
    }
}

// ============================================================================
// FileIndex Tests - TypeScript extensions
// ============================================================================

#[test]
fn test_index_typescript_extensions() {
    let temp_dir = TempDir::new().unwrap();

    File::create(temp_dir.path().join("test.ts")).unwrap();
    File::create(temp_dir.path().join("test.tsx")).unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["typescript".to_string()],
        1024 * 1024,
        &[],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 2);
    for file in &index.files {
        assert_eq!(file.language, "typescript");
    }
}

// ============================================================================
// FileIndex Tests - JavaScript extensions
// ============================================================================

#[test]
fn test_index_javascript_extensions() {
    let temp_dir = TempDir::new().unwrap();

    File::create(temp_dir.path().join("test.js")).unwrap();
    File::create(temp_dir.path().join("test.jsx")).unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["javascript".to_string()],
        1024 * 1024,
        &[],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 2);
    for file in &index.files {
        assert_eq!(file.language, "javascript");
    }
}

// ============================================================================
// FileIndex Tests - C# extension
// ============================================================================

#[test]
fn test_index_csharp_extension() {
    let temp_dir = TempDir::new().unwrap();

    File::create(temp_dir.path().join("test.cs")).unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["csharp".to_string()],
        1024 * 1024,
        &[],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 1);
    assert_eq!(index.files[0].language, "csharp");
}

// ============================================================================
// FileIndex Tests - case insensitive exclude patterns
// ============================================================================

#[test]
fn test_index_excludes_case_insensitive() {
    let temp_dir = TempDir::new().unwrap();

    File::create(temp_dir.path().join("test.c")).unwrap();
    let subdir = temp_dir.path().join("TESTS");
    std::fs::create_dir(&subdir).unwrap();
    File::create(subdir.join("test2.c")).unwrap();

    let index = FileIndex::index_project(
        temp_dir.path().to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &["tests/".to_string()],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 1);
}
// ============================================================================
// get_language_extensions() Tests
// ============================================================================

#[test]
fn test_get_language_extensions() {
    let exts = get_language_extensions(&["c".to_string()]);
    assert_eq!(exts.get("c"), Some(&"c".to_string()));
    assert_eq!(exts.get("h"), Some(&"c".to_string()));

    let exts = get_language_extensions(&["cpp".to_string()]);
    assert_eq!(exts.get("cpp"), Some(&"cpp".to_string()));
    assert_eq!(exts.get("hpp"), Some(&"cpp".to_string()));

    let exts = get_language_extensions(&["python".to_string()]);
    assert_eq!(exts.get("py"), Some(&"python".to_string()));

    let exts = get_language_extensions(&["rust".to_string()]);
    assert_eq!(exts.get("rs"), Some(&"rust".to_string()));
}

#[test]
fn test_get_language_extensions_unsupported() {
    let exts = get_language_extensions(&["unknown".to_string()]);
    assert!(exts.is_empty());
}

#[test]
fn test_get_language_extensions_multiple() {
    let exts =
        get_language_extensions(&["c".to_string(), "python".to_string(), "rust".to_string()]);
    assert_eq!(exts.get("c"), Some(&"c".to_string()));
    assert_eq!(exts.get("py"), Some(&"python".to_string()));
    assert_eq!(exts.get("rs"), Some(&"rust".to_string()));
}

// ============================================================================
// FileIndex::index_project() Additional Tests
// ============================================================================

#[test]
fn test_index_single_file() {
    let temp_dir = std::env::temp_dir().join(format!(
        "baco_test_index_{}",
        chrono::Utc::now().timestamp()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let test_file = temp_dir.join("test.c");
    std::fs::write(&test_file, "int main() { return 0; }").unwrap();

    let index = FileIndex::index_project(
        temp_dir.to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &[],
        true,
    )
    .unwrap();

    assert_eq!(index.files.len(), 1);
    assert_eq!(index.files[0].language, "c");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_index_empty_directory() {
    let temp_dir = std::env::temp_dir().join(format!(
        "baco_test_empty_{}",
        chrono::Utc::now().timestamp()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);

    let index = FileIndex::index_project(
        temp_dir.to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &[],
        true,
    )
    .unwrap();

    assert_eq!(index.files.len(), 0);
    assert_eq!(index.total_size, 0);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_index_multiple_files() {
    let temp_dir = std::env::temp_dir().join(format!(
        "baco_test_multi_{}",
        chrono::Utc::now().timestamp()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    std::fs::write(temp_dir.join("test.c"), "int x;").unwrap();
    std::fs::write(temp_dir.join("test.cpp"), "int y;").unwrap();
    std::fs::write(temp_dir.join("test.py"), "z = 1").unwrap();
    std::fs::write(temp_dir.join("test.rs"), "fn main() {}").unwrap();
    std::fs::write(temp_dir.join("test.go"), "package main").unwrap();
    std::fs::write(temp_dir.join("test.java"), "public class Test {}").unwrap();
    std::fs::write(temp_dir.join("test.cs"), "class Test {}").unwrap();
    std::fs::write(temp_dir.join("test.js"), "const a = 1;").unwrap();
    std::fs::write(temp_dir.join("test.ts"), "const b: string = \"hello\";").unwrap();
    std::fs::write(temp_dir.join("test.rb"), "def hello;").unwrap();
    std::fs::write(temp_dir.join("test.php"), "<?php echo 'hi';").unwrap();

    let index = FileIndex::index_project(
        temp_dir.to_str().unwrap(),
        &[
            "c".to_string(),
            "cpp".to_string(),
            "rust".to_string(),
            "python".to_string(),
            "go".to_string(),
            "java".to_string(),
            "csharp".to_string(),
            "javascript".to_string(),
            "typescript".to_string(),
            "ruby".to_string(),
            "php".to_string(),
        ],
        1024 * 1024,
        &[],
        true,
    )
    .unwrap();

    assert_eq!(index.files.len(), 11);
    assert!(index.total_size > 0);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_index_excludes_directories() {
    let temp_dir =
        std::env::temp_dir().join(format!("baco_test_dirs_{}", chrono::Utc::now().timestamp()));
    let _ = std::fs::create_dir_all(&temp_dir);

    std::fs::write(temp_dir.join("test.c"), "int x;").unwrap();
    let subdir = temp_dir.join("subdir");
    std::fs::create_dir(&subdir).unwrap();
    std::fs::write(subdir.join("test2.c"), "int y;").unwrap();

    let index = FileIndex::index_project(
        temp_dir.to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &[],
        true,
    )
    .unwrap();

    assert_eq!(index.files.len(), 2); // Both files included since no excludes

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_index_over_size_limit() {
    let temp_dir = std::env::temp_dir().join("baco_test_size");
    let _ = std::fs::create_dir_all(&temp_dir);

    let large_file = temp_dir.join("large.c");
    std::fs::write(&large_file, "0".repeat(2000).as_str()).unwrap();

    let index = FileIndex::index_project(
        temp_dir.to_str().unwrap(),
        &["c".to_string()],
        1000,
        &[],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 0);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_index_with_excludes() {
    let temp_dir = std::env::temp_dir().join("baco_test_excludes");
    let _ = std::fs::create_dir_all(&temp_dir);
    std::fs::write(temp_dir.join("test.c"), "int x;").unwrap();
    let subdir = temp_dir.join("tests");
    std::fs::create_dir(&subdir).unwrap();
    std::fs::write(subdir.join("test2.c"), "int y;").unwrap();

    let index = FileIndex::index_project(
        temp_dir.to_str().unwrap(),
        &["c".to_string()],
        1024 * 1024,
        &["tests/".to_string()],
        false,
    )
    .unwrap();

    assert_eq!(index.files.len(), 1);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_index_invalid_path() {
    let result = FileIndex::index_project(
        "/nonexistent/path/that/does/not/exist",
        &["c".to_string()],
        1024 * 1024,
        &[],
        false,
    );
    assert!(result.is_err());
}
