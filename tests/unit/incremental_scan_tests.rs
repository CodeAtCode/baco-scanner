//! Unit tests for src/incremental_scan.rs
//!
//! Tests cover FileHashStore operations, save/load functionality,
//! and incremental scanning logic.

use baco::incremental_scan::FileHashStore;
use std::path::PathBuf;
use tempfile::TempDir;

// ============================================================================
// FileHashStore::new() Tests
// ============================================================================

#[test]
fn test_file_hash_store_new_creates_empty_store() {
    let store = FileHashStore::new();

    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
}

// ============================================================================
// FileHashStore::insert_hash() Tests
// ============================================================================

#[test]
fn test_insert_hash_adds_new_entry() {
    let mut store = FileHashStore::new();
    let path = PathBuf::from("/test/file.txt");

    store.insert_hash(&path, "abc123".to_string());

    assert_eq!(store.len(), 1);
    assert_eq!(store.get_hash(&path), Some(&"abc123".to_string()));
}

#[test]
fn test_insert_hash_updates_existing_entry() {
    let mut store = FileHashStore::new();
    let path = PathBuf::from("/test/file.txt");

    store.insert_hash(&path, "old_hash".to_string());
    store.insert_hash(&path, "new_hash".to_string());

    assert_eq!(store.len(), 1);
    assert_eq!(store.get_hash(&path), Some(&"new_hash".to_string()));
}

#[test]
fn test_insert_hash_different_paths() {
    let mut store = FileHashStore::new();
    let path1 = PathBuf::from("/test/file1.txt");
    let path2 = PathBuf::from("/test/file2.txt");
    let path3 = PathBuf::from("/test/file3.txt");

    store.insert_hash(&path1, "hash1".to_string());
    store.insert_hash(&path2, "hash2".to_string());
    store.insert_hash(&path3, "hash3".to_string());

    assert_eq!(store.len(), 3);
    assert_eq!(store.get_hash(&path1), Some(&"hash1".to_string()));
    assert_eq!(store.get_hash(&path2), Some(&"hash2".to_string()));
    assert_eq!(store.get_hash(&path3), Some(&"hash3".to_string()));
}

// ============================================================================
// FileHashStore::get_hash() Tests
// ============================================================================

#[test]
fn test_get_hash_returns_none_for_missing_file() {
    let store = FileHashStore::new();
    let path = PathBuf::from("/nonexistent/file.txt");

    assert!(store.get_hash(&path).is_none());
}

#[test]
fn test_get_hash_with_different_path_formats() {
    let mut store = FileHashStore::new();
    let path = PathBuf::from("/test/file.txt");

    store.insert_hash(&path, "test_hash".to_string());

    // Same path should work
    assert!(store.get_hash(&path).is_some());

    // Different path should return None
    let different_path = PathBuf::from("/test/other.txt");
    assert!(store.get_hash(&different_path).is_none());
}

// ============================================================================
// FileHashStore::len() and is_empty() Tests
// ============================================================================

#[test]
fn test_len_returns_correct_count() {
    let mut store = FileHashStore::new();

    assert_eq!(store.len(), 0);

    store.insert_hash(&PathBuf::from("file1.txt"), "hash1".to_string());
    assert_eq!(store.len(), 1);

    store.insert_hash(&PathBuf::from("file2.txt"), "hash2".to_string());
    assert_eq!(store.len(), 2);

    store.insert_hash(&PathBuf::from("file1.txt"), "updated_hash".to_string());
    assert_eq!(store.len(), 2); // Should still be 2, not 3
}

#[test]
fn test_is_empty_changes_with_content() {
    let mut store = FileHashStore::new();

    assert!(store.is_empty());

    store.insert_hash(&PathBuf::from("file.txt"), "hash".to_string());

    assert!(!store.is_empty());
}

// ============================================================================
// FileHashStore::save() and load() Tests
// ============================================================================

#[test]
fn test_save_and_load_preserves_data() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("hash_store.json");

    let mut store = FileHashStore::new();
    store.insert_hash(&PathBuf::from("file1.txt"), "hash1".to_string());
    store.insert_hash(&PathBuf::from("file2.txt"), "hash2".to_string());

    store.save(path.to_str().unwrap()).unwrap();

    let loaded = FileHashStore::load(path.to_str().unwrap()).unwrap();

    assert_eq!(loaded.len(), 2);
    assert_eq!(
        loaded.get_hash(&PathBuf::from("file1.txt")),
        Some(&"hash1".to_string())
    );
    assert_eq!(
        loaded.get_hash(&PathBuf::from("file2.txt")),
        Some(&"hash2".to_string())
    );
}

#[test]
fn test_save_creates_parent_directories() {
    let temp_dir = TempDir::new().unwrap();
    let nested_path = temp_dir.path().join("nested/deep/path/hash_store.json");

    let store = FileHashStore::new();
    let result = store.save(nested_path.to_str().unwrap());

    assert!(result.is_ok());
    assert!(nested_path.exists());
}

#[test]
fn test_load_from_nonexistent_file_returns_error() {
    let result = FileHashStore::load("/nonexistent/path/hash_store.json");

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Failed to read"));
}

#[test]
fn test_load_with_invalid_json_returns_error() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("invalid.json");

    std::fs::write(&path, "this is not valid json {{{{").unwrap();

    let result = FileHashStore::load(path.to_str().unwrap());

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Failed to parse"));
}

#[test]
fn test_load_with_empty_file_returns_error() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("empty.json");

    std::fs::write(&path, "").unwrap();

    let result = FileHashStore::load(path.to_str().unwrap());

    assert!(result.is_err());
}

// ============================================================================
// FileHashStore::set_last_scan() and get_last_scan() Tests
// ============================================================================

#[test]
fn test_last_scan_timestamp_initially_none() {
    let store = FileHashStore::new();

    assert!(store.get_last_scan().is_none());
}

#[test]
fn test_set_last_scan_updates_timestamp() {
    let mut store = FileHashStore::new();

    store.set_last_scan(1234567890);

    assert_eq!(store.get_last_scan(), Some(1234567890));
}

#[test]
fn test_last_scan_can_be_updated() {
    let mut store = FileHashStore::new();

    store.set_last_scan(1000000000);
    assert_eq!(store.get_last_scan(), Some(1000000000));

    store.set_last_scan(2000000000);
    assert_eq!(store.get_last_scan(), Some(2000000000));
}

#[test]
fn test_last_scan_with_negative_timestamp() {
    let mut store = FileHashStore::new();

    store.set_last_scan(-1000);

    assert_eq!(store.get_last_scan(), Some(-1000));
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_empty_hash_string() {
    let mut store = FileHashStore::new();
    let path = PathBuf::from("/test/file.txt");

    store.insert_hash(&path, "".to_string());

    assert_eq!(store.get_hash(&path), Some(&"".to_string()));
}

#[test]
fn test_very_long_hash_string() {
    let mut store = FileHashStore::new();
    let path = PathBuf::from("/test/file.txt");
    let long_hash = "a".repeat(1000);

    store.insert_hash(&path, long_hash.clone());

    assert_eq!(store.get_hash(&path), Some(&long_hash));
}

#[test]
fn test_special_characters_in_path() {
    let mut store = FileHashStore::new();
    let path = PathBuf::from("/test/文件/file with spaces.txt");

    store.insert_hash(&path, "hash".to_string());

    assert!(store.get_hash(&path).is_some());
}

#[test]
fn test_same_hash_for_multiple_files() {
    let mut store = FileHashStore::new();
    let path1 = PathBuf::from("/test/file1.txt");
    let path2 = PathBuf::from("/test/file2.txt");
    let path3 = PathBuf::from("/test/file3.txt");
    let identical_hash = "identical_hash_123".to_string();

    store.insert_hash(&path1, identical_hash.clone());
    store.insert_hash(&path2, identical_hash.clone());
    store.insert_hash(&path3, identical_hash.clone());

    assert_eq!(store.len(), 3);
    assert_eq!(store.get_hash(&path1), Some(&identical_hash));
    assert_eq!(store.get_hash(&path2), Some(&identical_hash));
    assert_eq!(store.get_hash(&path3), Some(&identical_hash));
}

#[test]
fn test_many_files_performance() {
    let mut store = FileHashStore::new();

    for i in 0..100 {
        let path = PathBuf::from(format!("/test/file{}.txt", i));
        store.insert_hash(&path, format!("hash{}", i));
    }

    assert_eq!(store.len(), 100);

    // Verify a few specific entries
    assert_eq!(
        store.get_hash(&PathBuf::from("/test/file0.txt")),
        Some(&"hash0".to_string())
    );
    assert_eq!(
        store.get_hash(&PathBuf::from("/test/file50.txt")),
        Some(&"hash50".to_string())
    );
    assert_eq!(
        store.get_hash(&PathBuf::from("/test/file99.txt")),
        Some(&"hash99".to_string())
    );
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_full_save_load_cycle_with_timestamps() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("full_cycle.json");

    let mut store = FileHashStore::new();
    store.insert_hash(&PathBuf::from("file1.txt"), "hash1".to_string());
    store.set_last_scan(1234567890);

    store.save(path.to_str().unwrap()).unwrap();

    let loaded = FileHashStore::load(path.to_str().unwrap()).unwrap();

    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded.get_last_scan(), Some(1234567890));
    assert_eq!(
        loaded.get_hash(&PathBuf::from("file1.txt")),
        Some(&"hash1".to_string())
    );
}

#[test]
fn test_multiple_save_load_cycles() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("cycles.json");

    let mut store = FileHashStore::new();

    // First cycle
    store.insert_hash(&PathBuf::from("file1.txt"), "hash1".to_string());
    store.save(path.to_str().unwrap()).unwrap();

    // Second cycle - update and add
    let loaded1 = FileHashStore::load(path.to_str().unwrap()).unwrap();
    let mut store2 = loaded1;
    store2.insert_hash(&PathBuf::from("file2.txt"), "hash2".to_string());
    store2.save(path.to_str().unwrap()).unwrap();

    // Third cycle - verify both exist
    let loaded2 = FileHashStore::load(path.to_str().unwrap()).unwrap();
    assert_eq!(loaded2.len(), 2);
    assert_eq!(
        loaded2.get_hash(&PathBuf::from("file1.txt")),
        Some(&"hash1".to_string())
    );
    assert_eq!(
        loaded2.get_hash(&PathBuf::from("file2.txt")),
        Some(&"hash2".to_string())
    );
}
