//! Tests for incremental scan functionality
//!
//! These tests cover file change detection, hash store operations,
//! and incremental scanning logic including edge cases.

use baco::file_hash::calculate_file_hash;
use baco::incremental_scan::{
    FileHashStore, IncrementalScanResult, IncrementalScanner,
};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use tempfile::TempDir;

// ============================================================================
// FileHashStore Tests
// ============================================================================

#[test]
fn test_get_last_scan_none() {
    let store = FileHashStore::new();
    assert!(store.get_last_scan().is_none());
}

#[test]
fn test_get_last_scan_after_set() {
    let mut store = FileHashStore::new();
    let timestamp = 1234567890;
    
    store.set_last_scan(timestamp);
    
    assert_eq!(store.get_last_scan(), Some(timestamp));
}

#[test]
fn test_from_file_nonexistent() {
    let result = FileHashStore::load("/nonexistent/path/hash_store.json");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Failed to read hash store"));
}

#[test]
fn test_from_file_valid() {
    use tempfile::NamedTempFile;
    
    let temp_file = NamedTempFile::new().unwrap();
    let temp_path = temp_file.path().to_str().unwrap();
    
    // Create a valid hash store file
    let store_content = r#"{
        "hashes": {
            "file1.txt": "abc123",
            "file2.txt": "def456"
        },
        "last_scan": 1234567890
    }"#;
    
    std::fs::write(temp_path, store_content).unwrap();
    
    let store = FileHashStore::load(temp_path).unwrap();
    
    assert_eq!(store.len(), 2);
    assert_eq!(store.get_last_scan(), Some(1234567890));
    assert_eq!(store.get_hash(&PathBuf::from("file1.txt")), Some(&"abc123".to_string()));
}

#[test]
fn test_from_file_invalid_json() {
    use tempfile::NamedTempFile;
    
    let temp_file = NamedTempFile::new().unwrap();
    let temp_path = temp_file.path().to_str().unwrap();
    
    std::fs::write(temp_path, "invalid json").unwrap();
    
    let result = FileHashStore::load(temp_path);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Failed to parse hash store"));
}

// ============================================================================
// IncrementalScanResult Tests
// ============================================================================

#[test]
fn test_files_to_process_empty() {
    let result = IncrementalScanResult {
        new_files: vec![],
        changed_files: vec![],
        unchanged_files: vec![],
        deleted_files: vec![],
    };
    
    assert_eq!(result.files_to_process(), 0);
}

#[test]
fn test_files_to_process_with_new_and_changed() {
    let result = IncrementalScanResult {
        new_files: vec![PathBuf::from("new1.rs"), PathBuf::from("new2.rs")],
        changed_files: vec![PathBuf::from("changed1.rs")],
        unchanged_files: vec![PathBuf::from("unchanged1.rs")],
        deleted_files: vec![PathBuf::from("deleted1.rs")],
    };
    
    assert_eq!(result.files_to_process(), 3); // 2 new + 1 changed
}

#[test]
fn test_total_files() {
    let result = IncrementalScanResult {
        new_files: vec![PathBuf::from("new1.rs")],
        changed_files: vec![PathBuf::from("changed1.rs"), PathBuf::from("changed2.rs")],
        unchanged_files: vec![PathBuf::from("unchanged1.rs"), PathBuf::from("unchanged2.rs")],
        deleted_files: vec![PathBuf::from("deleted1.rs")],
    };
    
    assert_eq!(result.total_files(), 5); // 1 + 2 + 2 (excludes deleted)
}

#[test]
fn test_has_changes_false() {
    let result = IncrementalScanResult {
        new_files: vec![],
        changed_files: vec![],
        unchanged_files: vec![PathBuf::from("unchanged1.rs")],
        deleted_files: vec![],
    };
    
    assert!(!result.has_changes());
}

#[test]
fn test_has_changes_with_new_files() {
    let result = IncrementalScanResult {
        new_files: vec![PathBuf::from("new.rs")],
        changed_files: vec![],
        unchanged_files: vec![],
        deleted_files: vec![],
    };
    
    assert!(result.has_changes());
}

#[test]
fn test_has_changes_with_changed_files() {
    let result = IncrementalScanResult {
        new_files: vec![],
        changed_files: vec![PathBuf::from("changed.rs")],
        unchanged_files: vec![],
        deleted_files: vec![],
    };
    
    assert!(result.has_changes());
}

#[test]
fn test_has_changes_with_deleted_only() {
    let result = IncrementalScanResult {
        new_files: vec![],
        changed_files: vec![],
        unchanged_files: vec![PathBuf::from("unchanged.rs")],
        deleted_files: vec![PathBuf::from("deleted.rs")],
    };
    
    // Deleted files don't count as "changes" for processing
    assert!(!result.has_changes());
}

// ============================================================================
// IncrementalScanner Tests
// ============================================================================

#[test]
fn test_get_hash_store() {
    let store = FileHashStore::new();
    let scanner = IncrementalScanner::new(store);
    
    let hash_store = scanner.get_hash_store();
    assert!(hash_store.is_empty());
}

#[test]
fn test_get_hash_store_mut() {
    let store = FileHashStore::new();
    let mut scanner = IncrementalScanner::new(store);
    
    let hash_store_mut = scanner.get_hash_store_mut();
    let path = PathBuf::from("test.txt");
    hash_store_mut.insert_hash(&path, "test_hash".to_string());
    
    // Verify the change persisted
    let hash_store = scanner.get_hash_store();
    assert_eq!(hash_store.get_hash(&path), Some(&"test_hash".to_string()));
}

#[test]
fn test_update_hash_success() {
        let temp_dir = TempDir::new().unwrap();
    
    let file_path = temp_dir.path().join("test.txt");
    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"test content").unwrap();
    
    let mut scanner = IncrementalScanner::new(FileHashStore::new());
    
    let result = scanner.update_hash(&file_path);
    assert!(result.is_ok());
    
    // Verify hash was stored
    let hash_store = scanner.get_hash_store();
    assert!(hash_store.get_hash(&file_path).is_some());
}

#[test]
fn test_update_hash_nonexistent_file() {
    let mut scanner = IncrementalScanner::new(FileHashStore::new());
    
    let result = scanner.update_hash(&PathBuf::from("/nonexistent/file.txt"));
    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(err_msg.contains("Cannot read file") || err_msg.contains("Cannot open file"));
}

#[test]
fn test_from_file_success() {
    use tempfile::NamedTempFile;
    
    let temp_file = NamedTempFile::new().unwrap();
    let temp_path = temp_file.path().to_str().unwrap();
    
    // Create a valid hash store file
    let store_content = r#"{
        "hashes": {
            "file1.txt": "abc123"
        },
        "last_scan": 1234567890
    }"#;
    
    std::fs::write(temp_path, store_content).unwrap();
    
    let scanner = IncrementalScanner::from_file(temp_path);
    assert!(scanner.is_ok());
    
    let scanner = scanner.unwrap();
    let hash_store = scanner.get_hash_store();
    assert_eq!(hash_store.len(), 1);
}

#[test]
fn test_from_file_invalid_path() {
    let result = IncrementalScanner::from_file("/nonexistent/path/hash_store.json");
    assert!(result.is_err());
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_empty_scan_result() {
    let result = IncrementalScanResult {
        new_files: vec![],
        changed_files: vec![],
        unchanged_files: vec![],
        deleted_files: vec![],
    };
    
    assert_eq!(result.files_to_process(), 0);
    assert_eq!(result.total_files(), 0);
    assert!(!result.has_changes());
}

#[test]
fn test_compare_files_empty_current() {
    let mut store = FileHashStore::new();
    store.insert_hash(&PathBuf::from("file1.txt"), "hash1".to_string());
    
    let mut scanner = IncrementalScanner::new(store);
    let result = scanner.compare_files(&[]);
    
    // All previous files should be marked as deleted
    assert_eq!(result.deleted_files.len(), 1);
    assert!(result.new_files.is_empty());
    assert!(result.changed_files.is_empty());
    assert!(result.unchanged_files.is_empty());
}

#[test]
fn test_compare_files_empty_previous() {
    use tempfile::TempDir;
    let temp_dir = TempDir::new().unwrap();
    
    let file1 = temp_dir.path().join("file1.txt");
    let mut f1 = File::create(&file1).unwrap();
    f1.write_all(b"content1").unwrap();
    
    let mut scanner = IncrementalScanner::new(FileHashStore::new());
    let result = scanner.compare_files(std::slice::from_ref(&file1));
    
    // All current files should be marked as new
    assert_eq!(result.new_files.len(), 1);
    assert!(result.changed_files.is_empty());
    assert!(result.unchanged_files.is_empty());
    assert!(result.deleted_files.is_empty());
}

#[test]
fn test_build_hash_store_with_unreadable_file() {
    use tempfile::TempDir;
    let temp_dir = TempDir::new().unwrap();
    
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    
    let mut f1 = File::create(&file1).unwrap();
    f1.write_all(b"content1").unwrap();
    
    // file2 doesn't exist
    
    let mut scanner = IncrementalScanner::new(FileHashStore::new());
    let store = scanner.build_hash_store(&[file1.clone(), file2.clone()]).unwrap();
    
    // Should have only the readable file
    assert_eq!(store.len(), 1);
    assert!(store.get_hash(&file1).is_some());
    assert!(store.get_last_scan().is_some());
}

#[test]
fn test_first_scan_all_new() {
    use tempfile::TempDir;
    let temp_dir = TempDir::new().unwrap();
    
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    
    let mut f1 = File::create(&file1).unwrap();
    f1.write_all(b"content1").unwrap();
    
    let mut f2 = File::create(&file2).unwrap();
    f2.write_all(b"content2").unwrap();
    
    // Empty previous store (first scan)
    let mut scanner = IncrementalScanner::new(FileHashStore::new());
    let result = scanner.compare_files(&[file1.clone(), file2.clone()]);
    
    assert_eq!(result.new_files.len(), 2);
    assert!(result.changed_files.is_empty());
    assert!(result.unchanged_files.is_empty());
}

#[test]
fn test_subsequent_scan_all_unchanged() {
    use tempfile::TempDir;
    let temp_dir = TempDir::new().unwrap();
    
    let file1 = temp_dir.path().join("file1.txt");
    let mut f1 = File::create(&file1).unwrap();
    f1.write_all(b"content1").unwrap();
    
    let hash = calculate_file_hash(&file1).unwrap();
    
    // Previous store with correct hash
    let mut store = FileHashStore::new();
    store.insert_hash(&file1, hash);
    
    let mut scanner = IncrementalScanner::new(store);
    let result = scanner.compare_files(std::slice::from_ref(&file1));
    
    assert_eq!(result.unchanged_files.len(), 1);
    assert!(result.new_files.is_empty());
    assert!(result.changed_files.is_empty());
}

#[test]
fn test_hash_store_clear() {
    let mut store = FileHashStore::new();
    store.insert_hash(&PathBuf::from("file1.txt"), "hash1".to_string());
    store.insert_hash(&PathBuf::from("file2.txt"), "hash2".to_string());
    store.set_last_scan(1234567890);
    
    assert_eq!(store.len(), 2);
    assert!(store.get_last_scan().is_some());
    
    store.clear();
    
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
    assert!(store.get_last_scan().is_none());
}

#[test]
fn test_hash_store_paths() {
    let mut store = FileHashStore::new();
    store.insert_hash(&PathBuf::from("file1.txt"), "hash1".to_string());
    store.insert_hash(&PathBuf::from("file2.txt"), "hash2".to_string());
    
    let paths = store.paths();
    
    assert_eq!(paths.len(), 2);
    assert!(paths.contains(&&"file1.txt".to_string()));
    assert!(paths.contains(&&"file2.txt".to_string()));
}
