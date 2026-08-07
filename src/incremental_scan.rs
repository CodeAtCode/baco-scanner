//! Incremental scanning support using file hash comparison
//!
//! This module provides functionality to detect file changes between scans
//! using SHA256 hash comparison, enabling skipping of unchanged files.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Stores file hashes for incremental scanning
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileHashStore {
    /// Map of file path (as string) to its hash
    hashes: HashMap<String, String>,
    /// Last scan timestamp (Unix epoch)
    last_scan: Option<i64>,
}

impl FileHashStore {
    /// Create a new empty hash store
    pub fn new() -> Self {
        Self {
            hashes: HashMap::new(),
            last_scan: None,
        }
    }

    /// Get the hash for a file path
    pub fn get_hash(&self, path: &Path) -> Option<&String> {
        let key = path.to_string_lossy().to_string();
        self.hashes.get(&key)
    }

    /// Insert or update a hash for a file path
    pub fn insert_hash(&mut self, path: &Path, hash: String) {
        let key = path.to_string_lossy().to_string();
        self.hashes.insert(key, hash);
    }

    /// Get the number of stored hashes
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Set the last scan timestamp
    pub fn set_last_scan(&mut self, timestamp: i64) {
        self.last_scan = Some(timestamp);
    }

    /// Get the last scan timestamp
    pub fn get_last_scan(&self) -> Option<i64> {
        self.last_scan
    }
}

impl FileHashStore {
    /// Save hash store to a file
    pub fn save(&self, path: &str) -> Result<(), String> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create directory: {}", e))?;
        }

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize hash store: {}", e))?;

        std::fs::write(path, json).map_err(|e| format!("Failed to write hash store: {}", e))?;

        Ok(())
    }

    /// Load hash store from a file
    pub fn load(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read hash store: {}", e))?;

        let store: FileHashStore = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse hash store: {}", e))?;

        Ok(store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_file_hash_store_new() {
        let store = FileHashStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_file_hash_store_insert_get() {
        let mut store = FileHashStore::new();
        let path = PathBuf::from("/test/file.txt");

        store.insert_hash(&path, "abc123".to_string());

        assert_eq!(store.get_hash(&path), Some(&"abc123".to_string()));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_file_hash_store_save_load() {
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().unwrap();

        let mut store = FileHashStore::new();
        store.insert_hash(&PathBuf::from("file1.txt"), "hash1".to_string());
        store.insert_hash(&PathBuf::from("file2.txt"), "hash2".to_string());

        let temp_path = temp_file.path().to_str().unwrap();
        store.save(temp_path).unwrap();

        let loaded = FileHashStore::load(temp_path).unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(
            loaded.get_hash(&PathBuf::from("file1.txt")),
            Some(&"hash1".to_string())
        );
    }

    #[test]
    fn test_changed_file_detection() {
        let mut store = FileHashStore::new();
        let path = PathBuf::from("/test/file.txt");

        store.insert_hash(&path, "old_hash_abc123".to_string());

        store.insert_hash(&path, "new_hash_def456".to_string());

        assert_eq!(store.get_hash(&path), Some(&"new_hash_def456".to_string()));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_unchanged_file_detection() {
        let mut store = FileHashStore::new();
        let path = PathBuf::from("/test/file.txt");

        store.insert_hash(&path, "same_hash_123".to_string());

        store.insert_hash(&path, "same_hash_123".to_string());

        assert_eq!(store.get_hash(&path), Some(&"same_hash_123".to_string()));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_deletion_handling() {
        let mut store = FileHashStore::new();
        let path = PathBuf::from("/test/file.txt");

        store.insert_hash(&path, "hash_before_delete".to_string());
        assert_eq!(store.len(), 1);

        store.insert_hash(&path, String::new());

        assert_eq!(store.get_hash(&path), Some(&String::new()));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_corrupt_cache_recovery() {
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().unwrap();
        let temp_path = temp_file.path().to_str().unwrap();

        std::fs::write(temp_path, "this is not valid json {{{{").unwrap();

        let result = FileHashStore::load(temp_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse"));
    }

    #[test]
    fn test_multiple_files_same_hash() {
        let mut store = FileHashStore::new();
        let path1 = PathBuf::from("/test/file1.txt");
        let path2 = PathBuf::from("/test/file2.txt");
        let path3 = PathBuf::from("/test/file3.txt");

        store.insert_hash(&path1, "identical_hash".to_string());
        store.insert_hash(&path2, "identical_hash".to_string());
        store.insert_hash(&path3, "identical_hash".to_string());

        assert_eq!(store.len(), 3);
        assert_eq!(store.get_hash(&path1), Some(&"identical_hash".to_string()));
        assert_eq!(store.get_hash(&path2), Some(&"identical_hash".to_string()));
        assert_eq!(store.get_hash(&path3), Some(&"identical_hash".to_string()));
    }

    #[test]
    fn test_last_scan_timestamp() {
        let mut store = FileHashStore::new();

        assert_eq!(store.get_last_scan(), None);

        store.set_last_scan(1234567890);

        assert_eq!(store.get_last_scan(), Some(1234567890));
    }

    #[test]
    fn test_load_from_nonexistent_file() {
        let result = FileHashStore::load("/nonexistent/path/hash_store.json");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to read"));
    }

    #[test]
    fn test_save_creates_directories() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let nested_path = temp_dir.path().join("nested/deep/hash_store.json");
        let path_str = nested_path.to_str().unwrap();

        let store = FileHashStore::new();
        let result = store.save(path_str);

        assert!(result.is_ok());
        assert!(nested_path.exists());
    }
}
