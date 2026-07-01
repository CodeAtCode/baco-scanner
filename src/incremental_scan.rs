//! Incremental scanning support using file hash comparison
//!
//! This module provides functionality to detect file changes between scans
//! using SHA256 hash comparison, enabling skipping of unchanged files.

use crate::file_hash::{calculate_file_hash, FileHasher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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

    /// Check if a file has changed since last scan
    pub fn has_changed(&self, path: &Path, current_hash: &str) -> bool {
        match self.get_hash(path) {
            Some(stored_hash) => stored_hash != current_hash,
            None => true, // New file (not in store)
        }
    }

    /// Get all file paths in the store
    pub fn paths(&self) -> Vec<&String> {
        self.hashes.keys().collect()
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

    /// Remove a file from the store
    pub fn remove(&mut self, path: &Path) {
        let key = path.to_string_lossy().to_string();
        self.hashes.remove(&key);
    }

    /// Clear all hashes
    pub fn clear(&mut self) {
        self.hashes.clear();
        self.last_scan = None;
    }
}

/// Result of comparing files for incremental scanning
#[derive(Debug, Clone)]
pub struct IncrementalScanResult {
    /// Files that are new (not in previous scan)
    pub new_files: Vec<PathBuf>,
    /// Files that have changed (hash differs from previous)
    pub changed_files: Vec<PathBuf>,
    /// Files that are unchanged (hash matches previous)
    pub unchanged_files: Vec<PathBuf>,
    /// Files that were in previous scan but no longer exist
    pub deleted_files: Vec<PathBuf>,
}

impl IncrementalScanResult {
    /// Total number of files that need processing (new + changed)
    pub fn files_to_process(&self) -> usize {
        self.new_files.len() + self.changed_files.len()
    }

    /// Total number of files in the result
    pub fn total_files(&self) -> usize {
        self.new_files.len() + self.changed_files.len() + self.unchanged_files.len()
    }

    /// Check if there are any files to process
    pub fn has_changes(&self) -> bool {
        !self.new_files.is_empty() || !self.changed_files.is_empty()
    }
}

/// Incremental scanner that compares file hashes to detect changes
#[allow(dead_code)]
pub struct IncrementalScanner {
    /// Store of previous file hashes
    previous_hashes: FileHashStore,
    /// Current file hasher
    hasher: FileHasher,
}

impl IncrementalScanner {
    /// Create a new incremental scanner with the given hash store
    pub fn new(previous_hashes: FileHashStore) -> Self {
        Self {
            previous_hashes,
            hasher: FileHasher::new(),
        }
    }

    /// Create an incremental scanner from a previous hash store file
    pub fn from_file(path: &str) -> Result<Self, String> {
        let previous_hashes = FileHashStore::load(path)?;
        Ok(Self::new(previous_hashes))
    }

    /// Compare current files against previous scan
    pub fn compare_files(&mut self, current_files: &[PathBuf]) -> IncrementalScanResult {
        let mut result = IncrementalScanResult {
            new_files: Vec::new(),
            changed_files: Vec::new(),
            unchanged_files: Vec::new(),
            deleted_files: Vec::new(),
        };

        // Track which current files we've seen
        let mut current_paths: std::collections::HashSet<String> = current_files
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();

        // Check each current file
        for file_path in current_files {
            // Calculate current hash (with error handling for unreadable files)
            let current_hash = match calculate_file_hash(file_path) {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!(
                        "Failed to hash file {}: {}, treating as changed",
                        file_path.display(),
                        e
                    );
                    result.changed_files.push(file_path.clone());
                    let key = file_path.to_string_lossy().to_string();
                    current_paths.remove(&key);
                    continue;
                }
            };

            // Check if file has changed
            if self.previous_hashes.has_changed(file_path, &current_hash) {
                // File is new or changed
                if self.previous_hashes.get_hash(file_path).is_some() {
                    result.changed_files.push(file_path.clone());
                } else {
                    result.new_files.push(file_path.clone());
                }
            } else {
                result.unchanged_files.push(file_path.clone());
            }

            // Mark this path as seen
            let key = file_path.to_string_lossy().to_string();
            current_paths.remove(&key);
        }

        // Any remaining paths in previous_hashes not seen in current are deleted
        for path_str in self.previous_hashes.paths() {
            if !current_paths.contains(path_str) {
                result.deleted_files.push(PathBuf::from(path_str));
            }
        }

        result
    }

    /// Get the hash store for persistence
    pub fn get_hash_store(&self) -> &FileHashStore {
        &self.previous_hashes
    }

    /// Get mutable hash store for updates
    pub fn get_hash_store_mut(&mut self) -> &mut FileHashStore {
        &mut self.previous_hashes
    }

    /// Update hash for a file (call after processing)
    pub fn update_hash(&mut self, path: &Path) -> Result<(), String> {
        let hash = calculate_file_hash(path)?;
        self.previous_hashes.insert_hash(path, hash);
        Ok(())
    }

    /// Build hash store from current files
    pub fn build_hash_store(&mut self, files: &[PathBuf]) -> Result<FileHashStore, String> {
        let mut store = FileHashStore::new();

        for file_path in files {
            match calculate_file_hash(file_path) {
                Ok(hash) => {
                    store.insert_hash(file_path, hash);
                }
                Err(e) => {
                    tracing::warn!("Failed to hash file {}: {}", file_path.display(), e);
                }
            }
        }

        // Set timestamp
        store.set_last_scan(chrono::Utc::now().timestamp());

        Ok(store)
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
    use std::fs::File;
    use std::io::Write;

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
    fn test_file_hash_store_has_changed() {
        let mut store = FileHashStore::new();
        let path = PathBuf::from("/test/file.txt");

        // New file should show as changed
        assert!(store.has_changed(&path, "abc123"));

        // Insert the hash
        store.insert_hash(&path, "abc123".to_string());

        // Same hash should not show as changed
        assert!(!store.has_changed(&path, "abc123"));

        // Different hash should show as changed
        assert!(store.has_changed(&path, "xyz789"));
    }

    #[test]
    fn test_file_hash_store_remove() {
        let mut store = FileHashStore::new();
        let path = PathBuf::from("/test/file.txt");

        store.insert_hash(&path, "abc123".to_string());
        assert!(store.get_hash(&path).is_some());

        store.remove(&path);
        assert!(store.get_hash(&path).is_none());
    }

    #[test]
    fn test_file_hash_store_save_load() {
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().unwrap();

        let mut store = FileHashStore::new();
        store.insert_hash(&PathBuf::from("file1.txt"), "hash1".to_string());
        store.insert_hash(&PathBuf::from("file2.txt"), "hash2".to_string());

        // Save to temp file
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
    fn test_incremental_scan_result() {
        let result = IncrementalScanResult {
            new_files: vec![PathBuf::from("new1.rs")],
            changed_files: vec![PathBuf::from("changed1.rs")],
            unchanged_files: vec![PathBuf::from("unchanged1.rs")],
            deleted_files: vec![],
        };

        assert_eq!(result.files_to_process(), 2);
        assert_eq!(result.total_files(), 3);
        assert!(result.has_changes());
    }

    #[test]
    fn test_incremental_scan_result_no_changes() {
        let result = IncrementalScanResult {
            new_files: vec![],
            changed_files: vec![],
            unchanged_files: vec![PathBuf::from("unchanged1.rs")],
            deleted_files: vec![],
        };

        assert_eq!(result.files_to_process(), 0);
        assert!(!result.has_changes());
    }

    #[test]
    fn test_incremental_scanner_compare_files() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();

        // Create a file in the previous scan
        let file1 = temp_dir.path().join("file1.txt");
        let mut f1 = File::create(&file1).unwrap();
        f1.write_all(b"content1").unwrap();

        // Create previous hash store with file1 and another file that's now deleted
        let mut store = FileHashStore::new();
        store.insert_hash(&file1, "old_hash".to_string());
        store.insert_hash(
            &temp_dir.path().join("deleted.txt"),
            "deleted_hash".to_string(),
        );

        // Update file1 with new content
        let mut f1 = File::create(&file1).unwrap();
        f1.write_all(b"new_content1").unwrap();

        // Create a new file
        let file2 = temp_dir.path().join("file2.txt");
        let mut f2 = File::create(&file2).unwrap();
        f2.write_all(b"content2").unwrap();

        // Run comparison
        let mut scanner = IncrementalScanner::new(store);
        let current_files = vec![file1.clone(), file2.clone()];
        let result = scanner.compare_files(&current_files);

        // file1 should be marked as changed (content changed)
        assert!(result.changed_files.iter().any(|p| p == &file1));
        // file2 should be new
        assert!(result.new_files.iter().any(|p| p == &file2));
        // deleted.txt should be in deleted_files
        assert!(result
            .deleted_files
            .iter()
            .any(|p| p.to_string_lossy().contains("deleted.txt")));
    }

    #[test]
    fn test_incremental_scanner_unchanged_files() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();

        // Create a file
        let file1 = temp_dir.path().join("file1.txt");
        let mut f1 = File::create(&file1).unwrap();
        f1.write_all(b"same_content").unwrap();

        // Calculate its hash
        let hash = calculate_file_hash(&file1).unwrap();

        // Create previous hash store with the same hash
        let mut store = FileHashStore::new();
        store.insert_hash(&file1, hash);

        // Run comparison
        let mut scanner = IncrementalScanner::new(store);
        let result = scanner.compare_files(std::slice::from_ref(&file1));

        // file1 should be unchanged
        assert!(result.unchanged_files.iter().any(|p| p == &file1));
        assert!(result.changed_files.is_empty());
        assert!(result.new_files.is_empty());
    }

    #[test]
    fn test_build_hash_store() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();

        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");

        let mut f1 = File::create(&file1).unwrap();
        f1.write_all(b"content1").unwrap();

        let mut f2 = File::create(&file2).unwrap();
        f2.write_all(b"content2").unwrap();

        let mut scanner = IncrementalScanner::new(FileHashStore::new());
        let store = scanner
            .build_hash_store(&[file1.clone(), file2.clone()])
            .unwrap();

        assert_eq!(store.len(), 2);
        assert!(store.get_hash(&file1).is_some());
        assert!(store.get_hash(&file2).is_some());
        assert!(store.get_last_scan().is_some());
    }
}
