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
