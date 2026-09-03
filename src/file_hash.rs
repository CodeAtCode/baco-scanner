//! File hash calculator for incremental scanning
//!
//! Provides SHA256 hash calculation for file content to detect changes
//! between scans for incremental scanning support.

use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Maximum file size to hash (10MB)
const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Calculate SHA256 hash of file content
///
/// # Arguments
/// * `path` - Path to the file to hash
///
/// # Returns
/// * `Ok(String)` - Hex-encoded SHA256 hash
/// * `Err(String)` - Error message if file cannot be read or is too large
pub fn calculate_file_hash(path: &Path) -> Result<String, String> {
    // Check file size first
    let metadata = fs::metadata(path).map_err(|e| format!("Cannot read file metadata: {}", e))?;

    let file_size = metadata.len();

    if file_size > MAX_FILE_SIZE {
        tracing::warn!(
            "File {} is {} bytes (>10MB), skipping hash calculation",
            path.display(),
            file_size
        );
        return Err(format!(
            "File too large ({} bytes > {} MB)",
            file_size,
            MAX_FILE_SIZE / (1024 * 1024)
        ));
    }

    // Read file content
    let mut file = fs::File::open(path).map_err(|e| format!("Cannot open file: {}", e))?;

    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .map_err(|e| format!("Cannot read file: {}", e))?;

    Ok(calculate_content_hash(&contents))
}

/// Calculate SHA256 hash of content bytes
///
/// # Arguments
/// * `content` - Byte slice to hash
///
/// # Returns
/// Hex-encoded SHA256 hash
pub fn calculate_content_hash(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Check if content has changed compared to previous hash
///
/// # Arguments
/// * `old_hash` - Previous hash value
/// * `new_content` - New content to compare
///
/// File hash calculator for use in FileIndex
pub struct FileHasher {
    /// Cache of calculated hashes (file_path -> hash)
    pub cache: std::collections::HashMap<PathBuf, String>,
}

impl FileHasher {
    /// Create new file hasher
    pub fn new() -> Self {
        Self {
            cache: std::collections::HashMap::new(),
        }
    }

    /// Calculate and cache hash for a file
    pub fn hash_file(&mut self, path: &Path) -> Result<String, String> {
        // Check cache first
        if let Some(hash) = self.cache.get(path) {
            return Ok(hash.clone());
        }

        // Calculate hash
        let hash = calculate_file_hash(path)?;

        // Cache result
        self.cache.insert(path.to_path_buf(), hash.clone());

        Ok(hash)
    }
}

impl Default for FileHasher {
    fn default() -> Self {
        Self::new()
    }
}
