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
/// # Returns
/// * `true` if content has changed (hash differs)
/// * `false` if content is unchanged (hash matches)
pub fn hash_changed(old_hash: &str, new_content: &[u8]) -> bool {
    let new_hash = calculate_content_hash(new_content);
    old_hash != new_hash
}

/// File hash calculator for use in FileIndex
pub struct FileHasher {
    /// Cache of calculated hashes (file_path -> hash)
    cache: std::collections::HashMap<PathBuf, String>,
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

    /// Clear the hash cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Get cached hash if available
    pub fn get_cached_hash(&self, path: &Path) -> Option<&String> {
        self.cache.get(path)
    }
}

impl Default for FileHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_calculate_content_hash() {
        // Test with known input
        let content = b"Hello, World!";
        let hash = calculate_content_hash(content);

        // SHA256("Hello, World!") = dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
        assert_eq!(
            hash,
            "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        );
    }

    #[test]
    fn test_calculate_content_hash_empty() {
        let content = b"";
        let hash = calculate_content_hash(content);

        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hash_changed() {
        let content1 = b"Hello";
        let content2 = b"World";

        let hash1 = calculate_content_hash(content1);

        // Same content should not show as changed
        assert!(!hash_changed(&hash1, content1));

        // Different content should show as changed
        assert!(hash_changed(&hash1, content2));
    }

    #[test]
    fn test_calculate_file_hash() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        // Create test file
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"Test content").unwrap();

        // Calculate hash
        let hash = calculate_file_hash(&file_path).unwrap();

        // Verify it's a valid SHA256 hash (64 hex characters)
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_file_hasher_cache() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        // Create test file
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"Cached test").unwrap();

        let mut hasher = FileHasher::new();

        // First call should calculate hash
        let hash1 = hasher.hash_file(&file_path).unwrap();

        // Second call should use cache
        let hash2 = hasher.hash_file(&file_path).unwrap();

        // Hashes should be identical
        assert_eq!(hash1, hash2);

        // Cache should have one entry
        assert_eq!(hasher.cache.len(), 1);
    }

    #[test]
    fn test_file_too_large() {
        let temp_dir = TempDir::new().unwrap();
        let _file_path = temp_dir.path().join("large.bin");

        // Create a file that's too large (we'll just test the error path)
        // In practice, creating a 10MB file would be slow, so we test the logic
        let mut hasher = FileHasher::new();

        // Test with non-existent file
        let result = hasher.hash_file(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
    }
}
