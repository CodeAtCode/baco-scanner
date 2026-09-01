//! LLM response cache module
//!
//! Provides content-addressed caching of LLM responses based on request parameters.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Compute the cache key for an LLM request.
/// Key = hex SHA256 of: model + "\0" + base_url + "\0" + temperature + "\0" + max_tokens + "\0" + canonical JSON messages
pub fn compute_cache_key(
    model: &str,
    base_url: &str,
    temperature: f32,
    max_tokens: Option<usize>,
    messages_json: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(model.as_bytes());
    hasher.update(b"\0");
    hasher.update(base_url.as_bytes());
    hasher.update(b"\0");
    hasher.update(temperature.to_le_bytes());
    hasher.update(b"\0");
    if let Some(mt) = max_tokens {
        hasher.update(mt.to_le_bytes());
    } else {
        hasher.update(b"null");
    }
    hasher.update(b"\0");
    hasher.update(messages_json);
    let hash = hasher.finalize();
    hex::encode(hash)
}

/// Get the effective cache directory.
/// If cache_dir is None and caching is enabled, returns "baco-output/llm-cache" relative to CWD.
pub fn get_effective_cache_dir(cache_dir: Option<&String>) -> PathBuf {
    match cache_dir {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from("baco-output/llm-cache"),
    }
}

/// Get the cache file path for a given key.
pub fn cache_file_path(cache_dir: &Path, key: &str) -> PathBuf {
    cache_dir.join(format!("{}.json", key))
}

/// Try to read a cached response from disk.
/// Returns Ok(Some(content)) if found, Ok(None) if not found, Err on read error.
pub fn read_cached_response(cache_dir: &Path, key: &str) -> Result<Option<String>, String> {
    let path = cache_file_path(cache_dir, key);
    match std::fs::read_to_string(&path) {
        Ok(content) => Ok(Some(content)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("Failed to read cache file {:?}: {}", path, e)),
    }
}

/// Try to write a response to the cache.
/// Returns Ok(()) on success, Err on write failure.
/// This is best-effort: failures should not prevent the request from proceeding.
pub fn write_cached_response(cache_dir: &Path, key: &str, content: &str) -> Result<(), String> {
    let path = cache_file_path(cache_dir, key);
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return Err(format!(
                "Failed to create cache directory {:?}: {}",
                parent, e
            ));
        }
    }
    match std::fs::write(&path, content) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to write cache file {:?}: {}", path, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_compute_cache_key_deterministic() {
        let key1 = compute_cache_key("model1", "http://localhost:8080", 0.5, Some(100), b"[]");
        let key2 = compute_cache_key("model1", "http://localhost:8080", 0.5, Some(100), b"[]");
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_compute_cache_key_different_inputs() {
        let key1 = compute_cache_key("model1", "http://localhost:8080", 0.5, Some(100), b"[]");
        let key2 = compute_cache_key("model2", "http://localhost:8080", 0.5, Some(100), b"[]");
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_file_path() {
        let dir = PathBuf::from("/tmp/cache");
        let path = cache_file_path(&dir, "abc123");
        assert_eq!(path, PathBuf::from("/tmp/cache/abc123.json"));
    }

    #[test]
    fn test_get_effective_cache_dir_default() {
        let dir = get_effective_cache_dir(None);
        assert_eq!(dir, PathBuf::from("baco-output/llm-cache"));
    }

    #[test]
    fn test_get_effective_cache_dir_custom() {
        let custom = "/custom/cache".to_string();
        let dir = get_effective_cache_dir(Some(&custom));
        assert_eq!(dir, PathBuf::from("/custom/cache"));
    }

    #[test]
    fn test_cache_read_write() {
        let tmpdir = TempDir::new().unwrap();
        let key = "test_key_123";
        let content = r#"{"content": "test response", "model": "test-model"}"#;

        // Write
        let write_result = write_cached_response(tmpdir.path(), key, content);
        assert!(write_result.is_ok());

        // Read
        let read_result = read_cached_response(tmpdir.path(), key);
        assert!(read_result.is_ok());
        assert_eq!(read_result.unwrap(), Some(content.to_string()));
    }

    #[test]
    fn test_cache_read_missing() {
        let tmpdir = TempDir::new().unwrap();
        let result = read_cached_response(tmpdir.path(), "nonexistent_key");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }
}
