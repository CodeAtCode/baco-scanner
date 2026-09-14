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
