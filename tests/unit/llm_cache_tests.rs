//! Unit tests for llm_cache module

use baco::llm_cache::{
    cache_file_path, compute_cache_key, get_effective_cache_dir, read_cached_response,
    write_cached_response,
};
use std::path::PathBuf;
use tempfile::TempDir;

// ============================================================================
// compute_cache_key() Tests
// ============================================================================

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

// ============================================================================
// cache_file_path() Tests
// ============================================================================

#[test]
fn test_cache_file_path() {
    let dir = PathBuf::from("/tmp/cache");
    let path = cache_file_path(&dir, "abc123");
    assert_eq!(path, PathBuf::from("/tmp/cache/abc123.json"));
}

// ============================================================================
// get_effective_cache_dir() Tests
// ============================================================================

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

// ============================================================================
// write_cached_response() and read_cached_response() Tests
// ============================================================================

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
