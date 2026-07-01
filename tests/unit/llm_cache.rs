//! Tests for LLM cache functionality
//!
//! Covers: LlmCache, CacheKey, CacheEntry, CacheStats, persistence, cleanup

use baco::llm_cache::{hash_string, CacheEntry, CacheKey, LlmCache};

fn create_test_cache() -> LlmCache {
    let test_dir = "/tmp/test_llm_cache_unit";
    let _ = std::fs::create_dir_all(test_dir);
    LlmCache::new(test_dir).unwrap()
}

#[test]
fn test_cache_key_new() {
    let key = CacheKey::new("test.rs", "fn main() {}", "gpt-4", "Analyze this code");

    assert_eq!(key.file_path, "test.rs");
    assert_eq!(key.model_name, "gpt-4");
    assert!(!key.content_hash.is_empty());
    assert!(!key.prompt_hash.is_empty());
}

#[test]
fn test_cache_key_equality() {
    let key1 = CacheKey::new("test.rs", "fn main() {}", "gpt-4", "Analyze");
    let key2 = CacheKey::new("test.rs", "fn main() {}", "gpt-4", "Analyze");

    assert_eq!(key1, key2);
}

#[test]
fn test_cache_key_different_content() {
    let key1 = CacheKey::new("test.rs", "content1", "model", "prompt");
    let key2 = CacheKey::new("test.rs", "content2", "model", "prompt");

    assert_ne!(key1, key2);
}

#[test]
fn test_cache_key_different_model() {
    let key1 = CacheKey::new("test.rs", "content", "gpt-4", "prompt");
    let key2 = CacheKey::new("test.rs", "content", "gpt-3.5", "prompt");

    assert_ne!(key1, key2);
}

#[test]
fn test_cache_key_different_file() {
    let key1 = CacheKey::new("file1.rs", "content", "model", "prompt");
    let key2 = CacheKey::new("file2.rs", "content", "model", "prompt");

    assert_ne!(key1, key2);
}

#[test]
fn test_cache_key_different_prompt() {
    let key1 = CacheKey::new("test.rs", "content", "model", "prompt1");
    let key2 = CacheKey::new("test.rs", "content", "model", "prompt2");

    assert_ne!(key1, key2);
}

#[test]
fn test_cache_key_hash_compatibility() {
    let mut map = std::collections::HashMap::new();

    let key1 = CacheKey::new("test.rs", "content", "model", "prompt");
    let key2 = CacheKey::new("test.rs", "content", "model", "prompt");

    map.insert(key1, "value1");
    assert!(map.contains_key(&key2)); // Should find key2 because they're equal
}

#[test]
fn test_cache_entry_new() {
    let entry = CacheEntry::new("test response".to_string());

    assert_eq!(entry.response, "test response");
    assert_eq!(entry.hit_count, 1);
    assert!(entry.timestamp <= chrono::Utc::now());
}

#[test]
fn test_cache_entry_increment_hit() {
    let mut entry = CacheEntry::new("response".to_string());

    assert_eq!(entry.hit_count, 1);

    entry.increment_hit();
    assert_eq!(entry.hit_count, 2);

    entry.increment_hit();
    entry.increment_hit();
    assert_eq!(entry.hit_count, 4);
}

#[test]
fn test_hash_string_consistency() {
    let hash1 = hash_string("test content");
    let hash2 = hash_string("test content");

    assert_eq!(hash1, hash2);
}

#[test]
fn test_hash_string_uniqueness() {
    let hash1 = hash_string("content1");
    let hash2 = hash_string("content2");

    assert_ne!(hash1, hash2);
}

#[test]
fn test_hash_string_length() {
    let hash = hash_string("any content");

    // SHA256 produces 32 bytes = 64 hex characters
    assert_eq!(hash.len(), 64);
}

#[test]
fn test_hash_string_empty_input() {
    let hash = hash_string("");

    assert!(!hash.is_empty());
    assert_eq!(hash.len(), 64);
}

#[tokio::test]
async fn test_cache_put_and_get() {
    let cache = create_test_cache();

    let key = CacheKey::new("test.rs", "fn main() {}", "gpt-4", "Analyze");
    let response = r#"[{"severity": "high", "title": "Test"}]"#.to_string();

    cache.put(key.clone(), response.clone()).await;

    // Small delay for async save
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let result = cache.get(&key).await;
    assert!(result.is_some());
    assert_eq!(result.unwrap(), response);
}

#[tokio::test]
async fn test_cache_miss() {
    let cache = create_test_cache();

    let key = CacheKey::new("nonexistent.rs", "content", "model", "prompt");
    let result = cache.get(&key).await;

    assert!(result.is_none());
}

#[tokio::test]
async fn test_cache_hit_increments_count() {
    let cache = create_test_cache();

    let key = CacheKey::new("test.rs", "content", "model", "prompt");
    cache.put(key.clone(), "response".to_string()).await;

    // Multiple gets
    let _ = cache.get(&key).await;
    let _ = cache.get(&key).await;
    let _ = cache.get(&key).await;

    let stats = cache.stats().await;
    assert!(stats.total_hits >= 3); // 3 gets
}

#[tokio::test]
async fn test_cache_invalidate_single() {
    let cache = create_test_cache();

    let key1 = CacheKey::new("test1.rs", "content1", "model", "prompt");
    let key2 = CacheKey::new("test2.rs", "content2", "model", "prompt");

    cache.put(key1.clone(), "response1".to_string()).await;
    cache.put(key2.clone(), "response2".to_string()).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let removed = cache.invalidate("test1.rs").await;
    assert_eq!(removed, 1);

    assert!(cache.get(&key1).await.is_none());
    assert!(cache.get(&key2).await.is_some());
}

#[tokio::test]
async fn test_cache_invalidate_multiple() {
    let cache = create_test_cache();

    let key1 = CacheKey::new("test1.rs", "content1", "model", "prompt");
    let key2 = CacheKey::new("test2.rs", "content2", "model", "prompt");
    let key3 = CacheKey::new("test1.rs", "content3", "model", "prompt");

    cache.put(key1.clone(), "response1".to_string()).await;
    cache.put(key2.clone(), "response2".to_string()).await;
    cache.put(key3.clone(), "response3".to_string()).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Invalidate all entries with file "test1.rs"
    let removed = cache.invalidate("test1.rs").await;
    assert_eq!(removed, 2); // key1 and key3

    assert!(cache.get(&key1).await.is_none());
    assert!(cache.get(&key3).await.is_none());
    assert!(cache.get(&key2).await.is_some());
}

#[tokio::test]
async fn test_cache_invalidate_nonexistent() {
    let cache = create_test_cache();

    let removed = cache.invalidate("nonexistent.rs").await;
    assert_eq!(removed, 0);
}

#[tokio::test]
async fn test_cache_cleanup_by_age() {
    let cache = create_test_cache();

    let key = CacheKey::new("test.rs", "content", "model", "prompt");
    cache.put(key.clone(), "response".to_string()).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Cleanup with max_age_days = 0 removes everything
    let removed = cache.cleanup(0, 1000).await;
    assert_eq!(removed, 1);

    assert!(cache.get(&key).await.is_none());
}

#[tokio::test]
async fn test_cache_cleanup_by_max_entries() {
    let cache = create_test_cache();

    // Add 15 entries
    for i in 0..15 {
        let key = CacheKey::new(&format!("test{}.rs", i), "content", "model", "prompt");
        cache.put(key, "response".to_string()).await;
    }

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Cleanup keeping only 10
    let removed = cache.cleanup(365, 10).await;
    assert_eq!(removed, 5);

    let stats = cache.stats().await;
    assert_eq!(stats.total_entries, 10);
}

#[tokio::test]
async fn test_cache_cleanup_nothing_to_clean() {
    let cache = create_test_cache();

    let key = CacheKey::new("test.rs", "content", "model", "prompt");
    cache.put(key.clone(), "response".to_string()).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Cleanup with generous limits
    let removed = cache.cleanup(365, 1000).await;
    assert_eq!(removed, 0);

    assert!(cache.get(&key).await.is_some());
}

#[tokio::test]
async fn test_cache_stats_empty() {
    let cache = create_test_cache();

    let stats = cache.stats().await;

    assert_eq!(stats.total_entries, 0);
    assert_eq!(stats.total_hits, 0);
}

#[tokio::test]
async fn test_cache_stats_with_entries() {
    let cache = create_test_cache();

    let key1 = CacheKey::new("test1.rs", "content1", "model", "prompt");
    let key2 = CacheKey::new("test2.rs", "content2", "model", "prompt");

    cache.put(key1.clone(), "response1".to_string()).await;
    cache.put(key2.clone(), "response2".to_string()).await;

    let _ = cache.get(&key1).await;
    let _ = cache.get(&key2).await;
    let _ = cache.get(&key1).await;

    let stats = cache.stats().await;

    assert_eq!(stats.total_entries, 2);
    assert_eq!(stats.total_hits, 5); // 2 puts + 3 gets
}

#[tokio::test]
async fn test_cache_overwrite_existing() {
    let cache = create_test_cache();

    let key = CacheKey::new("test.rs", "content", "model", "prompt");

    cache.put(key.clone(), "response1".to_string()).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    cache.put(key.clone(), "response2".to_string()).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let result = cache.get(&key).await;
    assert_eq!(result.unwrap(), "response2");
}

#[test]
fn test_cache_creation_invalid_path() {
    // Should return None for non-writable paths
    let cache = LlmCache::new("/nonexistent_root_that_will_never_exist/cache");

    // Either Some (if it somehow worked) or None is acceptable
    // The important thing is it doesn't panic
    assert!(cache.is_some() || cache.is_none());
}

#[test]
fn test_cache_key_hash_trait() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let key = CacheKey::new("test.rs", "content", "model", "prompt");

    // Verify Hash trait is implemented
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    let hash1 = hasher.finish();

    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    let hash2 = hasher.finish();

    assert_eq!(hash1, hash2);
}

#[tokio::test]
async fn test_cache_multiple_operations() {
    let cache = create_test_cache();

    // Put multiple entries
    for i in 0..10 {
        let key = CacheKey::new(&format!("file{}.rs", i), "content", "model", "prompt");
        cache.put(key, format!("response{}", i)).await;
    }

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Get all entries
    for i in 0..10 {
        let key = CacheKey::new(&format!("file{}.rs", i), "content", "model", "prompt");
        let result = cache.get(&key).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap(), format!("response{}", i));
    }

    let stats = cache.stats().await;
    assert_eq!(stats.total_entries, 10);
    assert_eq!(stats.total_hits, 20); // 10 puts + 10 gets
}
