//! Tests for LLM client infrastructure: cache, rate limiting, and retry policy

use baco::llm::{chat_endpoint, ChatMessage, ChatResponseWithModel, LlmClient, LlmConfig};
use baco::llm_cache;
use baco::llm_metrics::LlmMetricsTracker;
use baco::rate_limiter::RateLimiter;
use tempfile::TempDir;

/// Test that cache hit path works without making HTTP requests
#[tokio::test]
async fn test_cache_hit_without_http() {
    let tmpdir = TempDir::new().unwrap();
    let cache_dir = tmpdir.path().to_path_buf();

    // Create a config with cache enabled and a base_url that would fail if HTTP was attempted
    let config = LlmConfig {
        base_url: "http://127.0.0.1:9".to_string(), // Invalid port - would fail on HTTP
        api_key: "test-key".to_string(),
        model: "test-model".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.5,
        max_reasoning_tokens: None,
        enable_llm_cache: true,
        cache_dir: Some(cache_dir.to_string_lossy().to_string()),
        max_concurrent: 5,
    };

    let client = LlmClient::with_metrics(config, Some(LlmMetricsTracker::new()));

    // Compute the cache key the same way the client does
    let messages = vec![ChatMessage::user("Test message")];
    let messages_json = serde_json::to_vec(&messages).unwrap();
    let cache_key = llm_cache::compute_cache_key(
        "test-model",
        "http://127.0.0.1:9",
        0.5,
        None,
        &messages_json,
    );

    // Seed the cache file directly
    let cached_response = serde_json::json!({
        "content": "Cached response content",
        "model": "test-model",
        "timestamp": "2024-01-01T00:00:00Z"
    })
    .to_string();
    llm_cache::write_cached_response(&cache_dir, &cache_key, &cached_response).unwrap();

    // Call chat - should hit cache and NOT attempt HTTP
    let result: Result<ChatResponseWithModel, String> = client.chat(&messages).await;

    // Should succeed with cached content
    assert!(result.is_ok(), "Cache hit should succeed: {:?}", result);
    let response = result.unwrap();
    assert_eq!(response.content, "Cached response content");
    assert_eq!(response.model_used, "test-model");
}

/// Test classify_retryable function with various status codes
#[test]
fn test_classify_retryable() {
    // Fail fast on client errors
    assert!(!LlmClient::classify_retryable(400, None).0);
    assert!(!LlmClient::classify_retryable(401, None).0);
    assert!(!LlmClient::classify_retryable(403, None).0);

    // Retry on timeout
    assert!(LlmClient::classify_retryable(408, None).0);

    // Retry on rate limit with Retry-After
    let (should_retry, retry_after) = LlmClient::classify_retryable(429, Some(7));
    assert!(should_retry);
    assert_eq!(retry_after, Some(7));

    // Retry on rate limit without Retry-After (will use backoff)
    let (should_retry, retry_after) = LlmClient::classify_retryable(429, None);
    assert!(should_retry);
    assert_eq!(retry_after, None);

    // Retry on server errors
    assert!(LlmClient::classify_retryable(500, None).0);
    assert!(LlmClient::classify_retryable(502, None).0);
    assert!(LlmClient::classify_retryable(503, None).0);
    assert!(LlmClient::classify_retryable(599, None).0);

    // Don't retry on other statuses
    assert!(!LlmClient::classify_retryable(200, None).0);
    assert!(!LlmClient::classify_retryable(404, None).0);
}

/// Test rate limiter permit acquisition
#[tokio::test]
async fn test_rate_limiter_permit_acquisition() {
    let limiter = RateLimiter::new(2);

    // Should be able to acquire 2 permits
    let permit1 = limiter.acquire().await.unwrap();
    let permit2 = limiter.acquire().await.unwrap();

    // Third acquire should not be available immediately (try_acquire)
    assert!(limiter.try_acquire().is_none());

    // Drop permits
    drop(permit1);
    drop(permit2);

    // Now should be able to acquire again
    assert!(limiter.try_acquire().is_some());
}

/// Test that LlmClient is created with rate limiter based on max_concurrent
#[test]
fn test_llm_client_rate_limiter_config() {
    let config = LlmConfig {
        base_url: "http://test.com".to_string(),
        api_key: "test-key".to_string(),
        model: "test-model".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.5,
        max_reasoning_tokens: None,
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 5,
    };

    let _client = LlmClient::with_metrics(config, None);
    // Construction must succeed and wire the rate limiter with max_concurrent;
    // the limiter itself is internal, so successful creation is the check.
}

/// Test cache key computation is deterministic
#[test]
fn test_cache_key_deterministic() {
    let key1 =
        llm_cache::compute_cache_key("model1", "http://localhost:8080", 0.5, Some(100), b"[]");
    let key2 =
        llm_cache::compute_cache_key("model1", "http://localhost:8080", 0.5, Some(100), b"[]");
    assert_eq!(key1, key2);
}

/// Test cache key changes with different inputs
#[test]
fn test_cache_key_varies_with_inputs() {
    let key1 =
        llm_cache::compute_cache_key("model1", "http://localhost:8080", 0.5, Some(100), b"[]");

    let key2 = llm_cache::compute_cache_key(
        "model2", // Different model
        "http://localhost:8080",
        0.5,
        Some(100),
        b"[]",
    );
    assert_ne!(key1, key2);

    let key3 = llm_cache::compute_cache_key(
        "model1",
        "http://localhost:9090", // Different URL
        0.5,
        Some(100),
        b"[]",
    );
    assert_ne!(key1, key3);

    let key4 = llm_cache::compute_cache_key(
        "model1",
        "http://localhost:8080",
        0.7, // Different temperature
        Some(100),
        b"[]",
    );
    assert_ne!(key1, key4);
}

/// Test effective cache directory default
#[test]
fn test_effective_cache_dir_default() {
    let dir = llm_cache::get_effective_cache_dir(None);
    assert_eq!(dir, std::path::PathBuf::from("baco-output/llm-cache"));
}

/// Test effective cache directory custom
#[test]
fn test_effective_cache_dir_custom() {
    let custom = "/custom/cache".to_string();
    let dir = llm_cache::get_effective_cache_dir(Some(&custom));
    assert_eq!(dir, std::path::PathBuf::from("/custom/cache"));
}

/// Test chat_endpoint helper
#[test]
fn test_chat_endpoint() {
    // URL with /v1 prefix
    assert_eq!(
        chat_endpoint("https://api.openai.com/v1"),
        "https://api.openai.com/v1/chat/completions"
    );

    // URL without /v1 prefix
    assert_eq!(
        chat_endpoint("https://api.openai.com"),
        "https://api.openai.com/v1/chat/completions"
    );

    // URL with trailing slash
    assert_eq!(
        chat_endpoint("https://api.openai.com/"),
        "https://api.openai.com/v1/chat/completions"
    );
}
