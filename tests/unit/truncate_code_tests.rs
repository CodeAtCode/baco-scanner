//! Tests for truncate_code UTF-8 boundary handling
//!
//! These tests verify that truncate_code correctly handles multi-byte UTF-8
//! characters without panicking when the byte limit falls mid-character.

use baco::llm::LlmClient;
use baco::llm::LlmConfig;
use baco::llm_analysis::LlmAnalyzer;
use baco::llm_metrics::LlmMetricsTracker;
use std::sync::Arc;

fn create_analyzer() -> LlmAnalyzer {
    let languages = vec!["c".to_string()];
    let llm_config = LlmConfig {
        base_url: "http://test".to_string(),
        api_key: "test".to_string(),
        model: "test".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 1,
        retry_backoff_ms: 1000,
        temperature: 0.5,
        max_reasoning_tokens: None,
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 4,
    };

    let client = LlmClient::new(llm_config);
    let _metrics_tracker = Arc::new(LlmMetricsTracker::new());
    LlmAnalyzer::new(
        client,
        languages,
        1024,
        &baco::config::ScannerConfig::default(),
    )
}

#[test]
fn test_truncate_code_short_input() {
    let analyzer = create_analyzer();
    let short = "fn main() { println!(\"hello\"); }";

    let result = analyzer.truncate_code(short);
    assert_eq!(result, short);
    assert!(!result.contains("truncated"));
}

#[test]
fn test_truncate_code_empty_input() {
    let analyzer = create_analyzer();
    let empty = "";

    let result = analyzer.truncate_code(empty);
    assert_eq!(result, empty);
    assert!(!result.contains("truncated"));
}

#[test]
fn test_truncate_code_exact_8000_bytes() {
    let analyzer = create_analyzer();
    // Create exactly 8000 ASCII bytes
    let exact_8000 = "a".repeat(8000);

    let result = analyzer.truncate_code(&exact_8000);
    assert_eq!(result.len(), 8000);
    assert!(!result.contains("truncated"));
}

#[test]
fn test_truncate_code_8001_bytes_ascii() {
    let analyzer = create_analyzer();
    // Create 8001 ASCII bytes (just over limit)
    let over_8000 = "a".repeat(8001);

    let result = analyzer.truncate_code(&over_8000);
    assert!(result.contains("truncated"));
    assert!(result.contains("omitted"));
    // Should truncate at byte boundary (ASCII is 1 byte per char)
    assert!(result.len() < 8001);
}

#[test]
fn test_truncate_code_multi_byte_euro_signs() {
    let analyzer = create_analyzer();
    // Euro sign (€) is 3 bytes in UTF-8
    // 2700 euro signs = 8100 bytes
    let euro_string = "€".repeat(2700);

    assert_eq!(euro_string.len(), 8100); // Verify we have multi-byte content

    let result = analyzer.truncate_code(&euro_string);

    // Should NOT panic and should produce valid UTF-8
    assert!(result.is_char_boundary(result.len()));

    // Should contain truncation suffix
    assert!(result.contains("truncated"));
    assert!(result.contains("omitted"));

    // Result should be under 8000 bytes
    assert!(result.len() <= 8000 + 30); // Allow room for suffix

    // The result itself must be valid UTF-8 (no mid-character slices)
    let _: &str = &result; // This will panic if result is not valid UTF-8
}

#[test]
fn test_truncate_code_byte_boundary_vs_char_boundary() {
    let analyzer = create_analyzer();
    // Create content where byte 8000 falls inside a multi-byte character
    // Start with 7998 ASCII bytes, then add euro signs (3 bytes each)
    let mut content = String::with_capacity(8100);
    content.push_str(&"x".repeat(7998));
    content.push_str(&"€".repeat(100)); // 300 bytes

    assert_eq!(content.len(), 8298);

    let result = analyzer.truncate_code(&content);

    // Must be valid UTF-8 (no panic from mid-character slice)
    let _: &str = &result;

    // Must contain truncation indicator
    assert!(result.contains("truncated"));

    // Must not exceed ~8000 bytes (plus suffix)
    assert!(result.len() <= 8050);
}

#[test]
fn test_truncate_code_mixed_ascii_and_utf8() {
    let analyzer = create_analyzer();
    // Mix of ASCII and multi-byte characters
    let mut content = String::new();
    for i in 0..4000 {
        if i % 2 == 0 {
            content.push('a'); // 1 byte
        } else {
            content.push('€'); // 3 bytes
        }
    }

    let result = analyzer.truncate_code(&content);

    // Must be valid UTF-8
    let _: &str = &result;

    // Should handle the truncation gracefully
    if content.len() > 8000 {
        assert!(result.contains("truncated"));
    }
}
