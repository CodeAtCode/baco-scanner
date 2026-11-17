//! Byte-budget truncation must snap to a UTF-8 char boundary.

use baco::llm_analysis::prev_char_boundary;

#[test]
fn test_prev_char_boundary_keeps_an_offset_that_is_already_a_boundary() {
    let s = "ascii and ☃";
    assert_eq!(prev_char_boundary(s, 0), 0);
    assert_eq!(prev_char_boundary(s, 9), 9);
    assert_eq!(prev_char_boundary(s, s.len()), s.len());
}

#[test]
fn test_prev_char_boundary_snaps_back_inside_a_multibyte_char() {
    // "☃" is three bytes wide, so offsets 1 and 2 land inside it.
    let s = "☃";
    assert_eq!(prev_char_boundary(s, 1), 0);
    assert_eq!(prev_char_boundary(s, 2), 0);
    assert_eq!(prev_char_boundary(s, 3), 3);
}

#[test]
fn test_prev_char_boundary_snaps_at_a_byte_budget() {
    let s = "☃".repeat(1000);

    // 2000 is two bytes into the 667th char (667 * 3 = 2001), so it must snap back.
    let snapped = prev_char_boundary(&s, 2000);
    assert_eq!(snapped, 1998);
    // Slicing at the snapped offset must not panic.
    assert_eq!(s[..snapped].chars().count(), 666);
}

#[tokio::test]
async fn test_semantic_path_summarize_does_not_panic_on_a_multibyte_source() {
    let client = baco::llm::LlmClient::new(baco::llm::LlmConfig {
        base_url: "http://127.0.0.1:9/v1".to_string(),
        api_key: "test-key".to_string(),
        model: "test-model".to_string(),
        models: vec![],
        timeout: 5,
        max_retries: 0,
        retry_backoff_ms: 1,
        temperature: 0.5,
        max_reasoning_tokens: None,
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 1,
    });

    // 6000 bytes, so the 2000-byte cut lands inside a multi-byte character.
    let source = "☃".repeat(2000);

    let result = baco::context::semantic_path::summarize(&source, &client).await;
    assert!(
        result.is_err(),
        "an unreachable endpoint must surface an error, not a panic"
    );
}
