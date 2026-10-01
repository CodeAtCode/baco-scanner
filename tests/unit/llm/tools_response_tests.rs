//! A tools response that carries nothing actionable is not an answer.
//!
//! An earlier version of this file asserted `content.is_empty() && tool_calls.is_empty()`
//! — the condition the fix checks — in the test body, having re-derived `content`
//! itself. That asserts a boolean, not the code: it passed with the fix disabled.
//! These tests call the production predicate instead.

use baco::llm::{
    ChatMessage, FunctionToolDefinition, LlmClient, LlmConfig, ToolSchema, parse_tool_calls,
    tools_response_is_malformed,
};
use serde_json::json;

fn message(content: serde_json::Value, tool_calls: serde_json::Value) -> serde_json::Value {
    json!({ "content": content, "tool_calls": tool_calls })
}

fn tool_call_json(name: &str) -> serde_json::Value {
    json!([{ "id": "call_1", "function": { "name": name, "arguments": "{}" } }])
}

#[test]
fn test_a_response_with_neither_content_nor_tool_calls_is_malformed() {
    let msg = message(json!(null), json!(null));
    let tool_calls = parse_tool_calls(&msg);
    let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");

    assert!(tool_calls.is_empty());
    assert!(tools_response_is_malformed(content, tool_calls.len()));
}

#[test]
fn test_a_response_with_content_is_not_malformed() {
    let msg = message(json!("I found nothing of concern"), json!(null));
    let tool_calls = parse_tool_calls(&msg);
    let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");

    assert!(!tools_response_is_malformed(content, tool_calls.len()));
}

#[test]
fn test_tool_calls_alone_are_a_valid_answer() {
    // A model acting through a tool does not narrate. Empty content next to a
    // real tool call is not a broken response.
    let msg = message(json!(null), tool_call_json("scan_file"));
    let tool_calls = parse_tool_calls(&msg);
    let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");

    assert_eq!(tool_calls.len(), 1);
    assert_eq!(tool_calls[0].name, "scan_file");
    assert!(
        !tools_response_is_malformed(content, tool_calls.len()),
        "tool calls without prose must be accepted"
    );
}

#[test]
fn test_whitespace_only_content_counts_as_empty() {
    // A provider that returns " " has not answered, whatever it returned.
    assert!(tools_response_is_malformed("", 0));
    assert!(tools_response_is_malformed("   ", 0));
    assert!(tools_response_is_malformed("\n\t ", 0));
}

#[test]
fn test_whitespace_content_with_a_tool_call_is_still_valid() {
    assert!(!tools_response_is_malformed("  ", 1));
}

#[test]
fn test_a_tool_call_that_does_not_parse_does_not_rescue_an_empty_response() {
    // `parse_tool_calls` drops malformed entries, so an unparseable tool_calls
    // array leaves zero calls. That is a broken response, not a tool-using one.
    let msg = message(json!(null), json!([{ "not_a_tool_call": true }]));
    let tool_calls = parse_tool_calls(&msg);
    let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");

    assert!(tool_calls.is_empty());
    assert!(tools_response_is_malformed(content, tool_calls.len()));
}
// ============================================================================
// End-to-end, through the real HTTP path
// ============================================================================
//
// The tests above pin the decision. These drive it through an actual request, so
// the seam cannot be satisfied by a function nothing calls.

fn config_for(url: String) -> LlmConfig {
    LlmConfig {
        base_url: url,
        api_key: "test".to_string(),
        model: "test-model".to_string(),
        models: vec!["test-model".to_string()],
        timeout: 5,
        max_retries: 0,
        retry_backoff_ms: 0,
        temperature: 0.5,
        max_reasoning_tokens: None,
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 4,
        pricing: Default::default(),
    }
}

fn tool_schema() -> Vec<ToolSchema> {
    vec![ToolSchema {
        type_: "function".to_string(),
        function: FunctionToolDefinition {
            name: "file_read".to_string(),
            description: "Read a file".to_string(),
            parameters: json!({ "type": "object" }),
        },
    }]
}

#[tokio::test]
async fn test_chat_with_tools_rejects_a_response_with_nothing_in_it() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"choices":[{"message":{"content":null}}]}"#)
        .create();

    let client = LlmClient::new(config_for(server.url()));
    let result = client
        .chat_with_tools(&[ChatMessage::user("read p.rs")], &tool_schema())
        .await;

    assert!(
        result.is_err(),
        "a response with neither content nor tool calls must not read as an empty answer"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn test_chat_with_tools_accepts_tool_calls_without_prose() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"choices":[{"message":{"content":null,"tool_calls":[
                 {"id":"c1","function":{"name":"file_read","arguments":"{}"}}]}}]}"#,
        )
        .create();

    let client = LlmClient::new(config_for(server.url()));
    let response = client
        .chat_with_tools(&[ChatMessage::user("read p.rs")], &tool_schema())
        .await
        .expect("a model acting through a tool needs no prose");

    assert_eq!(response.tool_calls.len(), 1);
    assert_eq!(response.tool_calls[0].name, "file_read");
    mock.assert_async().await;
}

#[tokio::test]
async fn test_chat_rejects_an_empty_answer() {
    // The plain chat path had no equivalent check. An empty string parsed as
    // "no findings", so a provider that returned nothing looked exactly like a
    // model that read the file and found it clean.
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"choices":[{"message":{"content":""}}]}"#)
        .create();

    let client = LlmClient::new(config_for(server.url()));
    let result = client.chat(&[ChatMessage::user("analyse p.rs")]).await;

    assert!(
        result.is_err(),
        "an empty answer must be an error, not a successful scan of nothing"
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn test_chat_accepts_a_padded_but_real_answer() {
    // Rejecting empty must not reject a real answer that happens to be padded.
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/v1/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"choices":[{"message":{"content":"  []  "}}]}"#)
        .create();

    let client = LlmClient::new(config_for(server.url()));
    let response = client
        .chat(&[ChatMessage::user("analyse p.rs")])
        .await
        .expect("padded content is still content");

    assert_eq!(response.content.trim(), "[]");
    mock.assert_async().await;
}
