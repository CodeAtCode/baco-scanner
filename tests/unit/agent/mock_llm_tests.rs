//! Comprehensive unit tests for MockLlmClient
//!
//! Migrated from src/agent/mock_llm.rs inline tests

use baco::agent::mock_llm::MockLlmClient;
use baco::llm::ChatResponse;
use serde_json::json;

#[test]
fn test_mock_llm_client_new() {
    let responses = vec![
        ChatResponse {
            content: "First response".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock-model".to_string(),
        },
        ChatResponse {
            content: "Second response".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock-model".to_string(),
        },
    ];

    let mock = MockLlmClient::new(responses);
    assert_eq!(mock.response_count(), 2);
}

#[tokio::test]
async fn test_mock_tool_call() {
    let response = MockLlmClient::mock_tool_call(
        "search_tool",
        json!({
            "query": "test",
            "limit": 10
        }),
    );

    assert_eq!(response.tool_calls.len(), 1);
    assert_eq!(response.tool_calls[0].name, "search_tool");
    assert_eq!(
        response.tool_calls[0].arguments,
        json!({
            "query": "test",
            "limit": 10
        })
    );
    assert!(!response.content.is_empty());
}

#[tokio::test]
async fn test_mock_final_response() {
    let response = MockLlmClient::mock_final_response("Converged to final answer");

    assert_eq!(response.content, "Converged to final answer");
    assert!(response.tool_calls.is_empty());
}

#[tokio::test]
async fn test_mock_responses_in_order() {
    let responses = vec![
        ChatResponse {
            content: "Turn 1".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock-model".to_string(),
        },
        ChatResponse {
            content: "Turn 2".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock-model".to_string(),
        },
        ChatResponse {
            content: "Turn 3".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock-model".to_string(),
        },
    ];

    let mock = MockLlmClient::new(responses.clone());

    // First call should return first response
    let result = mock.chat_with_tools(&[], &[]).await.unwrap();
    assert_eq!(result.content, "Turn 1");

    // Second call should return second response
    let result = mock.chat_with_tools(&[], &[]).await.unwrap();
    assert_eq!(result.content, "Turn 2");

    // Third call should return third response
    let result = mock.chat_with_tools(&[], &[]).await.unwrap();
    assert_eq!(result.content, "Turn 3");
}

#[tokio::test]
async fn test_mock_exhausted_responses_panic() {
    let responses = vec![ChatResponse {
        content: "Only one response".to_string(),
        tool_calls: vec![],
        raw: json!({}),
        model_used: "mock-model".to_string(),
    }];

    let mock = MockLlmClient::new(responses);

    // First call succeeds
    let result = mock.chat_with_tools(&[], &[]).await.unwrap();
    assert_eq!(result.content, "Only one response");

    // Second call should fail with error
    let result = mock.chat_with_tools(&[], &[]).await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("Exhausted"));
}

#[tokio::test]
async fn test_mock_with_tool_schemas() {
    let responses = vec![
        MockLlmClient::mock_tool_call(
            "analyze_code",
            json!({
                "code": "const x = 1;",
                "file": "test.ts"
            }),
        ),
        MockLlmClient::mock_final_response("Analysis complete: no issues found"),
    ];

    let mock = MockLlmClient::new(responses);

    let result = mock.chat_with_tools(&[], &[]).await.unwrap();
    assert_eq!(result.tool_calls[0].name, "analyze_code");

    let result = mock.chat_with_tools(&[], &[]).await.unwrap();
    assert!(result.tool_calls.is_empty());
    assert_eq!(result.content, "Analysis complete: no issues found");
}

#[test]
fn test_chat_response_structure() {
    let response = ChatResponse {
        content: "Test response".to_string(),
        tool_calls: vec![baco::agent::ToolCall {
            id: Some("call_abc".to_string()),
            name: "test_tool".to_string(),
            arguments: json!({ "arg1": "value1" }),
        }],
        raw: json!({ "test": true }),
        model_used: "mock-model".to_string(),
    };

    assert_eq!(response.content, "Test response");
    assert_eq!(response.tool_calls.len(), 1);
    assert_eq!(response.tool_calls[0].id, Some("call_abc".to_string()));
    assert_eq!(response.tool_calls[0].name, "test_tool");
    assert_eq!(
        response.tool_calls[0].arguments,
        json!({ "arg1": "value1" })
    );
    assert_eq!(response.raw, json!({ "test": true }));
}

#[test]
fn test_tool_call_with_various_arguments() {
    // Test with object arguments
    let response = MockLlmClient::mock_tool_call(
        "process_data",
        json!({
            "input": "hello",
            "mode": "strict",
            "flags": ["a", "b", "c"]
        }),
    );

    assert_eq!(
        response.tool_calls[0].arguments,
        json!({
            "input": "hello",
            "mode": "strict",
            "flags": ["a", "b", "c"]
        })
    );

    // Test with array arguments
    let response = MockLlmClient::mock_tool_call("list_files", json!(["file1.ts", "file2.ts"]));

    assert_eq!(
        response.tool_calls[0].arguments,
        json!(["file1.ts", "file2.ts"])
    );

    // Test with string arguments
    let response = MockLlmClient::mock_tool_call("read_file", json!("config.json"));

    assert_eq!(response.tool_calls[0].arguments, json!("config.json"));

    // Test with number arguments
    let response = MockLlmClient::mock_tool_call("process_batch", json!(42));

    assert_eq!(response.tool_calls[0].arguments, json!(42));
}

#[test]
fn test_final_response_variations() {
    let response1 = MockLlmClient::mock_final_response("Error: file not found");
    assert_eq!(response1.content, "Error: file not found");
    assert!(response1.tool_calls.is_empty());

    let response2 = MockLlmClient::mock_final_response("Success! All 10 items processed.");
    assert_eq!(response2.content, "Success! All 10 items processed.");
    assert!(response2.tool_calls.is_empty());

    let response3 = MockLlmClient::mock_final_response("");
    assert_eq!(response3.content, "");
    assert!(response3.tool_calls.is_empty());
}

#[test]
fn test_mock_client_model_name_method() {
    let responses = vec![];
    let mock = MockLlmClient::new(responses.clone());

    // Test model_name() method
    assert_eq!(mock.model_name(), "mock-model");

    // Test with custom model name
    let mock_with_model = MockLlmClient::with_model(responses, "custom-model".to_string());
    assert_eq!(mock_with_model.model_name(), "custom-model");
}

#[test]
fn test_mock_client_response_count() {
    let responses = vec![
        ChatResponse {
            content: "Response 1".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        },
        ChatResponse {
            content: "Response 2".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        },
        ChatResponse {
            content: "Response 3".to_string(),
            tool_calls: vec![],
            raw: json!({}),
            model_used: "mock".to_string(),
        },
    ];

    let mock = MockLlmClient::new(responses);
    assert_eq!(mock.response_count(), 3);

    // Empty responses
    let empty_mock = MockLlmClient::new(vec![]);
    assert_eq!(empty_mock.response_count(), 0);
}
