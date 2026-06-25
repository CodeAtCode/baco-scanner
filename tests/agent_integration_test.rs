// Integration tests for the agent module.
// Tests the mock LLM client and tool execution flow.

use baco::agent::mock_llm::MockLlmClient;

#[test]
fn test_mock_tool_call_response() {
    // Test that mock_tool_call creates correct response format
    let response = MockLlmClient::mock_tool_call(
        "file_read",
        serde_json::json!({
            "path": "test.c"
        }),
    );

    assert_eq!(response.tool_calls.len(), 1);
    assert_eq!(response.tool_calls[0].name, "file_read");
    assert_eq!(response.tool_calls[0].arguments["path"], "test.c");
    assert!(!response.content.is_empty());
}

#[test]
fn test_mock_final_response() {
    // Test that mock_final_response creates correct response format
    let response = MockLlmClient::mock_final_response("Analysis complete: found 2 issues");

    assert_eq!(response.content, "Analysis complete: found 2 issues");
    assert!(response.tool_calls.is_empty());
}

#[tokio::test]
async fn test_mock_llm_sequential_responses() {
    // Test that mock returns responses in sequence
    let responses = vec![
        MockLlmClient::mock_tool_call("file_read", serde_json::json!({ "path": "test.c" })),
        MockLlmClient::mock_tool_call("pattern_search", serde_json::json!({ "pattern": "vuln" })),
        MockLlmClient::mock_final_response("Found vulnerability"),
    ];

    let client = MockLlmClient::new(responses);

    // First call should return tool call
    let result1 = client.chat_with_tools(&[], &[]).await.unwrap();
    assert!(!result1.tool_calls.is_empty());

    // Second call should return second tool call
    let result2 = client.chat_with_tools(&[], &[]).await.unwrap();
    assert!(!result2.tool_calls.is_empty());

    // Third call should return final response
    let result3 = client.chat_with_tools(&[], &[]).await.unwrap();
    assert!(result3.tool_calls.is_empty());
    assert_eq!(result3.content, "Found vulnerability");

    // Fourth call should fail (no more responses)
    let result4 = client.chat_with_tools(&[], &[]).await;
    assert!(result4.is_err());
}

#[tokio::test]
async fn test_mock_llm_exhausted_responses() {
    // Test error when no more responses available
    let responses = vec![MockLlmClient::mock_final_response("Done")];

    let client = MockLlmClient::new(responses);

    // First call succeeds
    let _ = client.chat_with_tools(&[], &[]).await.unwrap();

    // Second call fails
    let result = client.chat_with_tools(&[], &[]).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Exhausted"));
}

#[tokio::test]
async fn test_full_tool_flow_simulation() {
    // Simulate a full agentic flow with multiple tool calls
    let responses = vec![
        // Turn 1: Read file
        MockLlmClient::mock_tool_call("file_read", serde_json::json!({ "path": "src/main.c" })),
        // Turn 2: Search for pattern
        MockLlmClient::mock_tool_call(
            "pattern_search",
            serde_json::json!({
                "pattern": "strcpy",
                "path": "src"
            }),
        ),
        // Turn 3: Write test
        MockLlmClient::mock_tool_call(
            "file_write",
            serde_json::json!({
                "path": "test_vuln.c",
                "content": "int main() { return 0; }"
            }),
        ),
        // Turn 4: Compile test
        MockLlmClient::mock_tool_call(
            "test_compile",
            serde_json::json!({
                "source_path": "test_vuln.c",
                "language": "c"
            }),
        ),
        // Turn 5: Run test
        MockLlmClient::mock_tool_call(
            "test_run",
            serde_json::json!({
                "executable_path": "test_vuln"
            }),
        ),
        // Turn 6: Final findings
        MockLlmClient::mock_final_response(
            r#"Analysis complete: found buffer overflow vulnerability"#,
        ),
    ];

    let client = MockLlmClient::new(responses);

    // Simulate 6 turns
    for i in 0..6 {
        let result = client.chat_with_tools(&[], &[]).await;
        assert!(result.is_ok(), "Turn {} should succeed", i + 1);
    }

    // 7th turn should fail
    let result = client.chat_with_tools(&[], &[]).await;
    assert!(result.is_err(), "Turn 7 should fail (no more responses)");
}

#[tokio::test]
async fn test_max_turns_simulation() {
    // Simulate agent that never converges (always returns tool calls)
    let responses: Vec<_> = (0..10)
        .map(|i| {
            MockLlmClient::mock_tool_call(
                "pattern_search",
                serde_json::json!({ "pattern": format!("pattern_{}", i), "path": "src" }),
            )
        })
        .collect();

    let client = MockLlmClient::new(responses);

    // Should be able to make 10 calls
    for i in 0..10 {
        let result = client.chat_with_tools(&[], &[]).await;
        assert!(result.is_ok(), "Turn {} should succeed", i + 1);
        assert!(!result.unwrap().tool_calls.is_empty());
    }

    // 11th call should fail
    let result = client.chat_with_tools(&[], &[]).await;
    assert!(result.is_err(), "Turn 11 should fail (no more responses)");
}

#[tokio::test]
async fn test_error_handling_graceful() {
    // Test that mock handles edge cases gracefully
    let responses = vec![
        MockLlmClient::mock_tool_call("file_read", serde_json::json!({ "path": "test.c" })),
        MockLlmClient::mock_final_response("Error: unable to parse response"),
    ];

    let client = MockLlmClient::new(responses);

    // Both calls should succeed (even error message is a valid response)
    let result1 = client.chat_with_tools(&[], &[]).await;
    assert!(result1.is_ok());

    let result2 = client.chat_with_tools(&[], &[]).await;
    assert!(result2.is_ok());

    // Third call should fail
    let result3 = client.chat_with_tools(&[], &[]).await;
    assert!(result3.is_err());
}

#[tokio::test]
async fn test_multiple_languages_in_flow() {
    // Test flow with multiple language compilations
    let responses = vec![
        MockLlmClient::mock_tool_call(
            "file_write",
            serde_json::json!({
                "path": "test_rust.rs",
                "content": "fn main() {}"
            }),
        ),
        MockLlmClient::mock_tool_call(
            "test_compile",
            serde_json::json!({
                "source_path": "test_rust.rs",
                "language": "rust"
            }),
        ),
        MockLlmClient::mock_tool_call(
            "file_write",
            serde_json::json!({
                "path": "test_py.py",
                "content": "print('hello')"
            }),
        ),
        MockLlmClient::mock_tool_call(
            "test_compile",
            serde_json::json!({
                "source_path": "test_py.py",
                "language": "python"
            }),
        ),
        MockLlmClient::mock_final_response("Both tests compiled successfully"),
    ];

    let client = MockLlmClient::new(responses);

    for i in 0..5 {
        let result = client.chat_with_tools(&[], &[]).await;
        assert!(result.is_ok(), "Turn {} should succeed", i + 1);
    }
}

#[tokio::test]
async fn test_false_positive_detection_flow() {
    // Simulate false positive detection: test passes = not a vulnerability
    let responses = vec![
        MockLlmClient::mock_tool_call(
            "file_write",
            serde_json::json!({
                "path": "test_fp.c",
                "content": "int main() { return 0; }"
            }),
        ),
        MockLlmClient::mock_tool_call(
            "test_compile",
            serde_json::json!({
                "source_path": "test_fp.c",
                "language": "c"
            }),
        ),
        MockLlmClient::mock_tool_call(
            "test_run",
            serde_json::json!({
                "executable_path": "test_fp"
            }),
        ),
        MockLlmClient::mock_final_response(
            "compiled=true|test_passed=true|log=No vulnerability - test passed",
        ),
    ];

    let client = MockLlmClient::new(responses);

    // Run through the flow
    for i in 0..4 {
        let result = client.chat_with_tools(&[], &[]).await;
        assert!(result.is_ok(), "Turn {} should succeed", i + 1);
    }
}

#[tokio::test]
async fn test_confirmed_vulnerability_flow() {
    // Simulated confirmed vulnerability: test fails = vulnerability exists
    let responses = vec![
        MockLlmClient::mock_tool_call(
            "file_write",
            serde_json::json!({
                "path": "test_vuln.c",
                "content": "int main() { trigger_bug(); return 0; }"
            }),
        ),
        MockLlmClient::mock_tool_call(
            "test_compile",
            serde_json::json!({
                "source_path": "test_vuln.c",
                "language": "c"
            }),
        ),
        MockLlmClient::mock_tool_call(
            "test_run",
            serde_json::json!({
                "executable_path": "test_vuln"
            }),
        ),
        MockLlmClient::mock_final_response(
            "compiled=true|test_passed=false|log=Test triggered vulnerability - CONFIRMED",
        ),
    ];

    let client = MockLlmClient::new(responses);

    // Run through the flow
    for i in 0..4 {
        let result = client.chat_with_tools(&[], &[]).await;
        assert!(result.is_ok(), "Turn {} should succeed", i + 1);
    }
}
