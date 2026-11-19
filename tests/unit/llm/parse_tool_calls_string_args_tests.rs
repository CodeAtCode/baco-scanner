/// Tests for parse_tool_calls with string-shaped arguments
use baco::llm::parse_tool_calls;

#[test]
fn test_parse_tool_calls_with_string_arguments() {
    // OpenAI-shaped response where arguments is a JSON string
    let message = serde_json::json!({
        "tool_calls": [
            {
                "id": "call_123",
                "function": {
                    "name": "file_read",
                    "arguments": "{\"path\":\"test.py\",\"start_line\":10}"
                }
            }
        ]
    });

    let calls = parse_tool_calls(&message);

    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].id, Some("call_123".to_string()));
    assert_eq!(calls[0].name, "file_read");
    assert_eq!(calls[0].arguments["path"], "test.py");
    assert_eq!(calls[0].arguments["start_line"], 10);
}

#[test]
fn test_parse_tool_calls_with_object_arguments() {
    // Standard shape where arguments is already a JSON object
    let message = serde_json::json!({
        "tool_calls": [
            {
                "id": "call_456",
                "function": {
                    "name": "pattern_search",
                    "arguments": {
                        "pattern": "unsafe",
                        "path": "./src"
                    }
                }
            }
        ]
    });

    let calls = parse_tool_calls(&message);

    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].id, Some("call_456".to_string()));
    assert_eq!(calls[0].name, "pattern_search");
    assert_eq!(calls[0].arguments["pattern"], "unsafe");
    assert_eq!(calls[0].arguments["path"], "./src");
}
