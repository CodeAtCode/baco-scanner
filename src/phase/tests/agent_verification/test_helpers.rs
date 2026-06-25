//! Test helper functions for security agent verification tests

use crate::agent::mock_llm::MockLlmClient;
use crate::agent::ToolCall;
use crate::llm::ChatResponse;
use serde_json::json;

/// Create a mock LLM client that simulates agent tool usage
pub fn create_agent_mock_client(responses: Vec<ChatResponse>) -> MockLlmClient {
    MockLlmClient::new(responses)
}

/// Helper to create ChatResponse with default raw field
pub fn make_chat_response(
    content: &str,
    model_used: &str,
    tool_calls: Vec<ToolCall>,
) -> ChatResponse {
    ChatResponse {
        content: content.to_string(),
        model_used: model_used.to_string(),
        tool_calls,
        raw: serde_json::Value::Null,
    }
}

/// Helper to create a file_read tool call
pub fn make_file_read_tool(path: &str) -> ToolCall {
    ToolCall {
        id: None,
        name: "file_read".to_string(),
        arguments: json!({ "path": path }),
    }
}

/// Helper to create a pattern_search tool call
pub fn make_pattern_search_tool(pattern: &str, path: &str) -> ToolCall {
    ToolCall {
        id: None,
        name: "pattern_search".to_string(),
        arguments: json!({ "pattern": pattern, "path": path }),
    }
}

/// Helper to create a file_write tool call
pub fn make_file_write_tool(path: &str, content: &str) -> ToolCall {
    ToolCall {
        id: None,
        name: "file_write".to_string(),
        arguments: json!({ "path": path, "content": content }),
    }
}

/// Helper to create a run_test tool call
pub fn make_run_test_tool(command: &str) -> ToolCall {
    ToolCall {
        id: None,
        name: "run_test".to_string(),
        arguments: json!({ "command": command }),
    }
}
