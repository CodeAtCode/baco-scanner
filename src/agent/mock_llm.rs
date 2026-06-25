use crate::agent::session::AgentLlmClient;
use crate::agent::ToolCall;
use crate::llm::{ChatMessage, ChatResponse, ToolSchema};
use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Mock LLM client for testing without calling real LLM endpoints
/// Implements LlmClient trait with pre-programmed responses
pub struct MockLlmClient {
    /// Pre-programmed responses in predetermined order
    responses: Vec<ChatResponse>,
    /// Current turn counter (thread-safe)
    turn_counter: Arc<AtomicUsize>,
    /// Model name to report
    model_name: String,
}

impl MockLlmClient {
    /// Create a new MockLlmClient with a sequence of pre-programmed responses
    pub fn new(responses: Vec<ChatResponse>) -> Self {
        Self {
            responses,
            turn_counter: Arc::new(AtomicUsize::new(0)),
            model_name: "mock-model".to_string(),
        }
    }

    /// Create a new MockLlmClient with custom model name
    pub fn with_model(responses: Vec<ChatResponse>, model_name: String) -> Self {
        Self {
            responses,
            turn_counter: Arc::new(AtomicUsize::new(0)),
            model_name,
        }
    }

    /// Get the model name
    pub fn model_name(&self) -> String {
        self.model_name.clone()
    }

    /// Get the number of pre-programmed responses
    pub fn response_count(&self) -> usize {
        self.responses.len()
    }

    /// Get the next response from the sequence, returning error if exhausted
    fn next_response(&self) -> Result<ChatResponse, String> {
        let turn = self.turn_counter.fetch_add(1, Ordering::SeqCst);
        if turn >= self.responses.len() {
            return Err(format!(
                "MockLlmClient: Exhausted pre-programmed responses (turn {} >= {})",
                turn,
                self.responses.len()
            ));
        }
        Ok(self.responses[turn].clone())
    }

    /// Execute a chat with tools - returns the next pre-programmed response
    pub async fn chat_with_tools(
        &self,
        _messages: &[ChatMessage],
        _tools: &[ToolSchema],
    ) -> Result<ChatResponse, String> {
        self.next_response()
    }

    /// Helper to create a ChatResponse with tool_calls
    pub fn mock_tool_call(tool_name: &str, arguments: serde_json::Value) -> ChatResponse {
        let args_str = serde_json::to_string(&arguments).unwrap_or_default();
        ChatResponse {
            content: format!("Executing tool: {}", tool_name),
            tool_calls: vec![ToolCall {
                id: Some("call_123".to_string()),
                name: tool_name.to_string(),
                arguments,
            }],
            raw: serde_json::json!({
                "choices": [{
                    "message": {
                        "content": format!("Executing tool: {}", tool_name),
                        "tool_calls": [{
                            "id": "call_123",
                            "function": {
                                "name": tool_name,
                                "arguments": args_str
                            }
                        }]
                    }
                }]
            }),
            model_used: "mock-model".to_string(),
        }
    }

    /// Helper to create a ChatResponse with no tool_calls (convergence)
    pub fn mock_final_response(content: &str) -> ChatResponse {
        ChatResponse {
            content: content.to_string(),
            tool_calls: vec![],
            raw: serde_json::json!({
                "choices": [{
                    "message": {
                        "content": content.to_string(),
                        "tool_calls": null
                    }
                }]
            }),
            model_used: "mock-model".to_string(),
        }
    }
}

impl Default for MockLlmClient {
    fn default() -> Self {
        Self::new(vec![])
    }
}

/// Implement the agent client trait for MockLlmClient
#[async_trait]
impl AgentLlmClient for MockLlmClient {
    async fn chat_with_tools(
        &self,
        _messages: &[ChatMessage],
        _tools: &[ToolSchema],
    ) -> Result<ChatResponse, String> {
        self.next_response()
    }
    fn model_name(&self) -> String {
        self.model_name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let err_msg = result.unwrap_err();
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
            tool_calls: vec![ToolCall {
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
}
