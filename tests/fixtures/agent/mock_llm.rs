use async_trait::async_trait;
use baco::agent::ToolCall;
use baco::agent::session::AgentLlmClient;
use baco::llm::{ChatMessage, ChatResponse, ToolSchema};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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
    fn next_response(&self) -> Result<ChatResponse, baco::error::ScanError> {
        let turn = self.turn_counter.fetch_add(1, Ordering::SeqCst);
        if turn >= self.responses.len() {
            return Err(baco::error::ScanError::Unknown(format!(
                "MockLlmClient: Exhausted pre-programmed responses (turn {} >= {})",
                turn,
                self.responses.len()
            )));
        }
        Ok(self.responses[turn].clone())
    }

    /// Execute a chat with tools - returns the next pre-programmed response
    pub async fn chat_with_tools(
        &self,
        _messages: &[ChatMessage],
        _tools: &[ToolSchema],
    ) -> Result<ChatResponse, baco::error::ScanError> {
        let mut resp = self.next_response()?;
        // Ensure the response uses our configured model name
        resp.model_used = self.model_name.clone();
        Ok(resp)
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
    ) -> Result<ChatResponse, baco::error::ScanError> {
        self.next_response()
    }
    fn model_name(&self) -> String {
        self.model_name.clone()
    }
}

// ============================================================================
// Unit tests for MockLlmClient itself
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_mock_llm_exhausts_responses() {
        let responses = vec![
            MockLlmClient::mock_final_response("first"),
            MockLlmClient::mock_final_response("second"),
        ];
        let client = MockLlmClient::new(responses);

        // First two calls should succeed
        let r1 = client.chat_with_tools(&[], &[]).await;
        assert!(r1.is_ok());
        assert_eq!(r1.unwrap().content, "first");

        let r2 = client.chat_with_tools(&[], &[]).await;
        assert!(r2.is_ok());
        assert_eq!(r2.unwrap().content, "second");

        // Third call should fail
        let r3 = client.chat_with_tools(&[], &[]).await;
        assert!(r3.is_err());
        assert!(r3.unwrap_err().to_string().contains("Exhausted"));
    }

    #[tokio::test]
    async fn test_mock_llm_custom_model_name() {
        let responses = vec![MockLlmClient::mock_final_response("test")];
        let client = MockLlmClient::with_model(responses, "custom-v2".to_string());

        assert_eq!(client.model_name(), "custom-v2");

        let r = client.chat_with_tools(&[], &[]).await;
        assert!(r.is_ok());
        assert_eq!(r.unwrap().model_used, "custom-v2");
    }

    #[test]
    fn test_mock_tool_call_structure() {
        let response = MockLlmClient::mock_tool_call("file_read", json!({ "path": "test.rs" }));

        assert_eq!(response.tool_calls.len(), 1);
        assert_eq!(response.tool_calls[0].name, "file_read");
        assert!(response.content.contains("file_read"));
    }

    #[test]
    fn test_mock_final_response_structure() {
        let response = MockLlmClient::mock_final_response("all clear");

        assert!(response.tool_calls.is_empty());
        assert_eq!(response.content, "all clear");
    }

    #[tokio::test]
    async fn test_mock_llm_response_count() {
        let responses = vec![
            MockLlmClient::mock_final_response("1"),
            MockLlmClient::mock_final_response("2"),
            MockLlmClient::mock_final_response("3"),
        ];
        let client = MockLlmClient::new(responses);

        assert_eq!(client.response_count(), 3);
    }
}
