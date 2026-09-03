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
    fn next_response(&self) -> Result<ChatResponse, crate::error::ScanError> {
        let turn = self.turn_counter.fetch_add(1, Ordering::SeqCst);
        if turn >= self.responses.len() {
            return Err(crate::error::ScanError::Unknown(format!(
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
    ) -> Result<ChatResponse, crate::error::ScanError> {
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
    ) -> Result<ChatResponse, crate::error::ScanError> {
        self.next_response()
    }
    fn model_name(&self) -> String {
        self.model_name.clone()
    }
}
