use crate::agent::ToolCall;
pub use crate::llm_metrics::LlmMetricsTracker;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod tgi;
pub use tgi::{CompletionOptions, TgiClient};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String, // Legacy: single model
    #[serde(default)]
    pub models: Vec<String>, // New: list of models
    pub timeout: u64,
    pub max_retries: u32,
    pub retry_backoff_ms: u64,
}

impl LlmConfig {
    /// Get list of models (supports backward compatibility)
    pub fn get_models(&self) -> Vec<String> {
        if !self.models.is_empty() {
            self.models.clone()
        } else if !self.model.is_empty() {
            vec![self.model.clone()]
        } else {
            vec![]
        }
    }
}

/// Round-robin selector for multiple models
pub struct ModelSelector {
    models: Vec<String>,
    index: AtomicUsize,
}

impl ModelSelector {
    pub fn new(models: Vec<String>) -> Self {
        Self {
            models,
            index: AtomicUsize::new(0),
        }
    }

    /// Get next model in round-robin fashion
    pub fn next(&self) -> Option<String> {
        if self.models.is_empty() {
            return None;
        }
        let idx = self.index.fetch_add(1, Ordering::SeqCst) % self.models.len();
        Some(self.models[idx].clone())
    }

    /// Get all models
    pub fn all_models(&self) -> Vec<String> {
        self.models.clone()
    }
}

/// Response from chat methods including the model used
#[derive(Debug, Clone)]
pub struct ChatResponseWithModel {
    pub content: String,
    pub model_used: String,
}

impl ChatResponseWithModel {
    pub fn new(content: String, model_used: String) -> Self {
        Self {
            content,
            model_used,
        }
    }
}

/// Represents a tool definition for function calling
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionToolDefinition {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub parameters: serde_json::Value,
}

/// Complete tool schema with OpenAI format
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolSchema {
    pub type_: String,
    pub function: FunctionToolDefinition,
}

/// Parsed response from chat_with_tools
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChatResponse {
    pub content: String,
    #[serde(default)]
    pub tool_calls: Vec<ToolCall>,
    #[serde(default)]
    pub raw: serde_json::Value,
    #[serde(default)]
    pub model_used: String,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            base_url: "https://api.openai.com/v1".to_string(),
            api_key: "".to_string(),
            model: "gpt-4".to_string(),
            models: vec![],
            timeout: 30,
            max_retries: 3,
            retry_backoff_ms: 1000,
        }
    }
}

#[derive(Clone)]
pub struct LlmClient {
    config: LlmConfig,
    model_selector: Option<Arc<ModelSelector>>,
    metrics_tracker: Option<LlmMetricsTracker>,
    tgi_client: Option<TgiClient>,
}

impl LlmClient {
    /// Get the current model name (uses first available model if config.model is empty)
    pub fn model_name(&self) -> String {
        self.get_current_model()
    }

    pub fn new(config: LlmConfig) -> Self {
        Self::with_metrics(config, None)
    }

    pub fn with_metrics(config: LlmConfig, tracker: Option<LlmMetricsTracker>) -> Self {
        let models = config.get_models();
        let model_selector = if models.len() > 1 {
            Some(Arc::new(ModelSelector::new(models)))
        } else {
            None
        };

        Self {
            config,
            model_selector,
            metrics_tracker: tracker,
            tgi_client: None,
        }
    }

    /// Attach a TGI client for specialized reasoning tasks
    pub fn with_tgi(mut self, config: &crate::config::TgiConfig) -> Result<Self, String> {
        if config.enabled {
            self.tgi_client = Some(TgiClient::new(config)?);
        }
        Ok(self)
    }

    /// Complete a prompt via TGI if available
    pub async fn complete_via_tgi(&self, prompt: &str) -> Option<Result<String, String>> {
        let client = self.tgi_client.as_ref()?;
        Some(client.complete(prompt).await)
    }

    /// Check if TGI client is available and healthy
    pub fn tgi_is_available(&self) -> bool {
        self.tgi_client.as_ref().is_some_and(|c| c.is_available())
    }

    /// Get current model (uses round-robin if multiple models configured)
    fn get_current_model(&self) -> String {
        if let Some(ref selector) = self.model_selector {
            selector.next().unwrap_or_else(|| {
                // Fallback to first available model if selector is exhausted
                selector.all_models().first().cloned().unwrap_or_default()
            })
        } else {
            // No selector: use config.model or first from config.models
            if !self.config.model.is_empty() {
                self.config.model.clone()
            } else if let Some(first) = self.config.models.first() {
                first.clone()
            } else {
                String::new()
            }
        }
    }

    /// Get all configured models
    pub fn get_all_models(&self) -> Vec<String> {
        if let Some(ref selector) = self.model_selector {
            selector.all_models()
        } else {
            vec![self.config.model.clone()]
        }
    }

    /// Helper to record metrics
    async fn record_metrics(&self, params: RecordMetricsParams) {
        if let Some(ref tracker) = self.metrics_tracker {
            tracker.record_request(params.into()).await;
        }
    }

    /// Try a single chat request against the given URL
    async fn try_chat_request(
        &self,
        base_url: &str,
        payload: serde_json::Value,
        messages_for_metrics: usize,
    ) -> Result<ChatResponseWithModel, String> {
        let url = format!("{}/v1/chat/completions", base_url);
        let model = self.get_current_model();
        let start_time = std::time::Instant::now();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(self.config.timeout))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let mut retries = 0;
        let max_attempts = self.config.max_retries;

        loop {
            tracing::debug!(
                "LLM request attempt {}/{} to {} (model: {})",
                retries + 1,
                max_attempts,
                url,
                model
            );

            let response = client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", self.config.api_key))
                .json(&payload)
                .send()
                .await;

            match response {
                Ok(resp) if resp.status().is_success() => {
                    let result: serde_json::Value = resp
                        .json()
                        .await
                        .map_err(|e| format!("Failed to parse response: {}", e))?;

                    let content = result
                        .get("choices")
                        .and_then(|c: &serde_json::Value| c.as_array())
                        .and_then(|arr: &Vec<serde_json::Value>| arr.first())
                        .and_then(|choice| choice.get("message"))
                        .and_then(|msg: &serde_json::Value| msg.get("content"))
                        .and_then(|c: &serde_json::Value| c.as_str())
                        .ok_or("Invalid response format")?;

                    let latency_ms = start_time.elapsed().as_millis() as u64;

                    // Record metrics
                    let tokens_prompt: usize = messages_for_metrics;
                    let tokens_completion: usize = content.len() / 4;
                    self.record_metrics(RecordMetricsParams {
                        model: model.clone(),
                        operation: "chat".to_string(),
                        phase: "unknown".to_string(),
                        tokens_prompt,
                        tokens_completion,
                        latency_ms,
                        success: true,
                    })
                    .await;

                    return Ok(ChatResponseWithModel::new(
                        content.to_string(),
                        model.clone(),
                    ));
                }
                Ok(resp) => {
                    let status = resp.status();
                    let error = resp.text().await.unwrap_or_default();
                    tracing::warn!(
                        "LLM request failed with status {} (attempt {}/{}) to {}",
                        status,
                        retries + 1,
                        max_attempts,
                        url
                    );
                    if retries + 1 >= max_attempts {
                        let latency_ms = start_time.elapsed().as_millis() as u64;
                        self.record_metrics(RecordMetricsParams {
                            model: model.clone(),
                            operation: "chat".to_string(),
                            phase: "unknown".to_string(),
                            tokens_prompt: 0,
                            tokens_completion: 0,
                            latency_ms,
                            success: false,
                        })
                        .await;

                        return Err(format!(
                            "LLM API request failed after {} retries to URL {}\nStatus: {}\nResponse: {}\nModel: {}",
                            max_attempts.saturating_sub(1),
                            url,
                            status,
                            error,
                            model
                        ));
                    }
                }
                Err(e) => {
                    let (status, url_e, kind) = get_error_details(&e);
                    tracing::warn!(
                        "LLM request error on model '{}': {}\n(status: {}, type: {}, url: {}) (attempt {}/{})",
                        model, e, status, kind, url_e, retries + 1, max_attempts
                    );
                    if retries + 1 >= max_attempts {
                        let latency_ms = start_time.elapsed().as_millis() as u64;
                        self.record_metrics(RecordMetricsParams {
                            model: model.clone(),
                            operation: "chat".to_string(),
                            phase: "unknown".to_string(),
                            tokens_prompt: 0,
                            tokens_completion: 0,
                            latency_ms,
                            success: false,
                        })
                        .await;

                        return Err(format!(
                            "LLM HTTP request failed after {} retries\nError: {:?}\nStatus: {}\nType: {}\nURL: {}\nModel: {}",
                            max_attempts.saturating_sub(1),
                            e,
                            status,
                            kind,
                            url_e,
                            model
                        ));
                    }
                }
            }

            retries += 1;
            let backoff = self.config.retry_backoff_ms * retries as u64;
            tokio::time::sleep(Duration::from_millis(backoff)).await;
        }
    }

    /// Try a single chat_with_tools request against the given URL
    async fn try_chat_with_tools_request(
        &self,
        base_url: &str,
        payload: serde_json::Value,
    ) -> Result<ChatResponse, String> {
        let url = format!("{}/v1/chat/completions", base_url);
        let model = self.get_current_model();
        let start_time = std::time::Instant::now();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(self.config.timeout))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let mut retries = 0;
        let max_attempts = self.config.max_retries;

        loop {
            tracing::debug!(
                "LLM request with tools attempt {}/{} to {} (model: {})",
                retries + 1,
                max_attempts,
                url,
                model
            );

            let response = client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", self.config.api_key))
                .json(&payload)
                .send()
                .await;

            match response {
                Ok(resp) if resp.status().is_success() => {
                    let result: serde_json::Value = resp
                        .json()
                        .await
                        .map_err(|e| format!("Failed to parse response: {}", e))?;

                    let choice = result
                        .get("choices")
                        .and_then(|c: &serde_json::Value| c.as_array())
                        .and_then(|arr: &Vec<serde_json::Value>| arr.first())
                        .ok_or("Invalid response format: no choices")?;

                    let message = choice
                        .get("message")
                        .ok_or("Invalid response format: no message")?;

                    let content = message
                        .get("content")
                        .and_then(|c: &serde_json::Value| c.as_str())
                        .unwrap_or("")
                        .to_string();

                    // Parse tool_calls if present
                    let tool_calls = message
                        .get("tool_calls")
                        .map(|tc| {
                            tc.as_array()
                                .unwrap_or(&vec![])
                                .iter()
                                .filter_map(|tc| {
                                    tc.get("function")
                                        .and_then(|f| f.get("name"))
                                        .and_then(|name| name.as_str())
                                        .map(|name| ToolCall {
                                            id: tc
                                                .get("id")
                                                .and_then(|i| i.as_str())
                                                .map(|s| s.to_string()),
                                            name: name.to_string(),
                                            arguments: tc
                                                .get("function")
                                                .and_then(|f| f.get("arguments"))
                                                .and_then(|a| a.as_object())
                                                .map(|o| {
                                                    serde_json::to_value(o).unwrap_or_default()
                                                })
                                                .unwrap_or_default(),
                                        })
                                })
                                .collect()
                        })
                        .unwrap_or_default();

                    let raw = result.clone();
                    let latency_ms = start_time.elapsed().as_millis() as u64;

                    // Record metrics
                    let tokens_prompt: usize = 0;
                    self.record_metrics(RecordMetricsParams {
                        model: model.clone(),
                        operation: "chat_with_tools".to_string(),
                        phase: "unknown".to_string(),
                        tokens_prompt,
                        tokens_completion: 0,
                        latency_ms,
                        success: true,
                    })
                    .await;

                    return Ok(ChatResponse {
                        content,
                        tool_calls,
                        raw,
                        model_used: model.clone(),
                    });
                }
                Ok(resp) => {
                    let status = resp.status();
                    let error = resp.text().await.unwrap_or_default();
                    tracing::warn!(
                        "LLM request with tools failed with status {} (attempt {}/{}) to {}",
                        status,
                        retries + 1,
                        max_attempts,
                        url
                    );
                    if retries + 1 >= max_attempts {
                        return Err(format!(
                            "LLM API request failed after {} retries to URL {}\nStatus: {}\nResponse: {}\nModel: {}",
                            max_attempts.saturating_sub(1),
                            url,
                            status,
                            error,
                            model
                        ));
                    }
                }
                Err(e) => {
                    let (status, url_e, kind) = get_error_details(&e);
                    tracing::warn!(
                        "LLM request error on model '{}': {}\n(status: {}, type: {}, url: {}) (attempt {}/{})",
                        model, e, status, kind, url_e, retries + 1, max_attempts
                    );
                    if retries + 1 >= max_attempts {
                        return Err(format!(
                            "LLM HTTP request failed after {} retries\nError: {:?}\nStatus: {}\nType: {}\nURL: {}\nEndpoint: {}chat/completions\nModel: {}",
                            max_attempts.saturating_sub(1),
                            e,
                            status,
                            kind,
                            url_e,
                            base_url,
                            model
                        ));
                    }
                }
            }

            retries += 1;
            let backoff = self.config.retry_backoff_ms * retries as u64;
            tokio::time::sleep(Duration::from_millis(backoff)).await;
        }
    }

    pub async fn chat(&self, messages: &[ChatMessage]) -> Result<ChatResponseWithModel, String> {
        let payload = serde_json::json!({
            "model": self.get_current_model(),
            "messages": messages,
            "temperature": 0.7
        });
        let tokens_prompt: usize = messages.iter().map(|m| m.content.len() / 4).sum();

        let chat_url = format!("{}/v1/chat/completions", self.config.base_url);
        tracing::info!("Trying LLM API at: {}", chat_url);

        match self
            .try_chat_request(&self.config.base_url, payload, tokens_prompt)
            .await
        {
            Ok(response) => Ok(response),
            Err(e) => {
                tracing::warn!("LLM API {} failed: {}", chat_url, e);
                Err("LLM API request failed".to_string())
            }
        }
    }

    /// Chat with tool capabilities - sends tools array to LLM for function calling
    pub async fn chat_with_tools(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolSchema],
    ) -> Result<ChatResponse, String> {
        let model = self.get_current_model();
        let payload = if tools.is_empty() {
            serde_json::json!({
                "model": model,
                "messages": messages,
                "temperature": 0.7
            })
        } else {
            serde_json::json!({
                "model": model,
                "messages": messages,
                "tools": tools,
                "tool_choice": "auto",
                "temperature": 0.7
            })
        };

        let chat_url = format!("{}/v1/chat/completions", self.config.base_url);
        tracing::info!("Trying LLM API (with tools) at: {}", chat_url);

        match self
            .try_chat_with_tools_request(&self.config.base_url, payload)
            .await
        {
            Ok(response) => Ok(response),
            Err(e) => {
                tracing::warn!("LLM API (with tools) {} failed: {}", chat_url, e);
                Err("LLM API request failed".to_string())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

impl ChatMessage {
    pub fn system(content: &str) -> Self {
        Self {
            role: "system".to_string(),
            content: content.to_string(),
        }
    }

    pub fn user(content: &str) -> Self {
        Self {
            role: "user".to_string(),
            content: content.to_string(),
        }
    }

    pub fn assistant(content: &str) -> Self {
        Self {
            role: "assistant".to_string(),
            content: content.to_string(),
        }
    }
}

pub trait LlmProvider {
    fn chat(&self, messages: &[ChatMessage]) -> Result<String, String>;
}

// Note: LlmProvider trait is kept for backwards compatibility
// LlmClient::chat is now async and should be used directly

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;

    mock! {
        #[derive(Debug)]
        pub LlmProvider {}

        impl LlmProvider for LlmProvider {
            fn chat(&self, messages: &[ChatMessage]) -> Result<String, String>;
        }
    }

    #[test]
    fn test_chat_message_creation() {
        let sys = ChatMessage::system("You are a security expert");
        assert_eq!(sys.role, "system");
        assert_eq!(sys.content, "You are a security expert");

        let user = ChatMessage::user("Analyze this code");
        assert_eq!(user.role, "user");
    }

    #[test]
    fn test_chat_message_assistant() {
        let assistant = ChatMessage::assistant("I found a vulnerability");
        assert_eq!(assistant.role, "assistant");
        assert_eq!(assistant.content, "I found a vulnerability");
    }

    #[test]
    fn test_llm_config_validation() {
        let config = LlmConfig {
            base_url: "https://api.test.com/v1".to_string(),
            api_key: "test-key".to_string(),
            model: "test-model".to_string(),
            models: vec![],
            timeout: 30,
            max_retries: 3,
            retry_backoff_ms: 1000,
        };
        assert_eq!(config.base_url, "https://api.test.com/v1");
        assert_eq!(config.model, "test-model");
    }

    #[test]
    fn test_llm_client_new() {
        let config = LlmConfig {
            base_url: "https://api.test.com/v1".to_string(),
            api_key: "test-key".to_string(),
            model: "test-model".to_string(),
            models: vec![],
            timeout: 30,
            max_retries: 3,
            retry_backoff_ms: 1000,
        };
        let client = LlmClient::new(config);
        assert!(client.config.base_url.contains("api.test.com"));
    }

    #[tokio::test]
    async fn test_mock_provider_chat_success() {
        let mut mock_provider = MockLlmProvider::new();
        mock_provider
            .expect_chat()
            .times(1)
            .returning(|_| Ok("Successfully analyzed".to_string()));

        let messages = vec![ChatMessage::user("Test message")];
        let result = mock_provider.chat(&messages);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Successfully analyzed");
    }

    #[tokio::test]
    async fn test_mock_provider_chat_error() {
        let mut mock_provider = MockLlmProvider::new();
        mock_provider
            .expect_chat()
            .times(1)
            .returning(|_| Err("API Error".to_string()));

        let messages = vec![ChatMessage::user("Test message")];
        let result = mock_provider.chat(&messages);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "API Error");
    }

    #[tokio::test]
    async fn test_mock_provider_with_different_messages() {
        let mut mock_provider = MockLlmProvider::new();
        mock_provider.expect_chat().times(1).returning(|messages| {
            assert_eq!(messages.len(), 2);
            Ok(format!("Responded to {} messages", messages.len()))
        });

        let messages = vec![
            ChatMessage::system("You are helpful"),
            ChatMessage::user("Hello"),
        ];
        let result = mock_provider.chat(&messages);
        assert!(result.is_ok());
    }

    #[test]
    fn test_chat_message_empty_content() {
        let empty = ChatMessage::user("");
        assert_eq!(empty.content, "");
        assert_eq!(empty.role, "user");
    }

    #[test]
    fn test_chat_message_long_content() {
        let long_content = "A".repeat(1000);
        let msg = ChatMessage::user(&long_content);
        assert_eq!(msg.content.len(), 1000);
    }
}

/// Parameters for record_metrics to reduce argument count
pub struct RecordMetricsParams {
    model: String,
    operation: String,
    phase: String,
    tokens_prompt: usize,
    tokens_completion: usize,
    latency_ms: u64,
    success: bool,
}

impl From<RecordMetricsParams> for crate::llm_metrics::RecordRequestParams {
    fn from(p: RecordMetricsParams) -> Self {
        crate::llm_metrics::RecordRequestParams {
            model_name: p.model,
            operation: p.operation,
            phase: p.phase,
            prompt_tokens: p.tokens_prompt as u64,
            completion_tokens: p.tokens_completion as u64,
            latency_ms: p.latency_ms,
            success: p.success,
        }
    }
}

/// Extract error details from reqwest error
fn get_error_details(e: &reqwest::Error) -> (String, String, &'static str) {
    let status = e
        .status()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "N/A".to_string());
    let url_e = e
        .url()
        .map(|u| u.to_string())
        .unwrap_or_else(|| "N/A".to_string());
    let kind = if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connection"
    } else if e.is_request() {
        "request"
    } else if e.is_body() {
        "body"
    } else if e.is_decode() {
        "decode"
    } else {
        "unknown"
    };
    (status, url_e, kind)
}

/// Helper to create LLM client with metrics from phase config
pub fn create_llm_client_with_metrics(
    scanner: &crate::scanner::Scanner,
    phase_name: &str,
) -> Option<LlmClient> {
    let phase_config = match phase_name {
        "discovery" => &scanner.config.llm.phases.discovery,
        "verification" => &scanner.config.llm.phases.verification,
        _ => return None,
    };

    let api_key = phase_config.api_key.as_ref()?;

    let llm_config = LlmConfig {
        base_url: phase_config.base_url.clone(),
        api_key: api_key.clone(),
        model: phase_config.model.clone(),
        models: phase_config.get_models(),
        timeout: scanner.config.llm.timeout_secs,
        max_retries: scanner.config.llm.max_retries as u32,
        retry_backoff_ms: scanner.config.llm.retry_backoff_ms,
    };

    Some(LlmClient::with_metrics(
        llm_config,
        Some(scanner.metrics_tracker.clone()),
    ))
}
