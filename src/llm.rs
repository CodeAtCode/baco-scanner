use crate::agent::ToolCall;
use crate::error::ScanError;
pub use crate::llm_cache;
pub use crate::llm_metrics::LlmMetricsTracker;
use crate::rate_limiter::RateLimiter;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

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
    #[serde(default = "default_runtime_temperature")]
    pub temperature: f32,
    #[serde(default)]
    pub max_reasoning_tokens: Option<usize>,
    #[serde(default)]
    pub enable_llm_cache: bool,
    #[serde(default)]
    pub cache_dir: Option<String>,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
}

fn default_max_concurrent() -> usize {
    3
}

fn default_runtime_temperature() -> f32 {
    0.5
}

/// Build the chat-completions endpoint, tolerating base URLs that already
/// include the `/v1` prefix (the documented convention for OpenAI/Mistral).
pub fn chat_endpoint(base_url: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let base = base.strip_suffix("/v1").unwrap_or(base);
    format!("{}/v1/chat/completions", base)
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

/// JSON schema for structured outputs (response_format)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JsonSchema {
    pub name: String,
    #[serde(default)]
    pub strict: bool,
    #[serde(default)]
    pub schema: serde_json::Value,
}

/// Response format configuration for structured JSON outputs
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseFormat {
    #[serde(default, rename = "type")]
    pub type_: String, // "json_schema"
    #[serde(default)]
    pub json_schema: JsonSchema,
}

/// Complete tool schema with OpenAI format
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolSchema {
    #[serde(rename = "type")]
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
            temperature: 0.5,
            max_reasoning_tokens: None,
            enable_llm_cache: false,
            cache_dir: None,
            max_concurrent: 3,
        }
    }
}

/// Shared HTTP client, initialized once
static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn get_client() -> &'static reqwest::Client {
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client")
    })
}

#[derive(Clone)]
pub struct LlmClient {
    pub config: LlmConfig,
    model_selector: Option<Arc<ModelSelector>>,
    metrics_tracker: Option<LlmMetricsTracker>,
    rate_limiter: Arc<RateLimiter>,
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

        let max_concurrent = config.max_concurrent.max(1);
        let rate_limiter = Arc::new(RateLimiter::new(max_concurrent));

        Self {
            config,
            model_selector,
            metrics_tracker: tracker,
            rate_limiter,
        }
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

    /// Classify whether a response status should be retried.
    /// Returns (should_retry, retry_after_secs).
    pub fn classify_retryable(status: u16, retry_after: Option<u64>) -> (bool, Option<u64>) {
        match status {
            // Fail fast on client errors
            400 => (false, None),
            401 | 403 => (false, None),
            // Retry on timeout, rate limit, and server errors
            408 | 429 | 500..=599 => {
                if status == 429 {
                    // Honor Retry-After header on 429
                    (true, retry_after)
                } else {
                    (true, None)
                }
            }
            _ => (false, None),
        }
    }

    /// Try a single chat request against the given URL
    async fn try_chat_request(
        &self,
        base_url: &str,
        payload: serde_json::Value,
        messages_for_metrics: usize,
    ) -> Result<ChatResponseWithModel, ScanError> {
        let url = chat_endpoint(base_url);
        let model = self.get_current_model();
        let start_time = std::time::Instant::now();

        // Acquire rate limiter permit
        let _permit = self
            .rate_limiter
            .acquire()
            .await
            .map_err(|e| format!("Failed to acquire rate limiter permit: {}", e))?;

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

            let response = get_client()
                .post(&url)
                .timeout(Duration::from_secs(self.config.timeout))
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", self.config.api_key))
                .json(&payload)
                .send()
                .await;

            match response {
                Ok(resp) if resp.status().is_success() => {
                    let result: serde_json::Value = resp.json().await?;

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
                    let status = resp.status().as_u16();

                    // Extract Retry-After header before consuming resp
                    let retry_after = resp
                        .headers()
                        .get("Retry-After")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok());

                    let error = resp.text().await.unwrap_or_default();
                    tracing::warn!(
                        "LLM request failed with status {} (attempt {}/{}) to {}",
                        status,
                        retries + 1,
                        max_attempts,
                        url
                    );

                    // Classify the error
                    let (should_retry, _) = Self::classify_retryable(status, retry_after);

                    // Fail fast on 400/401/403
                    if status == 400 {
                        return Err(ScanError::Parse {
                            message: format!(
                                "Malformed LLM request (400): {}",
                                error.chars().take(200).collect::<String>()
                            ),
                            source: None,
                        });
                    }
                    if status == 401 || status == 403 {
                        return Err(ScanError::Auth {
                            message: "LLM authentication failed (401/403) — check the API key"
                                .to_string(),
                            source: None,
                        });
                    }

                    if !should_retry || retries + 1 >= max_attempts {
                        record_failure_metrics(
                            self,
                            model.clone(),
                            start_time.elapsed().as_millis() as u64,
                        )
                        .await;

                        return Err(ScanError::Server {
                            message: format!(
                                "LLM API request failed after {} retries to URL {}\nStatus: {}\nResponse: {}\nModel: {}",
                                max_attempts.saturating_sub(1),
                                url,
                                status,
                                error,
                                model
                            ),
                            source: None,
                        });
                    }

                    // Honor Retry-After on 429
                    let backoff = match (status, retry_after) {
                        (429, Some(secs)) => secs * 1000,
                        _ => self.config.retry_backoff_ms * (retries + 1) as u64,
                    };
                    retries += 1;
                    tracing::debug!("Retrying after {}ms", backoff);
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                }
                Err(e) => {
                    // Network/timeout errors are retryable
                    let is_timeout = e.is_timeout();
                    let (status, url_e, kind) = get_error_details(&e);
                    tracing::warn!(
                        "LLM request error on model '{}': {}\n(status: {}, type: {}, url: {}) (attempt {}/{})",
                        model, e, status, kind, url_e, retries + 1, max_attempts
                    );

                    if !is_timeout && retries + 1 >= max_attempts {
                        record_failure_metrics(
                            self,
                            model.clone(),
                            start_time.elapsed().as_millis() as u64,
                        )
                        .await;

                        return Err(ScanError::Network {
                            message: format!(
                                "LLM HTTP request failed after {} retries\nError: {:?}\nStatus: {}\nType: {}\nURL: {}\nModel: {}",
                                max_attempts.saturating_sub(1),
                                e,
                                status,
                                kind,
                                url_e,
                                model
                            ),
                            source: Some(Box::new(e) as _),
                        });
                    }

                    retries += 1;
                    let backoff = self.config.retry_backoff_ms * retries as u64;
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                }
            }
        }
    }

    /// Try a single chat_with_tools request against the given URL
    async fn try_chat_with_tools_request(
        &self,
        base_url: &str,
        payload: serde_json::Value,
    ) -> Result<ChatResponse, ScanError> {
        let url = chat_endpoint(base_url);
        let model = self.get_current_model();
        let start_time = std::time::Instant::now();

        // Acquire rate limiter permit
        let _permit = self
            .rate_limiter
            .acquire()
            .await
            .map_err(|e| format!("Failed to acquire rate limiter permit: {}", e))?;

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

            let response = get_client()
                .post(&url)
                .timeout(Duration::from_secs(self.config.timeout))
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", self.config.api_key))
                .json(&payload)
                .send()
                .await;

            match response {
                Ok(resp) if resp.status().is_success() => {
                    let result: serde_json::Value = resp.json().await?;

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
                    let status = resp.status().as_u16();

                    // Extract Retry-After header before consuming resp
                    let retry_after = resp
                        .headers()
                        .get("Retry-After")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok());

                    let error = resp.text().await.unwrap_or_default();
                    tracing::warn!(
                        "LLM request with tools failed with status {} (attempt {}/{}) to {}",
                        status,
                        retries + 1,
                        max_attempts,
                        url
                    );

                    // Classify the error
                    let (should_retry, _) = Self::classify_retryable(status, retry_after);

                    // Fail fast on 400/401/403
                    if status == 400 {
                        return Err(ScanError::Parse {
                            message: format!(
                                "Malformed LLM request (400): {}",
                                error.chars().take(200).collect::<String>()
                            ),
                            source: None,
                        });
                    }
                    if status == 401 || status == 403 {
                        return Err(ScanError::Auth {
                            message: "LLM authentication failed (401/403) — check the API key"
                                .to_string(),
                            source: None,
                        });
                    }

                    if !should_retry || retries + 1 >= max_attempts {
                        return Err(ScanError::Server {
                            message: format!(
                                "LLM API request failed after {} retries to URL {}\nStatus: {}\nResponse: {}\nModel: {}",
                                max_attempts.saturating_sub(1),
                                url,
                                status,
                                error,
                                model
                            ),
                            source: None,
                        });
                    }

                    // Honor Retry-After on 429
                    let backoff = match (status, retry_after) {
                        (429, Some(secs)) => secs * 1000,
                        _ => self.config.retry_backoff_ms * (retries + 1) as u64,
                    };
                    retries += 1;
                    tracing::debug!("Retrying after {}ms", backoff);
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                }
                Err(e) => {
                    // Network/timeout errors are retryable
                    let is_timeout = e.is_timeout();
                    let (status, url_e, kind) = get_error_details(&e);
                    tracing::warn!(
                        "LLM request error on model '{}': {}\n(status: {}, type: {}, url: {}) (attempt {}/{})",
                        model, e, status, kind, url_e, retries + 1, max_attempts
                    );

                    if !is_timeout && retries + 1 >= max_attempts {
                        return Err(ScanError::Network {
                            message: format!(
                                "LLM HTTP request failed after {} retries\nError: {:?}\nStatus: {}\nType: {}\nURL: {}\nEndpoint: {}chat/completions\nModel: {}",
                                max_attempts.saturating_sub(1),
                                e,
                                status,
                                kind,
                                url_e,
                                base_url,
                                model
                            ),
                            source: Some(Box::new(e) as _),
                        });
                    }

                    retries += 1;
                    let backoff = self.config.retry_backoff_ms * retries as u64;
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                }
            }
        }
    }

    /// Build chat payload with optional structured output support
    fn build_chat_payload(
        &self,
        model: &str,
        messages: &[ChatMessage],
        response_format: Option<&ResponseFormat>,
    ) -> serde_json::Value {
        let mut payload = serde_json::json!({
            "model": model,
            "messages": messages,
            "temperature": self.config.temperature
        });

        if let Some(max_tokens) = self.config.max_reasoning_tokens {
            payload["max_tokens"] = serde_json::json!(max_tokens);
        }

        // Add response_format for structured JSON outputs
        if let Some(format) = response_format {
            payload["response_format"] = serde_json::to_value(format).unwrap_or_default();
            // Lower temperature for structured outputs if not explicitly set
            if self.config.temperature == default_runtime_temperature() {
                payload["temperature"] = serde_json::json!(0.2);
            }
        }

        payload
    }

    pub async fn chat(&self, messages: &[ChatMessage]) -> Result<ChatResponseWithModel, ScanError> {
        let model = self.get_current_model();
        let payload = Self::build_chat_payload(self, &model, messages, None);

        let tokens_prompt: usize = messages.iter().map(|m| m.content.len() / 4).sum();

        // Check cache if enabled
        if self.config.enable_llm_cache {
            let cache_dir =
                crate::llm_cache::get_effective_cache_dir(self.config.cache_dir.as_ref());

            // Compute cache key
            let messages_json = serde_json::to_vec(messages)
                .map_err(|e| format!("Failed to serialize messages: {}", e))?;
            let cache_key = crate::llm_cache::compute_cache_key(
                &model,
                &self.config.base_url,
                self.config.temperature,
                self.config.max_reasoning_tokens,
                &messages_json,
            );

            // Try to read from cache
            match crate::llm_cache::read_cached_response(&cache_dir, &cache_key) {
                Ok(Some(cached_content)) => {
                    tracing::info!("Cache hit for key {}", cache_key);
                    // Record cached request metric
                    if let Some(ref tracker) = self.metrics_tracker {
                        tracker
                            .record_cached_request(&model, "chat", "unknown", tokens_prompt as u64)
                            .await;
                    }
                    // Parse cached response
                    let cached_response: serde_json::Value = serde_json::from_str(&cached_content)
                        .map_err(|e| format!("Failed to parse cached response: {}", e))?;
                    let content = cached_response
                        .get("content")
                        .and_then(|c| c.as_str())
                        .unwrap_or("")
                        .to_string();
                    return Ok(ChatResponseWithModel::new(content, model));
                }
                Ok(None) => {
                    tracing::debug!("Cache miss for key {}", cache_key);
                }
                Err(e) => {
                    tracing::warn!("Cache read error: {}", e);
                }
            }
        }

        let chat_url = chat_endpoint(&self.config.base_url);
        tracing::info!("Trying LLM API at: {}", chat_url);

        match self
            .try_chat_request(&self.config.base_url, payload, tokens_prompt)
            .await
        {
            Ok(response) => {
                // Best-effort write to cache if enabled
                if self.config.enable_llm_cache {
                    let cache_dir =
                        crate::llm_cache::get_effective_cache_dir(self.config.cache_dir.as_ref());
                    let messages_json = serde_json::to_vec(messages)
                        .map_err(|e| format!("Failed to serialize messages: {}", e))?;
                    let cache_key = crate::llm_cache::compute_cache_key(
                        &model,
                        &self.config.base_url,
                        self.config.temperature,
                        self.config.max_reasoning_tokens,
                        &messages_json,
                    );
                    let cache_content = serde_json::json!({
                        "content": response.content,
                        "model": response.model_used,
                        "timestamp": chrono::Utc::now().to_rfc3339()
                    })
                    .to_string();
                    if let Err(e) = crate::llm_cache::write_cached_response(
                        &cache_dir,
                        &cache_key,
                        &cache_content,
                    ) {
                        tracing::warn!("Failed to write cache: {}", e);
                    }
                }
                Ok(response)
            }
            Err(e) => {
                tracing::warn!("LLM API {} failed: {}", chat_url, e);
                Err(ScanError::Network {
                    message: "LLM API request failed".to_string(),
                    source: None,
                })
            }
        }
    }

    /// Chat with structured JSON output using JSON schema
    /// When schema is provided, sets response_format with json_schema type and strict mode
    /// Also lowers temperature to 0.2 if using default temperature
    pub async fn chat_with_json_schema(
        &self,
        messages: &[ChatMessage],
        schema_name: &str,
        json_schema: serde_json::Value,
    ) -> Result<ChatResponseWithModel, ScanError> {
        let model = self.get_current_model();

        let response_format = ResponseFormat {
            type_: "json_schema".to_string(),
            json_schema: JsonSchema {
                name: schema_name.to_string(),
                strict: true,
                schema: json_schema,
            },
        };

        let payload = Self::build_chat_payload(self, &model, messages, Some(&response_format));

        let tokens_prompt: usize = messages.iter().map(|m| m.content.len() / 4).sum();

        let chat_url = chat_endpoint(&self.config.base_url);
        tracing::info!("Trying LLM API with JSON schema at: {}", chat_url);

        match self
            .try_chat_request(&self.config.base_url, payload, tokens_prompt)
            .await
        {
            Ok(response) => Ok(response),
            Err(e) => {
                tracing::warn!("LLM API with JSON schema {} failed: {}", chat_url, e);
                Err(ScanError::Network {
                    message: "LLM API request with JSON schema failed".to_string(),
                    source: None,
                })
            }
        }
    }

    /// Chat with tool capabilities - sends tools array to LLM for function calling
    pub async fn chat_with_tools(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolSchema],
    ) -> Result<ChatResponse, ScanError> {
        let model = self.get_current_model();
        let payload = Self::build_chat_payload(self, &model, messages, None);
        let mut payload = if !tools.is_empty() {
            let mut p = payload;
            p["tools"] = serde_json::to_value(tools).unwrap_or_default();
            p["tool_choice"] = serde_json::json!("auto");
            p
        } else {
            payload
        };

        if let Some(max_tokens) = self.config.max_reasoning_tokens {
            payload["max_tokens"] = serde_json::json!(max_tokens);
        }

        // Check cache if enabled
        if self.config.enable_llm_cache {
            let cache_dir =
                crate::llm_cache::get_effective_cache_dir(self.config.cache_dir.as_ref());

            // Compute cache key (include tools in the key)
            let payload_for_cache = serde_json::to_vec(&payload)
                .map_err(|e| format!("Failed to serialize payload: {}", e))?;
            let cache_key = crate::llm_cache::compute_cache_key(
                &model,
                &self.config.base_url,
                self.config.temperature,
                self.config.max_reasoning_tokens,
                &payload_for_cache,
            );

            // Try to read from cache
            match crate::llm_cache::read_cached_response(&cache_dir, &cache_key) {
                Ok(Some(cached_content)) => {
                    tracing::info!("Cache hit for key {}", cache_key);
                    // Record cached request metric
                    if let Some(ref tracker) = self.metrics_tracker {
                        tracker
                            .record_cached_request(&model, "chat_with_tools", "unknown", 0)
                            .await;
                    }
                    // Parse cached response
                    let cached_response: serde_json::Value = serde_json::from_str(&cached_content)
                        .map_err(|e| format!("Failed to parse cached response: {}", e))?;
                    let content = cached_response
                        .get("content")
                        .and_then(|c| c.as_str())
                        .unwrap_or("")
                        .to_string();
                    return Ok(ChatResponse {
                        content,
                        tool_calls: vec![],
                        raw: cached_response,
                        model_used: model,
                    });
                }
                Ok(None) => {
                    tracing::debug!("Cache miss for key {}", cache_key);
                }
                Err(e) => {
                    tracing::warn!("Cache read error: {}", e);
                }
            }
        }

        let chat_url = chat_endpoint(&self.config.base_url);
        tracing::info!("Trying LLM API (with tools) at: {}", chat_url);

        match self
            .try_chat_with_tools_request(&self.config.base_url, payload.clone())
            .await
        {
            Ok(response) => {
                // Best-effort write to cache if enabled
                if self.config.enable_llm_cache {
                    let cache_dir =
                        crate::llm_cache::get_effective_cache_dir(self.config.cache_dir.as_ref());
                    let payload_for_cache = serde_json::to_vec(&payload)
                        .map_err(|e| format!("Failed to serialize payload: {}", e))?;
                    let cache_key = crate::llm_cache::compute_cache_key(
                        &model,
                        &self.config.base_url,
                        self.config.temperature,
                        self.config.max_reasoning_tokens,
                        &payload_for_cache,
                    );
                    let cache_content = serde_json::json!({
                        "content": response.content,
                        "model": response.model_used,
                        "timestamp": chrono::Utc::now().to_rfc3339()
                    })
                    .to_string();
                    if let Err(e) = crate::llm_cache::write_cached_response(
                        &cache_dir,
                        &cache_key,
                        &cache_content,
                    ) {
                        tracing::warn!("Failed to write cache: {}", e);
                    }
                }
                Ok(response)
            }
            Err(e) => {
                tracing::warn!("LLM API (with tools) {} failed: {}", chat_url, e);
                Err(ScanError::Network {
                    message: "LLM API request failed".to_string(),
                    source: None,
                })
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

/// Async trait for LLM chat clients - enables testing with mock implementations
#[allow(async_fn_in_trait)]
#[cfg_attr(test, mockall::automock)]
pub trait LlmChatClient: Send + Sync {
    async fn chat(&self, messages: &[ChatMessage]) -> Result<ChatResponseWithModel, ScanError>;
}

/// Implement LlmChatClient for LlmClient
impl LlmChatClient for LlmClient {
    async fn chat(&self, messages: &[ChatMessage]) -> Result<ChatResponseWithModel, ScanError> {
        self.chat(messages).await
    }
}

pub trait LlmProvider {
    fn chat(&self, messages: &[ChatMessage]) -> Result<String, ScanError>;
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

pub fn create_llm_client_with_metrics(
    scanner: &crate::scanner::Scanner,
    phase_name: &str,
) -> Option<LlmClient> {
    let phase_config = match phase_name {
        "discovery" => &scanner.config.llm.phases.discovery,
        "verification" => &scanner.config.llm.phases.verification,
        _ => return None,
    };

    let api_key = phase_config.api_key.as_ref();
    if api_key.is_none() {
        eprintln!(
                "\u{1B}[33m[SCANNER] {} skipped: LLM not configured (set LLM_API_KEY or llm.api_key)\u{1B}[0m",
                phase_name
            );
    }

    // Use the new unified helper for consistency
    let llm_config = phase_llm_config(&scanner.config, phase_name, None);

    Some(LlmClient::with_metrics(
        llm_config,
        Some(scanner.metrics_tracker.clone()),
    ))
}

/// Helper to record failure metrics for failed LLM requests
async fn record_failure_metrics(client: &LlmClient, model: String, latency_ms: u64) {
    client
        .record_metrics(RecordMetricsParams {
            model,
            operation: "chat".to_string(),
            phase: "unknown".to_string(),
            tokens_prompt: 0,
            tokens_completion: 0,
            latency_ms,
            success: false,
        })
        .await;
}

// ============================================================================
// Unified LLM Config Construction (T26)
// ============================================================================

use crate::config::ScannerConfig;

/// Build LlmConfig for a specific phase from ScannerConfig
/// Reads base_url/api_key/timeout/temperature/max_concurrent/max_reasoning_tokens from global config,
/// applies [llm.phases.<phase>] overrides if present, NEVER hardcodes temperature.
pub fn phase_llm_config(
    scanner_config: &ScannerConfig,
    phase: &str,
    model_override: Option<&str>,
) -> LlmConfig {
    // Get global LLM settings
    let global_llm = &scanner_config.llm;

    // Get phase-specific config if available
    let phase_config = get_phase_config(&global_llm.phases, phase);

    // Build base_url: phase override > global
    let base_url = if !phase_config.base_url.is_empty() {
        phase_config.base_url.clone()
    } else {
        // Default OpenAI endpoint
        "https://api.openai.com/v1".to_string()
    };

    // Build api_key: phase override > env var > empty
    let api_key = phase_config
        .api_key
        .clone()
        .or_else(|| std::env::var("LLM_API_KEY").ok())
        .unwrap_or_default();

    // Build model: override param > phase models > phase model > global
    let model = if let Some(override_model) = model_override {
        override_model.to_string()
    } else if !phase_config.get_models().is_empty() {
        phase_config.get_models()[0].clone()
    } else if !phase_config.model.is_empty() {
        phase_config.model.clone()
    } else {
        "gpt-4".to_string()
    };

    // Build timeout: phase override > global
    let timeout = phase_config.timeout_secs.unwrap_or(global_llm.timeout_secs);

    // Temperature: phase override > global - NEVER hardcode
    let temperature = phase_config.temperature.unwrap_or(global_llm.temperature);

    LlmConfig {
        base_url,
        api_key,
        model,
        models: vec![],
        timeout,
        max_retries: global_llm.max_retries as u32,
        retry_backoff_ms: global_llm.retry_backoff_ms,
        temperature,
        max_reasoning_tokens: global_llm.max_reasoning_tokens,
        enable_llm_cache: global_llm.enable_llm_cache,
        cache_dir: global_llm.cache_dir.clone(),
        max_concurrent: global_llm.max_concurrent,
    }
}

/// Get phase config by name from LlmPhasesConfig
fn get_phase_config(
    phases: &crate::config::LlmPhasesConfig,
    phase: &str,
) -> crate::config::LlmPhaseConfig {
    // Match phase name to config field
    match phase {
        "discovery" => phases.discovery.clone(),
        "verification" => phases.verification.clone(),
        "aggregation" => phases.aggregation.clone(),
        "semgrep" => phases.semgrep.clone(),
        "ticket_crossref" => phases.ticket_crossref.clone(),
        "git_analysis" => phases.git_analysis.clone(),
        "cross_file_analysis" => phases.cross_file_analysis.clone(),
        "confidence_scoring" => phases.confidence_scoring.clone(),
        "ai_aggregation" => phases.ai_aggregation.clone(),
        "reporting" => phases.reporting.clone(),
        "indexing" => phases.indexing.clone(),
        "static_analysis" => {
            // static_analysis uses discovery config as fallback
            phases.discovery.clone()
        }
        _ => crate::config::LlmPhaseConfig::default(),
    }
}
