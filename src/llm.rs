use crate::agent::ToolCall;
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
    config: LlmConfig,
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
    ) -> Result<ChatResponseWithModel, String> {
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
                        return Err(format!(
                            "Malformed LLM request (400): {}",
                            error.chars().take(200).collect::<String>()
                        ));
                    }
                    if status == 401 || status == 403 {
                        return Err(
                            "LLM authentication failed (401/403) — check the API key".to_string()
                        );
                    }

                    if !should_retry || retries + 1 >= max_attempts {
                        record_failure_metrics(
                            self,
                            model.clone(),
                            start_time.elapsed().as_millis() as u64,
                        )
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
    ) -> Result<ChatResponse, String> {
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
                        return Err(format!(
                            "Malformed LLM request (400): {}",
                            error.chars().take(200).collect::<String>()
                        ));
                    }
                    if status == 401 || status == 403 {
                        return Err(
                            "LLM authentication failed (401/403) — check the API key".to_string()
                        );
                    }

                    if !should_retry || retries + 1 >= max_attempts {
                        return Err(format!(
                            "LLM API request failed after {} retries to URL {}\nStatus: {}\nResponse: {}\nModel: {}",
                            max_attempts.saturating_sub(1),
                            url,
                            status,
                            error,
                            model
                        ));
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

                    retries += 1;
                    let backoff = self.config.retry_backoff_ms * retries as u64;
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                }
            }
        }
    }

    pub async fn chat(&self, messages: &[ChatMessage]) -> Result<ChatResponseWithModel, String> {
        let model = self.get_current_model();
        let mut payload = serde_json::json!({
            "model": model,
            "messages": messages,
            "temperature": self.config.temperature
        });

        if let Some(max_tokens) = self.config.max_reasoning_tokens {
            payload["max_tokens"] = serde_json::json!(max_tokens);
        }

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
        let mut payload = if tools.is_empty() {
            serde_json::json!({
                "model": model,
                "messages": messages,
                "temperature": self.config.temperature
            })
        } else {
            serde_json::json!({
                "model": model,
                "messages": messages,
                "tools": tools,
                "tool_choice": "auto",
                "temperature": self.config.temperature
            })
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
            temperature: 0.5,
            ..Default::default()
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
            temperature: 0.5,
            ..Default::default()
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

    let api_key = api_key?;

    let llm_config = LlmConfig {
        base_url: phase_config.base_url.clone(),
        api_key: api_key.clone(),
        model: phase_config.model.clone(),
        models: phase_config.get_models(),
        timeout: scanner.config.llm.timeout_secs,
        max_retries: scanner.config.llm.max_retries as u32,
        retry_backoff_ms: scanner.config.llm.retry_backoff_ms,
        temperature: 0.5,
        max_reasoning_tokens: scanner.config.llm.max_reasoning_tokens,
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 3,
    };

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
