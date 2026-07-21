//! TGI (Text Generation Inference) client for specialized reasoning LLMs
//!
//! This module provides a client for communicating with Hugging Face's TGI server,
//! which can serve models like R2Vul and VULPO for vulnerability detection.
//!
//! References:
//! - R2Vul: arxiv.org/abs/2504.04699
//! - VULPO: arxiv.org/abs/2511.11896
//! - TGI: https://github.com/huggingface/text-generation-inference

use crate::config::TgiConfig;
use reqwest::Client;
use std::time::Duration;

/// Client for TGI (Text Generation Inference) servers
#[derive(Clone, Debug)]
pub struct TgiClient {
    endpoint: String,
    model: String,
    max_new_tokens: usize,
    temperature: f32,
    http: Client,
}

/// Request body for TGI chat completions
#[derive(serde::Serialize)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<ChatMessage>,
    max_tokens: usize,
    temperature: f32,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop: Option<Vec<String>>,
}

/// Response from TGI chat completions endpoint
#[derive(serde::Deserialize, Debug)]
struct ChatCompletionResponse {
    choices: Vec<Choice>,
}

#[derive(serde::Deserialize, Debug)]
struct Choice {
    message: Message,
}

#[derive(serde::Deserialize, Debug)]
struct Message {
    content: String,
}

/// Chat message for the request
#[derive(serde::Serialize, Debug)]
struct ChatMessage {
    role: String,
    content: String,
}

/// Optional completion settings that can override config defaults
#[derive(Debug, Clone, Default)]
pub struct CompletionOptions {
    /// Override max new tokens
    pub max_new_tokens: Option<usize>,
    /// Override temperature
    pub temperature: Option<f32>,
    /// Stop sequences
    pub stop: Vec<String>,
}

impl TgiClient {
    /// Create a new TgiClient from configuration
    pub fn new(config: &TgiConfig) -> Result<Self, String> {
        if !config.enabled {
            return Err("TGI is not enabled in configuration".to_string());
        }

        if config.endpoint.is_empty() {
            return Err("TGI endpoint is required".to_string());
        }

        if config.model.is_empty() {
            return Err("TGI model name is required".to_string());
        }

        let http = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        Ok(Self {
            endpoint: config.endpoint.clone(),
            model: config.model.clone(),
            max_new_tokens: config.max_new_tokens,
            temperature: config.temperature,
            http,
        })
    }

    /// Create a new TgiClient with custom options
    pub fn with_options(config: &TgiConfig, options: &CompletionOptions) -> Result<Self, String> {
        let mut client = Self::new(config)?;

        if let Some(max_tokens) = options.max_new_tokens {
            client.max_new_tokens = max_tokens;
        }
        if let Some(temp) = options.temperature {
            client.temperature = temp;
        }

        Ok(client)
    }

    /// Check if the TGI server is available via health endpoint
    pub fn is_available(&self) -> bool {
        let health_url = format!("{}/health", self.endpoint);

        // Use a short timeout for health checks
        let http = Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap_or_else(|_| Client::new());

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            match http.get(&health_url).send().await {
                Ok(resp) => resp.status().is_success(),
                Err(_) => false,
            }
        })
    }

    /// Complete a prompt using the TGI server
    pub async fn complete(&self, prompt: &str) -> Result<String, String> {
        self.complete_with_options(prompt, &CompletionOptions::default())
            .await
    }

    /// Complete a prompt with custom options
    pub async fn complete_with_options(
        &self,
        prompt: &str,
        options: &CompletionOptions,
    ) -> Result<String, String> {
        let url = format!("{}/v1/chat/completions", self.endpoint);

        let max_tokens = options.max_new_tokens.unwrap_or(self.max_new_tokens);
        let temperature = options.temperature.unwrap_or(self.temperature);

        let request = ChatCompletionRequest {
            model: self.model.clone(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            max_tokens,
            temperature,
            stream: false,
            stop: if options.stop.is_empty() {
                None
            } else {
                Some(options.stop.clone())
            },
        };

        let response = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("Failed to send request to TGI: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let error = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!(
                "TGI request failed with status {}: {}",
                status, error
            ));
        }

        let result: ChatCompletionResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse TGI response: {}", e))?;

        result
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .ok_or_else(|| "TGI response missing choices".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tgi_config_default_disabled() {
        let config = TgiConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.endpoint, "http://localhost:8080");
        assert_eq!(config.max_new_tokens, 2048);
        assert_eq!(config.temperature, 0.1);
        assert_eq!(config.timeout_secs, 120);
        assert!(config.do_sample);
    }

    #[test]
    fn test_tgi_client_new_disabled() {
        let config = TgiConfig::default();
        let result = TgiClient::new(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not enabled"));
    }

    #[test]
    fn test_tgi_client_new_missing_endpoint() {
        let config = TgiConfig {
            enabled: true,
            endpoint: String::new(),
            model: "test-model".to_string(),
            ..Default::default()
        };
        let result = TgiClient::new(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("endpoint"));
    }

    #[test]
    fn test_tgi_client_new_missing_model() {
        let config = TgiConfig {
            enabled: true,
            endpoint: "http://localhost:8080".to_string(),
            model: String::new(),
            ..Default::default()
        };
        let result = TgiClient::new(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("model"));
    }

    #[test]
    fn test_completion_options_default() {
        let options = CompletionOptions::default();
        assert!(options.max_new_tokens.is_none());
        assert!(options.temperature.is_none());
        assert!(options.stop.is_empty());
    }

    #[test]
    fn test_completion_options_custom() {
        let options = CompletionOptions {
            max_new_tokens: Some(512),
            temperature: Some(0.8),
            stop: vec!["\n".to_string(), "END".to_string()],
        };
        assert_eq!(options.max_new_tokens, Some(512));
        assert_eq!(options.temperature, Some(0.8));
        assert_eq!(options.stop.len(), 2);
    }
}
