use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LlmConfig {
    pub timeout_secs: u64,
    pub max_retries: u8,
    pub retry_backoff_ms: u64,
    #[serde(default = "crate::config::default_max_concurrent")]
    pub max_concurrent: usize,
    #[serde(default = "crate::config::default_llm_temperature")]
    pub temperature: f32,
    #[serde(default)]
    pub phases: LlmPhasesConfig,
    #[serde(default)]
    pub max_reasoning_tokens: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LlmPhasesConfig {
    #[serde(default)]
    pub discovery: LlmPhaseConfig,
    #[serde(default)]
    pub verification: LlmPhaseConfig,
    #[serde(default)]
    pub aggregation: LlmPhaseConfig,
    #[serde(default)]
    pub semgrep: LlmPhaseConfig,
    #[serde(default)]
    pub ticket_crossref: LlmPhaseConfig,
    #[serde(default)]
    pub git_analysis: LlmPhaseConfig,
    #[serde(default)]
    pub cross_file_analysis: LlmPhaseConfig,
    #[serde(default)]
    pub confidence_scoring: LlmPhaseConfig,
    #[serde(default)]
    pub ai_aggregation: LlmPhaseConfig,
    #[serde(default)]
    pub reporting: LlmPhaseConfig,
    #[serde(default)]
    pub indexing: LlmPhaseConfig,
    #[serde(default)]
    pub prompt_overrides: PromptOverrides,
}

impl LlmPhasesConfig {
    /// Create a PromptEngine with overrides from this config
    pub fn create_prompt_engine(&self) -> crate::prompt::PromptEngine {
        crate::prompt::PromptEngine::from_config_overrides(
            self.prompt_overrides.phase_overrides.clone(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LlmPhaseConfig {
    pub base_url: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default, rename = "model")]
    pub model: String, // Legacy: single model string
    #[serde(default, rename = "models")]
    pub models: Vec<String>, // New: list of models (takes precedence over model)
    #[serde(default)]
    pub timeout_secs: Option<u64>, // Optional per-phase timeout override
}

impl LlmPhaseConfig {
    /// Get list of models for this phase (supports backward compatibility)
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

/// Prompt override configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PromptOverrides {
    #[serde(default, rename = "phases")]
    pub phase_overrides: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "crate::config::default_max_turns")]
    pub max_turns: u32,
    #[serde(default = "crate::config::default_tool_timeout")]
    pub tool_timeout_secs: u64,
    #[serde(default = "crate::config::default_trusted_paths")]
    pub trusted_paths: Vec<String>,
    #[serde(default)]
    pub keep_artifacts: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_turns: crate::config::default_max_turns(),
            tool_timeout_secs: crate::config::default_tool_timeout(),
            trusted_paths: crate::config::default_trusted_paths(),
            keep_artifacts: false,
        }
    }
}
