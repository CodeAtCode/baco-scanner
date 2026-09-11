use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LlmConfig {
    #[serde(default)]
    pub timeout_secs: u64,
    #[serde(default)]
    pub max_retries: u8,
    #[serde(default)]
    pub retry_backoff_ms: u64,
    #[serde(default = "crate::config::default_max_concurrent")]
    pub max_concurrent: usize,
    #[serde(default = "crate::config::default_llm_temperature")]
    pub temperature: f32,
    #[serde(default)]
    pub phases: LlmPhasesConfig,
    #[serde(default)]
    pub max_reasoning_tokens: Option<usize>,
    #[serde(default = "default_enable_llm_cache")]
    pub enable_llm_cache: bool,
    #[serde(default)]
    pub cache_dir: Option<String>,
    /// Optional pricing table for cost estimation: model name → { prompt_per_1k, completion_per_1k }
    /// When empty, only token counts are reported (no cost line).
    #[serde(default)]
    pub pricing: HashMap<String, ModelPricing>,
}

fn default_enable_llm_cache() -> bool {
    false
}

/// Pricing for a specific LLM model (per 1K tokens)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModelPricing {
    /// Cost per 1K prompt tokens (in USD or currency unit of choice)
    #[serde(default)]
    pub prompt_per_1k: f64,
    /// Cost per 1K completion tokens (in USD or currency unit of choice)
    #[serde(default)]
    pub completion_per_1k: f64,
}

impl ModelPricing {
    /// Calculate cost for given token counts
    pub fn cost(&self, prompt_tokens: u64, completion_tokens: u64) -> f64 {
        (prompt_tokens as f64 / 1000.0) * self.prompt_per_1k
            + (completion_tokens as f64 / 1000.0) * self.completion_per_1k
    }
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
    pub static_analysis: LlmPhaseConfig,
    #[serde(default)]
    pub security_agent_verification: LlmPhaseConfig,
    #[serde(default)]
    pub threat_modeling: LlmPhaseConfig,
    #[serde(default)]
    pub prompt_overrides: PromptOverrides,
}

impl LlmPhasesConfig {}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LlmPhaseConfig {
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default, rename = "model")]
    pub model: String, // Legacy: single model string
    #[serde(default, rename = "models")]
    pub models: Vec<String>, // New: list of models (takes precedence over model)
    #[serde(default)]
    pub timeout_secs: Option<u64>, // Optional per-phase timeout override
    #[serde(default)]
    pub temperature: Option<f32>, // Optional per-phase temperature override
    /// AgentFlow gate for this phase
    #[serde(default)]
    pub agent_flow: AgentFlowPhaseConfig,
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

/// AgentFlow phase configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentFlowPhaseConfig {
    /// Gate: run AgentFlow harness synthesis
    #[serde(default)]
    pub enabled: bool,
    /// Maximum iterations for AgentFlow loop
    #[serde(default = "default_agent_flow_max_iterations")]
    pub max_iterations: u32,
}

fn default_agent_flow_max_iterations() -> u32 {
    5
}

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
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_turns: crate::config::default_max_turns(),
            tool_timeout_secs: crate::config::default_tool_timeout(),
            trusted_paths: crate::config::default_trusted_paths(),
        }
    }
}
