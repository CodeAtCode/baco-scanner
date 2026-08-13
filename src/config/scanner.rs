use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScannerSettings {
    pub commit_lookback_days: u32,
    pub max_file_size_kb: u64,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    #[serde(default)]
    pub semgrep: SemgrepSettings,
    #[serde(default)]
    pub performance: PerformanceSettings,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SemgrepSettings {
    pub exclude_rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSettings {
    #[serde(default)]
    pub enable_incremental_scan: bool,
    #[serde(default)]
    pub early_termination_threshold: f32,
    // v3 feature flags
    #[serde(default = "crate::config::default_enable_threat_modeling")]
    pub enable_threat_modeling: bool,
    #[serde(default = "crate::config::default_enable_root_cause_dedup")]
    pub enable_root_cause_dedup: bool,
    #[serde(default = "crate::config::default_enable_multi_verifier")]
    pub enable_multi_verifier: bool,
    #[serde(default = "crate::config::default_enable_auto_patching")]
    pub enable_auto_patching: bool,
    #[serde(default = "crate::config::default_enable_poc_compilation")]
    pub enable_poc_compilation: bool,
    #[serde(default = "crate::config::default_enable_confidence_refinement")]
    pub enable_confidence_refinement: bool,
    #[serde(default = "crate::config::default_enable_cve_bootstrap")]
    pub enable_cve_bootstrap: bool,
    #[serde(default = "crate::config::default_enable_variant_search")]
    pub enable_variant_search: bool,
}

impl Default for PerformanceSettings {
    fn default() -> Self {
        Self {
            enable_incremental_scan: false,
            early_termination_threshold: 1000.0,
            enable_threat_modeling: crate::config::default_enable_threat_modeling(),
            enable_root_cause_dedup: crate::config::default_enable_root_cause_dedup(),
            enable_multi_verifier: crate::config::default_enable_multi_verifier(),
            enable_auto_patching: crate::config::default_enable_auto_patching(),
            enable_poc_compilation: crate::config::default_enable_poc_compilation(),
            enable_confidence_refinement: crate::config::default_enable_confidence_refinement(),
            enable_cve_bootstrap: crate::config::default_enable_cve_bootstrap(),
            enable_variant_search: crate::config::default_enable_variant_search(),
        }
    }
}

/// Router configuration for MoE per-CWE / per-language routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterConfig {
    /// Whether the router is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Default prompt template name
    #[serde(default = "crate::config::default_llm_static_analysis")]
    pub default_prompt: String,
    /// CWE ID -> PromptSpec overrides
    #[serde(default)]
    pub cwe_overrides: HashMap<String, PromptSpec>,
    /// Language -> PromptSpec overrides
    #[serde(default)]
    pub language_overrides: HashMap<String, PromptSpec>,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_prompt: crate::config::default_llm_static_analysis(),
            cwe_overrides: HashMap::new(),
            language_overrides: HashMap::new(),
        }
    }
}

/// Prompt specification for router overrides
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PromptSpec {
    /// The prompt template name to use
    #[serde(default = "crate::config::default_llm_static_analysis")]
    pub prompt_template: String,
    /// Optional model override for this prompt
    pub model_override: Option<String>,
}

impl Default for PromptSpec {
    fn default() -> Self {
        Self {
            prompt_template: crate::config::default_llm_static_analysis(),
            model_override: None,
        }
    }
}

impl RouterConfig {
    /// Create a RouterRegistry from this config
    pub fn to_registry(&self) -> crate::router::RouterRegistry {
        let mut registry = crate::router::RouterRegistry::new();
        for (cwe_id, spec) in &self.cwe_overrides {
            registry.add_cwe_override(cwe_id.clone(), spec.clone());
        }
        for (language, spec) in &self.language_overrides {
            registry.add_language_override(language.clone(), spec.clone());
        }
        registry
    }
}
