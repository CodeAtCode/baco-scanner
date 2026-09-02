use crate::vuln_spec::schema::VulnSpecConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::config::{default_four, default_true};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScannerSettings {
    #[serde(default)]
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
    #[serde(default)]
    pub rulesets: Vec<String>,
    #[serde(default)]
    pub exclude_rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSettings {
    #[serde(default)]
    pub enable_incremental_scan: bool,
    #[serde(default)]
    pub early_termination_threshold: f32,
    // Phantom config keys - implemented
    #[serde(default = "default_true")]
    pub enable_file_filtering: bool,
    #[serde(default = "default_four")]
    pub max_parallel_tasks: usize,
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
    /// Domain-routed hunt prompts: select per-attack-class prompt modules
    /// from the target's languages during LLM discovery
    #[serde(default)]
    pub enable_hunt_prompts: bool,
    /// VulInSpec configuration
    #[serde(default)]
    pub vuln_spec: VulnSpecConfig,
}

impl Default for PerformanceSettings {
    fn default() -> Self {
        Self {
            enable_incremental_scan: false,
            early_termination_threshold: 1000.0,
            enable_file_filtering: default_true(),
            max_parallel_tasks: default_four(),
            enable_threat_modeling: crate::config::default_enable_threat_modeling(),
            enable_root_cause_dedup: crate::config::default_enable_root_cause_dedup(),
            enable_multi_verifier: crate::config::default_enable_multi_verifier(),
            enable_auto_patching: crate::config::default_enable_auto_patching(),
            enable_poc_compilation: crate::config::default_enable_poc_compilation(),
            enable_confidence_refinement: crate::config::default_enable_confidence_refinement(),
            enable_cve_bootstrap: crate::config::default_enable_cve_bootstrap(),
            enable_variant_search: crate::config::default_enable_variant_search(),
            enable_hunt_prompts: false,
            vuln_spec: VulnSpecConfig::default(),
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
    /// Create a RouterRegistry from this config, translating CWE overrides
    /// into the domain-keyed registry via the shared CWE-to-domain mapping
    pub fn to_registry(&self) -> crate::router::RouterRegistry {
        let mut registry = crate::router::RouterRegistry::new();
        for (cwe_id, spec) in &self.cwe_overrides {
            if let Some(domain) = crate::prompt::templates::cwe_to_hunt_domain(cwe_id) {
                registry.add_domain(
                    domain.to_string(),
                    crate::router::DomainConfig {
                        model_override: spec.model_override.clone(),
                    },
                );
            }
        }
        registry
    }
}
