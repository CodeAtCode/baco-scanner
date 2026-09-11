use crate::config::{default_four, default_max_file_size_kb, default_true};
use crate::vuln_spec::schema::VulnSpecConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Pipeline profile selection: which phases run by default
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ScanPipelineProfile {
    /// Core profile: runs the essential phases that constitute a sensible default scan
    #[default]
    Core,
    /// All profile: runs all phases including experimental ones (still individually flag-gated)
    All,
}

/// Pattern configuration for variant search
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VariantSearchPattern {
    /// Type of vulnerability (e.g., "command_injection", "sql_injection")
    #[serde(default)]
    pub vulnerability_type: String,
    /// Regex pattern to match in code
    #[serde(default)]
    pub code_pattern: String,
    /// Context keywords that increase similarity score
    #[serde(default)]
    pub context_keywords: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScannerSettings {
    #[serde(default = "default_max_file_size_kb")]
    pub max_file_size_kb: u64,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    /// Pipeline profile: "core" (default) or "all"
    #[serde(default)]
    pub profile: ScanPipelineProfile,
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
    /// Inline semgrep rule YAML documents (full `rules:` blocks) shipped in
    /// presets; materialized to temp files and passed as extra `--config` args
    /// at scan time so presets stay self-contained.
    #[serde(default)]
    pub custom_rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSettings {
    #[serde(default)]
    pub enable_incremental_scan: bool,
    /// Early termination threshold: scan stops when Medium-and-above finding count exceeds this value.
    /// Info findings are NOT counted toward the threshold (flood-resistant). Default: 1000.0.
    /// Set to 0.0 to disable early termination.
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
    /// Never-submit pattern filter - heavily penalizes findings matching known false-positive patterns
    #[serde(default = "crate::config::default_never_submit_enabled")]
    pub never_submit_enabled: bool,
    /// Multiplier applied to confidence when never-submit pattern matches (default 0.1)
    #[serde(default = "crate::config::default_never_submit_multiplier")]
    pub never_submit_multiplier: f32,
    /// Variant search patterns - code patterns to search for vulnerability variants
    #[serde(default)]
    pub variant_search_patterns: Vec<VariantSearchPattern>,
}

pub const DEFAULT_NEVER_SUBMIT_ENABLED: bool = true;
pub fn default_never_submit_enabled() -> bool {
    DEFAULT_NEVER_SUBMIT_ENABLED
}

pub const DEFAULT_NEVER_SUBMIT_MULTIPLIER: f32 = 0.1;
pub fn default_never_submit_multiplier() -> f32 {
    DEFAULT_NEVER_SUBMIT_MULTIPLIER
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
            never_submit_enabled: crate::config::default_never_submit_enabled(),
            never_submit_multiplier: crate::config::default_never_submit_multiplier(),
            variant_search_patterns: Vec::new(),
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
