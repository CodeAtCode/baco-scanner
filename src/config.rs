use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScannerConfig {
    #[serde(default)]
    pub project: ProjectConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub scanner: ScannerSettings,
    #[serde(default)]
    pub llm: LlmConfig,
    #[serde(default)]
    pub tickets: TicketConfig,
    #[serde(default)]
    pub agent: AgentConfig,
    #[serde(default)]
    pub router: RouterConfig,
    #[serde(default)]
    pub aggregation: AggregationConfig,
    #[serde(default)]
    pub rulesynth: RuleSynthConfig,
    #[serde(default)]
    pub orchestration: OrchestrationConfig,
    #[serde(default)]
    pub normalization: NormalizationConfig,
    #[serde(default)]
    pub cpg: CpgConfig,
    #[serde(default)]
    pub exploit: ExploitConfig,
}

/// Config error with field path and TOML location information
#[derive(Debug)]
pub enum ConfigError {
    /// IO error reading config file
    Io(std::io::Error),
    /// TOML parse error with location
    Parse {
        message: String,
        line: Option<u32>,
        column: Option<u32>,
    },
    /// Validation error with field path
    Validation { field: String, message: String },
    /// Missing dependency (e.g., semgrep)
    MissingDependency {
        tool: String,
        install_hints: Vec<String>,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(err) => write!(f, "IO error: {}", err),
            ConfigError::Parse {
                message,
                line,
                column,
            } => {
                if let (Some(l), Some(c)) = (line, column) {
                    write!(
                        f,
                        "TOML parse error at line {}, column {}: {}",
                        l, c, message
                    )
                } else {
                    write!(f, "TOML parse error: {}", message)
                }
            }
            ConfigError::Validation { field, message } => {
                write!(f, "Validation error at {}: {}", field, message)
            }
            ConfigError::MissingDependency {
                tool,
                install_hints,
            } => {
                write!(f, "{} is not installed or not in PATH", tool)?;
                if !install_hints.is_empty() {
                    write!(f, "\nInstall with:")?;
                    for hint in install_hints {
                        write!(f, "\n  {}", hint)?;
                    }
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(err: std::io::Error) -> Self {
        ConfigError::Io(err)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(err: toml::de::Error) -> Self {
        // toml::de::Error implements Display with location info like "TOML parse error at line 1, column 10"
        let msg = err.to_string();
        ConfigError::Parse {
            message: msg.clone(),
            line: None, // toml::de::Error doesn't expose line/column publicly in v0.8
            column: None,
        }
    }
}

impl ScannerConfig {
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        let config: ScannerConfig = toml::from_str(&content)?;
        Ok(config)
    }

    fn validate_phase(phase_name: &str, phase: &LlmPhaseConfig) -> Result<(), ConfigError> {
        // If api_key is empty/None, LLM is disabled for this phase - skip validation
        if phase.api_key.as_ref().is_none_or(|k| k.is_empty()) {
            return Ok(());
        }

        if phase.base_url.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{}.base_url", phase_name),
                message: "base_url is required when API key is set".to_string(),
            });
        }
        let models = phase.get_models();
        if models.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{}.model or {}.models", phase_name, phase_name),
                message: "at least one model must be specified (use 'model' or 'models' field)"
                    .to_string(),
            });
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        Self::validate_phase("llm.phases.discovery", &self.llm.phases.discovery)?;
        Self::validate_phase("llm.phases.verification", &self.llm.phases.verification)?;
        Self::validate_phase("llm.phases.aggregation", &self.llm.phases.aggregation)?;
        let project_path = PathBuf::from(&self.project.path);
        if !project_path.exists() {
            return Err(ConfigError::Validation {
                field: "project.path".to_string(),
                message: format!("Project path does not exist: {}", self.project.path),
            });
        }
        if which::which("semgrep").is_err() {
            return Err(ConfigError::MissingDependency {
                tool: "Semgrep".to_string(),
                install_hints: vec![
                    "brew install semgrep".to_string(),
                    "pip install semgrep".to_string(),
                ],
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectConfig {
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub languages: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OutputConfig {
    pub dir: String,
    #[serde(default)]
    pub format: Vec<String>,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemgrepSettings {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub cache_dir: Option<String>,
    #[serde(default)]
    pub exclude_rules: Vec<String>,
}

impl Default for SemgrepSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_dir: None,
            exclude_rules: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSettings {
    #[serde(default)]
    pub enable_parallel_phases: bool,
    #[serde(default = "default_max_parallel_tasks")]
    pub max_parallel_tasks: usize,
    #[serde(default)]
    pub enable_llm_cache: bool,
    #[serde(default)]
    pub enable_incremental_scan: bool,
    #[serde(default)]
    pub llm_cache_dir: Option<String>,
    #[serde(default = "default_enable_file_filtering")]
    pub enable_file_filtering: bool,
    #[serde(default)]
    pub enable_batch_llm: bool,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    #[serde(default)]
    pub early_termination_threshold: f32,
    #[serde(default = "default_enable_v3_features")]
    pub enable_v3_features: bool,
    // v3 feature flags
    #[serde(default = "default_enable_threat_modeling")]
    pub enable_threat_modeling: bool,
    #[serde(default = "default_enable_root_cause_dedup")]
    pub enable_root_cause_dedup: bool,
    #[serde(default = "default_enable_multi_verifier")]
    pub enable_multi_verifier: bool,
    #[serde(default = "default_enable_auto_patching")]
    pub enable_auto_patching: bool,
    #[serde(default = "default_enable_poc_compilation")]
    pub enable_poc_compilation: bool,
    #[serde(default = "default_enable_confidence_refinement")]
    pub enable_confidence_refinement: bool,
    #[serde(default = "default_enable_cve_bootstrap")]
    pub enable_cve_bootstrap: bool,
    #[serde(default = "default_enable_variant_search")]
    pub enable_variant_search: bool,
    #[serde(default = "default_true")]
    pub never_submit_filter: bool,
}

impl Default for PerformanceSettings {
    fn default() -> Self {
        Self {
            enable_parallel_phases: false,
            max_parallel_tasks: default_max_parallel_tasks(),
            enable_llm_cache: false,
            enable_incremental_scan: false,
            llm_cache_dir: None,
            enable_file_filtering: default_enable_file_filtering(),
            enable_batch_llm: false,
            batch_size: default_batch_size(),
            early_termination_threshold: 1000.0,
            enable_v3_features: default_enable_v3_features(),
            enable_threat_modeling: default_enable_threat_modeling(),
            enable_root_cause_dedup: default_enable_root_cause_dedup(),
            enable_multi_verifier: default_enable_multi_verifier(),
            enable_auto_patching: default_enable_auto_patching(),
            enable_poc_compilation: default_enable_poc_compilation(),
            enable_confidence_refinement: default_enable_confidence_refinement(),
            enable_cve_bootstrap: default_enable_cve_bootstrap(),
            enable_variant_search: default_enable_variant_search(),
            never_submit_filter: default_true(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LlmConfig {
    pub timeout_secs: u64,
    pub max_retries: u8,
    pub retry_backoff_ms: u64,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
    #[serde(default)]
    pub phases: LlmPhasesConfig,
    #[serde(default)]
    pub tgi: TgiConfig,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TicketConfig {
    #[serde(default)]
    pub systems: Vec<TicketSystemConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TicketSystemConfig {
    pub system_type: String,
    pub url: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
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
    #[serde(default = "default_max_turns")]
    pub max_turns: u32,
    #[serde(default = "default_tool_timeout")]
    pub tool_timeout_secs: u64,
    #[serde(default = "default_trusted_paths")]
    pub trusted_paths: Vec<String>,
    #[serde(default)]
    pub keep_artifacts: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_turns: default_max_turns(),
            tool_timeout_secs: default_tool_timeout(),
            trusted_paths: default_trusted_paths(),
            keep_artifacts: false,
        }
    }
}

fn default_max_concurrent() -> usize {
    4
}

fn default_max_turns() -> u32 {
    10
}

fn default_tool_timeout() -> u64 {
    30
}

fn default_trusted_paths() -> Vec<String> {
    vec![".".to_string()]
}

/// Router configuration for MoE per-CWE / per-language routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterConfig {
    /// Whether the router is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Default prompt template name
    #[serde(default = "default_llm_static_analysis")]
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
            default_prompt: default_llm_static_analysis(),
            cwe_overrides: HashMap::new(),
            language_overrides: HashMap::new(),
        }
    }
}

/// Prompt specification for router overrides
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PromptSpec {
    /// The prompt template name to use
    #[serde(default = "default_llm_static_analysis")]
    pub prompt_template: String,
    /// Optional model override for this prompt
    pub model_override: Option<String>,
}

impl Default for PromptSpec {
    fn default() -> Self {
        Self {
            prompt_template: default_llm_static_analysis(),
            model_override: None,
        }
    }
}

fn default_llm_static_analysis() -> String {
    "llm_static_analysis".to_string()
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

/// Aggregation configuration including false positive store settings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AggregationConfig {
    /// Path to the false positive store JSON file
    #[serde(default)]
    pub fp_store_path: Option<PathBuf>,
}

/// Rule synthesis configuration (MoCQ: LLM→semgrep rule generation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSynthConfig {
    /// Whether rule synthesis is enabled
    #[serde(default = "default_false")]
    pub enabled: bool,
    /// Output directory for generated rules
    #[serde(default = "default_rulesynth_output_dir")]
    pub output_dir: PathBuf,
    /// Maximum rules to generate per CWE
    #[serde(default = "default_max_rules_per_cwe")]
    pub max_rules_per_cwe: usize,
}

impl Default for RuleSynthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            output_dir: default_rulesynth_output_dir(),
            max_rules_per_cwe: default_max_rules_per_cwe(),
        }
    }
}

fn default_max_parallel_tasks() -> usize {
    4
}

fn default_false() -> bool {
    false
}

fn default_rulesynth_output_dir() -> PathBuf {
    PathBuf::from("./output/generated_rules")
}

fn default_max_rules_per_cwe() -> usize {
    5
}

fn default_enable_file_filtering() -> bool {
    true
}

fn default_batch_size() -> usize {
    8
}

fn default_enable_v3_features() -> bool {
    false
}

fn default_enable_threat_modeling() -> bool {
    false
}

fn default_enable_root_cause_dedup() -> bool {
    false
}

fn default_enable_multi_verifier() -> bool {
    false
}

fn default_enable_auto_patching() -> bool {
    false
}

fn default_enable_poc_compilation() -> bool {
    false
}

fn default_enable_confidence_refinement() -> bool {
    true
}

fn default_enable_cve_bootstrap() -> bool {
    true
}

fn default_enable_variant_search() -> bool {
    true
}

/// Orchestration configuration for T2.5 six-phase pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestrationConfig {
    /// Whether orchestration is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Hunt classes to run (default: all 7 Cloudflare classes)
    #[serde(default)]
    pub hunt_classes: Vec<String>,
    /// Batch size for validation phase
    #[serde(default = "default_validate_batch_size")]
    pub validate_batch_size: usize,
    /// Whether independent verification is enabled
    #[serde(default = "default_true")]
    pub independent_verify: bool,
}

impl Default for OrchestrationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hunt_classes: vec![
                "injection".into(),
                "auth".into(),
                "xss".into(),
                "path_traversal".into(),
                "crypto".into(),
                "resource".into(),
                "deserialization".into(),
            ],
            validate_batch_size: 10,
            independent_verify: true,
        }
    }
}

fn default_validate_batch_size() -> usize {
    10
}

/// Normalization tier for confidence calibration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Default)]
pub enum NormalizationTier {
    /// No normalization — raw confidence scores.
    #[default]
    None,
    /// Normalize relative to project's historical FP rate.
    ProjectRelative,
    /// Normalize using isotonic regression on past triage outcomes.
    Isotonic,
}

/// Configuration for confidence normalization.
/// TGI (Text Generation Inference) configuration for specialized reasoning LLMs
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct TgiConfig {
    /// Whether TGI is enabled
    pub enabled: bool,
    /// TGI server endpoint URL
    pub endpoint: String,
    /// Model name to serve
    pub model: String,
    /// Maximum new tokens to generate
    pub max_new_tokens: usize,
    /// Sampling temperature
    pub temperature: f32,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Whether to use sampling (vs greedy decoding)
    pub do_sample: bool,
}

impl Default for TgiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "http://localhost:8080".to_string(),
            model: String::new(),
            max_new_tokens: 2048,
            temperature: 0.1,
            timeout_secs: 120,
            do_sample: true,
        }
    }
}

/// Configuration for confidence normalization.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct NormalizationConfig {
    /// Whether normalization is enabled.
    pub enabled: bool,
    /// Normalization tier to use.
    pub normalization_tier: NormalizationTier,
    /// Path to project baseline file.
    pub project_baseline_path: Option<PathBuf>,
}

impl Default for NormalizationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            normalization_tier: NormalizationTier::None,
            project_baseline_path: None,
        }
    }
}

/// Configuration for CPG-guided slicing (T3.1)
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CpgConfig {
    /// Whether CPG slicing is enabled
    pub enabled: bool,
    /// Path to Joern binary (None = search PATH)
    pub joern_path: Option<PathBuf>,
    /// Maximum lines to include in a slice
    pub slice_budget_lines: usize,
}

impl Default for CpgConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            joern_path: None,
            slice_budget_lines: 200,
        }
    }
}

/// Configuration for exploit synthesis (T3.2)
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ExploitConfig {
    /// Whether exploit synthesis is enabled
    pub enabled: bool,
    /// Docker image for sandboxed exploit execution
    pub sandbox_image: String,
    /// Timeout for exploit execution in seconds
    pub timeout_secs: u64,
    /// Maximum number of exploit attempts per finding
    pub max_exploits_per_finding: usize,
}

impl Default for ExploitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sandbox_image: "python:3.11-slim".to_string(),
            timeout_secs: 30,
            max_exploits_per_finding: 1,
        }
    }
}

fn load_env_api_keys() -> HashMap<String, Option<String>> {
    let mut overrides = HashMap::new();
    if let Ok(key) = env::var("LLM_DISCOVERY_KEY") {
        overrides.insert("discovery".to_string(), Some(key));
    }
    if let Ok(key) = env::var("LLM_VERIFICATION_KEY") {
        overrides.insert("verification".to_string(), Some(key));
    }
    if let Ok(key) = env::var("LLM_AGGREGATION_KEY") {
        overrides.insert("aggregation".to_string(), Some(key));
    }
    overrides
}

pub fn apply_env_overrides(config: &mut ScannerConfig) {
    let env_keys = load_env_api_keys();
    for (phase_name, override_key) in env_keys {
        if let Some(api_key) = override_key {
            match phase_name.as_str() {
                "discovery" => {
                    if config.llm.phases.discovery.api_key.is_none() {
                        config.llm.phases.discovery.api_key = Some(api_key);
                    }
                }
                "verification" => {
                    if config.llm.phases.verification.api_key.is_none() {
                        config.llm.phases.verification.api_key = Some(api_key);
                    }
                }
                "aggregation" => {
                    if config.llm.phases.aggregation.api_key.is_none() {
                        config.llm.phases.aggregation.api_key = Some(api_key);
                    }
                }
                _ => {
                    tracing::warn!("Unknown LLM phase: {}", phase_name);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::collections::HashMap;

    /// Guard for environment variables that auto-cleans on drop
    struct EnvVarGuard {
        vars: HashMap<String, Option<String>>,
    }

    impl EnvVarGuard {
        fn set(vars: &[(&str, &str)]) -> Self {
            let mut previous = HashMap::new();
            for &(key, value) in vars {
                let old_value = std::env::var(key).ok();
                std::env::set_var(key, value);
                previous.insert(key.to_string(), old_value);
            }
            Self { vars: previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            for (key, old_value) in &self.vars {
                match old_value {
                    Some(v) => unsafe { std::env::set_var(key, v) },
                    None => unsafe { std::env::remove_var(key) },
                }
            }
        }
    }

    #[test]
    fn test_parse() -> Result<(), Box<dyn std::error::Error>> {
        let toml_str = r#"
            [project]
            name = "test-project"
            path = "/tmp/test-project"
            languages = ["c", "python"]

            [output]
            dir = "./baco-output"
            format = ["json", "html"]

            [scanner]
            commit_lookback_days = 90
            max_file_size_kb = 512
            exclude_paths = ["tests/", "docs/"]

            [llm]
            timeout_secs = 60
            max_retries = 3
            retry_backoff_ms = 2000
            max_concurrent = 4

            [llm.phases.discovery]
            base_url = "https://api.mistral.ai/v1"
            api_key = "test-key"
            model = "mistral-small"

            [llm.phases.verification]
            base_url = "https://api.mistral.ai/v1"
            api_key = "test-key-verify"
            model = "qwen35"

            [llm.phases.aggregation]
            base_url = "https://api.mistral.ai/v1"
            api_key = "test-key-agg"
            model = "mistral-medium"

            [tickets]
            [[tickets.systems]]
            system_type = "github"
            url = "https://github.com/GNOME/libxml2"
            project = "libxml2"
        "#;

        let config: ScannerConfig = toml::from_str(toml_str)?;
        assert_eq!(config.project.name, "test-project");
        assert_eq!(config.project.path, "/tmp/test-project");
        assert_eq!(
            config.project.languages,
            vec!["c".to_string(), "python".to_string()]
        );
        assert_eq!(
            config.output.format,
            vec!["json".to_string(), "html".to_string()]
        );
        assert_eq!(config.scanner.commit_lookback_days, 90);
        assert_eq!(config.scanner.max_file_size_kb, 512);
        assert_eq!(config.llm.max_retries, 3);
        assert_eq!(config.llm.phases.discovery.model, "mistral-small");
        assert_eq!(config.llm.phases.verification.model, "qwen35");
        assert_eq!(config.llm.phases.aggregation.model, "mistral-medium");
        Ok(())
    }

    #[test]
    #[serial]
    fn test_env_override() {
        // Use EnvVarGuard for automatic cleanup and parallel safety
        let _guard = EnvVarGuard::set(&[("LLM_DISCOVERY_KEY", "env-discovery-key")]);

        let toml_str = r#"
            [project]
            name = "test"
            path = "/tmp/test"

            [output]
            dir = "./out"
            format = ["json"]

            [scanner]
            commit_lookback_days = 30
            max_file_size_kb = 100

            [llm]
            timeout_secs = 30
            max_retries = 2
            retry_backoff_ms = 1000
            max_concurrent = 2

            [llm.phases.discovery]
            base_url = "http://test"
            model = "test-model"

            [llm.phases.verification]
            base_url = "http://test"
            model = "test-model"
            api_key = "toml-verify"

            [llm.phases.aggregation]
            base_url = "http://test"
            model = "test-model"

            [tickets]
            [[tickets.systems]]
            system_type = "github"
            url = "https://github.com"
        "#;

        let mut config: ScannerConfig = toml::from_str(toml_str).unwrap();
        apply_env_overrides(&mut config);
        assert_eq!(
            config.llm.phases.discovery.api_key,
            Some("env-discovery-key".to_string())
        );
        assert_eq!(
            config.llm.phases.verification.api_key,
            Some("toml-verify".to_string())
        );
        // EnvVarGuard auto-cleans on drop
    }

    #[test]
    #[serial]
    fn test_env_override_phase_isolation() {
        // Set up phase-specific API key environment variables
        let _guard = EnvVarGuard::set(&[
            ("LLM_DISCOVERY_KEY", "only-discovery-key"),
            ("LLM_VERIFICATION_KEY", "only-verification-key"),
            ("LLM_AGGREGATION_KEY", "only-aggregation-key"),
        ]);

        let toml_str = r#"
            [project]
            name = "test"
            path = "/tmp/test"

            [output]
            dir = "./out"
            format = ["json"]

            [scanner]
            commit_lookback_days = 30
            max_file_size_kb = 100

            [llm]
            timeout_secs = 30
            max_retries = 2
            retry_backoff_ms = 1000
            max_concurrent = 2

            [llm.phases.discovery]
            base_url = "http://test"
            model = "test-model"

            [llm.phases.verification]
            base_url = "http://test"
            model = "test-model"

            [llm.phases.aggregation]
            base_url = "http://test"
            model = "test-model"
        "#;

        let mut config: ScannerConfig = toml::from_str(toml_str).unwrap();
        apply_env_overrides(&mut config);

        // Discovery should get the env key
        assert_eq!(
            config.llm.phases.discovery.api_key,
            Some("only-discovery-key".to_string())
        );

        // Verification should get its own env key (no key in TOML)
        assert_eq!(
            config.llm.phases.verification.api_key,
            Some("only-verification-key".to_string())
        );

        // Aggregation should get its own env key (no key in TOML)
        assert_eq!(
            config.llm.phases.aggregation.api_key,
            Some("only-aggregation-key".to_string())
        );
        // EnvVarGuard auto-cleans on drop
    }

    #[test]
    fn test_validate_missing() {
        let toml_str = r#"
            [project]
            name = "test"
            path = "/tmp/test"

            [output]
            dir = "./out"
            format = ["json"]

            [scanner]
            commit_lookback_days = 30
            max_file_size_kb = 100

            [llm]
            timeout_secs = 30
            max_retries = 2
            retry_backoff_ms = 1000
            max_concurrent = 2

            [llm.phases.discovery]
            base_url = ""
            api_key = "test-key"
            model = "test"

            [llm.phases.verification]
            base_url = "http://test"
            api_key = "test-key"
            model = "test"

            [llm.phases.aggregation]
            base_url = "http://test"
            api_key = "test-key"
            model = "test"

            [tickets]
            [[tickets.systems]]
            system_type = "github"
            url = "https://github.com"
        "#;

        let config: ScannerConfig = toml::from_str(toml_str).unwrap();
        let result = config.validate();
        assert!(result.is_err());
        let err_msg = result.err().unwrap();
        assert!(err_msg.to_string().contains("base_url"));
    }

    #[test]
    fn test_from_file() {
        let temp_dir = std::env::temp_dir().join("baco_config_test");
        let _ = std::fs::create_dir_all(&temp_dir);
        let config_file = temp_dir.join("test.toml");

        let toml_str = r#"
            [project]
            name = "test"
            path = "/tmp/test"
            languages = ["c"]

            [output]
            dir = "./out"
            format = ["json"]

            [scanner]
            commit_lookback_days = 30
            max_file_size_kb = 100

            [llm]
            timeout_secs = 30
            max_retries = 2
            retry_backoff_ms = 1000
            max_concurrent = 2

            [llm.phases.discovery]
            base_url = "http://test"
            model = "test"

            [llm.phases.verification]
            base_url = "http://test"
            model = "test"

            [llm.phases.aggregation]
            base_url = "http://test"
            model = "test"
        "#;

        std::fs::write(&config_file, toml_str).unwrap();
        let result = ScannerConfig::from_file(config_file.to_str().unwrap());
        assert!(result.is_ok());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
