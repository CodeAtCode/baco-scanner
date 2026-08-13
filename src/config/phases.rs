use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    /// Whether rules synthesis is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Output directory for generated rules
    #[serde(default = "crate::config::default_rulesynth_output_dir")]
    pub output_dir: PathBuf,
    /// Maximum rules to generate per CWE
    #[serde(default = "crate::config::default_max_rules_per_cwe")]
    pub max_rules_per_cwe: usize,
    /// Use MoCQ proposer loop with symbolic validation (vs old RuleSynthesizer)
    #[serde(default)]
    pub mocq_mode: bool,
    /// Max iterations for the proposer loop
    #[serde(default = "crate::config::default_mocq_max_iterations")]
    pub max_iterations: u8,
    /// Path to labelled trace corpus for symbolic validation
    #[serde(default)]
    pub corpus_path: Option<PathBuf>,
}

impl Default for RuleSynthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            output_dir: crate::config::default_rulesynth_output_dir(),
            max_rules_per_cwe: crate::config::default_max_rules_per_cwe(),
            mocq_mode: false,
            max_iterations: crate::config::default_mocq_max_iterations(),
            corpus_path: None,
        }
    }
}

pub fn default_rulesynth_output_dir() -> PathBuf {
    PathBuf::from("./output/generated_rules")
}

pub fn default_max_rules_per_cwe() -> usize {
    5
}

pub fn default_mocq_max_iterations() -> u8 {
    5
}

pub fn default_enable_threat_modeling() -> bool {
    true
}

pub fn default_enable_root_cause_dedup() -> bool {
    true
}

pub fn default_enable_multi_verifier() -> bool {
    true
}

pub fn default_enable_auto_patching() -> bool {
    false
}

pub fn default_enable_poc_compilation() -> bool {
    false
}

pub fn default_enable_confidence_refinement() -> bool {
    true
}

pub fn default_enable_cve_bootstrap() -> bool {
    true
}

pub fn default_enable_variant_search() -> bool {
    true
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

/// Configuration for the Validate phase (CORRECT paper arxiv:2504.13474)
///
/// LLM-as-judge rationale validation: evaluates the soundness of reasoning
/// behind each finding and adjusts confidence accordingly (+0.10 sound, -0.20 flawed).
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct ValidateConfig {
    /// Whether the Validate phase is enabled
    pub enabled: bool,
}

/// Configuration for VulTriage triple-path context augmentation (P1).
/// Augments LLM input with control path (AST/CFG/DFG), knowledge path
/// (CWE pattern RAG), and semantic path (function summary) before judgement.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct VultriageConfig {
    /// Whether triple-path context augmentation is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Whether to include the control path (AST/CFG/DFG verbalisation)
    #[serde(default = "crate::config::default_true")]
    pub control_path: bool,
    /// Whether to include the knowledge path (CWE pattern RAG)
    #[serde(default = "crate::config::default_true")]
    pub knowledge_path: bool,
    /// Whether to include the semantic path (function summary)
    #[serde(default = "crate::config::default_true")]
    pub semantic_path: bool,
}

/// Configuration for policy-based generation (P2.2 — VulnLLM-R).
/// Queries the LLM N times to get a CWE candidate set ("policy"),
/// then a final call with the policy as context to pick one label.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PolicySamplingConfig {
    /// Whether policy-based generation is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Number of sampling rounds to build the policy (default: 4)
    #[serde(default = "crate::config::default_policy_samples")]
    pub samples: u8,
}

impl Default for PolicySamplingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            samples: crate::config::default_policy_samples(),
        }
    }
}

/// Configuration for the VulnLLM-R agent scaffold (P2.5).
/// Builds 3-path call-graph context + function-lookup tool per target.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct AgentScaffoldConfig {
    /// Whether the agent scaffold is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Maximum interaction rounds per target function
    #[serde(default = "crate::config::default_agent_max_rounds")]
    pub max_rounds: u8,
    /// Number of call-graph paths to sample per target function
    #[serde(default = "crate::config::default_agent_paths_per_target")]
    pub paths_per_target: u8,
}

impl Default for AgentScaffoldConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_rounds: crate::config::default_agent_max_rounds(),
            paths_per_target: crate::config::default_agent_paths_per_target(),
        }
    }
}

/// Configuration for PacVD primitive-API abstraction (P4).
/// Appends callee abstraction at one of four granularity levels to the
/// LLM prompt. With `auto_level = true`, the level is chosen based on
/// the configured model name.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PacvdConfig {
    /// Whether PacVD abstraction is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Abstraction level 1-4 (1 = fuzzy branches only; 4 = concrete branches + key variables)
    #[serde(default = "crate::config::default_pacvd_level")]
    pub level: u8,
    /// Whether to auto-select the level based on the configured LLM model
    #[serde(default)]
    pub auto_level: bool,
}

impl Default for PacvdConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            level: crate::config::default_pacvd_level(),
            auto_level: false,
        }
    }
}

/// Configuration for AgentFlow multi-agent harness synthesis (P5).
/// Represents the harness as a typed graph DSL; search loop proposes,
/// executes, observes, and diagnoses harness rewrites.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct AgentFlowConfig {
    /// Whether AgentFlow is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Maximum search-loop iterations
    #[serde(default = "crate::config::default_agent_flow_max_iterations")]
    pub max_iterations: u8,
    /// Whether the target must be built with coverage/sanitizer instrumentation
    #[serde(default)]
    pub requires_instrumented_target: bool,
}

impl Default for AgentFlowConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_iterations: crate::config::default_agent_flow_max_iterations(),
            requires_instrumented_target: false,
        }
    }
}

pub fn default_true() -> bool {
    true
}

pub fn default_policy_samples() -> u8 {
    4
}

pub fn default_agent_max_rounds() -> u8 {
    5
}

pub fn default_agent_paths_per_target() -> u8 {
    3
}

pub fn default_pacvd_level() -> u8 {
    2
}

pub fn default_agent_flow_max_iterations() -> u8 {
    10
}
