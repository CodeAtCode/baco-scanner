use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Aggregation configuration including false positive store settings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AggregationConfig {}

pub const DEFAULT_ENABLE_ROOT_CAUSE_DEDUP: bool = true;
pub fn default_enable_root_cause_dedup() -> bool {
    DEFAULT_ENABLE_ROOT_CAUSE_DEDUP
}
pub const DEFAULT_ENABLE_CONFIDENCE_REFINEMENT: bool = true;
pub fn default_enable_confidence_refinement() -> bool {
    DEFAULT_ENABLE_CONFIDENCE_REFINEMENT
}
pub const DEFAULT_ENABLE_CVE_BOOTSTRAP: bool = true;
pub fn default_enable_cve_bootstrap() -> bool {
    DEFAULT_ENABLE_CVE_BOOTSTRAP
}
pub const DEFAULT_ENABLE_ABSENCE_DETECTION: bool = true;
pub fn default_enable_absence_detection() -> bool {
    DEFAULT_ENABLE_ABSENCE_DETECTION
}
pub const DEFAULT_ENABLE_MERGE_ORDER_DETECTION: bool = true;
pub fn default_enable_merge_order_detection() -> bool {
    DEFAULT_ENABLE_MERGE_ORDER_DETECTION
}
pub const DEFAULT_ENABLE_HUNT_PROMPTS: bool = true;
pub fn default_enable_hunt_prompts() -> bool {
    DEFAULT_ENABLE_HUNT_PROMPTS
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
#[serde(deny_unknown_fields)]
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

/// Configuration for the Validate phase (CORRECT paper arxiv:2504.13474)
///
/// LLM-as-judge rationale validation: evaluates the soundness of reasoning
/// behind each finding and adjusts confidence accordingly (+0.10 sound, -0.20 flawed).
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ValidateConfig {
    /// Whether the Validate phase is enabled
    pub enabled: bool,
}

/// Configuration for VulTriage triple-path context augmentation.
/// Augments LLM input with control path (AST/CFG/DFG), knowledge path
/// (CWE pattern RAG), and semantic path (function summary) before judgement.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct VultriageConfig {
    /// Whether triple-path context augmentation is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Whether to include the semantic path (function summary)
    #[serde(default = "crate::config::default_true")]
    pub semantic_path: bool,
}

/// Configuration for the triage cascade (T17).
/// First pass: cheap model triage per file to filter out non-suspicious files.
/// Second pass: deep analysis only on files that pass the suspicion threshold.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct TriageConfig {
    /// Whether triage cascade is enabled (default: false)
    #[serde(default)]
    pub enabled: bool,
    /// Model to use for triage pass (default: mistral-small)
    #[serde(default = "crate::config::default_triage_model")]
    pub model: String,
    /// Batch size for triage requests (default: 8)
    #[serde(default = "crate::config::default_triage_batch_size")]
    pub batch_size: u8,
    /// Suspicion threshold for deep analysis (default: 0.35)
    #[serde(default = "crate::config::default_triage_threshold")]
    pub suspicion_threshold: f32,
}

impl Default for TriageConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model: crate::config::default_triage_model(),
            batch_size: crate::config::default_triage_batch_size(),
            suspicion_threshold: crate::config::default_triage_threshold(),
        }
    }
}

/// Configuration for file prioritization (T18).
/// Scores files based on recency, entry-point status, and size to prioritize LLM budget.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorityConfig {
    /// Whether prioritization is enabled (default: false)
    #[serde(default)]
    pub enabled: bool,
    /// Boost factor for recently modified files (git or mtime < 7 days)
    #[serde(default = "crate::config::default_priority_git_recent_boost")]
    pub git_recent_boost: f32,
    /// Boost factor for entry-point files (main.*, index.*, app.*, server.*, __init__.*)
    #[serde(default = "crate::config::default_priority_entry_point_boost")]
    pub entry_point_boost: f32,
    /// Boost factor for small files (< 10KB)
    #[serde(default = "crate::config::default_priority_small_file_boost")]
    pub small_file_boost: f32,
    /// Path/content patterns that mark a file as an entry point (empty = built-in defaults)
    #[serde(default)]
    pub entry_point_patterns: Vec<String>,
    /// Content substrings that mark a file as security-relevant; a match boosts priority
    #[serde(default)]
    pub sink_patterns: Vec<String>,
}

impl Default for PriorityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            git_recent_boost: crate::config::default_priority_git_recent_boost(),
            entry_point_boost: crate::config::default_priority_entry_point_boost(),
            small_file_boost: crate::config::default_priority_small_file_boost(),
            entry_point_patterns: Vec::new(),
            sink_patterns: Vec::new(),
        }
    }
}

/// Configuration for LLM budget enforcement (T18).
/// Limits total LLM calls and reserves budget for high-risk files.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetConfig {
    /// Whether budget enforcement is enabled (default: false)
    #[serde(default)]
    pub enabled: bool,
    /// Maximum total LLM calls (triage + deep analysis)
    #[serde(default = "crate::config::default_budget_max_llm_calls")]
    pub max_llm_calls: usize,
    /// Percent of budget to reserve for high-risk files (default: 20)
    #[serde(default = "crate::config::default_budget_reserve_percent")]
    pub reserve_percent_for_high_risk: u8,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_llm_calls: crate::config::default_budget_max_llm_calls(),
            reserve_percent_for_high_risk: crate::config::default_budget_reserve_percent(),
        }
    }
}

/// Configuration for policy-based generation (P2.2 — VulnLLM-R).
/// Queries the LLM N times to get a CWE candidate set ("policy"),
/// then a final call with the policy as context to pick one label.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
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

/// Configuration for PacVD primitive-API abstraction.
/// Appends callee abstraction at one of four granularity levels to the
/// LLM prompt. With `auto_level = true`, the level is chosen based on
/// the configured model name.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
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

pub const DEFAULT_POLICY_SAMPLES: u8 = 4;
pub fn default_policy_samples() -> u8 {
    DEFAULT_POLICY_SAMPLES
}
pub const DEFAULT_PACVD_LEVEL: u8 = 2;
pub fn default_pacvd_level() -> u8 {
    DEFAULT_PACVD_LEVEL
}
