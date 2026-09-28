/// Preset system for loading project-type-specific scanner configurations.
///
/// Presets provide a base configuration layer under user config.toml.
/// Loading order: built-in defaults → preset file → user config.toml → env → CLI flags.
/// User config wins over preset (TOML deep merge of explicit user keys).
use serde::{Deserialize, Serialize};

use std::fs;
use std::path::PathBuf;

use crate::config::ScannerConfig;
use crate::error::ScanError;

/// Embedded preset names (bundled at compile time)
pub const BUILTIN_PRESETS: &[&str] = &[
    "wordpress-core",
    "wordpress-plugin",
    "django",
    "laravel",
    "cpp",
    "litellm",
    "oss-python",
    "oss-monorepo",
];

/// A preset overlay that merges into ScannerConfig
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PresetOverlay {
    #[serde(default)]
    pub project: Option<crate::config::ProjectConfig>,
    #[serde(default)]
    pub scanner: Option<crate::config::ScannerSettings>,
    #[serde(default)]
    pub llm: Option<crate::config::LlmConfig>,
    #[serde(default)]
    pub triage: Option<crate::config::TriageConfig>,
    #[serde(default)]
    pub priority: Option<crate::config::PriorityConfig>,
    #[serde(default)]
    pub budget: Option<crate::config::BudgetConfig>,
    #[serde(default)]
    pub agent_flow: Option<crate::config::AgentFlowConfig>,
    #[serde(default)]
    pub agent: Option<crate::config::AgentConfig>,
    #[serde(default)]
    pub knowledge: Option<crate::config::KnowledgeConfig>,
}

impl PresetOverlay {
    /// Merge this preset overlay into a base ScannerConfig
    /// Preset values override base values where set; unset fields keep base values
    pub fn merge_into(self, base: &mut ScannerConfig) {
        if let Some(ref project) = self.project {
            if !project.name.is_empty() {
                base.project.name = project.name.clone();
            }
            if !project.path.is_empty() {
                base.project.path = project.path.clone();
            }
            if !project.languages.is_empty() {
                base.project.languages = project.languages.clone();
            }
        }

        if let Some(ref scanner) = self.scanner {
            base.scanner.max_file_size_kb = scanner.max_file_size_kb;
            if !scanner.exclude_paths.is_empty() {
                base.scanner.exclude_paths = scanner.exclude_paths.clone();
            }
            // Semgrep settings
            if !scanner.semgrep.rulesets.is_empty() {
                base.scanner.semgrep.rulesets = scanner.semgrep.rulesets.clone();
            }
            if !scanner.semgrep.exclude_rules.is_empty() {
                base.scanner.semgrep.exclude_rules = scanner.semgrep.exclude_rules.clone();
            }
            if !scanner.semgrep.custom_rules.is_empty() {
                base.scanner.semgrep.custom_rules = scanner.semgrep.custom_rules.clone();
            }
            // Performance settings - merge per-key to preserve user-configured values
            // Only apply non-default values from preset (to avoid overwriting user settings)
            if scanner.performance.enable_incremental_scan
                != crate::config::scanner::PerformanceSettings::default().enable_incremental_scan
            {
                base.scanner.performance.enable_incremental_scan =
                    scanner.performance.enable_incremental_scan;
            }
            // early_termination_threshold has #[serde(default)] on f32, so serde default is 0.0.
            // We cannot distinguish "omitted" (0.0) from "explicitly 0.0" without changing to Option<f32>.
            // Compare against serde default (0.0) to fix defect 1: omitted field preserves user value.
            // Note: explicitly setting 0.0 in a preset will NOT be applied (same as omitting it).
            // To support explicit 0.0, change early_termination_threshold to Option<f32> in scanner.rs.
            if scanner.performance.early_termination_threshold != 0.0 {
                base.scanner.performance.early_termination_threshold =
                    scanner.performance.early_termination_threshold;
            }
            if scanner.performance.enable_file_filtering
                != crate::config::scanner::PerformanceSettings::default().enable_file_filtering
            {
                base.scanner.performance.enable_file_filtering =
                    scanner.performance.enable_file_filtering;
            }
            if scanner.performance.max_parallel_tasks
                != crate::config::scanner::PerformanceSettings::default().max_parallel_tasks
            {
                base.scanner.performance.max_parallel_tasks =
                    scanner.performance.max_parallel_tasks;
            }
            if scanner.performance.enable_threat_modeling
                != crate::config::scanner::PerformanceSettings::default().enable_threat_modeling
            {
                base.scanner.performance.enable_threat_modeling =
                    scanner.performance.enable_threat_modeling;
            }
            if scanner.performance.enable_root_cause_dedup
                != crate::config::scanner::PerformanceSettings::default().enable_root_cause_dedup
            {
                base.scanner.performance.enable_root_cause_dedup =
                    scanner.performance.enable_root_cause_dedup;
            }
            if scanner.performance.enable_auto_patching
                != crate::config::scanner::PerformanceSettings::default().enable_auto_patching
            {
                base.scanner.performance.enable_auto_patching =
                    scanner.performance.enable_auto_patching;
            }
            if scanner.performance.enable_poc_compilation
                != crate::config::scanner::PerformanceSettings::default().enable_poc_compilation
            {
                base.scanner.performance.enable_poc_compilation =
                    scanner.performance.enable_poc_compilation;
            }
            if scanner.performance.enable_confidence_refinement
                != crate::config::scanner::PerformanceSettings::default()
                    .enable_confidence_refinement
            {
                base.scanner.performance.enable_confidence_refinement =
                    scanner.performance.enable_confidence_refinement;
            }
            if scanner.performance.enable_cve_bootstrap
                != crate::config::scanner::PerformanceSettings::default().enable_cve_bootstrap
            {
                base.scanner.performance.enable_cve_bootstrap =
                    scanner.performance.enable_cve_bootstrap;
            }
            if scanner.performance.enable_variant_search
                != crate::config::scanner::PerformanceSettings::default().enable_variant_search
            {
                base.scanner.performance.enable_variant_search =
                    scanner.performance.enable_variant_search;
            }
            if scanner.performance.enable_hunt_prompts
                != crate::config::scanner::PerformanceSettings::default().enable_hunt_prompts
            {
                base.scanner.performance.enable_hunt_prompts =
                    scanner.performance.enable_hunt_prompts;
            }
            if scanner.performance.never_submit_enabled
                != crate::config::scanner::PerformanceSettings::default().never_submit_enabled
            {
                base.scanner.performance.never_submit_enabled =
                    scanner.performance.never_submit_enabled;
            }
            if scanner.performance.never_submit_multiplier
                != crate::config::scanner::PerformanceSettings::default().never_submit_multiplier
            {
                base.scanner.performance.never_submit_multiplier =
                    scanner.performance.never_submit_multiplier;
            }
            if !scanner.performance.variant_search_patterns.is_empty() {
                base.scanner.performance.variant_search_patterns =
                    scanner.performance.variant_search_patterns.clone();
            }
            // VulnSpec config - merge if preset has non-default values
            if scanner.performance.vuln_spec.enabled
                != crate::config::scanner::PerformanceSettings::default()
                    .vuln_spec
                    .enabled
            {
                base.scanner.performance.vuln_spec.enabled = scanner.performance.vuln_spec.enabled;
            }
            if scanner.performance.vuln_spec.db_path
                != crate::config::scanner::PerformanceSettings::default()
                    .vuln_spec
                    .db_path
            {
                base.scanner.performance.vuln_spec.db_path =
                    scanner.performance.vuln_spec.db_path.clone();
            }
            if scanner.performance.vuln_spec.auto_extract_from_patches
                != crate::config::scanner::PerformanceSettings::default()
                    .vuln_spec
                    .auto_extract_from_patches
            {
                base.scanner.performance.vuln_spec.auto_extract_from_patches =
                    scanner.performance.vuln_spec.auto_extract_from_patches;
            }
        }

        if let Some(ref llm) = self.llm {
            if llm.timeout_secs > 0 {
                base.llm.timeout_secs = llm.timeout_secs;
            }
            if llm.max_concurrent > 0 {
                base.llm.max_concurrent = llm.max_concurrent;
            }
            // Apply temperature unconditionally - presence in preset means explicit value
            // This allows 0.0 and negative temperatures to be set from presets
            base.llm.temperature = llm.temperature;
            // Phase configs
            if !llm.phases.discovery.models.is_empty() {
                base.llm.phases.discovery.models = llm.phases.discovery.models.clone();
            }
            if !llm.phases.verification.models.is_empty() {
                base.llm.phases.verification.models = llm.phases.verification.models.clone();
            } else if !llm.phases.verification.model.is_empty() {
                base.llm.phases.verification.model = llm.phases.verification.model.clone();
            }
            if !llm.phases.aggregation.models.is_empty() {
                base.llm.phases.aggregation.models = llm.phases.aggregation.models.clone();
            } else if !llm.phases.aggregation.model.is_empty() {
                base.llm.phases.aggregation.model = llm.phases.aggregation.model.clone();
            }
        }

        if let Some(ref triage) = self.triage {
            base.triage.enabled = triage.enabled;
            if !triage.model.is_empty() {
                base.triage.model = triage.model.clone();
            }
            if triage.batch_size > 0 {
                base.triage.batch_size = triage.batch_size;
            }
            if triage.suspicion_threshold > 0.0 {
                base.triage.suspicion_threshold = triage.suspicion_threshold;
            }
        }

        if let Some(ref priority) = self.priority {
            base.priority.enabled = priority.enabled;
            base.priority.git_recent_boost = priority.git_recent_boost;
            base.priority.entry_point_boost = priority.entry_point_boost;
            base.priority.small_file_boost = priority.small_file_boost;
            if !priority.entry_point_patterns.is_empty() {
                base.priority.entry_point_patterns = priority.entry_point_patterns.clone();
            }
            if !priority.sink_patterns.is_empty() {
                base.priority.sink_patterns = priority.sink_patterns.clone();
            }
        }

        if let Some(ref budget) = self.budget {
            base.budget.enabled = budget.enabled;
            if budget.max_llm_calls > 0 {
                base.budget.max_llm_calls = budget.max_llm_calls;
            }
            if budget.reserve_percent_for_high_risk > 0 {
                base.budget.reserve_percent_for_high_risk = budget.reserve_percent_for_high_risk;
            }
        }

        if let Some(ref agent_flow) = self.agent_flow {
            base.agent_flow.enabled = agent_flow.enabled;
            base.agent_flow.max_iterations = agent_flow.max_iterations;
            base.agent_flow.requires_instrumented_target = agent_flow.requires_instrumented_target;
        }

        if let Some(ref agent) = self.agent {
            base.agent.enabled = agent.enabled;
            base.agent.max_turns = agent.max_turns;
            base.agent.tool_timeout_secs = agent.tool_timeout_secs;
            if !agent.trusted_paths.is_empty() {
                base.agent.trusted_paths = agent.trusted_paths.clone();
            }
        }

        if let Some(ref knowledge) = self.knowledge {
            if !knowledge.fp_patterns.is_empty() {
                base.knowledge.fp_patterns = knowledge.fp_patterns.clone();
            }
            if !knowledge.required_security_primitives.is_empty() {
                base.knowledge.required_security_primitives =
                    knowledge.required_security_primitives.clone();
            }
            if !knowledge.hook_registry.is_empty() {
                base.knowledge.hook_registry = knowledge.hook_registry.clone();
            }
        }
    }
}

/// Load a preset by name, resolving from:
/// 1. Bundled presets (via include_str! at compile time)
/// 2. User directory: `~/.config/baco/presets/<name>.toml`
pub fn load_preset(name: &str) -> Result<PresetOverlay, ScanError> {
    // Check bundled presets first
    if let Some(content) = get_bundled_preset(name) {
        return toml::from_str(content).map_err(ScanError::from_toml_error);
    }

    // Check user directory
    let user_preset_path = user_preset_dir().join(format!("{}.toml", name));

    if user_preset_path.exists() {
        let content = fs::read_to_string(&user_preset_path).map_err(ScanError::IoError)?;
        return toml::from_str(&content).map_err(ScanError::from_toml_error);
    }

    Err(ScanError::Config {
        message: format!(
            "Unknown preset '{}'. Available presets: {}",
            name,
            list_available_presets().join(", ")
        ),
        source: None,
    })
}

/// Get a bundled preset by name (embedded at compile time)
fn get_bundled_preset(name: &str) -> Option<&'static str> {
    match name {
        "wordpress-core" => Some(include_str!("../presets/wordpress-core.toml")),
        "wordpress-plugin" => Some(include_str!("../presets/wordpress-plugin.toml")),
        "django" => Some(include_str!("../presets/django.toml")),
        "laravel" => Some(include_str!("../presets/laravel.toml")),
        "cpp" => Some(include_str!("../presets/cpp.toml")),
        "litellm" => Some(include_str!("../presets/litellm.toml")),
        "oss-python" => Some(include_str!("../presets/oss-python.toml")),
        "oss-monorepo" => Some(include_str!("../presets/oss-monorepo.toml")),
        _ => None,
    }
}

/// List all available presets (bundled + user directory)
pub fn list_available_presets() -> Vec<String> {
    let mut presets = BUILTIN_PRESETS
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();

    // Add user directory presets
    let user_dir = user_preset_dir();

    if user_dir.exists() {
        if let Ok(entries) = fs::read_dir(&user_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension() {
                        if ext == "toml" {
                            if let Some(stem) = path.file_stem() {
                                let name = stem.to_string_lossy().to_string();
                                if !presets.contains(&name) {
                                    presets.push(format!("{} (user)", name));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    presets
}

/// User preset directory via the platform config dir.
fn user_preset_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("/.config"))
        .join("baco")
        .join("presets")
}

/// Get user preset path
pub fn user_preset_path(name: &str) -> PathBuf {
    user_preset_dir().join(format!("{}.toml", name))
}

/// Get bundled preset for display (public wrapper around private get_bundled_preset)
pub fn get_bundled_preset_for_display(name: &str) -> Option<&'static str> {
    get_bundled_preset(name)
}
