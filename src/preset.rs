/// Preset system for loading project-type-specific scanner configurations.
///
/// Presets provide a base configuration layer that can be overridden by user config.toml
/// and CLI flags. Loading order: built-in defaults → preset file → user config.toml → CLI flags.
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::PathBuf;

use crate::config::ScannerConfig;

/// Embedded preset names (bundled at compile time)
pub const BUILTIN_PRESETS: &[&str] = &[
    "wordpress-core",
    "wordpress-plugin",
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
            // Performance settings
            base.scanner.performance = scanner.performance.clone();
        }

        if let Some(ref llm) = self.llm {
            if llm.timeout_secs > 0 {
                base.llm.timeout_secs = llm.timeout_secs;
            }
            if llm.max_concurrent > 0 {
                base.llm.max_concurrent = llm.max_concurrent;
            }
            if llm.temperature > 0.0 {
                base.llm.temperature = llm.temperature;
            }
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
        }
    }
}

/// Load a preset by name, resolving from:
/// 1. Bundled presets (via include_str! at compile time)
/// 2. User directory: ~/.config/baco/presets/<name>.toml
pub fn load_preset(name: &str) -> Result<PresetOverlay, String> {
    // Check bundled presets first
    if let Some(content) = get_bundled_preset(name) {
        return toml::from_str(content)
            .map_err(|e| format!("Failed to parse bundled preset '{}': {}", name, e));
    }

    // Check user directory
    let user_preset_path = home_dir()
        .join(".config")
        .join("baco")
        .join("presets")
        .join(format!("{}.toml", name));

    if user_preset_path.exists() {
        let content = fs::read_to_string(&user_preset_path)
            .map_err(|e| format!("Failed to read user preset '{}': {}", name, e))?;
        return toml::from_str(&content)
            .map_err(|e| format!("Failed to parse user preset '{}': {}", name, e));
    }

    Err(format!(
        "Unknown preset '{}'. Available presets: {}",
        name,
        list_available_presets().join(", ")
    ))
}

/// Get a bundled preset by name (embedded at compile time)
fn get_bundled_preset(name: &str) -> Option<&'static str> {
    match name {
        "wordpress-core" => Some(include_str!("../presets/wordpress-core.toml")),
        "wordpress-plugin" => Some(include_str!("../presets/wordpress-plugin.toml")),
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
    let user_dir = home_dir().join(".config").join("baco").join("presets");

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

/// Get home directory (cross-platform)
pub fn home_dir() -> PathBuf {
    env::var("HOME")
        .map(PathBuf::from)
        .or_else(|_| env::var("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|_| PathBuf::from("/"))
}
