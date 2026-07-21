//! Prompt Engine with template substitution and config override support.
//!
//! Loads prompts from `prompts/phases/*.md` files at runtime.

use super::loader;
use std::collections::HashMap;
use std::fs;

use serde::{Deserialize, Serialize};

use super::templates::{BacoPhase, DefaultPrompts, ProjectType, TemplateVariables};

/// Configuration for prompt overrides
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PromptOverrides {
    #[serde(default, rename = "phases")]
    pub phase_overrides: HashMap<String, String>,
}

/// Engine for loading and rendering prompt templates
pub struct PromptEngine {
    pub(crate) defaults: DefaultPrompts,
    pub(crate) overrides: HashMap<String, String>,
    pub(crate) project_type: ProjectType,
}

impl PromptEngine {
    /// Create a new PromptEngine with defaults loaded from prompts/phases/*.md
    pub fn new() -> Self {
        Self::from_config_overrides(std::collections::HashMap::new())
    }

    /// Create a PromptEngine with overrides from config
    pub fn from_config_overrides(overrides: std::collections::HashMap<String, String>) -> Self {
        // Load prompts from markdown files
        let loaded_prompts = loader::load_phase_prompts(None);

        // Convert loaded prompts to DefaultPrompts structure
        let defaults = DefaultPrompts {
            indexing: loaded_prompts.get("indexing").cloned().unwrap_or_default(),
            semgrep: loaded_prompts.get("semgrep").cloned().unwrap_or_default(),
            llm_static_analysis: loaded_prompts
                .get("llm_static_analysis")
                .cloned()
                .unwrap_or_default(),
            llm_discovery: loaded_prompts
                .get("llm_discovery")
                .cloned()
                .unwrap_or_default(),
            llm_verification: loaded_prompts
                .get("llm_verification")
                .cloned()
                .unwrap_or_default(),
            ticket_crossref: loaded_prompts
                .get("ticket_crossref")
                .cloned()
                .unwrap_or_default(),
            git_analysis: loaded_prompts
                .get("git_analysis")
                .cloned()
                .unwrap_or_default(),
            cross_file_analysis: loaded_prompts
                .get("cross_file_analysis")
                .cloned()
                .unwrap_or_default(),
            confidence_scoring: loaded_prompts
                .get("confidence_scoring")
                .cloned()
                .unwrap_or_default(),
            ai_aggregation: loaded_prompts
                .get("ai_aggregation")
                .cloned()
                .unwrap_or_default(),
            reporting: loaded_prompts.get("reporting").cloned().unwrap_or_default(),
        };

        Self {
            defaults,
            overrides,
            project_type: ProjectType::Web, // default project type
        }
    }

    /// Load prompt overrides from a TOML file
    /// The file should have the structure:
    /// [phases]
    /// phase_name = "override prompt text"
    pub fn load_overrides_from_file(
        path: &str,
    ) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let overrides: PromptOverrides = toml::from_str(&content)?;
        Ok(overrides.phase_overrides)
    }

    /// Get prompt for a specific phase
    pub fn get_prompt(&self, phase: &BacoPhase) -> String {
        // Check for override first
        if let Some(override_prompt) = self.overrides.get(&phase.to_string()) {
            return self.render(override_prompt.clone());
        }

        // Fall back to default
        let default_prompt = match phase {
            BacoPhase::Indexing => self.defaults.indexing.clone(),
            BacoPhase::Semgrep => self.defaults.semgrep.clone(),
            BacoPhase::LlmStaticAnalysis => self.defaults.llm_static_analysis.clone(),
            BacoPhase::LlmDiscovery => self.defaults.llm_discovery.clone(),
            BacoPhase::LlmVerification => self.defaults.llm_verification.clone(),
            BacoPhase::TicketCrossRef => self.defaults.ticket_crossref.clone(),
            BacoPhase::GitAnalysis => self.defaults.git_analysis.clone(),
            BacoPhase::CrossFileAnalysis => self.defaults.cross_file_analysis.clone(),
            BacoPhase::ConfidenceScoring => self.defaults.confidence_scoring.clone(),
            BacoPhase::AiAggregation => self.defaults.ai_aggregation.clone(),
            BacoPhase::Reporting => self.defaults.reporting.clone(),
            // T2.5 six-phase orchestration - use discovery/verification defaults
            BacoPhase::Hunt => self.defaults.llm_discovery.clone(),
            BacoPhase::Validate => self.defaults.llm_verification.clone(),
            BacoPhase::IndependentVerify => self.defaults.llm_discovery.clone(),
        };

        self.render(default_prompt)
    }

    /// Render template by substituting {variable} placeholders
    fn render(&self, template: String) -> String {
        let mut result = template;

        // Common variables
        let common_vars = self.get_common_variables();

        for (var, value) in &common_vars {
            let pattern = format!("{{{{{}}}}}", var);
            result = result.replace(&pattern, value);
        }

        // Also support legacy %%VAR%% format
        for (var, value) in &common_vars {
            let pattern = format!("%%%{}%%%", var);
            result = result.replace(&pattern, value);
        }

        result
    }
    /// Get common variables for all templates
    fn get_common_variables(&self) -> HashMap<String, String> {
        let mut vars = TemplateVariables::new();

        // Project metadata
        vars.insert(
            "PROJECT_NAME".to_string(),
            "BACOSecurityScanner".to_string(),
        );
        vars.insert("PROJECT_PATH".to_string(), "/project/root/path".to_string());
        vars.insert("PROJECT_TYPE".to_string(), format!("{}", self.project_type));

        // File analysis settings
        vars.insert(
            "FILE_EXTENSIONS".to_string(),
            "c cpp h header py js ts java go rs".to_string(),
        );
        vars.insert(
            "LANGUAGES".to_string(),
            "C, C++, Python, JavaScript, TypeScript, Java, Go, Rust".to_string(),
        );
        vars.insert("MAX_FILE_SIZE".to_string(), "512KB".to_string());
        vars.insert(
            "EXCLUDE_PATHS".to_string(),
            "tests/, node_modules/, docs/, .git/".to_string(),
        );

        // Template-specific defaults
        vars.insert("CONTEXT_LINES".to_string(), "3".to_string());
        vars.insert(
            "CODE_CONTENT".to_string(),
            "<code_will_be_injected>".to_string(),
        );
        vars.insert("CWE_SPECS".to_string(), String::new());

        // Git analysis
        vars.insert("FINDING_TITLE".to_string(), "<finding_title>".to_string());
        vars.insert("FILE_PATH".to_string(), "<file_path>".to_string());
        vars.insert("LINE_NUMBER".to_string(), "0".to_string());
        vars.insert(
            "VULNERABILITY_DESCRIPTION".to_string(),
            "<vulnerability_description>".to_string(),
        );
        vars.insert("SOURCE_LIST".to_string(), "json".to_string());

        // Cross-file analysis
        vars.insert("VULNERABILITY_LIST".to_string(), "[]".to_string());

        // Confidence scoring
        vars.insert("FINDINGS_LIST".to_string(), "[]".to_string());
        vars.insert("original_score".to_string(), "0.5".to_string());

        // AI aggregation and reporting
        vars.insert("FINDINGS_COUNT".to_string(), "0".to_string());
        vars.insert("SCAN_DATE".to_string(), "2024-01-15".to_string());
        vars.insert(
            "TOOLS_USED".to_string(),
            "Semgrep, LLM Static Analysis, LLM Discovery, LLM Verification".to_string(),
        );
        vars.insert("SCAN_DURATION".to_string(), "15 minutes".to_string());

        // Convert to HashMap
        let mut result = HashMap::new();
        for (k, v) in vars.0 {
            result.insert(k, v);
        }
        result
    }
}

impl Default for PromptEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = PromptEngine::new();
        assert!(engine
            .defaults
            .indexing
            .contains("Analyze the project structure"));
    }

    #[test]
    fn test_get_prompt_phase() {
        let engine = PromptEngine::new();

        let indexing_prompt = engine.get_prompt(&BacoPhase::Indexing);
        assert!(indexing_prompt.contains("Analyze the project structure"));

        let semgrep_prompt = engine.get_prompt(&BacoPhase::Semgrep);
        assert!(semgrep_prompt.contains("Analyze code for security vulnerabilities using Semgrep"));

        let static_analysis = engine.get_prompt(&BacoPhase::LlmStaticAnalysis);
        assert!(static_analysis.contains("OFFENSIVE SECURITY RESEARCHER"));
        assert!(static_analysis.contains("%%LANGUAGE%%"));
    }

    #[test]
    fn test_template_substitution() {
        let engine = PromptEngine::new();
        let _ = engine.get_prompt(&BacoPhase::Indexing);

        // Test that placeholders exist
        assert!(engine.defaults.indexing.contains("%%PROJECT_PATH%%"));
        assert!(engine.defaults.semgrep.contains("%%PROJECT_PATH%%"));
    }

    #[test]
    fn test_legacy_placeholder_format() {
        let engine = PromptEngine::new();
        let prompt = engine.get_prompt(&BacoPhase::Indexing);

        // Both formats should be present
        assert!(prompt.contains("%%PROJECT_PATH%%"));
        assert!(!prompt.contains("{PROJECT_PATH}")); // New format not used in defaults
    }

    #[test]
    fn test_get_all_phases_have_templates() {
        let engine = PromptEngine::new();
        let phases = vec![
            &BacoPhase::Indexing,
            &BacoPhase::Semgrep,
            &BacoPhase::LlmStaticAnalysis,
            &BacoPhase::LlmDiscovery,
            &BacoPhase::LlmVerification,
            &BacoPhase::TicketCrossRef,
            &BacoPhase::GitAnalysis,
            &BacoPhase::CrossFileAnalysis,
            &BacoPhase::ConfidenceScoring,
            &BacoPhase::AiAggregation,
            &BacoPhase::Reporting,
        ];

        for phase in phases {
            let prompt = engine.get_prompt(phase);
            assert!(!prompt.is_empty(), "Phase {:?} has empty prompt", phase);
        }
    }

    #[test]
    fn test_prompt_contains_expected_placeholders() {
        let engine = PromptEngine::new();

        let indexing = engine.get_prompt(&BacoPhase::Indexing);
        assert!(indexing.contains("%%FILE_EXTENSIONS%%"));
        assert!(indexing.contains("%%LANGUAGES%%"));
        assert!(indexing.contains("%%MAX_FILE_SIZE%%"));
        assert!(indexing.contains("%%EXCLUDE_PATHS%%"));

        let static_analysis = engine.get_prompt(&BacoPhase::LlmStaticAnalysis);
        assert!(static_analysis.contains("%%LANGUAGE%%"));
        assert!(static_analysis.contains("%%FILE_PATH%%"));
        assert!(static_analysis.contains("%%LINE_RANGE%%"));
        assert!(static_analysis.contains("%%CODE_CONTENT%%"));

        let discovery = engine.get_prompt(&BacoPhase::LlmDiscovery);
        assert!(discovery.contains("%%FINDING_TITLE%%"));
        assert!(discovery.contains("%%FILE_PATH%%"));
        assert!(discovery.contains("%%LINE_NUMBER%%"));
    }
}
