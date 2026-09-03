//! Prompt Engine with template substitution and config override support.
//!
//! Loads prompts from `prompts/phases/*.md` files at runtime.

use super::loader;
use std::collections::HashMap;
use std::fs;

use serde::{Deserialize, Serialize};

use super::templates::{
    cwe_to_hunt_domain, BacoPhase, DefaultPrompts, ProjectType, TemplateVariables,
};

/// Configuration for prompt overrides
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PromptOverrides {
    #[serde(default, rename = "phases")]
    pub phase_overrides: HashMap<String, String>,
}

/// Engine for loading and rendering prompt templates
pub struct PromptEngine {
    pub defaults: DefaultPrompts,
    pub overrides: HashMap<String, String>,
    pub project_type: ProjectType,
    pub hunt_prompts: HashMap<String, String>,
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

        // Load hunt prompts
        let hunt_prompts = loader::load_hunt_prompts(None);

        Self {
            defaults,
            overrides,
            project_type: ProjectType::Web, // default project type
            hunt_prompts,
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
            // six-phase orchestration - use discovery/verification defaults
            BacoPhase::Hunt => self.defaults.llm_discovery.clone(),
            BacoPhase::Validate => self.defaults.llm_verification.clone(),
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

    /// Get prompt for a specific hunt domain
    pub fn get_hunt_prompt(&self, domain: &str) -> Option<String> {
        self.hunt_prompts
            .get(domain)
            .filter(|s| !s.is_empty())
            .cloned()
    }

    /// Get list of available hunt domains
    pub fn available_hunt_domains(&self) -> Vec<String> {
        let mut domains: Vec<String> = self.hunt_prompts.keys().cloned().collect();
        domains.sort();
        domains
    }

    /// Get hunt prompt content for a CWE ID
    /// Maps CWE → hunt domain → returns the prompt module content
    pub fn hunt_prompt_for_cwe(&self, cwe_id: &str) -> Option<String> {
        // Use the existing CWE to domain mapping
        let domain = cwe_to_hunt_domain(cwe_id)?;
        // Load the hunt prompt for that domain
        self.get_hunt_prompt(domain)
    }

    /// Select hunt domains based on programming languages
    /// Language matching is case-insensitive and uses contains() for substring matching
    pub fn select_hunt_domains(languages: &[String]) -> Vec<String> {
        // Language to domains mapping table
        // Each language maps to a list of relevant security domains
        let lang_to_domains: Vec<(&[&str], &[&str])> = vec![
            // C/C++/H -> injection, crypto, resource, memory_safety
            (
                &["c", "cpp", "h"],
                &["injection", "crypto", "resource", "memory_safety"],
            ),
            // Rust -> injection, crypto, memory_safety
            (&["rust"], &["injection", "crypto", "memory_safety"]),
            // JavaScript/TypeScript -> xss, injection, auth, path_traversal
            (
                &["javascript", "typescript"],
                &["xss", "injection", "auth", "path_traversal"],
            ),
            // PHP -> xss, injection, path_traversal, deserialization
            (
                &["php"],
                &["xss", "injection", "path_traversal", "deserialization"],
            ),
            // Python -> injection, auth, path_traversal
            (&["python"], &["injection", "auth", "path_traversal"]),
            // Java/C# -> injection, auth, crypto, deserialization
            (
                &["java", "csharp"],
                &["injection", "auth", "crypto", "deserialization"],
            ),
            // Go -> injection, crypto, resource
            (&["go"], &["injection", "crypto", "resource"]),
        ];

        let mut selected_domains: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for lang in languages {
            let lang_lower = lang.to_lowercase();

            // Find matching language entry
            for (lang_list, domains) in &lang_to_domains {
                // Check if this language matches any in the list
                for &l in *lang_list {
                    if lang_lower == l {
                        for &d in *domains {
                            selected_domains.insert(d.to_string());
                        }
                        break;
                    }
                }
            }
        }

        // If no languages matched, use default
        if selected_domains.is_empty() {
            for &d in &["injection", "auth"] {
                selected_domains.insert(d.to_string());
            }
        }

        // Convert to sorted vec for determinism
        let mut result: Vec<String> = selected_domains.into_iter().collect();
        result.sort();
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
