//! MoE per-CWE / per-language router for specialized prompt routing.
//!
//! Implements the MoEVD pattern: route findings to specialized prompts based on
//! CWE ID or language, falling back to a default prompt.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Prompt specification for a routing rule
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PromptSpec {
    /// The prompt template name to use
    pub prompt_template: String,
    /// Optional model override for this prompt
    pub model_override: Option<String>,
}

/// Registry of CWE and language overrides
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RouterRegistry {
    /// CWE ID -> PromptSpec mapping
    cwe_overrides: HashMap<String, PromptSpec>,
    /// Language -> PromptSpec mapping
    language_overrides: HashMap<String, PromptSpec>,
}

impl RouterRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            cwe_overrides: HashMap::new(),
            language_overrides: HashMap::new(),
        }
    }

    /// Add a CWE override
    pub fn add_cwe_override(&mut self, cwe_id: String, spec: PromptSpec) {
        self.cwe_overrides.insert(cwe_id, spec);
    }

    /// Add a language override
    pub fn add_language_override(&mut self, language: String, spec: PromptSpec) {
        self.language_overrides.insert(language, spec);
    }

    /// Get a CWE override
    pub fn get_cwe(&self, cwe_id: &str) -> Option<&PromptSpec> {
        self.cwe_overrides.get(cwe_id)
    }

    /// Get a language override
    pub fn get_language(&self, language: &str) -> Option<&PromptSpec> {
        self.language_overrides.get(language)
    }
}

/// Configuration for the router
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterConfig {
    /// Whether the router is enabled
    pub enabled: bool,
    /// Default prompt template name
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
            default_prompt: "llm_static_analysis".to_string(),
            cwe_overrides: HashMap::new(),
            language_overrides: HashMap::new(),
        }
    }
}

impl RouterConfig {
    /// Create a RouterRegistry from this config
    pub fn to_registry(&self) -> RouterRegistry {
        let mut registry = RouterRegistry::new();
        for (cwe_id, spec) in &self.cwe_overrides {
            registry.add_cwe_override(cwe_id.clone(), spec.clone());
        }
        for (language, spec) in &self.language_overrides {
            registry.add_language_override(language.clone(), spec.clone());
        }
        registry
    }
}

/// Router that dispatches findings to specialized prompts
#[derive(Debug, Clone)]
pub struct CweRouter {
    registry: RouterRegistry,
    default_prompt: String,
}

impl Default for CweRouter {
    fn default() -> Self {
        Self {
            registry: RouterRegistry::new(),
            default_prompt: "llm_static_analysis".to_string(),
        }
    }
}

impl CweRouter {
    /// Create a router from config
    pub fn from_config(config: &RouterConfig) -> Self {
        Self {
            registry: config.to_registry(),
            default_prompt: config.default_prompt.clone(),
        }
    }

    /// Route a finding to the appropriate prompt spec
    ///
    /// Priority: CWE ID > Language > Default
    pub fn route(&self, cwe_id: &Option<String>, language: &str) -> PromptSpec {
        // Try CWE match first
        if let Some(ref cwe) = cwe_id {
            // Normalize CWE ID (handle both "79" and "CWE-79" formats)
            let normalized = normalize_cwe_id(cwe);
            if let Some(spec) = self.registry.get_cwe(&normalized) {
                return spec.clone();
            }
        }

        // Try language match
        if let Some(spec) = self.registry.get_language(language) {
            return spec.clone();
        }

        // Fall back to default
        PromptSpec {
            prompt_template: self.default_prompt.clone(),
            model_override: None,
        }
    }

    /// Route by CWE ID only
    pub fn route_by_cwe(&self, cwe_id: &str) -> Option<PromptSpec> {
        let normalized = normalize_cwe_id(cwe_id);
        self.registry.get_cwe(&normalized).cloned()
    }

    /// Route by language only
    pub fn route_by_language(&self, language: &str) -> Option<PromptSpec> {
        self.registry.get_language(language).cloned()
    }

    /// Get the default prompt template name
    pub fn default_prompt(&self) -> &str {
        &self.default_prompt
    }
}

/// Normalize a CWE ID to just the number part
fn normalize_cwe_id(cwe: &str) -> String {
    cwe.trim_start_matches("CWE-")
        .trim_start_matches("cwe-")
        .to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_cwe_id() {
        assert_eq!(normalize_cwe_id("79"), "79");
        assert_eq!(normalize_cwe_id("CWE-79"), "79");
        assert_eq!(normalize_cwe_id("cwe-79"), "79");
        assert_eq!(normalize_cwe_id("CWE-89"), "89");
    }

    #[test]
    fn test_router_config_default() {
        let config = RouterConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.default_prompt, "llm_static_analysis");
        assert!(config.cwe_overrides.is_empty());
        assert!(config.language_overrides.is_empty());
    }

    #[test]
    fn test_router_registry() {
        let mut registry = RouterRegistry::new();

        let spec = PromptSpec {
            prompt_template: "xss_specialized".to_string(),
            model_override: None,
        };
        registry.add_cwe_override("79".to_string(), spec.clone());

        assert_eq!(registry.get_cwe("79"), Some(&spec));
        assert_eq!(registry.get_cwe("89"), None);
    }

    #[test]
    fn test_cwe_router_default() {
        let router = CweRouter::default();
        assert_eq!(router.default_prompt(), "llm_static_analysis");
    }

    #[test]
    fn test_cwe_router_from_config() {
        let mut cwe_overrides = HashMap::new();
        cwe_overrides.insert(
            "79".to_string(),
            PromptSpec {
                prompt_template: "xss_specialized".to_string(),
                model_override: None,
            },
        );

        let config = RouterConfig {
            enabled: true,
            default_prompt: "custom_default".to_string(),
            cwe_overrides,
            language_overrides: HashMap::new(),
        };

        let router = CweRouter::from_config(&config);
        assert_eq!(router.default_prompt(), "custom_default");
    }
}
