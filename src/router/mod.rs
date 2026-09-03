//! MoE per-CWE / per-language router for specialized prompt routing.
//!
//! Implements the MoEVD pattern: route findings to specialized prompts based on
//! CWE ID or language, falling back to a default prompt.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::config::RouterConfig;
use crate::prompt::templates::cwe_to_hunt_domain;

/// Route result for a CWE ID
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Route {
    /// Hunt domain (xss, injection, auth, etc.)
    pub domain: Option<String>,
    /// Optional model override for this route
    pub model_override: Option<String>,
}

/// Registry of domain-based routing configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RouterRegistry {
    /// Domain -> model_override mapping
    #[serde(default)]
    pub domains: HashMap<String, DomainConfig>,
}

/// Domain configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DomainConfig {
    /// Optional model override for this domain
    #[serde(default)]
    pub model_override: Option<String>,
}

impl RouterRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            domains: HashMap::new(),
        }
    }

    /// Add a domain configuration
    pub fn add_domain(&mut self, domain: String, config: DomainConfig) {
        self.domains.insert(domain, config);
    }

    /// Get domain configuration
    pub fn get_domain(&self, domain: &str) -> Option<&DomainConfig> {
        self.domains.get(domain)
    }
}

/// Router that routes CWE IDs to hunt domains
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
    /// Create a router from config, seeded with the shipped domain registry
    /// and overlaid with the config's CWE overrides (config wins)
    pub fn from_config(config: &RouterConfig) -> Self {
        let mut registry = Self::default_registry();
        for (domain, dc) in config.to_registry().domains {
            registry.add_domain(domain, dc);
        }
        Self {
            registry,
            default_prompt: config.default_prompt.clone(),
        }
    }

    /// Create a router from the scanner config's RouterConfig
    pub fn from_scanner_config(config: &crate::config::RouterConfig) -> Self {
        Self::from_config(config)
    }

    /// Domains shipped in registry.toml, embedded at compile time
    fn default_registry() -> RouterRegistry {
        static DEFAULT: std::sync::OnceLock<RouterRegistry> = std::sync::OnceLock::new();
        DEFAULT
            .get_or_init(|| {
                #[derive(Deserialize)]
                struct RegistryFile {
                    router: RegistryRouter,
                }
                #[derive(Deserialize)]
                struct RegistryRouter {
                    #[serde(default)]
                    domains: HashMap<String, DomainConfig>,
                }
                let parsed: RegistryFile = toml::from_str(include_str!("registry.toml"))
                    .unwrap_or_else(|e| {
                        tracing::warn!("Invalid registry.toml, using empty registry: {}", e);
                        RegistryFile {
                            router: RegistryRouter {
                                domains: HashMap::new(),
                            },
                        }
                    });
                RouterRegistry {
                    domains: parsed.router.domains,
                }
            })
            .clone()
    }

    /// Route a CWE ID to a domain and model override
    pub fn route_cwe(&self, cwe_id: &str) -> Route {
        // Map CWE to hunt domain using the shared mapping
        if let Some(domain) = cwe_to_hunt_domain(cwe_id) {
            // Look up the domain config
            if let Some(domain_config) = self.registry.get_domain(domain) {
                return Route {
                    domain: Some(domain.to_string()),
                    model_override: domain_config.model_override.clone(),
                };
            }
            // Domain exists in mapping but not in registry - return domain without override
            return Route {
                domain: Some(domain.to_string()),
                model_override: None,
            };
        }
        // Unknown CWE - return uncategorized
        Route {
            domain: None,
            model_override: None,
        }
    }

    /// Get the default prompt template name
    pub fn default_prompt(&self) -> &str {
        &self.default_prompt
    }
}

/// Public helper that returns (domain, prompt_content) for a CWE ID
/// Dead-code-safe: marked pub for external consumption
/// Returns None if CWE has no mapping or prompt content is empty
pub fn cwe_specialist_context(cwe_id: &str) -> Option<(String, String)> {
    use crate::prompt::engine::PromptEngine;

    let engine = PromptEngine::new();
    let domain = cwe_to_hunt_domain(cwe_id)?;
    let content = engine.get_hunt_prompt(domain)?;

    if content.is_empty() {
        None
    } else {
        Some((domain.to_string(), content))
    }
}
