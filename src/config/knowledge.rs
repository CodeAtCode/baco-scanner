use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Per-language hook registry configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HookRegistryLanguageConfig {
    /// Label used to synthesize hook names when the registration pattern lacks a `hook` named capture
    #[serde(default = "default_hook_label")]
    pub hook_label: String,
    /// Regex patterns for hook registrations; use (?P<hook>...) named capture for hook names
    #[serde(default)]
    pub registrations: Vec<String>,
    /// Optional override for handler callable patterns; None uses built-in PHP callable forms
    #[serde(default)]
    pub handler_patterns: Option<Vec<String>>,
}

fn default_hook_label() -> String {
    "entry_point".to_string()
}

/// Knowledge configuration: per-CWE false-positive indicator patterns
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KnowledgeConfig {
    /// CWE id ("CWE-79") -> literal code substrings indicating a likely false positive
    #[serde(default)]
    pub fp_patterns: HashMap<String, Vec<String>>,
    /// Language-keyed primitives that must guard privileged actions; verification prompt references them.
    #[serde(default)]
    pub required_security_primitives: HashMap<String, Vec<String>>,
    /// Per-language hook registry configuration for framework-specific entry point detection
    #[serde(default)]
    pub hook_registry: HashMap<String, HookRegistryLanguageConfig>,
}
