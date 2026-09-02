use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Knowledge configuration: per-CWE false-positive indicator patterns
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KnowledgeConfig {
    /// CWE id ("CWE-79") -> literal code substrings indicating a likely false positive
    #[serde(default)]
    pub fp_patterns: HashMap<String, Vec<String>>,
}
