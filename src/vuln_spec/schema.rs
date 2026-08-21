//! VulInSpec security specification data structures.
//!
//! This module defines the core data structures for the VulInSpec approach
//! (arXiv:2511.04014), which extracts security specifications from historical
//! vulnerabilities and patches to enhance vulnerability detection.

use serde::{Deserialize, Serialize};

/// Unique identifier for a security specification
pub type SpecId = String;

/// CWE (Common Weakness Enumeration) identifier
pub type CweId = String;

/// Domain category distinguishing general vs domain-specific specifications
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum DomainCategory {
    /// General specifications: fundamental safe behaviors across all projects
    #[default]
    General,
    /// Domain-specific: repeated violations in particular repositories/domains
    DomainSpecific(String),
}

/// A security specification extracted from historical vulnerabilities/patches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySpecification {
    /// Unique identifier for this specification
    pub id: SpecId,
    /// CWE category of the vulnerability this specification addresses
    pub vuln_type: CweId,
    /// Human-readable description of the vulnerability pattern
    pub description: String,
    /// Pattern describing the safe behavior that prevents this vulnerability
    pub safe_behavior_pattern: String,
    /// Project domain context (e.g., "web-server", "database", "crypto")
    pub project_domain: String,
    /// Hash of the source patch this specification was extracted from
    pub source_patch_hash: String,
    /// Category indicating if this is general or domain-specific
    #[serde(default)]
    pub category: DomainCategory,
}

/// Source information for a specification (the patch it came from)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecificationSource {
    /// Path to the project where this patch originated
    pub project_path: String,
    /// Git commit hash containing the patch
    pub commit_hash: String,
    /// The actual diff content
    pub patch_diff: String,
    /// Timestamp when this specification was extracted
    pub extracted_at: String,
}

/// Configuration for the VulInSpec module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnSpecConfig {
    /// Whether VulInSpec is enabled (default: false)
    #[serde(default = "default_false")]
    pub enabled: bool,

    /// Path to the specification database (JSON file)
    #[serde(default = "default_db_path")]
    pub db_path: String,

    /// Whether to automatically extract specs from incoming patches
    #[serde(default = "default_false")]
    pub auto_extract_from_patches: bool,
}

impl Default for VulnSpecConfig {
    fn default() -> Self {
        Self {
            enabled: default_false(),
            db_path: default_db_path(),
            auto_extract_from_patches: default_false(),
        }
    }
}

fn default_false() -> bool {
    false
}

fn default_db_path() -> String {
    "baco-output/vuln_spec_db.json".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_specification() {
        let spec = SecuritySpecification {
            id: "spec-001".to_string(),
            vuln_type: "CWE-79".to_string(),
            description: "Cross-site scripting vulnerability".to_string(),
            safe_behavior_pattern: "Sanitize all user input before rendering".to_string(),
            project_domain: "web-server".to_string(),
            source_patch_hash: "abc123".to_string(),
            category: DomainCategory::General,
        };

        assert_eq!(spec.id, "spec-001");
        assert_eq!(spec.vuln_type, "CWE-79");
        assert!(matches!(spec.category, DomainCategory::General));
    }

    #[test]
    fn test_domain_category_serialization() {
        let general = DomainCategory::General;
        let domain = DomainCategory::DomainSpecific("rust".to_string());

        let general_json = serde_json::to_string(&general).unwrap();
        let domain_json = serde_json::to_string(&domain).unwrap();

        assert_eq!(general_json, "\"General\"");
        assert!(domain_json.contains("rust"));
    }
}
