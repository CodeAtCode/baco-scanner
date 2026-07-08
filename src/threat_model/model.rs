//! Threat model data structures.
//!
//! Defines the core types for threat model representation including
//! YAML frontmatter metadata and markdown body content.

use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Threat model file with YAML frontmatter and markdown body
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ThreatModelFile {
    /// YAML frontmatter containing metadata
    pub frontmatter: ThreatModelFrontmatter,
    /// Markdown body containing threat analysis
    pub body: String,
}

/// YAML frontmatter for threat model metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThreatModelFrontmatter {
    /// Format version
    pub version: String,
    /// ISO 8601 timestamp
    pub generated_at: String,
    /// Project type detected
    pub project_type: String,
    /// Total threat count
    pub total_threats: u32,
    /// High risk areas (file paths)
    pub high_risk_areas: Vec<String>,
}

impl Default for ThreatModelFrontmatter {
    fn default() -> Self {
        Self {
            version: "1.0".to_string(),
            generated_at: Utc::now().to_rfc3339(),
            project_type: "unknown".to_string(),
            total_threats: 0,
            high_risk_areas: Vec::new(),
        }
    }
}
