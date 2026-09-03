//! CVE-related types

use serde::{Deserialize, Serialize};

use super::severity::V3Severity;

/// Source of CVE data
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum CveSource {
    #[default]
    NVD,
    KEV, // CISA Known Exploited Vulnerabilities - higher priority
}

/// CVE entry from CISA KEV or NVD
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CveEntry {
    pub cve_id: String,
    pub description: String,
    pub severity: V3Severity,
    pub source: CveSource,
    pub affected_products: Vec<String>,
    pub published_date: Option<String>,
}

impl CveEntry {
    pub fn new(cve_id: &str, description: &str, severity: V3Severity, source: CveSource) -> Self {
        Self {
            cve_id: cve_id.to_string(),
            description: description.to_string(),
            severity,
            source,
            affected_products: Vec::new(),
            published_date: None,
        }
    }
}

/// Root cause group for deduplication
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RootCauseGroup {
    pub root_cause_id: String, // SHA256 hash of AST slice
    pub findings: Vec<String>, // Finding IDs
    pub description: String,
    pub all_locations: Vec<(String, u32)>, // (file_path, line_number)
    pub severity: V3Severity,
}

impl RootCauseGroup {
    pub fn new(root_cause_id: &str, description: &str, severity: V3Severity) -> Self {
        Self {
            root_cause_id: root_cause_id.to_string(),
            findings: Vec::new(),
            description: description.to_string(),
            all_locations: Vec::new(),
            severity,
        }
    }

    pub fn add_finding(&mut self, finding_id: &str, file_path: &str, line_number: u32) {
        self.findings.push(finding_id.to_string());
        self.all_locations
            .push((file_path.to_string(), line_number));
    }
}

/// CVE cluster for threat intel
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CveCluster {
    pub pattern_name: String,
    pub cve_count: u32,
    pub example_cves: Vec<String>,
    pub affected_dependencies: Vec<String>,
}
