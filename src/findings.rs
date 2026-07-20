use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Confirmed,
    FalsePositive,
    NeedsReview,
    Failed,
}

impl std::fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationStatus::Confirmed => write!(f, "confirmed"),
            VerificationStatus::FalsePositive => write!(f, "false_positive"),
            VerificationStatus::NeedsReview => write!(f, "needs_review"),
            VerificationStatus::Failed => write!(f, "failed"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub const fn is_high_or_critical(&self) -> bool {
        matches!(self, Severity::High | Severity::Critical)
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "Critical"),
            Severity::High => write!(f, "High"),
            Severity::Medium => write!(f, "Medium"),
            Severity::Low => write!(f, "Low"),
            Severity::Info => write!(f, "Info"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueCategory {
    // Traditional (have CWE mappings)
    MemoryCorruption,
    Injection,
    AuthenticationBypass,
    IntegerOverflow,

    // Business Logic (no standard CWE)
    BusinessLogicFlaw,
    RaceCondition,
    DataLeakage,
    Misconfiguration,

    // Operational
    AvailabilityRisk,
    ComplianceViolation,
    PrivacyViolation,

    // Architectural
    TrustBoundaryViolation,
    UnsafeDependency,
    CryptographicMisuse,

    // Custom (user-defined)
    Custom(String),
}

impl Default for IssueCategory {
    fn default() -> Self {
        IssueCategory::Custom("generic".to_string())
    }
}

impl std::fmt::Display for IssueCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssueCategory::MemoryCorruption => write!(f, "memory_corruption"),
            IssueCategory::Injection => write!(f, "injection"),
            IssueCategory::AuthenticationBypass => write!(f, "authentication_bypass"),
            IssueCategory::IntegerOverflow => write!(f, "integer_overflow"),
            IssueCategory::BusinessLogicFlaw => write!(f, "business_logic_flaw"),
            IssueCategory::RaceCondition => write!(f, "race_condition"),
            IssueCategory::DataLeakage => write!(f, "data_leakage"),
            IssueCategory::Misconfiguration => write!(f, "misconfiguration"),
            IssueCategory::AvailabilityRisk => write!(f, "availability_risk"),
            IssueCategory::ComplianceViolation => write!(f, "compliance_violation"),
            IssueCategory::PrivacyViolation => write!(f, "privacy_violation"),
            IssueCategory::TrustBoundaryViolation => write!(f, "trust_boundary_violation"),
            IssueCategory::UnsafeDependency => write!(f, "unsafe_dependency"),
            IssueCategory::CryptographicMisuse => write!(f, "cryptographic_misuse"),
            IssueCategory::Custom(s) => write!(f, "{}", s),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityIssue {
    pub category: IssueCategory,
    #[serde(default)]
    pub cwe_id: Option<String>,
    #[serde(default)]
    pub owasp_category: Option<String>,
    #[serde(default)]
    pub mitre_attack: Option<String>,
    #[serde(default)]
    pub custom_tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence_score: f32,
    pub cwe_id: Option<String>,
    pub file_path: String,
    pub line_number: Option<u32>,
    pub code_snippet: Option<String>,
    /// Unified diff hunk showing the vulnerability and the fix.
    #[serde(default)]
    pub diff_hunk: Option<String>,
    pub recommendation: Option<String>,
    pub code_location: Option<String>,
    pub already_reported: bool,
    pub sources: Vec<String>,
    pub commit_reference: Option<String>,
    pub ticket_reference: Option<String>,
    pub priority_score: Option<f32>,
    pub cross_file_references: Option<Vec<String>>,
    #[serde(default)]
    pub verification_status: Option<VerificationStatus>,
    #[serde(default)]
    pub verification_notes: Option<String>,
    #[serde(default)]
    pub verification_error: Option<String>,
    #[serde(default)]
    pub agent_evidence_path: Option<String>,
    #[serde(default)]
    pub security_issue: Option<SecurityIssue>,
    /// Generated Proof of Concept code snippets.
    #[serde(default)]
    pub poc_code: Option<String>,
    /// Mitigation example code (safe version).
    #[serde(default)]
    pub mitigation_code: Option<String>,
    /// PoC format (rust, python, shell, go).
    #[serde(default)]
    pub poc_format: Option<String>,
    /// LLM model used for discovery/analysis
    #[serde(default)]
    pub llm_model: Option<String>,
    /// Whether agent mode was used for this finding
    #[serde(default)]
    pub agent_mode: bool,
}

impl VulnerabilityFinding {
    pub fn generate_id(file_path: &str, line_number: Option<u32>, cwe_id: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(file_path.as_bytes());
        if let Some(line) = line_number {
            hasher.update(line.to_string().as_bytes());
        }
        hasher.update(cwe_id.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }
}

pub struct FindingsMerger {
    findings: Vec<VulnerabilityFinding>,
}

impl FindingsMerger {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    pub fn merge(&mut self, new_findings: Vec<VulnerabilityFinding>) {
        for finding in new_findings {
            if !self.findings.iter().any(|f| f.id == finding.id) {
                self.findings.push(finding);
            }
        }
    }

    /// Merge findings from multiple scans, deduplicating by RootCauseId
    ///
    /// This method takes multiple scans (each scan is a Vec of findings) and merges them
    /// into a single deduplicated list. Findings with the same id are considered duplicates.
    pub fn merge_scans(scans: Vec<Vec<VulnerabilityFinding>>) -> Vec<VulnerabilityFinding> {
        let mut seen_ids = std::collections::HashSet::new();
        let mut merged = Vec::new();

        for scan in scans {
            for finding in scan {
                if seen_ids.insert(finding.id.clone()) {
                    merged.push(finding);
                }
            }
        }

        merged
    }

    pub fn into_findings(self) -> Vec<VulnerabilityFinding> {
        self.findings
    }
}

impl Default for FindingsMerger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_id_deterministic() {
        let id1 = VulnerabilityFinding::generate_id("test.c", Some(42), "CWE-79");
        let id2 = VulnerabilityFinding::generate_id("test.c", Some(42), "CWE-79");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_generate_id_different_inputs() {
        let id1 = VulnerabilityFinding::generate_id("test.c", Some(42), "CWE-79");
        let id2 = VulnerabilityFinding::generate_id("test.c", Some(43), "CWE-79");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_json_roundtrip() {
        let finding = VulnerabilityFinding {
            id: "test-id".to_string(),
            title: "Test Title".to_string(),
            description: "Test Description".to_string(),
            severity: Severity::High,
            confidence_score: 0.8,
            cwe_id: Some("CWE-79".to_string()),
            file_path: "test.c".to_string(),
            line_number: Some(42),
            code_snippet: Some("printf(x)".to_string()),
            diff_hunk: None,
            recommendation: Some("Sanitize input".to_string()),
            code_location: Some("test.c:42".to_string()),
            already_reported: false,
            sources: vec!["semgrep".to_string()],
            commit_reference: None,
            ticket_reference: None,
            priority_score: Some(0.9),
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: Some("poc code".to_string()),
            mitigation_code: Some("mitigation code".to_string()),
            poc_format: Some("python".to_string()),
            llm_model: None,
            agent_mode: false,
        };

        let json = serde_json::to_string(&finding).unwrap();
        let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding.id, deserialized.id);
        assert_eq!(finding.severity, deserialized.severity);
        assert_eq!(finding.file_path, deserialized.file_path);
        assert_eq!(finding.poc_code, deserialized.poc_code);
        assert_eq!(finding.mitigation_code, deserialized.mitigation_code);
    }

    #[test]
    fn test_findings_merger_deduplicates() {
        let mut merger = FindingsMerger::new();

        let finding1 = VulnerabilityFinding {
            id: "same-id".to_string(),
            title: "Title 1".to_string(),
            description: "Desc".to_string(),
            severity: Severity::High,
            confidence_score: 0.8,
            cwe_id: None,
            file_path: "test.c".to_string(),
            line_number: Some(42),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        };

        let finding2 = VulnerabilityFinding {
            id: "same-id".to_string(),
            title: "Title 2".to_string(),
            description: "Desc".to_string(),
            severity: Severity::High,
            confidence_score: 0.9,
            cwe_id: None,
            file_path: "test.c".to_string(),
            line_number: Some(42),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        };

        merger.merge(vec![finding1]);
        merger.merge(vec![finding2]);

        let findings = merger.into_findings();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Critical.to_string(), "Critical");
        assert_eq!(Severity::High.to_string(), "High");
        assert_eq!(Severity::Medium.to_string(), "Medium");
        assert_eq!(Severity::Low.to_string(), "Low");
        assert_eq!(Severity::Info.to_string(), "Info");
    }

    #[test]
    fn test_verification_status_display() {
        assert_eq!(VerificationStatus::Confirmed.to_string(), "confirmed");
        assert_eq!(
            VerificationStatus::FalsePositive.to_string(),
            "false_positive"
        );
        assert_eq!(VerificationStatus::NeedsReview.to_string(), "needs_review");
        assert_eq!(VerificationStatus::Failed.to_string(), "failed");
    }
}
