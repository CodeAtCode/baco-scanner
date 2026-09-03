use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TriageVerdict {
    #[default]
    Pass,
    Kill,
    Downgrade {
        adjusted_severity: Severity,
    },
    ChainRequired {
        chain_partner_ids: Vec<String>,
    },
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

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// Statement-level localization: (start_line, end_line) of vulnerable statements
    /// None means function-level only (backward compatible)
    #[serde(default)]
    pub statement_range: Option<(u32, u32)>,
    #[serde(default)]
    pub triage_verdict: Option<TriageVerdict>,
    #[serde(default)]
    pub evidence: Vec<crate::evidence::Evidence>,
    #[serde(default)]
    pub verification_tier: Option<crate::evidence::VerificationTier>,
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

    pub fn add_evidence(
        &mut self,
        source: crate::evidence::EvidenceSource,
        weight: f64,
        detail: String,
    ) {
        self.evidence.push(crate::evidence::Evidence {
            source,
            weight,
            detail,
            timestamp: chrono::Utc::now(),
        });
    }
}
