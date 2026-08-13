//! Git history analysis data models.

use serde::{Deserialize, Serialize};

/// Commit reference with metadata for vulnerability tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitReference {
    /// Full or abbreviated commit hash
    pub commit_hash: String,
    /// Full commit message
    pub commit_message: String,
    /// Author name
    pub author: String,
    /// Author email
    pub author_email: String,
    /// Commit timestamp (Unix epoch)
    pub timestamp: i64,
    /// Files modified in this commit
    pub modified_files: Vec<String>,
    /// Lines added
    pub lines_added: i32,
    /// Lines deleted
    pub lines_deleted: i32,
    /// Whether this appears to be a security fix
    pub is_security_fix: bool,
    /// CWE IDs mentioned in commit message
    pub cwe_references: Vec<String>,
}

/// Vulnerability pattern detected in git history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityPattern {
    /// Pattern type
    pub pattern_type: VulnerabilityPatternType,
    /// Description of the pattern
    pub description: String,
    /// Related CWE if any
    pub cwe_id: Option<String>,
    /// Commit where pattern was found
    pub commit: String,
    /// Confidence that this is a real vulnerability pattern
    pub confidence: f32,
}

impl VulnerabilityPattern {
    pub fn pattern_type_to_string(&self) -> String {
        match &self.pattern_type {
            VulnerabilityPatternType::SecurityVulnerability => "Security Vulnerability".to_string(),
            VulnerabilityPatternType::SecurityFix => "Security Fix".to_string(),
            VulnerabilityPatternType::SecurityTodo => "Security TODO".to_string(),
            VulnerabilityPatternType::SecurityDeprecation => "Security Deprecation".to_string(),
            VulnerabilityPatternType::VulnerableDependency => "Vulnerable Dependency".to_string(),
            VulnerabilityPatternType::InjectionRisk => "Injection Risk".to_string(),
            VulnerabilityPatternType::AuthIssue => "Auth Issue".to_string(),
            VulnerabilityPatternType::CryptoMisuse => "Crypto Misuse".to_string(),
            VulnerabilityPatternType::Custom(s) => s.clone(),
        }
    }
}

/// Types of vulnerability patterns to detect
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VulnerabilityPatternType {
    /// Direct mention of security vulnerability in commit
    SecurityVulnerability,
    /// Security fix (patch applied)
    SecurityFix,
    /// TODO/FIXME related to security
    SecurityTodo,
    /// Deprecated security-related code
    SecurityDeprecation,
    /// Known vulnerable dependency usage
    VulnerableDependency,
    /// Potential injection point
    InjectionRisk,
    /// Authentication/authorization issue
    AuthIssue,
    /// Cryptographic misuse
    CryptoMisuse,
    /// Custom pattern
    Custom(String),
}

/// Risky commit patterns that may indicate security concerns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskyCommitPattern {
    /// Type of risky pattern
    pub pattern_type: RiskyPatternType,
    /// Description
    pub description: String,
    /// Commit hash
    pub commit: String,
    /// Risk score (0.0 - 1.0)
    pub risk_score: f32,
}

/// Types of risky commit patterns
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskyPatternType {
    /// Large change (many files/lines)
    LargeChange,
    /// Hotfix branch (master/main directly)
    Hotfix,
    /// Revert commit
    Revert,
    /// Merge commit with conflicts
    MergeWithConflicts,
    /// Commit by unknown/first-time author
    NewAuthor,
    /// Emergency commit message pattern
    EmergencyCommit,
    /// Security-related bypass
    SecurityBypass,
}

/// Git-based confidence modifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitConfidenceModifier {
    /// Modifier source
    pub source: String,
    /// Value to add to confidence (positive or negative)
    pub modifier: f32,
    /// Reason for the modifier
    pub reason: String,
}

/// Analysis result containing all git-based findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitAnalysisResult {
    /// All commits related to the analyzed file
    pub related_commits: Vec<CommitReference>,
    /// Vulnerability patterns found in history
    pub vulnerability_patterns: Vec<VulnerabilityPattern>,
    /// Risky commit patterns detected
    pub risky_patterns: Vec<RiskyCommitPattern>,
    /// Git-based confidence modifiers
    pub confidence_modifiers: Vec<GitConfidenceModifier>,
    /// Overall git-based confidence score (0.0 - 1.0)
    pub git_confidence_score: f32,
}
