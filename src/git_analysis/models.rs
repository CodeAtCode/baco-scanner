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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_reference_creation() {
        let commit = CommitReference {
            commit_hash: "abc123".to_string(),
            commit_message: "Fix security issue".to_string(),
            author: "Test Author".to_string(),
            author_email: "test@example.com".to_string(),
            timestamp: 1234567890,
            modified_files: vec!["test.c".to_string()],
            lines_added: 10,
            lines_deleted: 5,
            is_security_fix: true,
            cwe_references: vec!["CWE-79".to_string()],
        };
        assert_eq!(commit.commit_hash, "abc123");
        assert!(commit.is_security_fix);
        assert_eq!(commit.cwe_references.len(), 1);
    }

    #[test]
    fn test_vulnerability_pattern_creation() {
        let pattern = VulnerabilityPattern {
            pattern_type: VulnerabilityPatternType::SecurityFix,
            description: "Security fix detected".to_string(),
            cwe_id: Some("CWE-79".to_string()),
            commit: "abc123".to_string(),
            confidence: 0.85,
        };
        assert_eq!(pattern.pattern_type_to_string(), "Security Fix");
        assert_eq!(pattern.confidence, 0.85);
    }

    #[test]
    fn test_vulnerability_pattern_type_to_string() {
        let pattern = VulnerabilityPattern {
            pattern_type: VulnerabilityPatternType::SecurityVulnerability,
            description: "Test".to_string(),
            cwe_id: None,
            commit: "abc".to_string(),
            confidence: 0.5,
        };
        assert_eq!(pattern.pattern_type_to_string(), "Security Vulnerability");

        let pattern = VulnerabilityPattern {
            pattern_type: VulnerabilityPatternType::SecurityTodo,
            description: "Test".to_string(),
            cwe_id: None,
            commit: "abc".to_string(),
            confidence: 0.5,
        };
        assert_eq!(pattern.pattern_type_to_string(), "Security TODO");

        let pattern = VulnerabilityPattern {
            pattern_type: VulnerabilityPatternType::Custom("my-custom".to_string()),
            description: "Test".to_string(),
            cwe_id: None,
            commit: "abc".to_string(),
            confidence: 0.5,
        };
        assert_eq!(pattern.pattern_type_to_string(), "my-custom");
    }

    #[test]
    fn test_risky_commit_pattern_creation() {
        let pattern = RiskyCommitPattern {
            pattern_type: RiskyPatternType::LargeChange,
            description: "Large change detected".to_string(),
            commit: "abc123".to_string(),
            risk_score: 0.75,
        };
        assert_eq!(pattern.risk_score, 0.75);
        assert!(pattern.risk_score >= 0.0 && pattern.risk_score <= 1.0);
    }

    #[test]
    fn test_git_confidence_modifier_creation() {
        let modifier = GitConfidenceModifier {
            source: "git-history".to_string(),
            modifier: 0.1,
            reason: "Security fix in history".to_string(),
        };
        assert_eq!(modifier.source, "git-history");
        assert_eq!(modifier.modifier, 0.1);
    }

    #[test]
    fn test_git_analysis_result_creation() {
        let result = GitAnalysisResult {
            related_commits: vec![],
            vulnerability_patterns: vec![],
            risky_patterns: vec![],
            confidence_modifiers: vec![],
            git_confidence_score: 0.5,
        };
        assert_eq!(result.git_confidence_score, 0.5);
        assert!(result.related_commits.is_empty());
    }

    #[test]
    fn test_json_roundtrip_commit_reference() {
        let commit = CommitReference {
            commit_hash: "abc123".to_string(),
            commit_message: "Fix security issue".to_string(),
            author: "Test Author".to_string(),
            author_email: "test@example.com".to_string(),
            timestamp: 1234567890,
            modified_files: vec!["test.c".to_string(), "src/main.rs".to_string()],
            lines_added: 10,
            lines_deleted: 5,
            is_security_fix: true,
            cwe_references: vec!["CWE-79".to_string(), "CWE-89".to_string()],
        };

        let json = serde_json::to_string(&commit).unwrap();
        let deserialized: CommitReference = serde_json::from_str(&json).unwrap();
        assert_eq!(commit.commit_hash, deserialized.commit_hash);
        assert_eq!(commit.modified_files, deserialized.modified_files);
        assert_eq!(commit.cwe_references, deserialized.cwe_references);
    }

    #[test]
    fn test_json_roundtrip_vulnerability_pattern() {
        let pattern = VulnerabilityPattern {
            pattern_type: VulnerabilityPatternType::InjectionRisk,
            description: "SQL injection risk".to_string(),
            cwe_id: Some("CWE-89".to_string()),
            commit: "def456".to_string(),
            confidence: 0.92,
        };

        let json = serde_json::to_string(&pattern).unwrap();
        let deserialized: VulnerabilityPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(pattern.description, deserialized.description);
        assert_eq!(pattern.confidence, deserialized.confidence);
    }
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
