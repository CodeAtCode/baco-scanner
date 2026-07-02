//! Tests for git_analysis models

use baco::git_analysis::{
    CommitReference, GitAnalysisResult, GitConfidenceModifier, RiskyCommitPattern,
    RiskyPatternType, VulnerabilityPattern, VulnerabilityPatternType,
};

#[test]
fn test_commit_reference_creation() {
    let commit = CommitReference {
        commit_hash: "abc12345".to_string(),
        commit_message: "Test commit".to_string(),
        author: "Test User".to_string(),
        author_email: "test@example.com".to_string(),
        timestamp: 1234567890,
        modified_files: vec!["file.txt".to_string()],
        lines_added: 10,
        lines_deleted: 5,
        is_security_fix: true,
        cwe_references: vec!["CWE-79".to_string()],
    };

    assert_eq!(commit.commit_hash, "abc12345");
    assert_eq!(commit.author, "Test User");
    assert!(commit.is_security_fix);
    assert_eq!(commit.cwe_references.len(), 1);
}

#[test]
fn test_vulnerability_pattern_type_to_string() {
    let patterns = vec![
        (
            VulnerabilityPatternType::SecurityVulnerability,
            "Security Vulnerability",
        ),
        (VulnerabilityPatternType::SecurityFix, "Security Fix"),
        (VulnerabilityPatternType::SecurityTodo, "Security TODO"),
        (
            VulnerabilityPatternType::SecurityDeprecation,
            "Security Deprecation",
        ),
        (
            VulnerabilityPatternType::VulnerableDependency,
            "Vulnerable Dependency",
        ),
        (VulnerabilityPatternType::InjectionRisk, "Injection Risk"),
        (VulnerabilityPatternType::AuthIssue, "Auth Issue"),
        (VulnerabilityPatternType::CryptoMisuse, "Crypto Misuse"),
        (VulnerabilityPatternType::Custom("Custom Pattern".to_string()), "Custom Pattern"),
    ];

    for (pattern_type, expected) in patterns {
        let pattern = VulnerabilityPattern {
            pattern_type: pattern_type.clone(),
            description: "Test".to_string(),
            cwe_id: None,
            commit: "abc12345".to_string(),
            confidence: 0.5,
        };
        assert_eq!(pattern.pattern_type_to_string(), expected);
    }
}

#[test]
fn test_risky_pattern_type_variants() {
    // Test that all variants can be created
    let _large = RiskyPatternType::LargeChange;
    let _hotfix = RiskyPatternType::Hotfix;
    let _revert = RiskyPatternType::Revert;
    let _merge = RiskyPatternType::MergeWithConflicts;
    let _new_author = RiskyPatternType::NewAuthor;
    let _emergency = RiskyPatternType::EmergencyCommit;
    let _security_bypass = RiskyPatternType::SecurityBypass;
}

#[test]
fn test_risky_commit_pattern_creation() {
    let pattern = RiskyCommitPattern {
        pattern_type: RiskyPatternType::LargeChange,
        description: "Large change detected".to_string(),
        commit: "abc12345".to_string(),
        risk_score: 0.75,
    };

    assert_eq!(pattern.pattern_type, RiskyPatternType::LargeChange);
    assert_eq!(pattern.risk_score, 0.75);
    assert!(pattern.risk_score >= 0.0 && pattern.risk_score <= 1.0);
}

#[test]
fn test_git_confidence_modifier_creation() {
    let modifier = GitConfidenceModifier {
        source: "test_source".to_string(),
        modifier: 0.15,
        reason: "Test reason".to_string(),
    };

    assert_eq!(modifier.source, "test_source");
    assert_eq!(modifier.modifier, 0.15);
    assert!(!modifier.reason.is_empty());
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

    assert!(result.related_commits.is_empty());
    assert!(result.vulnerability_patterns.is_empty());
    assert!(result.risky_patterns.is_empty());
    assert!(result.confidence_modifiers.is_empty());
    assert!(result.git_confidence_score >= 0.0 && result.git_confidence_score <= 1.0);
}

#[test]
fn test_commit_reference_serialization() {
    let commit = CommitReference {
        commit_hash: "abc12345".to_string(),
        commit_message: "Test commit".to_string(),
        author: "Test User".to_string(),
        author_email: "test@example.com".to_string(),
        timestamp: 1234567890,
        modified_files: vec!["file.txt".to_string(), "another.txt".to_string()],
        lines_added: 10,
        lines_deleted: 5,
        is_security_fix: true,
        cwe_references: vec!["CWE-79".to_string(), "CWE-89".to_string()],
    };

    // Test serialization
    let serialized = serde_json::to_string(&commit).expect("Failed to serialize");
    assert!(!serialized.is_empty());

    // Test deserialization
    let deserialized: CommitReference =
        serde_json::from_str(&serialized).expect("Failed to deserialize");

    assert_eq!(deserialized.commit_hash, commit.commit_hash);
    assert_eq!(deserialized.author, commit.author);
    assert_eq!(deserialized.is_security_fix, commit.is_security_fix);
}

#[test]
fn test_vulnerability_pattern_serialization() {
    let pattern = VulnerabilityPattern {
        pattern_type: VulnerabilityPatternType::SecurityFix,
        description: "Security fix detected".to_string(),
        cwe_id: Some("CWE-79".to_string()),
        commit: "abc12345".to_string(),
        confidence: 0.85,
    };

    let serialized = serde_json::to_string(&pattern).expect("Failed to serialize");
    let deserialized: VulnerabilityPattern =
        serde_json::from_str(&serialized).expect("Failed to deserialize");

    assert_eq!(deserialized.pattern_type, pattern.pattern_type);
    assert_eq!(deserialized.confidence, pattern.confidence);
    assert_eq!(deserialized.cwe_id, pattern.cwe_id);
}

#[test]
fn test_risky_pattern_type_equality() {
    let large1 = RiskyPatternType::LargeChange;
    let large2 = RiskyPatternType::LargeChange;
    let revert = RiskyPatternType::Revert;

    assert_eq!(large1, large2);
    assert_ne!(large1, revert);
}

#[test]
fn test_vulnerability_pattern_type_equality() {
    let vuln1 = VulnerabilityPatternType::SecurityFix;
    let vuln2 = VulnerabilityPatternType::SecurityFix;
    let todo = VulnerabilityPatternType::SecurityTodo;

    assert_eq!(vuln1, vuln2);
    assert_ne!(vuln1, todo);
}
