//! Unit tests for `baco::findings` module
//!
//! Covers: VerificationStatus, Severity, TriageVerdict, IssueCategory,
//! VulnerabilityFinding, SecurityIssue

use baco::findings::{
    IssueCategory, SecurityIssue, Severity, TriageVerdict, VerificationStatus, VulnerabilityFinding,
};

// ============================================================================
// VerificationStatus Tests
// ============================================================================

#[test]
fn test_verification_status_display_confirmed() {
    assert_eq!(VerificationStatus::Confirmed.to_string(), "confirmed");
}

#[test]
fn test_verification_status_display_false_positive() {
    assert_eq!(
        VerificationStatus::FalsePositive.to_string(),
        "false_positive"
    );
}

#[test]
fn test_verification_status_display_needs_review() {
    assert_eq!(VerificationStatus::NeedsReview.to_string(), "needs_review");
}

#[test]
fn test_verification_status_display_failed() {
    assert_eq!(VerificationStatus::Failed.to_string(), "failed");
}

#[test]
fn test_verification_status_serialize() {
    let confirmed = serde_json::to_string(&VerificationStatus::Confirmed).unwrap();
    assert_eq!(confirmed, "\"confirmed\"");

    let false_positive = serde_json::to_string(&VerificationStatus::FalsePositive).unwrap();
    assert_eq!(false_positive, "\"false_positive\"");

    let needs_review = serde_json::to_string(&VerificationStatus::NeedsReview).unwrap();
    assert_eq!(needs_review, "\"needs_review\"");

    let failed = serde_json::to_string(&VerificationStatus::Failed).unwrap();
    assert_eq!(failed, "\"failed\"");
}

#[test]
fn test_verification_status_deserialize() {
    let confirmed: VerificationStatus = serde_json::from_str("\"confirmed\"").unwrap();
    assert_eq!(confirmed, VerificationStatus::Confirmed);

    let false_positive: VerificationStatus = serde_json::from_str("\"false_positive\"").unwrap();
    assert_eq!(false_positive, VerificationStatus::FalsePositive);

    let needs_review: VerificationStatus = serde_json::from_str("\"needs_review\"").unwrap();
    assert_eq!(needs_review, VerificationStatus::NeedsReview);

    let failed: VerificationStatus = serde_json::from_str("\"failed\"").unwrap();
    assert_eq!(failed, VerificationStatus::Failed);
}

#[test]
fn test_verification_status_roundtrip() {
    let statuses = [
        VerificationStatus::Confirmed,
        VerificationStatus::FalsePositive,
        VerificationStatus::NeedsReview,
        VerificationStatus::Failed,
    ];

    for status in statuses {
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: VerificationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, deserialized);
    }
}

// ============================================================================
// Severity Tests
// ============================================================================

#[test]
fn test_severity_display_critical() {
    assert_eq!(Severity::Critical.to_string(), "Critical");
}

#[test]
fn test_severity_display_high() {
    assert_eq!(Severity::High.to_string(), "High");
}

#[test]
fn test_severity_display_medium() {
    assert_eq!(Severity::Medium.to_string(), "Medium");
}

#[test]
fn test_severity_display_low() {
    assert_eq!(Severity::Low.to_string(), "Low");
}

#[test]
fn test_severity_display_info() {
    assert_eq!(Severity::Info.to_string(), "Info");
}

#[test]
fn test_severity_is_high_or_critical_true() {
    assert!(Severity::Critical.is_high_or_critical());
    assert!(Severity::High.is_high_or_critical());
}

#[test]
fn test_severity_is_high_or_critical_false() {
    assert!(!Severity::Medium.is_high_or_critical());
    assert!(!Severity::Low.is_high_or_critical());
    assert!(!Severity::Info.is_high_or_critical());
}

#[test]
fn test_severity_serialize() {
    let critical = serde_json::to_string(&Severity::Critical).unwrap();
    assert_eq!(critical, "\"critical\"");

    let high = serde_json::to_string(&Severity::High).unwrap();
    assert_eq!(high, "\"high\"");

    let medium = serde_json::to_string(&Severity::Medium).unwrap();
    assert_eq!(medium, "\"medium\"");

    let low = serde_json::to_string(&Severity::Low).unwrap();
    assert_eq!(low, "\"low\"");

    let info = serde_json::to_string(&Severity::Info).unwrap();
    assert_eq!(info, "\"info\"");
}

#[test]
fn test_severity_deserialize() {
    let critical: Severity = serde_json::from_str("\"critical\"").unwrap();
    assert_eq!(critical, Severity::Critical);

    let high: Severity = serde_json::from_str("\"high\"").unwrap();
    assert_eq!(high, Severity::High);

    let medium: Severity = serde_json::from_str("\"medium\"").unwrap();
    assert_eq!(medium, Severity::Medium);

    let low: Severity = serde_json::from_str("\"low\"").unwrap();
    assert_eq!(low, Severity::Low);

    let info: Severity = serde_json::from_str("\"info\"").unwrap();
    assert_eq!(info, Severity::Info);
}

#[test]
fn test_severity_roundtrip() {
    let severities = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    for severity in severities {
        let json = serde_json::to_string(&severity).unwrap();
        let deserialized: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(severity, deserialized);
    }
}

// ============================================================================
// TriageVerdict Tests
// ============================================================================

#[test]
fn test_triage_verdict_default_is_pass() {
    let default_verdict = TriageVerdict::default();
    assert_eq!(default_verdict, TriageVerdict::Pass);
}

#[test]
fn test_triage_verdict_display_pass() {
    // TriageVerdict doesn't implement Display, use Debug format
    let verdict = TriageVerdict::Pass;
    let display = format!("{:?}", verdict);
    assert!(display.contains("Pass"));
}

#[test]
fn test_triage_verdict_display_kill() {
    let verdict = TriageVerdict::Kill;
    let display = format!("{:?}", verdict);
    assert!(display.contains("Kill"));
}

#[test]
fn test_triage_verdict_display_downgrade() {
    let verdict = TriageVerdict::Downgrade {
        adjusted_severity: Severity::Medium,
    };
    let display = format!("{:?}", verdict);
    assert!(display.contains("Downgrade"));
}

#[test]
fn test_triage_verdict_display_chain_required() {
    let verdict = TriageVerdict::ChainRequired {
        chain_partner_ids: vec!["partner1".to_string()],
    };
    let display = format!("{:?}", verdict);
    assert!(display.contains("ChainRequired"));
}

#[test]
fn test_triage_verdict_serialize_pass() {
    let json = serde_json::to_string(&TriageVerdict::Pass).unwrap();
    assert_eq!(json, "\"pass\"");
}

#[test]
fn test_triage_verdict_serialize_kill() {
    let json = serde_json::to_string(&TriageVerdict::Kill).unwrap();
    assert_eq!(json, "\"kill\"");
}

#[test]
fn test_triage_verdict_serialize_downgrade() {
    let verdict = TriageVerdict::Downgrade {
        adjusted_severity: Severity::Medium,
    };
    let json = serde_json::to_string(&verdict).unwrap();
    assert!(json.contains("downgrade"));
    assert!(json.contains("medium"));
}

#[test]
fn test_triage_verdict_serialize_chain_required() {
    let verdict = TriageVerdict::ChainRequired {
        chain_partner_ids: vec!["partner1".to_string(), "partner2".to_string()],
    };
    let json = serde_json::to_string(&verdict).unwrap();
    assert!(json.contains("chain_required"));
    assert!(json.contains("partner1"));
    assert!(json.contains("partner2"));
}

#[test]
fn test_triage_verdict_deserialize_pass() {
    let verdict: TriageVerdict = serde_json::from_str("\"pass\"").unwrap();
    assert_eq!(verdict, TriageVerdict::Pass);
}

#[test]
fn test_triage_verdict_deserialize_kill() {
    let verdict: TriageVerdict = serde_json::from_str("\"kill\"").unwrap();
    assert_eq!(verdict, TriageVerdict::Kill);
}

#[test]
fn test_triage_verdict_deserialize_downgrade() {
    let json = r#"{ "downgrade": { "adjusted_severity": "high" } }"#;
    let verdict: TriageVerdict = serde_json::from_str(json).unwrap();
    match verdict {
        TriageVerdict::Downgrade { adjusted_severity } => {
            assert_eq!(adjusted_severity, Severity::High);
        }
        _ => panic!("Expected Downgrade variant"),
    }
}

#[test]
fn test_triage_verdict_deserialize_chain_required() {
    let json = r#"{ "chain_required": { "chain_partner_ids": ["a", "b"] } }"#;
    let verdict: TriageVerdict = serde_json::from_str(json).unwrap();
    match verdict {
        TriageVerdict::ChainRequired { chain_partner_ids } => {
            assert_eq!(chain_partner_ids, vec!["a".to_string(), "b".to_string()]);
        }
        _ => panic!("Expected ChainRequired variant"),
    }
}

#[test]
fn test_triage_verdict_roundtrip_pass() {
    let verdict = TriageVerdict::Pass;
    let json = serde_json::to_string(&verdict).unwrap();
    let deserialized: TriageVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(verdict, deserialized);
}

#[test]
fn test_triage_verdict_roundtrip_kill() {
    let verdict = TriageVerdict::Kill;
    let json = serde_json::to_string(&verdict).unwrap();
    let deserialized: TriageVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(verdict, deserialized);
}

#[test]
fn test_triage_verdict_roundtrip_downgrade() {
    let verdict = TriageVerdict::Downgrade {
        adjusted_severity: Severity::Critical,
    };
    let json = serde_json::to_string(&verdict).unwrap();
    let deserialized: TriageVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(verdict, deserialized);
}

#[test]
fn test_triage_verdict_roundtrip_chain_required() {
    let verdict = TriageVerdict::ChainRequired {
        chain_partner_ids: vec!["chain1".to_string()],
    };
    let json = serde_json::to_string(&verdict).unwrap();
    let deserialized: TriageVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(verdict, deserialized);
}

// ============================================================================
// IssueCategory Tests
// ============================================================================

#[test]
fn test_issue_category_default() {
    let category = IssueCategory::default();
    match category {
        IssueCategory::Custom(s) => assert_eq!(s, "generic"),
        _ => panic!("Expected Custom(\"generic\")"),
    }
}

#[test]
fn test_issue_category_display_memory_corruption() {
    assert_eq!(
        IssueCategory::MemoryCorruption.to_string(),
        "memory_corruption"
    );
}

#[test]
fn test_issue_category_display_injection() {
    assert_eq!(IssueCategory::Injection.to_string(), "injection");
}

#[test]
fn test_issue_category_display_authentication_bypass() {
    assert_eq!(
        IssueCategory::AuthenticationBypass.to_string(),
        "authentication_bypass"
    );
}

#[test]
fn test_issue_category_display_integer_overflow() {
    assert_eq!(
        IssueCategory::IntegerOverflow.to_string(),
        "integer_overflow"
    );
}

#[test]
fn test_issue_category_display_business_logic_flaw() {
    assert_eq!(
        IssueCategory::BusinessLogicFlaw.to_string(),
        "business_logic_flaw"
    );
}

#[test]
fn test_issue_category_display_race_condition() {
    assert_eq!(IssueCategory::RaceCondition.to_string(), "race_condition");
}

#[test]
fn test_issue_category_display_data_leakage() {
    assert_eq!(IssueCategory::DataLeakage.to_string(), "data_leakage");
}

#[test]
fn test_issue_category_display_misconfiguration() {
    assert_eq!(
        IssueCategory::Misconfiguration.to_string(),
        "misconfiguration"
    );
}

#[test]
fn test_issue_category_display_availability_risk() {
    assert_eq!(
        IssueCategory::AvailabilityRisk.to_string(),
        "availability_risk"
    );
}

#[test]
fn test_issue_category_display_compliance_violation() {
    assert_eq!(
        IssueCategory::ComplianceViolation.to_string(),
        "compliance_violation"
    );
}

#[test]
fn test_issue_category_display_privacy_violation() {
    assert_eq!(
        IssueCategory::PrivacyViolation.to_string(),
        "privacy_violation"
    );
}

#[test]
fn test_issue_category_display_trust_boundary_violation() {
    assert_eq!(
        IssueCategory::TrustBoundaryViolation.to_string(),
        "trust_boundary_violation"
    );
}

#[test]
fn test_issue_category_display_unsafe_dependency() {
    assert_eq!(
        IssueCategory::UnsafeDependency.to_string(),
        "unsafe_dependency"
    );
}

#[test]
fn test_issue_category_display_cryptographic_misuse() {
    assert_eq!(
        IssueCategory::CryptographicMisuse.to_string(),
        "cryptographic_misuse"
    );
}

#[test]
fn test_issue_category_display_custom() {
    let category = IssueCategory::Custom("my_custom_category".to_string());
    assert_eq!(category.to_string(), "my_custom_category");
}

#[test]
fn test_issue_category_serialize() {
    let categories = [
        (IssueCategory::MemoryCorruption, "\"memory_corruption\""),
        (IssueCategory::Injection, "\"injection\""),
        (
            IssueCategory::AuthenticationBypass,
            "\"authentication_bypass\"",
        ),
        (IssueCategory::IntegerOverflow, "\"integer_overflow\""),
        (IssueCategory::BusinessLogicFlaw, "\"business_logic_flaw\""),
        (IssueCategory::RaceCondition, "\"race_condition\""),
        (IssueCategory::DataLeakage, "\"data_leakage\""),
        (IssueCategory::Misconfiguration, "\"misconfiguration\""),
        (IssueCategory::AvailabilityRisk, "\"availability_risk\""),
        (
            IssueCategory::ComplianceViolation,
            "\"compliance_violation\"",
        ),
        (IssueCategory::PrivacyViolation, "\"privacy_violation\""),
        (
            IssueCategory::TrustBoundaryViolation,
            "\"trust_boundary_violation\"",
        ),
        (IssueCategory::UnsafeDependency, "\"unsafe_dependency\""),
        (
            IssueCategory::CryptographicMisuse,
            "\"cryptographic_misuse\"",
        ),
    ];

    for (category, expected) in categories {
        let json = serde_json::to_string(&category).unwrap();
        assert_eq!(json, expected);
    }
}

#[test]
fn test_issue_category_serialize_custom() {
    let category = IssueCategory::Custom("custom_type".to_string());
    let json = serde_json::to_string(&category).unwrap();
    // Custom variant serializes as struct with "custom" key
    assert!(json.contains("custom_type"));
}

#[test]
fn test_issue_category_deserialize() {
    let categories: Vec<(String, IssueCategory)> = vec![
        (
            "\"memory_corruption\"".to_string(),
            IssueCategory::MemoryCorruption,
        ),
        ("\"injection\"".to_string(), IssueCategory::Injection),
        (
            "\"authentication_bypass\"".to_string(),
            IssueCategory::AuthenticationBypass,
        ),
        (
            "\"integer_overflow\"".to_string(),
            IssueCategory::IntegerOverflow,
        ),
        (
            "\"business_logic_flaw\"".to_string(),
            IssueCategory::BusinessLogicFlaw,
        ),
        (
            "\"race_condition\"".to_string(),
            IssueCategory::RaceCondition,
        ),
        ("\"data_leakage\"".to_string(), IssueCategory::DataLeakage),
        (
            "\"misconfiguration\"".to_string(),
            IssueCategory::Misconfiguration,
        ),
        (
            "\"availability_risk\"".to_string(),
            IssueCategory::AvailabilityRisk,
        ),
        (
            "\"compliance_violation\"".to_string(),
            IssueCategory::ComplianceViolation,
        ),
        (
            "\"privacy_violation\"".to_string(),
            IssueCategory::PrivacyViolation,
        ),
        (
            "\"trust_boundary_violation\"".to_string(),
            IssueCategory::TrustBoundaryViolation,
        ),
        (
            "\"unsafe_dependency\"".to_string(),
            IssueCategory::UnsafeDependency,
        ),
        (
            "\"cryptographic_misuse\"".to_string(),
            IssueCategory::CryptographicMisuse,
        ),
    ];

    for (json, expected) in categories {
        let deserialized: IssueCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, expected);
    }
}

#[test]
fn test_issue_category_deserialize_custom() {
    let json = r#"{"custom":"my_custom_issue"}"#;
    let category: IssueCategory = serde_json::from_str(json).unwrap();
    match category {
        IssueCategory::Custom(s) => assert_eq!(s, "my_custom_issue"),
        _ => panic!("Expected Custom variant"),
    }
}

#[test]
fn test_issue_category_roundtrip() {
    let categories = [
        IssueCategory::MemoryCorruption,
        IssueCategory::Injection,
        IssueCategory::AuthenticationBypass,
        IssueCategory::IntegerOverflow,
        IssueCategory::BusinessLogicFlaw,
        IssueCategory::RaceCondition,
        IssueCategory::DataLeakage,
        IssueCategory::Misconfiguration,
        IssueCategory::AvailabilityRisk,
        IssueCategory::ComplianceViolation,
        IssueCategory::PrivacyViolation,
        IssueCategory::TrustBoundaryViolation,
        IssueCategory::UnsafeDependency,
        IssueCategory::CryptographicMisuse,
        IssueCategory::Custom("custom".to_string()),
    ];

    for category in categories {
        let json = serde_json::to_string(&category).unwrap();
        let deserialized: IssueCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(category, deserialized);
    }
}

// ============================================================================
// SecurityIssue Tests
// ============================================================================

#[test]
fn test_security_issue_default() {
    let issue = SecurityIssue::default();
    assert_eq!(issue.category, IssueCategory::default());
    assert!(issue.cwe_id.is_none());
    assert!(issue.owasp_category.is_none());
    assert!(issue.mitre_attack.is_none());
    assert!(issue.custom_tags.is_empty());
}

#[test]
fn test_security_issue_serialize() {
    let issue = SecurityIssue {
        category: IssueCategory::Injection,
        cwe_id: Some("CWE-89".to_string()),
        owasp_category: Some("SQL Injection".to_string()),
        mitre_attack: Some("T1190".to_string()),
        custom_tags: vec!["web".to_string(), "database".to_string()],
    };

    let json = serde_json::to_string(&issue).unwrap();
    assert!(json.contains("injection"));
    assert!(json.contains("CWE-89"));
    assert!(json.contains("SQL Injection"));
}

#[test]
fn test_security_issue_deserialize() {
    let json = r#"{
        "category": "injection",
        "cwe_id": "CWE-89",
        "owasp_category": "SQL Injection",
        "mitre_attack": "T1190",
        "custom_tags": ["web", "database"]
    }"#;

    let issue: SecurityIssue = serde_json::from_str(json).unwrap();
    assert_eq!(issue.category, IssueCategory::Injection);
    assert_eq!(issue.cwe_id, Some("CWE-89".to_string()));
    assert_eq!(issue.owasp_category, Some("SQL Injection".to_string()));
    assert_eq!(issue.mitre_attack, Some("T1190".to_string()));
    assert_eq!(
        issue.custom_tags,
        vec!["web".to_string(), "database".to_string()]
    );
}

#[test]
fn test_security_issue_roundtrip() {
    let issue = SecurityIssue {
        category: IssueCategory::AuthenticationBypass,
        cwe_id: Some("CWE-287".to_string()),
        owasp_category: Some("Broken Authentication".to_string()),
        mitre_attack: Some("T1078".to_string()),
        custom_tags: vec!["auth".to_string()],
    };

    let json = serde_json::to_string(&issue).unwrap();
    let deserialized: SecurityIssue = serde_json::from_str(&json).unwrap();
    assert_eq!(issue, deserialized);
}

// ============================================================================
// VulnerabilityFinding Tests
// ============================================================================

#[test]
fn test_vulnerability_finding_construction() {
    let finding = VulnerabilityFinding {
        id: "test-id".to_string(),
        title: "".to_string(),
        description: "".to_string(),
        severity: Severity::Low,
        confidence_score: 0.0,
        cwe_id: None,
        file_path: "".to_string(),
        line_number: None,
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
        statement_range: None,
        triage_verdict: None,
        evidence: vec![],
        verification_tier: None,
    };

    assert_eq!(finding.id, "test-id");
    assert!(finding.title.is_empty());
    assert!(finding.description.is_empty());
    assert!(finding.file_path.is_empty());
    assert!(!finding.already_reported);
    assert!(finding.sources.is_empty());
}

#[test]
fn test_vulnerability_finding_generate_id_deterministic() {
    let id1 = VulnerabilityFinding::generate_id("test.c", Some(42), "CWE-79");
    let id2 = VulnerabilityFinding::generate_id("test.c", Some(42), "CWE-79");
    assert_eq!(id1, id2);
}

#[test]
fn test_vulnerability_finding_generate_id_different_file() {
    let id1 = VulnerabilityFinding::generate_id("file1.c", Some(42), "CWE-79");
    let id2 = VulnerabilityFinding::generate_id("file2.c", Some(42), "CWE-79");
    assert_ne!(id1, id2);
}

#[test]
fn test_vulnerability_finding_generate_id_different_line() {
    let id1 = VulnerabilityFinding::generate_id("test.c", Some(42), "CWE-79");
    let id2 = VulnerabilityFinding::generate_id("test.c", Some(43), "CWE-79");
    assert_ne!(id1, id2);
}

#[test]
fn test_vulnerability_finding_generate_id_different_cwe() {
    let id1 = VulnerabilityFinding::generate_id("test.c", Some(42), "CWE-79");
    let id2 = VulnerabilityFinding::generate_id("test.c", Some(42), "CWE-89");
    assert_ne!(id1, id2);
}

#[test]
fn test_vulnerability_finding_generate_id_no_line() {
    let id1 = VulnerabilityFinding::generate_id("test.c", None, "CWE-79");
    let id2 = VulnerabilityFinding::generate_id("test.c", None, "CWE-79");
    assert_eq!(id1, id2);
}

#[test]
fn test_vulnerability_finding_serialize() {
    let finding = VulnerabilityFinding {
        id: "test-id-123".to_string(),
        title: "XSS Vulnerability".to_string(),
        description: "Cross-site scripting in input handler".to_string(),
        severity: Severity::High,
        confidence_score: 0.85,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "src/handler.rs".to_string(),
        line_number: Some(42),
        code_snippet: Some("println!(user_input)".to_string()),
        diff_hunk: None,
        recommendation: Some("Sanitize user input".to_string()),
        code_location: Some("src/handler.rs:42".to_string()),
        already_reported: false,
        sources: vec!["semgrep".to_string(), "custom-rule".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: Some(0.9),
        cross_file_references: None,
        verification_status: None,
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: Some("exploit script".to_string()),
        mitigation_code: Some("safe version".to_string()),
        poc_format: Some("python".to_string()),
        llm_model: None,
        agent_mode: false,
        statement_range: None,
        triage_verdict: None,
        evidence: vec![],
        verification_tier: None,
    };

    let json = serde_json::to_string(&finding).unwrap();
    assert!(json.contains("test-id-123"));
    assert!(json.contains("XSS Vulnerability"));
    assert!(json.contains("high"));
    assert!(json.contains("semgrep"));
}

#[test]
fn test_vulnerability_finding_deserialize() {
    let json = r#"{
        "id": "finding-456",
        "title": "SQL Injection",
        "description": "Unsanitized query parameter",
        "severity": "critical",
        "confidence_score": 0.95,
        "cwe_id": "CWE-89",
        "file_path": "src/db.rs",
        "line_number": 100,
        "code_snippet": "query(user_input)",
        "diff_hunk": null,
        "recommendation": "Use prepared statements",
        "code_location": "src/db.rs:100",
        "already_reported": true,
        "sources": ["sqlmap"],
        "commit_reference": null,
        "ticket_reference": null,
        "priority_score": 0.98,
        "cross_file_references": null,
        "verification_status": null,
        "verification_notes": null,
        "verification_error": null,
        "agent_evidence_path": null,
        "security_issue": null,
        "poc_code": null,
        "mitigation_code": null,
        "poc_format": null,
        "llm_model": null,
        "agent_mode": false,
        "statement_range": null,
        "triage_verdict": null
    }"#;

    let finding: VulnerabilityFinding = serde_json::from_str(json).unwrap();
    assert_eq!(finding.id, "finding-456");
    assert_eq!(finding.title, "SQL Injection");
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.confidence_score, 0.95);
    assert_eq!(finding.cwe_id, Some("CWE-89".to_string()));
    assert_eq!(finding.file_path, "src/db.rs");
    assert_eq!(finding.line_number, Some(100));
    assert!(finding.already_reported);
    assert_eq!(finding.sources, vec!["sqlmap".to_string()]);
}

#[test]
fn test_vulnerability_finding_roundtrip() {
    let finding = VulnerabilityFinding {
        id: "roundtrip-test".to_string(),
        title: "Test Finding".to_string(),
        description: "Test description".to_string(),
        severity: Severity::Medium,
        confidence_score: 0.75,
        cwe_id: Some("CWE-200".to_string()),
        file_path: "src/test.rs".to_string(),
        line_number: Some(10),
        code_snippet: Some("unsafe_code()".to_string()),
        diff_hunk: Some("@@ -10 +10 @@\n-unsafe\n+safe".to_string()),
        recommendation: Some("Refactor to safe API".to_string()),
        code_location: Some("src/test.rs:10".to_string()),
        already_reported: false,
        sources: vec!["test-scanner".to_string()],
        commit_reference: Some("abc123".to_string()),
        ticket_reference: Some("SEC-123".to_string()),
        priority_score: Some(0.6),
        cross_file_references: Some(vec!["ref1".to_string(), "ref2".to_string()]),
        verification_status: Some(VerificationStatus::NeedsReview),
        verification_notes: Some("Needs manual review".to_string()),
        verification_error: None,
        agent_evidence_path: Some("evidence/poc1".to_string()),
        security_issue: Some(SecurityIssue {
            category: IssueCategory::MemoryCorruption,
            cwe_id: Some("CWE-119".to_string()),
            owasp_category: None,
            mitre_attack: None,
            custom_tags: vec!["memory".to_string()],
        }),
        poc_code: Some("poc".to_string()),
        mitigation_code: Some("mitigation".to_string()),
        poc_format: Some("rust".to_string()),
        llm_model: Some("gpt-4".to_string()),
        agent_mode: true,
        statement_range: Some((5, 15)),
        triage_verdict: Some(TriageVerdict::Downgrade {
            adjusted_severity: Severity::Low,
        }),
        evidence: vec![],
        verification_tier: None,
    };

    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, deserialized);
}

#[test]
fn test_vulnerability_finding_field_access() {
    let finding = VulnerabilityFinding {
        id: "access-test".to_string(),
        title: "Test".to_string(),
        description: "Desc".to_string(),
        severity: Severity::Low,
        confidence_score: 0.5,
        cwe_id: None,
        file_path: "test.rs".to_string(),
        line_number: None,
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: true,
        sources: vec![],
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status: Some(VerificationStatus::Confirmed),
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
        statement_range: None,
        triage_verdict: None,
        evidence: vec![],
        verification_tier: None,
    };

    assert_eq!(finding.id, "access-test");
    assert_eq!(finding.severity, Severity::Low);
    assert!(finding.already_reported);
    assert_eq!(
        finding.verification_status,
        Some(VerificationStatus::Confirmed)
    );
}
