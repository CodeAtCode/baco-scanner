//! Unit tests for evidence gate filtering in reports.

use baco::evidence::{EvidenceDetail, VerificationTier, classify_finding};
use baco::findings::{Severity, VulnerabilityFinding};
use baco::report::apply_evidence_gate;

/// Create a finding with the given evidence tier.
fn make_finding(id: &str, severity: Severity, tier: VerificationTier) -> VulnerabilityFinding {
    let evidence = match tier {
        VerificationTier::Verified => vec![EvidenceDetail::CodeMatch {
            file: "test.rs".to_string(),
            line: 42,
            snippet: "unsafe code here".to_string(),
        }],
        VerificationTier::Supported => vec![EvidenceDetail::StaticAnalysis {
            tool: "semgrep".to_string(),
            rule_id: "test-rule".to_string(),
        }],
        VerificationTier::Unverified => vec![EvidenceDetail::Heuristic {
            heuristic_name: "suspicious pattern".to_string(),
            confidence: 0.5,
        }],
    };

    VulnerabilityFinding {
        id: id.to_string(),
        title: format!("Test finding {}", id),
        description: "Test description".to_string(),
        severity,
        confidence_score: match tier {
            VerificationTier::Verified => 0.95,
            VerificationTier::Supported => 0.75,
            VerificationTier::Unverified => 0.4,
        },
        evidence,
        file_path: "src/test.rs".to_string(),
        line_number: Some(42),
        code_snippet: Some("test code".to_string()),
        diff_hunk: None,
        recommendation: "Fix this".to_string(),
        cwe_id: None,
        code_location: "src/test.rs:42".to_string(),
        already_reported: false,
        sources: vec!["test".to_string()],
        priority_score: 0.5,
        verification_status: None,
        agent_mode: false,
        llm_model: None,
        rejected: false,
        rejection_reason: None,
    }
}

#[test]
fn test_apply_evidence_gate_with_none_returns_all() {
    let findings = vec![
        make_finding("1", Severity::Critical, VerificationTier::Verified),
        make_finding("2", Severity::High, VerificationTier::Supported),
        make_finding("3", Severity::Medium, VerificationTier::Unverified),
    ];

    let filtered = apply_evidence_gate(&findings, None);

    // When cfg is None, all findings should be returned
    assert_eq!(filtered.len(), 3);
}

#[test]
fn test_apply_evidence_gate_disabled_returns_all() {
    let findings = vec![
        make_finding("1", Severity::Critical, VerificationTier::Verified),
        make_finding("2", Severity::High, VerificationTier::Supported),
        make_finding("3", Severity::Medium, VerificationTier::Unverified),
    ];

    // Create a config with evidence_gate = false
    let cfg = baco::config::ScannerConfig {
        output: baco::config::OutputConfig {
            dir: "/tmp".to_string(),
            evidence_gate: false,
            include_rejected: false,
        },
        ..Default::default()
    };

    let filtered = apply_evidence_gate(&findings, Some(&cfg));

    // When gate is disabled, all findings should be returned
    assert_eq!(filtered.len(), 3);
}

#[test]
fn test_apply_evidence_gate_enabled_filters_unverified() {
    let findings = vec![
        make_finding("1", Severity::Critical, VerificationTier::Verified),
        make_finding("2", Severity::High, VerificationTier::Supported),
        make_finding("3", Severity::Medium, VerificationTier::Unverified),
    ];

    // Create a config with evidence_gate = true
    let cfg = baco::config::ScannerConfig {
        output: baco::config::OutputConfig {
            dir: "/tmp".to_string(),
            evidence_gate: true,
            include_rejected: false,
        },
        ..Default::default()
    };

    let filtered = apply_evidence_gate(&findings, Some(&cfg));

    // When gate is enabled, only Verified and Supported should remain
    assert_eq!(filtered.len(), 2);
    assert!(filtered.iter().all(|f| {
        let tier = classify_finding(&f.evidence, f.confidence_score);
        matches!(
            tier,
            VerificationTier::Verified | VerificationTier::Supported
        )
    }));

    // Verify the unverified finding was removed
    assert!(filtered.iter().all(|f| f.id != "3"));
}

#[test]
fn test_apply_evidence_gate_keeps_verified_and_supported() {
    let findings = vec![
        make_finding("1", Severity::Critical, VerificationTier::Verified),
        make_finding("2", Severity::High, VerificationTier::Supported),
    ];

    let cfg = baco::config::ScannerConfig {
        output: baco::config::OutputConfig {
            dir: "/tmp".to_string(),
            evidence_gate: true,
            include_rejected: false,
        },
        ..Default::default()
    };

    let filtered = apply_evidence_gate(&findings, Some(&cfg));

    // Both should remain
    assert_eq!(filtered.len(), 2);
    assert!(filtered.iter().any(|f| f.id == "1"));
    assert!(filtered.iter().any(|f| f.id == "2"));
}

#[test]
fn test_apply_evidence_gate_removes_all_unverified() {
    let findings = vec![
        make_finding("1", Severity::Critical, VerificationTier::Unverified),
        make_finding("2", Severity::High, VerificationTier::Unverified),
        make_finding("3", Severity::Medium, VerificationTier::Unverified),
    ];

    let cfg = baco::config::ScannerConfig {
        output: baco::config::OutputConfig {
            dir: "/tmp".to_string(),
            evidence_gate: true,
            include_rejected: false,
        },
        ..Default::default()
    };

    let filtered = apply_evidence_gate(&findings, Some(&cfg));

    // All should be removed
    assert_eq!(filtered.len(), 0);
}
