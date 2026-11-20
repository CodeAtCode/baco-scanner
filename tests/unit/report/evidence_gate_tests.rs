//! Unit tests for evidence gate filtering in reports.

use baco::evidence::{Evidence, EvidenceSource, VerificationTier, classify_finding};
use baco::findings::{Severity, VulnerabilityFinding};
use baco::report::apply_evidence_gate;

/// Create a finding whose evidence classifies to the given tier.
///
/// The tier comes from `classify_finding`, not from a field, so the evidence
/// shape is what decides it: `Verified` needs two source kinds and a verifier,
/// `Supported` needs two items, `Unverified` is a single item below the
/// confidence threshold.
fn make_finding(id: &str, severity: Severity, tier: VerificationTier) -> VulnerabilityFinding {
    let now = chrono::Utc::now();
    let evidence = match tier {
        VerificationTier::Verified => vec![
            Evidence {
                source: EvidenceSource::Semgrep("test-rule".to_string()),
                weight: 1.0,
                detail: "static match".to_string(),
                timestamp: now,
            },
            Evidence {
                source: EvidenceSource::IndependentVerifier("verifier".to_string()),
                weight: 1.5,
                detail: "independent check".to_string(),
                timestamp: now,
            },
        ],
        VerificationTier::Supported => vec![
            Evidence {
                source: EvidenceSource::Semgrep("test-rule".to_string()),
                weight: 1.0,
                detail: "static match".to_string(),
                timestamp: now,
            },
            Evidence {
                source: EvidenceSource::LlmAnalysis("model".to_string()),
                weight: 1.0,
                detail: "model read the code".to_string(),
                timestamp: now,
            },
        ],
        VerificationTier::Unverified => vec![Evidence {
            source: EvidenceSource::LlmAnalysis("model".to_string()),
            weight: 1.0,
            detail: "model read the code".to_string(),
            timestamp: now,
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
        recommendation: Some("Fix this".to_string()),
        cwe_id: None,
        code_location: Some("src/test.rs:42".to_string()),
        sources: vec!["test".to_string()],
        priority_score: Some(0.5),
        ..Default::default()
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
