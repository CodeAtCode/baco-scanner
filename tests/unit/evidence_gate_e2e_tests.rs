//! End-to-end tests for the evidence-gating pipeline.
//!
//! These exercise the real production gate path:
//! `report::sarif::generate_sarif_report` (and JSON) calls `classify_finding`
//! and drops findings whose tier is Unverified when `cfg.output.evidence_gate`
//! is enabled. The unit tests in `evidence_tests.rs` cover `classify_finding`
//! in isolation; these verify the wiring from finding → filter → report output.

use baco::config::ScannerConfig;
use baco::evidence::{Evidence, EvidenceSource};
use baco::findings::{Severity, VulnerabilityFinding};
use baco::report::html::generate_html_report;
use baco::report::json::write_findings_json;
use baco::report::sarif::generate_sarif_report;
use chrono::Utc;

fn make_evidence(source: EvidenceSource) -> Evidence {
    Evidence {
        source,
        weight: 1.0,
        detail: "test".to_string(),
        timestamp: Utc::now(),
    }
}

fn make_finding(id: &str, evidence: Vec<Evidence>) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: format!("Finding {}", id),
        description: "desc".to_string(),
        severity: Severity::High,
        confidence_score: 0.5,
        cwe_id: None,
        file_path: format!("src/{}.rs", id),
        line_number: Some(1),
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
        evidence,
        verification_tier: None,
    }
}

fn gate_config() -> ScannerConfig {
    let mut cfg = ScannerConfig::default();
    cfg.output.evidence_gate = true;
    cfg
}

fn count_sarif_results(sarif: &str) -> usize {
    let parsed: serde_json::Value = serde_json::from_str(sarif).unwrap_or_default();
    parsed["runs"][0]["results"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0)
}

#[test]
fn gate_off_keeps_all_findings() {
    let findings = vec![
        make_finding("unverified", vec![]),
        make_finding(
            "verified",
            vec![
                make_evidence(EvidenceSource::Semgrep("x".into())),
                make_evidence(EvidenceSource::IndependentVerifier("v".into())),
            ],
        ),
    ];
    let cfg = ScannerConfig::default();
    let sarif = generate_sarif_report(&findings, Some(&cfg)).unwrap();
    assert_eq!(count_sarif_results(&sarif), 2);
}

#[test]
fn gate_on_drops_unverified_single_source_llm() {
    let findings = vec![
        make_finding(
            "llm_only",
            vec![make_evidence(EvidenceSource::LlmAnalysis("m".into()))],
        ),
        make_finding("empty", vec![]),
    ];
    let sarif = generate_sarif_report(&findings, Some(&gate_config())).unwrap();
    assert_eq!(count_sarif_results(&sarif), 0);
}

#[test]
fn gate_on_keeps_verified_and_supported() {
    let findings = vec![
        make_finding(
            "verified",
            vec![
                make_evidence(EvidenceSource::Semgrep("s".into())),
                make_evidence(EvidenceSource::IndependentVerifier("v".into())),
            ],
        ),
        make_finding(
            "supported",
            vec![
                make_evidence(EvidenceSource::Semgrep("s".into())),
                make_evidence(EvidenceSource::LlmAnalysis("m".into())),
            ],
        ),
        make_finding("unverified", vec![]),
    ];
    let sarif = generate_sarif_report(&findings, Some(&gate_config())).unwrap();
    assert_eq!(count_sarif_results(&sarif), 2);
}

#[test]
fn gate_on_keeps_high_confidence_supported() {
    let mut f = make_finding(
        "high_conf",
        vec![make_evidence(EvidenceSource::Semgrep("s".into()))],
    );
    f.confidence_score = 0.9;
    let sarif = generate_sarif_report(&[f], Some(&gate_config())).unwrap();
    assert_eq!(count_sarif_results(&sarif), 1);
}

#[test]
fn json_gate_on_includes_all_findings_with_tiers() {
    let findings = vec![
        make_finding("unverified", vec![]),
        make_finding(
            "verified",
            vec![
                make_evidence(EvidenceSource::Semgrep("s".into())),
                make_evidence(EvidenceSource::IndependentVerifier("v".into())),
            ],
        ),
    ];
    let path = "/tmp/baco_e2e_gate.json";
    let cfg = gate_config();
    write_findings_json(&findings, path, None, Some(&cfg)).unwrap();
    let content = std::fs::read_to_string(path).unwrap();
    let _ = std::fs::remove_file(path);
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let findings = parsed.as_array().unwrap();
    // JSON keeps ALL findings for transparency
    assert_eq!(findings.len(), 2);
    // Each finding has verification_tier set
    assert_eq!(findings[0]["verification_tier"], "unverified");
    assert_eq!(findings[1]["verification_tier"], "verified");
}

#[test]
fn html_gate_on_includes_appendix_for_unverified() {
    let findings = vec![
        make_finding("unverified", vec![]),
        make_finding(
            "verified",
            vec![
                make_evidence(EvidenceSource::Semgrep("s".into())),
                make_evidence(EvidenceSource::IndependentVerifier("v".into())),
            ],
        ),
    ];
    let path = "/tmp/baco_e2e_gate.html";
    let cfg = gate_config();
    generate_html_report(&findings, path, Some(&cfg), None).unwrap();
    let content = std::fs::read_to_string(path).unwrap();
    let _ = std::fs::remove_file(path);

    // Appendix section exists
    assert!(content.contains("Appendix: Unverified Findings"));
    // Unverified finding title is mentioned
    assert!(content.contains("Finding unverified"));
}

#[test]
fn html_gate_off_no_appendix() {
    let findings = vec![
        make_finding("unverified", vec![]),
        make_finding(
            "verified",
            vec![
                make_evidence(EvidenceSource::Semgrep("s".into())),
                make_evidence(EvidenceSource::IndependentVerifier("v".into())),
            ],
        ),
    ];
    let path = "/tmp/baco_e2e_no_gate.html";
    let cfg = ScannerConfig::default();
    generate_html_report(&findings, path, Some(&cfg), None).unwrap();
    let content = std::fs::read_to_string(path).unwrap();
    let _ = std::fs::remove_file(path);

    // No appendix when gate is off
    assert!(!content.contains("Appendix: Unverified Findings"));
}
