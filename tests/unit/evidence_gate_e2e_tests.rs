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

/// Helper for HTML tests that need severity customization
fn make_html_finding(
    id: &str,
    severity: Severity,
    file: &str,
    line: Option<u32>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: format!("Finding {}", id),
        description: "Test finding".to_string(),
        severity,
        confidence_score: 0.8,
        cwe_id: None,
        file_path: file.to_string(),
        line_number: line,
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

fn mixed_findings() -> Vec<VulnerabilityFinding> {
    vec![
        make_finding(
            "verified",
            vec![
                make_evidence(EvidenceSource::Semgrep("x".into())),
                make_evidence(EvidenceSource::IndependentVerifier("v".into())),
            ],
        ),
        make_finding(
            "supported",
            vec![
                make_evidence(EvidenceSource::Semgrep("x".into())),
                make_evidence(EvidenceSource::LlmAnalysis("m".into())),
            ],
        ),
        make_finding(
            "unverified",
            vec![make_evidence(EvidenceSource::LlmAnalysis("m".into()))],
        ),
    ]
}

fn json_finding_tier(json: &serde_json::Value, id: &str) -> Option<String> {
    json.as_array()?
        .iter()
        .find(|f| f["id"] == id)
        .and_then(|f| f["verification_tier"].as_str().map(String::from))
}

fn json_path(suffix: &str) -> String {
    let dir = std::env::temp_dir();
    dir.join(format!("baco-e2e-{}-{}.json", std::process::id(), suffix))
        .to_string_lossy()
        .into_owned()
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
fn test_sarif_gate_on_keeps_verified_and_supported() {
    // Pins the SARIF filter boundary: Unverified is dropped, Verified and
    // Supported both pass the gate.
    let findings = mixed_findings();
    let sarif = generate_sarif_report(&findings, Some(&gate_config())).unwrap();
    assert_eq!(
        count_sarif_results(&sarif),
        2,
        "Supported tier must pass the gate"
    );
    let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
    let rule_ids: Vec<String> = parsed["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["ruleId"].as_str().unwrap().to_string())
        .collect();
    assert!(rule_ids.contains(&"verified".to_string()));
    assert!(rule_ids.contains(&"supported".to_string()));
    assert!(!rule_ids.contains(&"unverified".to_string()));
}

#[test]
fn test_json_gate_on_tags_tiers_keeps_all_findings() {
    // Pinned behavior: JSON output never filters; with the gate on it
    // back-fills verification_tier on every finding.
    let findings = mixed_findings();
    let path = json_path("gate-on");
    write_findings_json(&findings, &path, None, Some(&gate_config())).unwrap();
    let raw = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let arr = parsed
        .as_array()
        .unwrap_or_else(|| panic!("JSON output must be a top-level array, got: {}", raw));
    assert_eq!(arr.len(), 3, "JSON must keep all findings for transparency");
    assert_eq!(
        json_finding_tier(&parsed, "verified").as_deref(),
        Some("verified")
    );
    assert_eq!(
        json_finding_tier(&parsed, "supported").as_deref(),
        Some("supported")
    );
    assert_eq!(
        json_finding_tier(&parsed, "unverified").as_deref(),
        Some("unverified")
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_json_gate_off_all_findings_tier_null() {
    let findings = mixed_findings();
    let path = json_path("gate-off");
    write_findings_json(&findings, &path, None, Some(&ScannerConfig::default())).unwrap();
    let raw = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let arr = parsed
        .as_array()
        .unwrap_or_else(|| panic!("JSON output must be a top-level array, got: {}", raw));
    assert_eq!(arr.len(), 3);
    for f in arr {
        let tier = f.get("verification_tier");
        assert!(
            tier.map(|t| t.is_null()).unwrap_or(true),
            "gate off must not back-fill tiers, got {:?}",
            tier
        );
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_json_gate_on_empty_findings_valid_empty_array() {
    let path = json_path("gate-on-empty");
    write_findings_json(&[], &path, None, Some(&gate_config())).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let arr = parsed
        .as_array()
        .expect("empty scan must still produce a JSON array");
    assert!(arr.is_empty());
    let _ = std::fs::remove_file(&path);
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

// ============================================================================
// Lane C Tests - JSON and SARIF Gate Behavior
// ============================================================================

/// Test 6: JSON, gate ON: output is a top-level array (regression of a past bug) and includes
/// all findings with verification_tier set (JSON keeps all findings for transparency).
#[test]
fn json_gate_on_top_level_array_with_tiers() {
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
    let path = "/tmp/lane_c_json_gate_on.json";
    let cfg = gate_config();
    write_findings_json(&findings, path, None, Some(&cfg)).unwrap();
    let content = std::fs::read_to_string(path).unwrap();
    let _ = std::fs::remove_file(path);
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

    // Regression check: output must be a top-level array
    assert!(parsed.is_array(), "JSON output must be a top-level array");
    let findings_array = parsed.as_array().unwrap();

    // Gate ON: JSON keeps ALL findings for transparency, with tier set
    assert_eq!(findings_array.len(), 2);

    // Each finding has verification_tier set
    assert_eq!(findings_array[0]["verification_tier"], "unverified");
    assert_eq!(findings_array[1]["verification_tier"], "verified");
}

/// Test 7: JSON, gate OFF: all findings present, verification_tier may be null or set.
#[test]
fn json_gate_off_all_findings_present() {
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
    let path = "/tmp/lane_c_json_gate_off.json";
    let cfg = ScannerConfig::default(); // gate OFF
    write_findings_json(&findings, path, None, Some(&cfg)).unwrap();
    let content = std::fs::read_to_string(path).unwrap();
    let _ = std::fs::remove_file(path);
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let findings_array = parsed.as_array().unwrap();

    // Gate OFF: all findings present
    assert_eq!(findings_array.len(), 2);

    // JSON preserves all findings regardless of gate state
    assert_eq!(findings_array[0]["id"], "unverified");
    assert_eq!(findings_array[1]["id"], "verified");
}

/// Test 8: SARIF, gate ON: only verified/supported tiers emitted.
#[test]
fn sarif_gate_on_verified_supported_only() {
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
    let sarif = generate_sarif_report(&findings, Some(&gate_config())).unwrap();
    let count = count_sarif_results(&sarif);

    // Gate ON: verified only (unverified excluded)
    // Note: "supported" requires 2 evidence items OR confidence > 0.8
    assert_eq!(count, 1);

    let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
    let results = parsed["runs"][0]["results"].as_array().unwrap();

    // Verify the emitted finding is verified
    assert_eq!(results[0]["ruleId"], "verified");
}

/// Test 9: SARIF, gate OFF: all findings emitted.
#[test]
fn sarif_gate_off_all_findings_emitted() {
    let findings = vec![
        make_finding("unverified", vec![]),
        make_finding(
            "supported",
            vec![make_evidence(EvidenceSource::Semgrep("s".into()))],
        ),
        make_finding(
            "verified",
            vec![
                make_evidence(EvidenceSource::Semgrep("s".into())),
                make_evidence(EvidenceSource::IndependentVerifier("v".into())),
            ],
        ),
    ];
    let cfg = ScannerConfig::default(); // gate OFF
    let sarif = generate_sarif_report(&findings, Some(&cfg)).unwrap();
    let count = count_sarif_results(&sarif);

    // Gate OFF: all 3 findings emitted
    assert_eq!(count, 3);
}

/// Test 10: HTML with findings at all four severity levels: all rendered with correct labels.
#[test]
fn test_html_all_severity_levels_rendered() {
    let findings = vec![
        make_html_finding("c1", Severity::Critical, "src/crit.rs", Some(1)),
        make_html_finding("h1", Severity::High, "src/high.rs", Some(2)),
        make_html_finding("m1", Severity::Medium, "src/med.rs", Some(3)),
        make_html_finding("l1", Severity::Low, "src/low.rs", Some(4)),
    ];
    let output_path = "/tmp/lane_c_test_all_severities.html";
    let _ = std::fs::remove_file(output_path);

    let result = generate_html_report(&findings, output_path, None, None);
    assert!(result.is_ok());

    let content = std::fs::read_to_string(output_path).unwrap();

    // All severity labels present
    assert!(content.contains("Critical"));
    assert!(content.contains("High"));
    assert!(content.contains("Medium"));
    assert!(content.contains("Low"));

    // All severity classes present
    assert!(content.contains("severity critical"));
    assert!(content.contains("severity high"));
    assert!(content.contains("severity medium"));
    assert!(content.contains("severity low"));

    // All findings rendered
    assert!(content.contains("4 findings"));

    let _ = std::fs::remove_file(output_path);
}
