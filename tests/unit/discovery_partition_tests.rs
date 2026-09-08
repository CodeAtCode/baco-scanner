//! Regression tests for discovery-phase finding partitioning.
//!
//! Guards against silently dropping already-described findings: the phase
//! previously discarded every finding carrying LlmAnalysis evidence.

use baco::evidence::EvidenceSource;
use baco::scanner::phases::llm_phases::discovery::partition_for_discovery;

fn finding_with_llm_evidence(id: &str) -> baco::findings::VulnerabilityFinding {
    let mut f = crate::fixtures::create_test_finding(id, "LLM finding", "src/vuln.c", 14);
    f.add_evidence(
        EvidenceSource::LlmAnalysis("static_analysis".into()),
        0.8,
        "found by LLM static analysis".into(),
    );
    f
}

#[test]
fn test_partition_preserves_already_described_findings() {
    let llm = finding_with_llm_evidence("llm-1");
    let plain = crate::fixtures::create_test_finding("plain-1", "Semgrep finding", "action.yml", 1);

    let (needs, described) = partition_for_discovery(vec![llm, plain]);

    assert_eq!(
        needs.len(),
        1,
        "finding without LLM evidence needs discovery"
    );
    assert_eq!(described.len(), 1, "LLM-evidence finding must be retained");
    assert_eq!(needs[0].id, "plain-1");
    assert_eq!(described[0].id, "llm-1");
}

#[test]
fn test_partition_never_drops_findings() {
    let findings = vec![
        finding_with_llm_evidence("a"),
        crate::fixtures::create_test_finding("b", "Semgrep", "f.yml", 1),
        finding_with_llm_evidence("c"),
    ];

    let (needs, described) = partition_for_discovery(findings);

    assert_eq!(
        needs.len() + described.len(),
        3,
        "regression: no finding may be dropped by partitioning"
    );
}

#[test]
fn test_partition_all_described() {
    let findings = vec![
        finding_with_llm_evidence("x"),
        finding_with_llm_evidence("y"),
    ];

    let (needs, described) = partition_for_discovery(findings);

    assert!(needs.is_empty());
    assert_eq!(described.len(), 2);
}
