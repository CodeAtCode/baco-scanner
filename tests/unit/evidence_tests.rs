use baco::evidence::{classify_finding, Evidence, EvidenceSource, VerificationTier};
use chrono::Utc;

fn make_evidence(source: EvidenceSource) -> Evidence {
    Evidence {
        source,
        weight: 1.0,
        detail: "test evidence".to_string(),
        timestamp: Utc::now(),
    }
}

#[test]
fn test_empty_evidence_unverified() {
    let evidence: Vec<Evidence> = vec![];
    assert_eq!(
        classify_finding(&evidence, 0.5),
        VerificationTier::Unverified
    );
}

#[test]
fn test_single_llm_analysis_unverified() {
    let evidence = vec![make_evidence(EvidenceSource::LlmAnalysis(
        "test".to_string(),
    ))];
    assert_eq!(
        classify_finding(&evidence, 0.5),
        VerificationTier::Unverified
    );
}

#[test]
fn test_semgrep_plus_llm_analysis_supported() {
    let evidence = vec![
        make_evidence(EvidenceSource::Semgrep("test".to_string())),
        make_evidence(EvidenceSource::LlmAnalysis("test".to_string())),
    ];
    // 2 different kinds (Static + Llm), but no Verifier → Supported
    assert_eq!(
        classify_finding(&evidence, 0.5),
        VerificationTier::Supported
    );
}

#[test]
fn test_semgrep_plus_independent_verifier_verified() {
    let evidence = vec![
        make_evidence(EvidenceSource::Semgrep("test".to_string())),
        make_evidence(EvidenceSource::IndependentVerifier("test".to_string())),
    ];
    // 2 different kinds (Static + Verifier), has verifier → Verified
    assert_eq!(classify_finding(&evidence, 0.5), VerificationTier::Verified);
}

#[test]
fn test_two_llm_analysis_same_kind_supported() {
    let evidence = vec![
        make_evidence(EvidenceSource::LlmAnalysis("test1".to_string())),
        make_evidence(EvidenceSource::LlmAnalysis("test2".to_string())),
    ];
    // Same kind (Llm), but 2 evidence items → Supported
    assert_eq!(
        classify_finding(&evidence, 0.5),
        VerificationTier::Supported
    );
}

#[test]
fn test_cpg_slice_plus_cwe_spec_supported() {
    let evidence = vec![
        make_evidence(EvidenceSource::CpgSlice("test".to_string())),
        make_evidence(EvidenceSource::CweSpec("test".to_string())),
    ];
    // 2 different kinds (Static + Specification), no verifier → Supported
    assert_eq!(
        classify_finding(&evidence, 0.5),
        VerificationTier::Supported
    );
}

#[test]
fn test_single_independent_verifier_unverified() {
    let evidence = vec![make_evidence(EvidenceSource::IndependentVerifier(
        "test".to_string(),
    ))];
    // 1 kind (Verifier), has verifier, but only 1 evidence → Unverified
    assert_eq!(
        classify_finding(&evidence, 0.5),
        VerificationTier::Unverified
    );
}

#[test]
fn test_zero_evidence_high_confidence_supported() {
    let evidence: Vec<Evidence> = vec![];
    assert_eq!(
        classify_finding(&evidence, 0.9),
        VerificationTier::Supported
    );
}

#[test]
fn test_zero_evidence_low_confidence_unverified() {
    let evidence: Vec<Evidence> = vec![];
    assert_eq!(
        classify_finding(&evidence, 0.5),
        VerificationTier::Unverified
    );
}
