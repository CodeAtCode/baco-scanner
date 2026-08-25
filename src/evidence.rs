use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Semgrep(String),
    LlmAnalysis(String),
    IndependentVerifier(String),
    CpgSlice(String),
    RuleSynthesis(String),
    CweSpec(String),
    SecurityAgentVerification(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub source: EvidenceSource,
    pub weight: f64,
    pub detail: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationTier {
    Verified,
    Supported,
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum EvidenceSourceKind {
    Static,
    Llm,
    Verifier,
    Specification,
}

fn source_kind(source: &EvidenceSource) -> EvidenceSourceKind {
    match source {
        EvidenceSource::Semgrep(_) | EvidenceSource::CpgSlice(_) => EvidenceSourceKind::Static,
        EvidenceSource::LlmAnalysis(_) | EvidenceSource::RuleSynthesis(_) => {
            EvidenceSourceKind::Llm
        }
        EvidenceSource::IndependentVerifier(_) | EvidenceSource::SecurityAgentVerification(_) => {
            EvidenceSourceKind::Verifier
        }
        EvidenceSource::CweSpec(_) => EvidenceSourceKind::Specification,
    }
}

/// Classify a finding's verification tier based on its evidence.
/// - Verified: >=2 different source kinds AND at least one Verifier
/// - Supported: >=2 evidence items total, OR confidence > 0.8
/// - Unverified: otherwise
pub fn classify_finding(evidence: &[Evidence], confidence_score: f32) -> VerificationTier {
    let unique_kinds: HashSet<_> = evidence.iter().map(|e| source_kind(&e.source)).collect();
    let has_verifier = evidence
        .iter()
        .any(|e| matches!(source_kind(&e.source), EvidenceSourceKind::Verifier));

    if unique_kinds.len() >= 2 && has_verifier {
        return VerificationTier::Verified;
    }
    if evidence.len() >= 2 || confidence_score > 0.8 {
        return VerificationTier::Supported;
    }
    VerificationTier::Unverified
}
