use crate::config::ScannerConfig;
use crate::evidence::{classify_finding, VerificationTier};
use crate::findings::VulnerabilityFinding;

pub mod aggregation;
pub mod ai_aggregation;
pub mod html;
pub mod json;
pub mod sarif;

/// Apply evidence gate filter to findings.
/// Returns all findings when cfg is None or evidence_gate is false.
/// When gate is enabled, retains only Verified/Supported tiers.
pub fn apply_evidence_gate(
    findings: &[VulnerabilityFinding],
    cfg: Option<&ScannerConfig>,
) -> Vec<VulnerabilityFinding> {
    match cfg {
        None => findings.to_vec(),
        Some(cfg) if !cfg.output.evidence_gate => findings.to_vec(),
        Some(_) => findings
            .iter()
            .filter(|f| {
                let tier = classify_finding(&f.evidence, f.confidence_score);
                matches!(
                    tier,
                    VerificationTier::Verified | VerificationTier::Supported
                )
            })
            .cloned()
            .collect(),
    }
}
