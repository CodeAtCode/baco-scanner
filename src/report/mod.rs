use crate::config::ScannerConfig;
use crate::evidence::{VerificationTier, classify_finding};
use crate::findings::VulnerabilityFinding;

pub mod ai_aggregation;
pub mod html;
pub mod json;
pub mod markdown;
pub mod presenter;
pub mod sarif;

/// Tag every finding's verification_tier if it doesn't already have one.
/// Uses crate::evidence::classify_finding to compute the tier from evidence + confidence.
pub fn tag_verification_tier(findings: &mut [VulnerabilityFinding]) {
    for finding in findings {
        if finding.verification_tier.is_none() {
            finding.verification_tier = Some(classify_finding(
                &finding.evidence,
                finding.confidence_score,
            ));
        }
    }
}

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
