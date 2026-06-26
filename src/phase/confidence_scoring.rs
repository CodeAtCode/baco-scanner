use super::{PhaseContext, PhaseError, ScanPhase};
use crate::confidence::ConfidenceCalculator;
use crate::findings::VulnerabilityFinding;
use async_trait::async_trait;

pub struct ConfidenceScoringPhase;

#[async_trait]
impl ScanPhase for ConfidenceScoringPhase {
    fn name(&self) -> &'static str {
        "ConfidenceScoring"
    }

    fn order(&self) -> u8 {
        9
    }

    async fn execute(
        &self,
        ctx: &mut PhaseContext,
    ) -> Result<Vec<VulnerabilityFinding>, PhaseError> {
        tracing::info!("Running Confidence Scoring phase...");

        let mut findings = ctx.scanner.findings();

        if findings.is_empty() {
            tracing::debug!("No findings to calculate confidence scores for");
            return Ok(Vec::new());
        }

        for finding in &mut findings {
            // Calculate composite confidence and set it on the finding
            finding.confidence_score = ConfidenceCalculator::calculate_composite(finding) * 100.0;
            ConfidenceCalculator::recalculate_priority(finding);
        }

        let avg_confidence: f64 = findings
            .iter()
            .map(|f| f.confidence_score as f64)
            .sum::<f64>()
            / findings.len() as f64;

        let avg_priority: f64 = findings
            .iter()
            .filter_map(|f| f.priority_score.map(|p| p as f64))
            .sum::<f64>()
            / findings.len() as f64;

        tracing::info!(
            "Confidence Scoring complete - {} findings processed, avg confidence: {:.2}, avg priority: {:.2}",
            findings.len(),
            avg_confidence,
            avg_priority
        );

        Ok(findings)
    }

    fn is_enabled(&self, _ctx: &PhaseContext) -> bool {
        true
    }
}
