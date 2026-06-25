use super::{PhaseContext, PhaseError, ScanPhase};
use crate::crossfile::CrossFileAnalyzer;
use crate::findings::VulnerabilityFinding;
use async_trait::async_trait;

pub struct CrossFileAnalysisPhase;

#[async_trait]
impl ScanPhase for CrossFileAnalysisPhase {
    fn name(&self) -> &'static str {
        "CrossFileAnalysis"
    }

    fn order(&self) -> u8 {
        8
    }

    async fn execute(
        &self,
        ctx: &mut PhaseContext,
    ) -> Result<Vec<VulnerabilityFinding>, PhaseError> {
        tracing::info!("Running Cross-File Analysis phase...");

        let findings = ctx.scanner.findings();

        if findings.is_empty() {
            tracing::debug!("No findings to analyze for cross-file references");
            return Ok(Vec::new());
        }

        let updated_findings = CrossFileAnalyzer::analyze_cross_file_references(&findings);

        tracing::info!(
            "Cross-File Analysis complete - {} findings processed, {} with cross-file references",
            updated_findings.len(),
            updated_findings
                .iter()
                .filter(|f| f
                    .cross_file_references
                    .as_ref()
                    .map(|r| !r.is_empty())
                    .unwrap_or(false))
                .count()
        );

        Ok(updated_findings)
    }

    fn is_enabled(&self, _ctx: &PhaseContext) -> bool {
        true
    }
}
