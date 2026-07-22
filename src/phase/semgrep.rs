use super::{PhaseContext, PhaseError, ScanPhase};
use crate::findings::VulnerabilityFinding;
use crate::semgrep::SemgrepRunner;
use async_trait::async_trait;

pub struct SemgrepPhase;

#[async_trait]
impl ScanPhase for SemgrepPhase {
    fn name(&self) -> &'static str {
        "Semgrep"
    }

    fn order(&self) -> u8 {
        2
    }

    async fn execute(
        &self,
        ctx: &mut PhaseContext,
    ) -> Result<Vec<VulnerabilityFinding>, PhaseError> {
        tracing::info!("Running Semgrep phase on {:?}", ctx.scanner.target_path);

        let runner = SemgrepRunner::new(
            None,
            ctx.scanner.config.scanner.semgrep.exclude_rules.clone(),
        );

        match runner
            .run(
                ctx.scanner.target_path.to_str().unwrap_or("."),
                &ctx.scanner.config.output.dir,
            )
            .await
        {
            Ok(semgrep_findings) => {
                tracing::info!(
                    "Semgrep phase complete - {} findings discovered",
                    semgrep_findings.len()
                );
                Ok(semgrep_findings)
            }
            Err(e) => {
                tracing::warn!("Semgrep failed: {}. Skipping phase.", e);
                Err(PhaseError {
                    phase_name: "Semgrep",
                    message: format!("Semgrep execution failed: {}", e),
                })
            }
        }
    }

    fn is_enabled(&self, _ctx: &PhaseContext) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semgrep_phase_name() {
        let phase = SemgrepPhase;
        assert_eq!(phase.name(), "Semgrep");
    }

    #[test]
    fn test_semgrep_phase_order() {
        let phase = SemgrepPhase;
        assert_eq!(phase.order(), 2);
    }

    #[test]
    fn test_semgrep_phase_creation() {
        let _phase = SemgrepPhase;
        assert!(true);
    }
}
