use super::{PhaseContext, PhaseError, ScanPhase};
use crate::agent::session::AgentSession;
use crate::findings::{VerificationStatus, VulnerabilityFinding};
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;

/// Helper to update finding with agent evidence path and test log
fn update_finding_with_agent_evidence(
    mut finding: VulnerabilityFinding,
    compile_path: Option<&PathBuf>,
    test_source_path: Option<&PathBuf>,
    agent_turns: usize,
    tools_used: &[String],
    test_log: Option<&String>,
) -> VulnerabilityFinding {
    // Store evidence path
    if let Some(path) = compile_path {
        finding.agent_evidence_path = Some(path.to_string_lossy().to_string());
    } else if let Some(path) = test_source_path {
        finding.agent_evidence_path = Some(path.to_string_lossy().to_string());
    } else if agent_turns > 0 {
        finding.agent_evidence_path =
            Some(format!("{} turns, {} tools", agent_turns, tools_used.len()));
    }

    // Store test log
    if let Some(log) = test_log {
        if finding.verification_notes.is_none() {
            finding.verification_notes = Some(log.clone().to_string());
        }
    }

    finding
}

/// Verification phase using embedded SecurityAgent with tool-based verification
pub struct SecurityAgentVerificationPhase;

#[async_trait]
impl ScanPhase for SecurityAgentVerificationPhase {
    fn name(&self) -> &'static str {
        "SecurityAgentVerification"
    }

    fn order(&self) -> u8 {
        6 // After LlmVerification
    }

    async fn execute(
        &self,
        ctx: &mut PhaseContext,
    ) -> Result<Vec<VulnerabilityFinding>, PhaseError> {
        tracing::debug!("Running SecurityAgent verification phase...");

        let findings = {
            let state = ctx.scanner.state.clone();
            let reader = state.borrow();
            reader.findings.clone()
        };

        if !ctx.scanner.config.agent.enabled {
            tracing::debug!("Agent mode disabled, skipping SecurityAgent verification");
            return Ok(findings);
        }

        let target_path = ctx.scanner.target_path.clone();
        let total_findings = findings.len();
        let mut verified_findings = Vec::with_capacity(findings.len());

        let Some(client) = crate::llm::create_llm_client_with_metrics(ctx.scanner, "discovery")
        else {
            tracing::debug!("No API key for agent, skipping SecurityAgent verification");
            return Ok(findings);
        };

        for (i, finding) in findings.into_iter().enumerate() {
            tracing::debug!(
                "Verifying finding [{}/{}] with SecurityAgent: {}",
                i + 1,
                total_findings,
                finding.title
            );

            // Create agent session
            let agent = AgentSession::new(
                client.clone(),
                &ctx.scanner.config.agent,
                &target_path,
                Arc::new(|msg| tracing::debug!("[AGENT] {}", msg)),
            );

            // Use verify_finding method which handles tool-based verification
            match agent.verify_finding(&finding.file_path, &finding).await {
                Ok(agent_result) => {
                    let updated_finding = update_finding_with_agent_evidence(
                        agent_result.finding,
                        agent_result.compile_path.as_ref(),
                        agent_result.test_source_path.as_ref(),
                        agent_result.agent_turns.try_into().unwrap_or(0),
                        &agent_result.tools_used,
                        agent_result.test_log.as_ref(),
                    );

                    tracing::debug!(
                        "SecurityAgent verified {}: {:?} - {} turns, {} tools",
                        updated_finding.title,
                        updated_finding.verification_status,
                        agent_result.agent_turns,
                        agent_result.tools_used.len()
                    );

                    verified_findings.push(updated_finding);
                }
                Err(e) => {
                    tracing::warn!(
                        "SecurityAgent verification failed for {}: {}",
                        finding.title,
                        e
                    );
                    let mut failed_finding = finding;
                    failed_finding.verification_status = Some(VerificationStatus::Failed);
                    failed_finding.verification_notes =
                        Some(format!("Agent verification failed: {}", e));
                    verified_findings.push(failed_finding);
                }
            }
        }

        tracing::debug!(
            "SecurityAgent verification complete - verified {} findings",
            total_findings
        );

        Ok(verified_findings)
    }

    fn is_enabled(&self, ctx: &PhaseContext) -> bool {
        ctx.scanner.config.agent.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_agent_verification_phase_name() {
        let phase = SecurityAgentVerificationPhase;
        assert_eq!(phase.name(), "SecurityAgentVerification");
    }

    #[test]
    fn test_security_agent_verification_phase_order() {
        let phase = SecurityAgentVerificationPhase;
        assert_eq!(phase.order(), 6);
    }

    #[test]
    fn test_security_agent_verification_phase_creation() {
        let _phase = SecurityAgentVerificationPhase;
        assert!(true);
    }
}
