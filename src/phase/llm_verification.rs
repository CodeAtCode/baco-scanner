use super::{PhaseContext, PhaseError, ScanPhase};
use crate::findings::{VerificationStatus, VulnerabilityFinding};
use crate::llm::ChatMessage;
use async_trait::async_trait;

pub struct LlmVerificationPhase;

#[async_trait]
impl ScanPhase for LlmVerificationPhase {
    fn name(&self) -> &'static str {
        "LlmVerification"
    }

    fn order(&self) -> u8 {
        5
    }

    async fn execute(
        &self,
        ctx: &mut PhaseContext,
    ) -> Result<Vec<VulnerabilityFinding>, PhaseError> {
        tracing::info!("Running LLM verification phase...");

        let findings = {
            let state = ctx.scanner.state.clone();
            let reader = state.borrow();
            reader.findings.clone()
        };

        let Some(client) = crate::llm::create_llm_client_with_metrics(&ctx.scanner, "verification") else {
            tracing::debug!("No API key for verification, skipping LLM verification");
            return Ok(findings);
        };

        let total_findings = findings.len();
        let mut verified_findings = Vec::with_capacity(findings.len());

        for (i, mut finding) in findings.into_iter().enumerate() {
            tracing::debug!(
                "Verifying finding [{}/{}]: {}",
                i + 1,
                total_findings,
                finding.title
            );

            let messages = vec![
                ChatMessage::system(
                    "You are a security vulnerability verifier. Analyze the finding and determine if it's a true positive, false positive, or needs review. Return JSON with verification_status (confirmed/false_positive/needs_review) and verification_notes."
                ),
                ChatMessage::user(&format!(
                    "Vulnerability: {}\nLocation: {}:{}\nDescription: {}\nSources: {:?}",
                    finding.title,
                    finding.file_path,
                    finding.line_number.unwrap_or(0),
                    finding.description,
                    finding.sources
                )),
            ];

            match client.chat(&messages).await {
                Ok(response_with_model) => {
                    let response_lower = response_with_model.content.to_lowercase();
                    if response_lower.contains("confirmed") {
                        finding.verification_status = Some(VerificationStatus::Confirmed);
                        finding.verification_notes =
                            Some("LLM verified as true positive".to_string());
                    } else if response_lower.contains("false_positive") {
                        finding.verification_status = Some(VerificationStatus::FalsePositive);
                        finding.verification_notes = Some(response_with_model.content);
                    } else {
                        finding.verification_status = Some(VerificationStatus::NeedsReview);
                        finding.verification_notes = Some(response_with_model.content);
                    }
                }
                Err(e) => {
                    tracing::warn!("LLM verification failed for {}: {}", finding.title, e);
                    finding.verification_status = Some(VerificationStatus::Failed);
                    finding.verification_notes = Some(format!("Verification failed: {}", e));
                }
            }

            verified_findings.push(finding);
        }

        tracing::info!(
            "LLM verification complete - verified {} findings",
            total_findings
        );

        Ok(verified_findings)
    }

    fn is_enabled(&self, ctx: &PhaseContext) -> bool {
        ctx.scanner.config.llm.phases.verification.api_key.is_some()
    }
}
