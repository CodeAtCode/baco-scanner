use super::{PhaseContext, PhaseError, ScanPhase};
use crate::findings::VulnerabilityFinding;
use crate::tickets::{TicketSearcher, TicketSystem};
use async_trait::async_trait;

pub struct TicketCrossRefPhase;

#[async_trait]
impl ScanPhase for TicketCrossRefPhase {
    fn name(&self) -> &'static str {
        "TicketCrossRef"
    }

    fn order(&self) -> u8 {
        6
    }

    async fn execute(
        &self,
        ctx: &mut PhaseContext,
    ) -> Result<Vec<VulnerabilityFinding>, PhaseError> {
        tracing::info!("Running ticket cross-reference phase...");

        let findings = ctx.scanner.findings();

        let systems: Vec<TicketSystem> = ctx
            .scanner
            .config
            .tickets
            .systems
            .iter()
            .map(|config| TicketSystem {
                name: format!("{} ({})", config.system_type, config.url),
                system_type: config.system_type.clone(),
                url: config.url.clone(),
                credentials: config.api_key.clone(),
            })
            .collect();

        if systems.is_empty() {
            tracing::debug!("No ticket systems configured, skipping ticket cross-reference");
            return Ok(findings);
        }

        let searcher = TicketSearcher::new(systems);
        let total_findings = findings.len();
        let mut matched_findings = Vec::with_capacity(findings.len());

        for (i, mut finding) in findings.into_iter().enumerate() {
            tracing::debug!(
                "Cross-referencing finding [{}/{}]: {}",
                i + 1,
                total_findings,
                finding.title
            );

            match searcher.search_for_finding(&finding.title).await {
                Ok(references) => {
                    if let Some(ticket_ref) = references.first() {
                        finding.ticket_reference = Some(format!(
                            "{}:{}:{}",
                            ticket_ref.system, ticket_ref.ticket_id, ticket_ref.title
                        ));
                        tracing::debug!(
                            "Found ticket reference for {}: {}",
                            finding.title,
                            finding.ticket_reference.as_ref().unwrap()
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("Ticket search failed for {}: {}", finding.title, e);
                }
            }

            matched_findings.push(finding);
        }

        tracing::info!(
            "Ticket cross-reference complete - processed {} findings",
            total_findings
        );

        Ok(matched_findings)
    }

    fn is_enabled(&self, ctx: &PhaseContext) -> bool {
        !ctx.scanner.config.tickets.systems.is_empty()
    }
}
