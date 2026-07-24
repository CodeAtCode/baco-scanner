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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ScannerConfig, TicketConfig, TicketSystemConfig};
    use crate::findings::Severity;
    use crate::scanner::Scanner;
    use tempfile::TempDir;

    fn create_test_scanner_with_tickets() -> (Scanner, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ScannerConfig::default();
        config.tickets = TicketConfig {
            systems: vec![TicketSystemConfig {
                system_type: "github".to_string(),
                url: "https://github.com/test/repo".to_string(),
                api_key: Some("test-key".to_string()),
                project: Some("test".to_string()),
            }],
        };
        let scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);
        (scanner, temp_dir)
    }

    fn create_test_scanner_without_tickets() -> (Scanner, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();
        let scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);
        (scanner, temp_dir)
    }

    #[test]
    fn test_ticket_crossref_phase_creation() {
        let phase = TicketCrossRefPhase;
        assert_eq!(phase.name(), "TicketCrossRef");
        assert_eq!(phase.order(), 6);
    }

    #[test]
    fn test_is_enabled_with_tickets() {
        let (scanner, _temp) = create_test_scanner_with_tickets();
        let analyzed_files = Vec::new();
        let ctx = PhaseContext {
            scanner: Box::leak(Box::new(scanner)),
            analyzed_files: Box::leak(Box::new(analyzed_files)),
        };
        let phase = TicketCrossRefPhase;
        assert!(phase.is_enabled(&ctx));
    }

    #[test]
    fn test_is_disabled_without_tickets() {
        let (scanner, _temp) = create_test_scanner_without_tickets();
        let analyzed_files = Vec::new();
        let ctx = PhaseContext {
            scanner: Box::leak(Box::new(scanner)),
            analyzed_files: Box::leak(Box::new(analyzed_files)),
        };
        let phase = TicketCrossRefPhase;
        assert!(!phase.is_enabled(&ctx));
    }

    #[tokio::test]
    async fn test_execute_with_empty_findings() {
        let (scanner, _temp) = create_test_scanner_with_tickets();
        let analyzed_files = Vec::new();
        let mut ctx = PhaseContext {
            scanner: Box::leak(Box::new(scanner)),
            analyzed_files: Box::leak(Box::new(analyzed_files)),
        };
        let phase = TicketCrossRefPhase;
        let result = phase.execute(&mut ctx).await;
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_execute_preserves_findings_without_ticket_match() {
        let (scanner, _temp) = create_test_scanner_with_tickets();
        scanner.state.send_modify(|s| {
            s.findings.push(VulnerabilityFinding {
                id: "test-1".to_string(),
                title: "Test vulnerability".to_string(),
                description: "Test description".to_string(),
                severity: Severity::High,
                confidence_score: 0.5,
                cwe_id: Some("CWE-79".to_string()),
                file_path: "test.c".to_string(),
                line_number: Some(10),
                code_snippet: None,
                diff_hunk: None,
                recommendation: None,
                code_location: None,
                already_reported: false,
                sources: vec!["test".to_string()],
                commit_reference: None,
                ticket_reference: None,
                priority_score: None,
                cross_file_references: None,
                verification_status: None,
                verification_notes: None,
                verification_error: None,
                agent_evidence_path: None,
                security_issue: None,
                poc_code: None,
                mitigation_code: None,
                poc_format: None,
                llm_model: None,
                agent_mode: false,
                statement_range: None,
                triage_verdict: None,
            });
        });
        let analyzed_files = Vec::new();
        let mut ctx = PhaseContext {
            scanner: Box::leak(Box::new(scanner)),
            analyzed_files: Box::leak(Box::new(analyzed_files)),
        };
        let phase = TicketCrossRefPhase;
        let result = phase.execute(&mut ctx).await;
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].ticket_reference.is_none());
    }
}
