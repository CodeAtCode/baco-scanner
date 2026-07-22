use super::{PhaseContext, PhaseError, ScanPhase};
use crate::analysis_context::AnalysisContext;
use crate::findings::VulnerabilityFinding;
use crate::llm::LlmConfig;
use crate::report::ai_aggregation::AiAggregationPhase as AiAggregationRunner;
use async_trait::async_trait;

pub struct AiAggregationPhase;

#[async_trait]
impl ScanPhase for AiAggregationPhase {
    fn name(&self) -> &'static str {
        "AiAggregation"
    }

    fn order(&self) -> u8 {
        10
    }

    async fn execute(
        &self,
        ctx: &mut PhaseContext,
    ) -> Result<Vec<VulnerabilityFinding>, PhaseError> {
        let scanner = &mut ctx.scanner;
        let findings = scanner.state.borrow().findings.clone();

        if findings.is_empty() {
            tracing::info!("No findings to aggregate");
            return Ok(findings);
        }

        if let Some(api_key) = &scanner.config.llm.phases.aggregation.api_key {
            let llm_config = LlmConfig {
                base_url: scanner.config.llm.phases.aggregation.base_url.clone(),
                api_key: api_key.clone(),
                model: scanner.config.llm.phases.aggregation.model.clone(),
                models: scanner.config.llm.phases.aggregation.get_models(),
                timeout: scanner.config.llm.timeout_secs,
                max_retries: scanner.config.llm.max_retries as u32,
                retry_backoff_ms: scanner.config.llm.retry_backoff_ms,
            };

            let aggregation_runner = AiAggregationRunner::new(llm_config);
            let context = AnalysisContext::default();

            tracing::info!("Running AI aggregation with LLM enrichment");
            let result = aggregation_runner.run(findings.clone(), &context).await;

            let enriched_findings = result.enriched_findings;

            // Check if LLM enrichment completely failed (all LLM calls failed)
            let llm_completely_failed = enriched_findings.iter().all(|f| {
                f.description.contains("LLM enrichment unavailable")
                    || f.description.contains("client error")
            }) && !enriched_findings.is_empty();

            if llm_completely_failed {
                tracing::error!(
                    "\n╔══════════════════════════════════════════════════════════════════════════════╗\n\
                     ║  ⚠️  LLM ENDPOINT UNREACHABLE  ════════════════════════════════════════════════╣\n\
                     ║                                                                              ║\n\
                     ║  AI aggregation failed because the LLM endpoint is not accessible:          ║\n\
                     ║  {}\n\
                     ║                                                                              ║\n\
                     ║  The scan has completed with {} findings, but they lack AI enrichment.     ║\n\
                     ║                                                                              ║\n\
                     ║  To proceed with AI enrichment, you have two options:                       ║\n\
                     ║                                                                              ║\n\
                     ║  1. Fix the LLM endpoint connectivity issue                                 ║\n\
                     ║                                                                              ║\n\
                     ║  2. Re-run the scan without AI phases (faster):                            ║\n\
                     ║     baco scan --config your_config.toml                                     ║\n\
                     ║     (then edit config to set api_key = \"\" or enabled = false for LLM phases)║\n\
                     ║                                                                              ║\n\
                     ║  The checkpoint has been saved. You can resume later with:                  ║\n\
                     ║     baco resume --config your_config.toml                                   ║\n\
                     ╚══════════════════════════════════════════════════════════════════════════════╝\n",
                    scanner.config.llm.phases.aggregation.base_url,
                    enriched_findings.len()
                );
            } else if !enriched_findings.is_empty() {
                tracing::info!(
                    "AI aggregation enriched {} findings",
                    enriched_findings.len()
                );
            }

            if !enriched_findings.is_empty() {
                scanner
                    .state
                    .send_modify(|s| s.findings = enriched_findings.clone());
            }

            Ok(enriched_findings)
        } else {
            tracing::info!("No LLM configured for aggregation phase, skipping AI aggregation");
            Ok(findings)
        }
    }

    fn is_enabled(&self, _ctx: &PhaseContext) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScannerConfig;
    use crate::findings::Severity;
    use crate::scanner::Scanner;
    use tempfile::TempDir;

    fn create_test_scanner() -> (Scanner, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();
        let scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);
        (scanner, temp_dir)
    }

    #[test]
    fn test_ai_aggregation_phase_creation() {
        let phase = AiAggregationPhase;
        assert_eq!(phase.name(), "AiAggregation");
        assert_eq!(phase.order(), 10);
    }

    #[test]
    fn test_is_enabled_always_true() {
        let (scanner, _temp) = create_test_scanner();
        let analyzed_files = Vec::new();
        let ctx = PhaseContext {
            scanner: Box::leak(Box::new(scanner)),
            analyzed_files: Box::leak(Box::new(analyzed_files)),
        };
        let phase = AiAggregationPhase;
        assert!(phase.is_enabled(&ctx));
    }

    #[tokio::test]
    async fn test_execute_with_empty_findings() {
        let (scanner, _temp) = create_test_scanner();
        let analyzed_files = Vec::new();
        let mut ctx = PhaseContext {
            scanner: Box::leak(Box::new(scanner)),
            analyzed_files: Box::leak(Box::new(analyzed_files)),
        };
        let phase = AiAggregationPhase;
        let result = phase.execute(&mut ctx).await;
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_execute_without_api_key() {
        let (scanner, _temp) = create_test_scanner();
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
            });
        });
        let analyzed_files = Vec::new();
        let mut ctx = PhaseContext {
            scanner: Box::leak(Box::new(scanner)),
            analyzed_files: Box::leak(Box::new(analyzed_files)),
        };
        let phase = AiAggregationPhase;
        let result = phase.execute(&mut ctx).await;
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
    }
}
