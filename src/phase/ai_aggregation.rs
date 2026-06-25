use super::{PhaseContext, PhaseError, ScanPhase};
use crate::context::AnalysisContext;
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
                f.description.contains("LLM enrichment unavailable") || 
                f.description.contains("client error")
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
                tracing::info!("AI aggregation enriched {} findings", enriched_findings.len());
            }
            
            if !enriched_findings.is_empty() {
                scanner.state.send_modify(|s| s.findings = enriched_findings.clone());
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
