use super::{PhaseContext, PhaseError, ScanPhase};
use crate::findings::VulnerabilityFinding;
use crate::report::html::generate_html_report;
use crate::report::json::write_findings_json;
use crate::report::sarif::generate_sarif_report;
use async_trait::async_trait;

pub struct ReportingPhase;

#[async_trait]
impl ScanPhase for ReportingPhase {
    fn name(&self) -> &'static str {
        "Reporting"
    }

    fn order(&self) -> u8 {
        11
    }

    async fn execute(
        &self,
        ctx: &mut PhaseContext,
    ) -> Result<Vec<VulnerabilityFinding>, PhaseError> {
        let scanner = &mut ctx.scanner;
        let findings = scanner.state.borrow().findings.clone();
        let output_dir = &scanner.config.output.dir;

        tracing::info!("Running reporting phase to {:?}", output_dir);

        let llm_metrics = scanner.metrics_tracker.finalize().await;

        let json_path = format!("{}/findings.json", output_dir);
        if let Err(e) =
            write_findings_json(&findings, json_path.as_str(), Some(llm_metrics.clone()))
        {
            tracing::warn!("Failed to write JSON report: {}", e);
        } else {
            tracing::info!("JSON report written to {}", json_path);
        }

        let html_path = format!("{}/report.html", output_dir);
        // Convert LlmMetrics to LlmMetricsSummary for HTML report
        let metrics_summary = crate::report::json::LlmMetricsSummary {
            total_requests: llm_metrics.total_requests as usize,
            successful_requests: llm_metrics.total_success as usize,
            failed_requests: llm_metrics.total_failed as usize,
            cached_requests: llm_metrics.total_cached as usize,
            total_tokens: llm_metrics.total_tokens as usize,
            avg_latency_ms: llm_metrics.avg_latency_ms,
            models: llm_metrics
                .by_model
                .iter()
                .map(|(name, m)| crate::report::json::ModelMetricsSummary {
                    model_name: name.clone(),
                    total_requests: m.total_requests as usize,
                    successful_requests: m.successful_requests as usize,
                    failed_requests: m.failed_requests as usize,
                    cached_requests: m.cached_requests as usize,
                    total_tokens: m.total_tokens as usize,
                })
                .collect(),
            operations: llm_metrics
                .by_operation
                .iter()
                .map(|(op, m)| crate::report::json::OperationMetricsSummary {
                    operation: op.clone(),
                    phase: m.phase.clone(),
                    requests: m.requests as usize,
                    successful: m.successful as usize,
                    failed: m.failed as usize,
                })
                .collect(),
        };

        if let Err(e) = generate_html_report(
            &findings,
            html_path.as_str(),
            Some(&scanner.config),
            Some(metrics_summary),
        ) {
            tracing::warn!("Failed to write HTML report: {}", e);
        } else {
            tracing::info!("HTML report written to {}", html_path);
        }

        let sarif_path = format!("{}/report.sarif", output_dir);
        match generate_sarif_report(&findings) {
            Ok(sarif_content) => {
                if let Err(e) = std::fs::write(&sarif_path, &sarif_content) {
                    tracing::warn!("Failed to write SARIF report: {}", e);
                } else {
                    tracing::info!("SARIF report written to {}", sarif_path);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to generate SARIF report: {}", e);
            }
        }

        Ok(findings)
    }

    fn is_enabled(&self, _ctx: &PhaseContext) -> bool {
        true
    }
}
