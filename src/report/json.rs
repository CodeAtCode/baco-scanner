use crate::findings::{Severity, VulnerabilityFinding};
use crate::llm_metrics::LlmMetrics;
use serde::Serialize;
use std::fs;

#[derive(Serialize)]
pub struct FindingsOutput {
    pub findings: Vec<VulnerabilityFinding>,
    pub summary: ReportSummary,
}

#[derive(Serialize)]
pub struct ReportSummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,

    /// Metriche LLM (se disponibili)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_metrics: Option<LlmMetricsSummary>,
}

#[derive(Serialize)]
pub struct LlmMetricsSummary {
    pub total_requests: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub cached_requests: usize,
    pub total_tokens: usize,
    pub avg_latency_ms: f64,

    /// Metriche per modello
    pub models: Vec<ModelMetricsSummary>,

    /// Metriche per operazione
    pub operations: Vec<OperationMetricsSummary>,
}

#[derive(Serialize)]
pub struct ModelMetricsSummary {
    pub model_name: String,
    pub total_requests: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub cached_requests: usize,
    pub total_tokens: usize,
}

#[derive(Serialize)]
pub struct OperationMetricsSummary {
    pub operation: String,
    pub phase: String,
    pub requests: usize,
    pub successful: usize,
    pub failed: usize,
}

pub fn write_findings_json(
    findings: &[VulnerabilityFinding],
    output_path: &str,
    llm_metrics: Option<LlmMetrics>,
) -> Result<(), String> {
    let _summary = ReportSummary {
        total_findings: findings.len(),
        critical: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical))
            .count(),
        high: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::High))
            .count(),
        medium: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Medium))
            .count(),
        low: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Low))
            .count(),
        info: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Info))
            .count(),
        llm_metrics: llm_metrics.map(|metrics| {
            let models: Vec<ModelMetricsSummary> = metrics
                .by_model
                .values()
                .map(|m| ModelMetricsSummary {
                    model_name: m.model_name.clone(),
                    total_requests: m.total_requests as usize,
                    successful_requests: m.successful_requests as usize,
                    failed_requests: m.failed_requests as usize,
                    cached_requests: m.cached_requests as usize,
                    total_tokens: m.total_tokens as usize,
                })
                .collect();

            let operations: Vec<OperationMetricsSummary> = metrics
                .by_operation
                .into_values()
                .map(|op| OperationMetricsSummary {
                    operation: op.operation.clone(),
                    phase: op.phase.clone(),
                    requests: op.requests as usize,
                    successful: op.successful as usize,
                    failed: op.failed as usize,
                })
                .collect();

            LlmMetricsSummary {
                total_requests: metrics.total_requests as usize,
                successful_requests: metrics.total_success as usize,
                failed_requests: metrics.total_failed as usize,
                cached_requests: metrics.total_cached as usize,
                total_tokens: metrics.total_tokens as usize,
                avg_latency_ms: metrics.avg_latency_ms,
                models,
                operations,
            }
        }),
    };

    let json = serde_json::to_string_pretty(&findings)
        .map_err(|e| format!("Failed to serialize findings: {}", e))?;

    fs::write(output_path, json).map_err(|e| format!("Failed to write findings.json: {}", e))?;

    Ok(())
}
