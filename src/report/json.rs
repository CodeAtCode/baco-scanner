use crate::config::ScannerConfig;
use crate::evidence::classify_finding;
use crate::findings::{Severity, VulnerabilityFinding};
use crate::llm_metrics::LlmMetrics;
use serde::Serialize;
use std::fs;

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

/// Rejected finding with its rejection reason for JSON serialization
#[derive(Serialize)]
struct RejectedFindingJson {
    #[serde(flatten)]
    finding: VulnerabilityFinding,
    rejection_reason: String,
}

pub fn write_findings_json(
    findings: &[VulnerabilityFinding],
    rejected_findings: &[(VulnerabilityFinding, String)],
    output_path: &str,
    llm_metrics: Option<LlmMetrics>,
    config: Option<&ScannerConfig>,
) -> Result<(), String> {
    // JSON output contains ALL findings for transparency (no filtering)
    // but ensures every finding has verification_tier set when gate is enabled
    let mut findings_with_tier = findings.to_vec();
    if let Some(cfg) = config {
        if cfg.output.evidence_gate {
            for finding in &mut findings_with_tier {
                if finding.verification_tier.is_none() {
                    finding.verification_tier = Some(classify_finding(
                        &finding.evidence,
                        finding.confidence_score,
                    ));
                }
            }
        }
    }

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

    let json = if let Some(cfg) = config {
        if cfg.output.include_rejected {
            // Include rejected findings with their reasons
            let rejected_json: Vec<RejectedFindingJson> = rejected_findings
                .iter()
                .map(|(finding, reason)| RejectedFindingJson {
                    finding: finding.clone(),
                    rejection_reason: reason.clone(),
                })
                .collect();

            // Create a custom JSON structure with both findings and rejected
            #[derive(Serialize)]
            struct FullReport {
                findings: Vec<VulnerabilityFinding>,
                rejected: Vec<RejectedFindingJson>,
                summary: ReportSummary,
            }

            let full_report = FullReport {
                findings: findings_with_tier,
                rejected: rejected_json,
                summary: _summary,
            };

            serde_json::to_string_pretty(&full_report)
                .map_err(|e| format!("Failed to serialize findings: {}", e))?
        } else {
            serde_json::to_string_pretty(&findings_with_tier)
                .map_err(|e| format!("Failed to serialize findings: {}", e))?
        }
    } else {
        serde_json::to_string_pretty(&findings_with_tier)
            .map_err(|e| format!("Failed to serialize findings: {}", e))?
    };

    // Create parent directory if it doesn't exist
    if let Some(parent) = std::path::Path::new(output_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create output directory: {}", e))?;
    }

    fs::write(output_path, json).map_err(|e| format!("Failed to write findings.json: {}", e))?;

    Ok(())
}
