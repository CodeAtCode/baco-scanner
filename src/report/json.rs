use crate::config::ScannerConfig;
use crate::error::ScanError;
use crate::findings::{Severity, VulnerabilityFinding};
use crate::llm::metrics::LlmMetrics;
use crate::scan_health::ScanHealth;
use crate::scanner::checkpoint::EarlyTerminationInfo;
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

    /// Early termination details (if triggered)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub early_termination: Option<EarlyTerminationInfo>,

    /// Metriche LLM (se disponibili)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_metrics: Option<LlmMetricsSummary>,

    /// Scan health report
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_health: Option<ScanHealth>,
}

#[derive(Serialize)]
pub struct LlmMetricsSummary {
    pub total_requests: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub cached_requests: usize,
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
    early_termination_info: Option<EarlyTerminationInfo>,
    scan_health: Option<ScanHealth>,
) -> Result<(), ScanError> {
    // JSON output contains ALL findings for transparency (no filtering)
    // but ensures every finding has verification_tier set when gate is enabled
    let mut findings_with_tier = findings.to_vec();
    if let Some(cfg) = config {
        if cfg.output.evidence_gate {
            crate::report::tag_verification_tier(&mut findings_with_tier);
        }
    }

    let count_sev = |sev: &Severity| {
        findings
            .iter()
            .filter(|f| std::mem::discriminant(&f.severity) == std::mem::discriminant(sev))
            .count()
    };

    let summary = ReportSummary {
        total_findings: findings.len(),
        critical: count_sev(&Severity::Critical),
        high: count_sev(&Severity::High),
        medium: count_sev(&Severity::Medium),
        low: count_sev(&Severity::Low),
        info: count_sev(&Severity::Info),
        early_termination: early_termination_info,
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
                avg_latency_ms: metrics.avg_latency_ms,
                models,
                operations,
            }
        }),
        scan_health,
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
            struct FullReportWithHealth {
                findings: Vec<VulnerabilityFinding>,
                rejected: Vec<RejectedFindingJson>,
                summary: ReportSummary,
            }

            let full_report = FullReportWithHealth {
                findings: findings_with_tier,
                rejected: rejected_json,
                summary,
            };

            serde_json::to_string_pretty(&full_report).map_err(ScanError::from_json_error)?
        } else {
            serde_json::to_string_pretty(&findings_with_tier).map_err(ScanError::from_json_error)?
        }
    } else {
        serde_json::to_string_pretty(&findings_with_tier).map_err(ScanError::from_json_error)?
    };

    // Create parent directory if it doesn't exist
    if let Some(parent) = std::path::Path::new(output_path).parent() {
        std::fs::create_dir_all(parent).map_err(ScanError::IoError)?;
    }

    fs::write(output_path, json).map_err(ScanError::IoError)?;

    Ok(())
}
