use crate::checkpoint::{Checkpoint as CheckpointStruct, ScanPhase};
use crate::findings::VulnerabilityFinding;
use crate::llm_metrics::LlmMetricsTracker;
use crate::report::json::write_findings_json;

/// Save a checkpoint with findings and analyzed files
pub async fn save_checkpoint(
    checkpoint_path: &std::path::Path,
    config: &crate::config::ScannerConfig,
    findings: &[VulnerabilityFinding],
    analyzed_files: &[String],
    phase: &ScanPhase,
    metrics_tracker: &LlmMetricsTracker,
) -> Result<(), String> {
    let scan_id = format!("scan-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
    let target_path = checkpoint_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""));
    let mut checkpoint =
        CheckpointStruct::new(&scan_id, &target_path.to_string_lossy(), chrono::Utc::now());

    checkpoint.current_phase = phase.clone();
    checkpoint.findings_so_far = findings.to_vec();
    checkpoint.analyzed_files = analyzed_files.to_vec();

    let json_path = format!("{}/findings.json", config.output.dir);
    #[allow(clippy::needless_borrow)]
    let llm_metrics = metrics_tracker.finalize().await;
    #[allow(clippy::needless_borrow)]
    if let Err(e) = write_findings_json(&findings, json_path.as_str(), Some(llm_metrics)) {
        tracing::warn!("Failed to write findings.json during {:?}: {}", phase, e);
    }

    // Get completed phases (all phases up to and including current)
    let all_phases = [
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::LlmStaticAnalysis,
        ScanPhase::LlmDiscovery,
        ScanPhase::LlmVerification,
        ScanPhase::TicketCrossRef,
        ScanPhase::GitAnalysis,
        ScanPhase::CrossFileAnalysis,
        ScanPhase::ConfidenceScoring,
        ScanPhase::AiAggregation,
        ScanPhase::Reporting,
    ];

    if let Some(pos) = all_phases.iter().position(|p| p == phase) {
        checkpoint.completed_phases = all_phases[..=pos].to_vec();
    }

    checkpoint
        .save(&checkpoint_path.to_string_lossy())
        .map_err(|e| format!("Failed to save checkpoint: {}", e))
}

/// Load findings from a checkpoint for a specific phase
pub async fn load_checkpoint_findings(
    checkpoint_path: &std::path::Path,
    phase: &ScanPhase,
) -> Vec<VulnerabilityFinding> {
    match CheckpointStruct::load(&checkpoint_path.to_string_lossy()) {
        Ok(checkpoint) => {
            // Check if the phase is in completed_phases
            if checkpoint.completed_phases.contains(phase) {
                checkpoint.findings_so_far
            } else {
                Vec::new()
            }
        }
        Err(e) => {
            tracing::warn!("Failed to load checkpoint: {}", e);
            Vec::new()
        }
    }
}
