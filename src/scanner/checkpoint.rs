use crate::findings::VulnerabilityFinding;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ScanPhase {
    Indexing,
    Semgrep,
    CweRouting,
    // T3.1: CPG-guided slicing
    CpgSlice,
    LlmStaticAnalysis,
    LlmDiscovery,
    LlmVerification,
    TicketCrossRef,
    GitAnalysis,
    CrossFileAnalysis,
    ConfidenceScoring,
    AiAggregation,
    Reporting,
    // v3 features
    ThreatModeling,
    RootCauseDedup,
    MultiVerifier,
    AutoPatching,
    CveBootstrap,
    PocCompiler,
    VariantSearch,
    SecurityAgentVerification,
    // T2.3: MoCQ LLM→semgrep rule synthesis phase
    RuleSynthesis,
    // CORRECT paper (arxiv:2504.13474) — LLM-as-judge rationale validation
    Validate,
    // T3.2: Exploit synthesis with sandbox
    ExploitSynth,
    Complete,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub scan_id: String,
    pub project_path: String,
    pub started_at: DateTime<Utc>,
    pub current_phase: ScanPhase,
    pub completed_phases: Vec<ScanPhase>,
    pub findings_so_far: Vec<VulnerabilityFinding>,
    pub file_count: usize,
    #[serde(default)]
    pub analyzed_files: Vec<String>,
}

impl Checkpoint {
    pub fn new(scan_id: &str, project_path: &str, started_at: DateTime<Utc>) -> Self {
        Self {
            scan_id: scan_id.to_string(),
            project_path: project_path.to_string(),
            started_at,
            current_phase: ScanPhase::Indexing,
            completed_phases: Vec::new(),
            findings_so_far: Vec::new(),
            file_count: 0,
            analyzed_files: Vec::new(),
        }
    }

    pub fn save(&self, path: &str) -> Result<(), std::io::Error> {
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    pub fn load(path: &str) -> Result<Self, String> {
        let content =
            fs::read_to_string(path).map_err(|e| format!("Failed to read checkpoint: {}", e))?;

        let checkpoint: Checkpoint = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse checkpoint: {}", e))?;

        checkpoint.validate()?;
        Ok(checkpoint)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.scan_id.is_empty() {
            return Err("scan_id is empty".to_string());
        }
        if self.project_path.is_empty() {
            return Err("project_path is empty".to_string());
        }
        Ok(())
    }

    pub fn resume_from(path: &str) -> Result<ScanPhase, String> {
        let checkpoint = Self::load(path)?;

        Ok(match checkpoint.current_phase {
            // Parallel phases (run concurrently: Indexing, Semgrep, CpgSlice, LlmStaticAnalysis)
            ScanPhase::Indexing => ScanPhase::Semgrep,
            ScanPhase::Semgrep => ScanPhase::CpgSlice,
            ScanPhase::CpgSlice => ScanPhase::LlmStaticAnalysis,
            ScanPhase::LlmStaticAnalysis => ScanPhase::CweRouting,
            // Sequential phases (match sequential_phases array in orchestrator.rs)
            ScanPhase::CweRouting => ScanPhase::RuleSynthesis,
            ScanPhase::RuleSynthesis => ScanPhase::LlmDiscovery,
            ScanPhase::LlmDiscovery => ScanPhase::LlmVerification,
            ScanPhase::LlmVerification => ScanPhase::Validate,
            ScanPhase::Validate => ScanPhase::SecurityAgentVerification,
            ScanPhase::SecurityAgentVerification => ScanPhase::TicketCrossRef,
            ScanPhase::TicketCrossRef => ScanPhase::GitAnalysis,
            ScanPhase::GitAnalysis => ScanPhase::CrossFileAnalysis,
            ScanPhase::CrossFileAnalysis => ScanPhase::ConfidenceScoring,
            ScanPhase::ConfidenceScoring => ScanPhase::AiAggregation,
            ScanPhase::AiAggregation => ScanPhase::ThreatModeling,
            ScanPhase::ThreatModeling => ScanPhase::RootCauseDedup,
            ScanPhase::RootCauseDedup => ScanPhase::MultiVerifier,
            ScanPhase::MultiVerifier => ScanPhase::AutoPatching,
            ScanPhase::AutoPatching => ScanPhase::CveBootstrap,
            ScanPhase::CveBootstrap => ScanPhase::PocCompiler,
            ScanPhase::PocCompiler => ScanPhase::ExploitSynth,
            ScanPhase::ExploitSynth => ScanPhase::VariantSearch,
            ScanPhase::VariantSearch => ScanPhase::Reporting,
            ScanPhase::Reporting => ScanPhase::Complete,
            ScanPhase::Complete | ScanPhase::Error => ScanPhase::Indexing,
        })
    }
}

/// Save a checkpoint with findings and analyzed files
pub async fn save_checkpoint(
    checkpoint_path: &std::path::Path,
    config: &crate::config::ScannerConfig,
    findings: &[VulnerabilityFinding],
    analyzed_files: &[String],
    phase: &ScanPhase,
    metrics_tracker: &crate::llm_metrics::LlmMetricsTracker,
) -> Result<(), String> {
    let scan_id = format!("scan-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
    let target_path = checkpoint_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""));
    let mut checkpoint =
        Checkpoint::new(&scan_id, &target_path.to_string_lossy(), chrono::Utc::now());

    checkpoint.current_phase = phase.clone();
    checkpoint.findings_so_far = findings.to_vec();
    checkpoint.analyzed_files = analyzed_files.to_vec();

    let json_path = format!("{}/findings.json", config.output.dir);
    #[allow(clippy::needless_borrow)]
    let _llm_metrics = metrics_tracker.finalize().await;
    #[allow(clippy::needless_borrow)]
    if let Err(e) =
        crate::report::json::write_findings_json(&findings, &[], json_path.as_str(), None, None)
    {
        tracing::warn!("Failed to write findings.json during {:?}: {}", phase, e);
    }

    // Get completed phases (all phases up to and including current)
    // Must match the pipeline order: 4 parallel + 20 sequential, Reporting last
    let all_phases = [
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::CpgSlice,
        ScanPhase::LlmStaticAnalysis,
        ScanPhase::CweRouting,
        ScanPhase::RuleSynthesis,
        ScanPhase::LlmDiscovery,
        ScanPhase::LlmVerification,
        ScanPhase::Validate,
        ScanPhase::SecurityAgentVerification,
        ScanPhase::TicketCrossRef,
        ScanPhase::GitAnalysis,
        ScanPhase::CrossFileAnalysis,
        ScanPhase::ConfidenceScoring,
        ScanPhase::AiAggregation,
        ScanPhase::ThreatModeling,
        ScanPhase::RootCauseDedup,
        ScanPhase::MultiVerifier,
        ScanPhase::AutoPatching,
        ScanPhase::CveBootstrap,
        ScanPhase::PocCompiler,
        ScanPhase::ExploitSynth,
        ScanPhase::VariantSearch,
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
    match Checkpoint::load(&checkpoint_path.to_string_lossy()) {
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
