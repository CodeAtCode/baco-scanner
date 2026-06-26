//! Scanner module - orchestrates security scanning phases

mod checkpoint;
mod core;
mod phases;

// Re-export public API from core
pub use core::{Scanner, ScannerState};

// Use the checkpoint module for save/load
use crate::checkpoint::ScanPhase;
use crate::findings::VulnerabilityFinding;
use checkpoint::{load_checkpoint_findings, save_checkpoint};

// Re-export Scanner methods that need access to all modules
impl Scanner {
    /// Execute a single scan phase
    async fn run_phase(
        &self,
        phase: &ScanPhase,
        findings: Vec<VulnerabilityFinding>,
        pb: &indicatif::ProgressBar,
        analyzed_files: &[String],
    ) -> Result<(Vec<VulnerabilityFinding>, Vec<String>), String> {
        phases::run_phase(
            self,
            phases::PhaseConfig {
                phase,
                findings,
                pb,
                analyzed_files,
                metrics_tracker: &self.metrics_tracker,
                target_path: &self.target_path,
                config: &self.config,
                project_stack: &self.project_stack,
            },
        )
        .await
    }

    /// Save checkpoint with current findings
    async fn save_checkpoint(
        &self,
        findings: &[VulnerabilityFinding],
        analyzed_files: &[String],
        phase: &ScanPhase,
    ) -> Result<(), String> {
        save_checkpoint(
            &self.checkpoint_path,
            &self.config,
            findings,
            analyzed_files,
            phase,
            &self.metrics_tracker,
        )
        .await
    }

    /// Load findings from checkpoint for a specific phase
    async fn load_checkpoint_findings(&self, phase: &ScanPhase) -> Vec<VulnerabilityFinding> {
        load_checkpoint_findings(&self.checkpoint_path, phase).await
    }
}
