//! Scanner module - orchestrates security scanning phases

pub mod checkpoint;
pub mod core;
pub mod env;
pub mod helpers;
pub mod orchestrator;

pub use orchestrator::structural_dedup;
pub mod parallel;
pub mod phases;
mod pipeline;
pub mod sequential;

// Re-export public API from core
pub use core::{Scanner, ScannerState};

// Re-export pipeline orchestration
pub use pipeline::orchestrator::PhaseGraph;

// Re-export phases for testing
#[cfg(test)]
pub use phases::{run_phase, PhaseConfig};

// Re-export utility functions from env
pub use env::{extract_owner_repo_from_url, get_git_remote_url};
// Re-export parallel module types for testing
pub use parallel::{combine_parallel_results, ParallelPhaseConfig, ParallelPhaseResult};

// Use the checkpoint module for save/load
use crate::checkpoint::ScanPhase;
use crate::findings::VulnerabilityFinding;
use checkpoint::save_checkpoint;

// Re-export Scanner methods that need access to all modules
impl Scanner {
    /// Execute a single scan phase
    pub async fn run_phase(
        &self,
        phase: &ScanPhase,
        findings: Vec<VulnerabilityFinding>,
        pb: &indicatif::ProgressBar,
        analyzed_files: &[String],
    ) -> Result<
        (
            Vec<VulnerabilityFinding>,
            Vec<String>,
            Vec<crate::scanner::phases::llm_phases::RejectedFinding>,
        ),
        String,
    > {
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
        .map_err(|e| e.to_string())
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

    /// Return the number of parallel phases (for testing)
    pub fn scheduled_parallel_phases() -> usize {
        4 // Indexing, Semgrep, CpgSlice, LlmStaticAnalysis
    }

    /// Return the number of sequential phases (for testing)
    pub fn scheduled_sequential_phases() -> usize {
        20 // All sequential phases including Validate
    }

    /// Return parallel and sequential phase counts (for testing)
    pub fn scheduled_phase_counts() -> (usize, usize) {
        (
            Self::scheduled_parallel_phases(),
            Self::scheduled_sequential_phases(),
        )
    }
}
