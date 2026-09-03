//! Scanner core types and state management

use crate::checkpoint::ScanPhase;
use crate::config;
use crate::findings::VulnerabilityFinding;
use crate::llm_metrics::LlmMetricsTracker;
use crate::scanner_types::{cve::CveEntry, project::ProjectStack};

use indicatif::{MultiProgress, ProgressBar};

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::watch;

// Type alias for phase result to reduce complexity
#[allow(dead_code)]
type PhaseResult = crate::error::ScanResult<(
    Vec<VulnerabilityFinding>,
    Vec<String>,
    Vec<crate::scanner::phases::llm_phases::RejectedFinding>,
)>;

pub struct ScannerState {
    pub findings: Vec<VulnerabilityFinding>,
    pub current_phase: ScanPhase,
    pub files_scanned: usize,
    pub errors: Vec<String>,
    pub cve_entries: Vec<CveEntry>,
    pub project_stack: Option<ProjectStack>,
    pub rejected_findings: Vec<crate::scanner::phases::llm_phases::RejectedFinding>,
}

pub struct Scanner {
    pub state: Arc<watch::Sender<ScannerState>>,
    pub(super) progress: MultiProgress,
    pub config: config::ScannerConfig,
    pub target_path: PathBuf,
    pub checkpoint_path: PathBuf,
    pub force: bool,
    pub metrics_tracker: LlmMetricsTracker,
    #[allow(dead_code)]
    cve_entries: Vec<CveEntry>,
    pub project_stack: Option<ProjectStack>,
}

impl Scanner {
    pub fn findings(&self) -> Vec<VulnerabilityFinding> {
        self.state.borrow().findings.clone()
    }

    pub fn findings_mut(&self) -> Vec<VulnerabilityFinding> {
        self.state.borrow().findings.clone()
    }

    pub fn update_findings(&self, findings: Vec<VulnerabilityFinding>) {
        self.state.send_modify(|s| {
            s.findings = findings;
        });
    }

    /// Check for early termination based on finding threshold.
    /// Returns Ok(true) if termination triggered, Ok(false) otherwise.
    #[allow(dead_code)]
    pub async fn check_early_termination(
        &self,
        findings: &[VulnerabilityFinding],
        analyzed_files: &[String],
        phase: &ScanPhase,
        pb: &ProgressBar,
    ) -> Result<bool, String> {
        let threshold = self.config.scanner.performance.early_termination_threshold;

        if threshold > 0.0 && findings.len() as f32 > threshold {
            tracing::warn!(
                "Early termination triggered after phase {:?}: {} findings > threshold {}",
                phase,
                findings.len(),
                threshold
            );

            if let Err(e) = self.save_checkpoint(findings, analyzed_files, phase).await {
                tracing::warn!("Failed to save checkpoint before early termination: {}", e);
            }

            pb.set_message(format!(
                "Early termination: {} findings (threshold: {})",
                findings.len(),
                threshold
            ));
            pb.finish();

            return Ok(true);
        }

        Ok(false)
    }

    pub fn add_finding(&self, finding: VulnerabilityFinding) {
        self.state.send_modify(|s| {
            s.findings.push(finding);
        });
    }

    pub fn target_path(&self) -> &Path {
        &self.target_path
    }

    pub fn new(config: config::ScannerConfig, target_path: PathBuf, force: bool) -> Self {
        Self::with_initial_findings(config, target_path, Vec::new(), force)
    }

    pub fn with_initial_findings(
        config: config::ScannerConfig,
        target_path: PathBuf,
        initial_findings: Vec<VulnerabilityFinding>,
        force: bool,
    ) -> Self {
        let (sender, _) = watch::channel(ScannerState {
            findings: initial_findings,
            current_phase: ScanPhase::Indexing,
            files_scanned: 0,
            errors: Vec::new(),
            cve_entries: Vec::new(),
            project_stack: None,
            rejected_findings: Vec::new(),
        });

        let output_dir = PathBuf::from(&config.output.dir);
        let checkpoint_path = output_dir.join("checkpoint.json");

        Self {
            state: Arc::new(sender),
            progress: MultiProgress::new(),
            config,
            target_path,
            checkpoint_path,
            force,
            metrics_tracker: LlmMetricsTracker::new(),
            cve_entries: Vec::new(),
            project_stack: None,
        }
    }

    pub async fn run(&self) -> crate::error::ScanResult<Vec<VulnerabilityFinding>> {
        super::orchestrator::run_scanner(self)
            .await
            .map_err(|e| e.into())
    }

    /// Extract owner and repository name from a Git URL
    pub fn extract_owner_repo_from_url(url: &str) -> Option<(String, String)> {
        super::env::extract_owner_repo_from_url(url)
    }

    /// Get Git remote URL from a repository path
    pub fn get_git_remote_url(repo_path: &str) -> Option<String> {
        super::env::get_git_remote_url(repo_path)
    }
}
