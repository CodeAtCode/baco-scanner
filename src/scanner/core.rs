use crate::checkpoint::ScanPhase;
use crate::config;
use crate::findings::VulnerabilityFinding;
use crate::llm_metrics::LlmMetricsTracker;
use crate::scanner_types::{CveEntry, ProjectStack};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::watch;

pub struct ScannerState {
    pub findings: Vec<VulnerabilityFinding>,
    pub current_phase: ScanPhase,
    pub files_scanned: usize,
    pub errors: Vec<String>,
    pub cve_entries: Vec<CveEntry>,
    pub project_stack: Option<ProjectStack>,
}

pub struct Scanner {
    pub state: Arc<watch::Sender<ScannerState>>,
    progress: MultiProgress,
    pub config: config::ScannerConfig,
    pub target_path: PathBuf,
    pub checkpoint_path: PathBuf,
    force: bool,
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
    async fn check_early_termination(
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

    pub async fn run(&self) -> Result<Vec<VulnerabilityFinding>, String> {
        let (mut findings, completed_phases, mut analyzed_files) = if self.force {
            tracing::info!("Force flag set - starting fresh, ignoring checkpoint");
            (Vec::new(), Vec::new(), Vec::new())
        } else if self.checkpoint_path.exists() {
            use crate::checkpoint::Checkpoint;
            match Checkpoint::load(&self.checkpoint_path.to_string_lossy()) {
                Ok(cp) => {
                    tracing::info!(
                        "Loaded checkpoint from phase {:?} with {} findings, {} analyzed files",
                        cp.current_phase,
                        cp.findings_so_far.len(),
                        cp.analyzed_files.len()
                    );
                    (cp.findings_so_far, cp.completed_phases, cp.analyzed_files)
                }
                Err(e) => {
                    tracing::warn!("Failed to load checkpoint: {}, starting fresh", e);
                    (Vec::new(), Vec::new(), Vec::new())
                }
            }
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        };

        // Define all phases in execution order
        let sequential_phases = [
            ScanPhase::LlmDiscovery,
            ScanPhase::LlmVerification,
            ScanPhase::SecurityAgentVerification,
            ScanPhase::TicketCrossRef,
            ScanPhase::GitAnalysis,
            ScanPhase::CrossFileAnalysis,
            ScanPhase::ConfidenceScoring,
            ScanPhase::AiAggregation,
            ScanPhase::Reporting,
            // v3 features
            ScanPhase::ThreatModeling,
            ScanPhase::RootCauseDedup,
            ScanPhase::MultiVerifier,
            ScanPhase::AutoPatching,
            ScanPhase::CveBootstrap,
            ScanPhase::PocCompiler,
            ScanPhase::VariantSearch,
        ];

        // Independent phases that can run in parallel
        let parallel_phases = [
            ScanPhase::Indexing,
            ScanPhase::Semgrep,
            ScanPhase::LlmStaticAnalysis,
        ];

        let enable_parallel = true; // Enable parallel execution

        // Print mode before progress bar appears
        if enable_parallel {
            tracing::info!("\u{1B}[34m[SCANNER]\u{1B}[0m Starting parallel phases: Indexing, Semgrep, LLM Static Analysis...");
        } else {
            tracing::info!(
                "\u{1B}[34m[SCANNER]\u{1B}[0m Starting SERIAL phases (parallel disabled)..."
            );
        }

        // Calculate total phases: 3 parallel + 12 sequential = 15 total (including v3 features)
        let total_phases = if enable_parallel {
            3 + sequential_phases.len()
        } else {
            parallel_phases.len() + sequential_phases.len()
        };
        let pb = self
            .progress
            .add(ProgressBar::new(total_phases as u64 * 100));
        tracing::debug!("Total phases: {}", total_phases);

        let style = ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {msg}")
            .unwrap()
            .progress_chars("=>-");
        pb.set_style(style);
        pb.set_message("Initializing BACO security scan...");

        let is_phase_completed = |phase: &ScanPhase| completed_phases.contains(phase);

        if enable_parallel {
            tracing::info!("\u{1B}[34m[SCANNER]\u{1B}[0m Parallel mode ENABLED");
            // Set draw target to stderr for proper visibility
            pb.set_draw_target(indicatif::ProgressDrawTarget::stderr());
            pb.enable_steady_tick(std::time::Duration::from_millis(100));
            pb.set_message("Running parallel phases (Indexing, Semgrep, LLM Static)...");

            let findings_for_parallel = findings.clone();
            tracing::info!(
                "\u{1B}[34m[SCANNER]\u{1B}[0m Findings cloned: {} items",
                findings_for_parallel.len()
            );

            let indexing_handle = if !is_phase_completed(&ScanPhase::Indexing) {
                let this = self;
                let pb = pb.clone();
                let initial_findings = findings_for_parallel.clone();
                Some(async move {
                    this.run_phase(&ScanPhase::Indexing, initial_findings, &pb, &[])
                        .await
                })
            } else {
                tracing::info!("Skipping Indexing phase (already completed in previous run)");
                None
            };

            let semgrep_handle = if !is_phase_completed(&ScanPhase::Semgrep) {
                let this = self;
                let pb = pb.clone();
                let initial_findings = findings_for_parallel.clone();
                Some(async move {
                    this.run_phase(&ScanPhase::Semgrep, initial_findings, &pb, &[])
                        .await
                })
            } else {
                tracing::info!("Skipping Semgrep phase (already completed in previous run)");
                None
            };

            let checkpoint_findings = if is_phase_completed(&ScanPhase::LlmStaticAnalysis) {
                self.load_checkpoint_findings(&ScanPhase::LlmStaticAnalysis)
                    .await
            } else {
                Vec::new()
            };

            // Check if checkpoint has valid findings (with non-empty descriptions)
            let has_valid_findings = !checkpoint_findings.is_empty()
                && checkpoint_findings
                    .iter()
                    .any(|f| !f.description.is_empty());

            let llm_static_handle = if !is_phase_completed(&ScanPhase::LlmStaticAnalysis)
                || !has_valid_findings
            {
                if !is_phase_completed(&ScanPhase::LlmStaticAnalysis) {
                    tracing::info!("[LLM] Running LLM Static Analysis phase");
                } else {
                    tracing::warn!("[LLM] Checkpoint has {} findings but all have empty descriptions - forcing re-run", checkpoint_findings.len());
                }
                let this = self;
                let pb = pb.clone();
                let initial_findings = findings_for_parallel;
                let analyzed_files_clone = analyzed_files.clone();
                Some(async move {
                    this.run_phase(
                        &ScanPhase::LlmStaticAnalysis,
                        initial_findings,
                        &pb,
                        &analyzed_files_clone,
                    )
                    .await
                })
            } else {
                tracing::info!(
                    "[LLM] Skipping phase ({} valid findings in checkpoint)",
                    checkpoint_findings.len()
                );
                findings.extend(checkpoint_findings);
                None
            };

            let start_time = Instant::now();

            let indexing_result = match indexing_handle {
                Some(handle) => Some(handle.await),
                None => None,
            };
            let semgrep_result = match semgrep_handle {
                Some(handle) => Some(handle.await),
                None => None,
            };
            let llm_static_result = match llm_static_handle {
                Some(handle) => Some(handle.await),
                None => None,
            };

            let parallel_duration = start_time.elapsed();
            tracing::info!("Parallel phases completed in {:?}", parallel_duration);

            // Combine results from all three phases
            if let Some(Ok((mut index_findings, _))) = indexing_result {
                findings.append(&mut index_findings);
            }
            if let Some(Ok((mut semgrep_findings, _))) = semgrep_result {
                findings.append(&mut semgrep_findings);
            }
            if let Some(Ok((mut llm_findings, new_files))) = llm_static_result {
                tracing::info!("[SCANNER] Added {} LLM findings", llm_findings.len());
                if !llm_findings.is_empty() {
                    tracing::debug!(
                        "[SCANNER] First finding description length: {}",
                        llm_findings[0].description.len()
                    );
                }
                findings.append(&mut llm_findings);
                analyzed_files = new_files;
            } else {
                tracing::warn!("[SCANNER] LLM static analysis result was None or Err");
            }

            tracing::info!("After parallel phases: {} findings total", findings.len());

            self.state.send_modify(|s| {
                s.current_phase = ScanPhase::LlmStaticAnalysis;
                s.findings = findings.clone();
            });

            // Check for early termination after parallel phases
            let threshold = self.config.scanner.performance.early_termination_threshold;
            if threshold > 0.0 && findings.len() as f32 > threshold {
                tracing::warn!(
                    "Early termination triggered after parallel phases: {} findings > threshold {}",
                    findings.len(),
                    threshold
                );
                if let Err(e) = self
                    .save_checkpoint(&findings, &analyzed_files, &ScanPhase::LlmStaticAnalysis)
                    .await
                {
                    tracing::warn!("Failed to save checkpoint before early termination: {}", e);
                }
                pb.set_message(format!(
                    "Early termination: {} findings (threshold: {})",
                    findings.len(),
                    threshold
                ));
                pb.finish();
                return Ok(findings);
            }

            if let Err(e) = self
                .save_checkpoint(&findings, &analyzed_files, &ScanPhase::LlmStaticAnalysis)
                .await
            {
                tracing::warn!("Failed to save checkpoint after parallel phases: {}", e);
            }

            // Re-enable progress bar and show completion
            pb.set_draw_target(indicatif::ProgressDrawTarget::stdout());
            pb.set_message("Parallel phases complete, running sequential phases...");
            pb.set_position(300);
        } else {
            // Original sequential execution for backward compatibility
            for (i, phase) in parallel_phases.iter().enumerate() {
                let phase_num = i + 1;
                pb.set_position((i as u64) * 100);

                if is_phase_completed(phase) {
                    tracing::info!(
                        "Skipping {:?} phase (already completed in previous run)",
                        phase
                    );
                    continue;
                }

                let phase_msg = match phase {
                    ScanPhase::Indexing => format!(
                        "Phase {}/{}: Indexing project files...",
                        phase_num, total_phases
                    ),
                    ScanPhase::Semgrep => format!(
                        "Phase {}/{}: Running Semgrep static analysis...",
                        phase_num, total_phases
                    ),
                    ScanPhase::LlmStaticAnalysis => format!(
                        "Phase {}/{}: LLM static analysis (analyzing files for vulnerabilities)...",
                        phase_num, total_phases
                    ),
                    ScanPhase::CveBootstrap => {
                        format!("Phase {}/{}: CVE bootstrap...", phase_num, total_phases)
                    }
                    ScanPhase::PocCompiler => format!(
                        "Phase {}/{}: PoC compilation check...",
                        phase_num, total_phases
                    ),
                    ScanPhase::VariantSearch => {
                        format!("Phase {}/{}: Variant search...", phase_num, total_phases)
                    }
                    _ => format!("Phase {}/{}: {:?}", phase_num, total_phases, phase),
                };
                pb.set_message(phase_msg);

                let phase_start = Instant::now();
                (findings, _) = self
                    .run_phase(phase, findings, &pb, &analyzed_files)
                    .await?;
                let phase_duration = phase_start.elapsed();
                tracing::info!("Phase {:?} completed in {:?}", phase, phase_duration);

                self.state.send_modify(|s| {
                    s.current_phase = phase.clone();
                    s.findings = findings.clone();
                });

                // Check for early termination
                match self
                    .check_early_termination(&findings, &analyzed_files, phase, &pb)
                    .await
                {
                    Ok(true) => return Ok(findings),
                    Ok(false) => {}
                    Err(e) => tracing::warn!("Early termination check failed: {}", e),
                }

                if let Err(e) = self
                    .save_checkpoint(&findings, &analyzed_files, phase)
                    .await
                {
                    tracing::warn!("Failed to save checkpoint after {:?}: {}", phase, e);
                }
            }
        }

        // Phases 4-11: Sequential execution (LlmDiscovery, LlmVerification, etc.)
        for (i, phase) in sequential_phases.iter().enumerate() {
            let phase_num = 4 + i;
            pb.set_position(300 + (i as u64) * 100);

            if is_phase_completed(phase) {
                tracing::info!(
                    "Skipping {:?} phase (already completed in previous run)",
                    phase
                );
                continue;
            }

            let phase_msg = match phase {
                ScanPhase::LlmDiscovery => format!(
                    "Phase {}/{}: LLM discovery (enriching findings with context)...",
                    phase_num, total_phases
                ),
                ScanPhase::LlmVerification => format!(
                    "Phase {}/{}: LLM verification (validating findings)...",
                    phase_num, total_phases
                ),
                ScanPhase::SecurityAgentVerification => format!(
                    "Phase {}/{}: SecurityAgent verification (tool-based validation)...",
                    phase_num, total_phases
                ),
                ScanPhase::TicketCrossRef => format!(
                    "Phase {}/{}: Searching ticket systems for references...",
                    phase_num, total_phases
                ),
                ScanPhase::GitAnalysis => format!(
                    "Phase {}/{}: Analyzing Git history for related commits...",
                    phase_num, total_phases
                ),
                ScanPhase::CrossFileAnalysis => format!(
                    "Phase {}/{}: Cross-file dependency analysis...",
                    phase_num, total_phases
                ),
                ScanPhase::ConfidenceScoring => format!(
                    "Phase {}/{}: Calculating confidence scores...",
                    phase_num, total_phases
                ),
                ScanPhase::AiAggregation => format!(
                    "Phase {}/{}: AI aggregation (generating executive summary)...",
                    phase_num, total_phases
                ),
                ScanPhase::Reporting => format!(
                    "Phase {}/{}: Generating reports (JSON/HTML/SARIF)...",
                    phase_num, total_phases
                ),
                ScanPhase::ThreatModeling => format!(
                    "Phase {}/{}: Threat modeling (STRIDE analysis)...",
                    phase_num, total_phases
                ),
                ScanPhase::RootCauseDedup => format!(
                    "Phase {}/{}: Root cause deduplication...",
                    phase_num, total_phases
                ),
                ScanPhase::MultiVerifier => format!(
                    "Phase {}/{}: Multi-verifier voting...",
                    phase_num, total_phases
                ),
                ScanPhase::AutoPatching => format!(
                    "Phase {}/{}: Auto-patching with staging validation...",
                    phase_num, total_phases
                ),
                ScanPhase::CveBootstrap => {
                    format!("Phase {}/{}: CVE bootstrap...", phase_num, total_phases)
                }
                ScanPhase::PocCompiler => format!(
                    "Phase {}/{}: PoC compilation check...",
                    phase_num, total_phases
                ),
                ScanPhase::VariantSearch => {
                    format!("Phase {}/{}: Variant search...", phase_num, total_phases)
                }
                _ => format!("Phase {}/{}: {:?}", phase_num, total_phases, phase),
            };
            pb.set_message(phase_msg);

            let phase_start = Instant::now();

            (findings, analyzed_files) = self
                .run_phase(phase, findings, &pb, &analyzed_files)
                .await?;
            let phase_duration = phase_start.elapsed();
            tracing::info!("Phase {:?} completed in {:?}", phase, phase_duration);

            self.state.send_modify(|s| {
                s.current_phase = phase.clone();
                s.findings = findings.clone();
            });

            // Check for early termination
            match self
                .check_early_termination(&findings, &analyzed_files, phase, &pb)
                .await
            {
                Ok(true) => return Ok(findings),
                Ok(false) => {}
                Err(e) => tracing::warn!("Early termination check failed: {}", e),
            }

            if let Err(e) = self
                .save_checkpoint(&findings, &analyzed_files, phase)
                .await
            {
                tracing::warn!("Failed to save checkpoint after {:?}: {}", phase, e);
            }
        }

        pb.set_message("Scan complete!");
        pb.finish();

        self.state.send_modify(|s| {
            s.current_phase = ScanPhase::Reporting;
            s.findings = findings.clone();
        });

        Ok(findings)
    }

    pub fn extract_owner_repo_from_url(url: &str) -> Option<(String, String)> {
        let url = url.trim();
        if url.starts_with("git@") {
            let without_git = url.trim_start_matches("git@");
            if let Some((_host, rest)) = without_git.split_once(':') {
                if let Some((owner, repo)) = rest.split_once('/') {
                    let repo = repo.trim_end_matches(".git");
                    return Some((owner.to_string(), repo.to_string()));
                }
            }
        } else if url.starts_with("https://") || url.starts_with("http://") {
            let without_scheme = url
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            if let Some((_host, rest)) = without_scheme.split_once('/') {
                let parts: Vec<&str> = rest.split('/').collect();
                if parts.len() >= 2 {
                    let repo = parts[1].trim_end_matches(".git");
                    return Some((parts[0].to_string(), repo.to_string()));
                }
            }
        }
        None
    }

    pub fn get_git_remote_url(repo_path: &str) -> Option<String> {
        use crate::git_analysis::GitHistoryAnalyzer;
        GitHistoryAnalyzer::new(repo_path)
            .ok()
            .and_then(|a| a.get_remote_url())
    }
}
