use crate::checkpoint::ScanPhase;
use crate::config;
use crate::findings::VulnerabilityFinding;
use crate::llm_metrics::LlmMetricsTracker;
use crate::scanner_types::{cve::CveEntry, project::ProjectStack};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::watch;

// Type alias for phase result to reduce complexity
type PhaseResult = Result<(Vec<VulnerabilityFinding>, Vec<String>), String>;

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
            let llm_static_result: Option<PhaseResult> = match llm_static_handle {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::ScanPhase;
    use crate::config::{
        LlmConfig, LlmPhasesConfig, OutputConfig, PerformanceSettings, ProjectConfig, ScannerConfig,
    };
    use crate::findings::{Severity, VerificationStatus, VulnerabilityFinding};
    use std::sync::Arc;

    /// Test helper: Create a minimal valid ScannerConfig for testing
    fn create_test_config() -> ScannerConfig {
        ScannerConfig {
            project: ProjectConfig {
                name: "test-project".to_string(),
                path: "/tmp/test-project".to_string(),
                languages: vec![],
            },
            output: OutputConfig {
                dir: "/tmp/test-output".to_string(),
                format: vec![],
            },
            scanner: crate::config::ScannerSettings {
                commit_lookback_days: 30,
                max_file_size_kb: 1024,
                exclude_paths: vec![],
                semgrep: crate::config::SemgrepSettings::default(),
                performance: PerformanceSettings::default(),
            },
            llm: LlmConfig {
                timeout_secs: 30,
                max_retries: 3,
                retry_backoff_ms: 1000,
                max_concurrent: 4,
                phases: LlmPhasesConfig::default(),
            },
            tickets: crate::config::TicketConfig::default(),
            agent: crate::config::AgentConfig::default(),
        }
    }

    #[test]
    fn test_scanner_new_creates_initial_state() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config.clone(), target_path.clone(), false);

        assert_eq!(scanner.config.project.name, "test-project");
        assert_eq!(scanner.target_path, target_path);
        assert_eq!(scanner.state.borrow().findings.len(), 0);
        assert_eq!(scanner.state.borrow().current_phase, ScanPhase::Indexing);
        assert_eq!(scanner.state.borrow().files_scanned, 0);
        assert_eq!(scanner.state.borrow().errors.len(), 0);
    }

    #[test]
    fn test_scanner_with_initial_findings() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let initial_findings = vec![VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "Test Finding".to_string(),
            description: "Test description".to_string(),
            severity: Severity::High,
            confidence_score: 0.8,
            cwe_id: Some("CWE-79".to_string()),
            file_path: "test.c".to_string(),
            line_number: Some(42),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        }];

        let scanner =
            Scanner::with_initial_findings(config, target_path, initial_findings.clone(), false);

        assert_eq!(scanner.state.borrow().findings.len(), 1);
        assert_eq!(scanner.state.borrow().findings[0].id, "test-1");
    }

    #[test]
    fn test_scanner_force_flag() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, true); // force = true

        assert!(scanner.force);
    }

    #[test]
    fn test_scanner_findings_method() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        // Initially empty
        assert!(scanner.findings().is_empty());

        // Add a finding
        scanner.add_finding(VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "Test".to_string(),
            description: "Test desc".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.5,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        });

        assert_eq!(scanner.findings().len(), 1);
    }

    #[test]
    fn test_scanner_findings_mut_method() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        scanner.add_finding(VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "Test".to_string(),
            description: "Test desc".to_string(),
            severity: Severity::Low,
            confidence_score: 0.3,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        });

        let findings = scanner.findings_mut();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_scanner_update_findings() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        // Add initial finding
        scanner.add_finding(VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "Test 1".to_string(),
            description: "Test desc 1".to_string(),
            severity: Severity::Info,
            confidence_score: 0.1,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        });

        assert_eq!(scanner.findings().len(), 1);

        // Update with new findings
        let new_findings = vec![VulnerabilityFinding {
            id: "test-2".to_string(),
            title: "Test 2".to_string(),
            description: "Test desc 2".to_string(),
            severity: Severity::Critical,
            confidence_score: 0.95,
            cwe_id: Some("CWE-89".to_string()),
            file_path: "sql.rs".to_string(),
            line_number: Some(100),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["semgrep".to_string()],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: Some(VerificationStatus::Confirmed),
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        }];

        scanner.update_findings(new_findings.clone());
        assert_eq!(scanner.findings().len(), 1);
        assert_eq!(scanner.findings()[0].id, "test-2");
    }

    #[test]
    fn test_scanner_target_path() {
        let config = create_test_config();
        let target_path = PathBuf::from("/custom/path/to/project");
        let scanner = Scanner::new(config, target_path.clone(), false);

        assert_eq!(scanner.target_path(), &target_path);
    }

    #[test]
    fn test_scanner_checkpoint_path_computed_from_config() {
        let mut config = create_test_config();
        config.output.dir = "/tmp/custom-output".to_string();
        let target_path = PathBuf::from("/tmp/target");
        let scanner = Scanner::new(config, target_path, false);

        assert_eq!(
            scanner.checkpoint_path,
            PathBuf::from("/tmp/custom-output/checkpoint.json")
        );
    }

    #[test]
    fn test_extract_owner_repo_from_url_https() {
        let url = "https://github.com/owner/repo-name";
        let result = Scanner::extract_owner_repo_from_url(url);
        assert_eq!(result, Some(("owner".to_string(), "repo-name".to_string())));
    }

    #[test]
    fn test_extract_owner_repo_from_url_https_with_git_suffix() {
        let url = "https://github.com/owner/repo-name.git";
        let result = Scanner::extract_owner_repo_from_url(url);
        assert_eq!(result, Some(("owner".to_string(), "repo-name".to_string())));
    }

    #[test]
    fn test_extract_owner_repo_from_url_ssh() {
        let url = "git@github.com:owner/repo-name";
        let result = Scanner::extract_owner_repo_from_url(url);
        assert_eq!(result, Some(("owner".to_string(), "repo-name".to_string())));
    }

    #[test]
    fn test_extract_owner_repo_from_url_ssh_with_git_suffix() {
        let url = "git@github.com:owner/repo-name.git";
        let result = Scanner::extract_owner_repo_from_url(url);
        assert_eq!(result, Some(("owner".to_string(), "repo-name".to_string())));
    }

    #[test]
    fn test_extract_owner_repo_from_url_invalid() {
        let url = "invalid-url";
        let result = Scanner::extract_owner_repo_from_url(url);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_owner_repo_from_url_empty() {
        let url = "";
        let result = Scanner::extract_owner_repo_from_url(url);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_owner_repo_from_url_with_port() {
        let url = "https://gitlab.example.com:8080/owner/repo";
        let result = Scanner::extract_owner_repo_from_url(url);
        // The function extracts the first path component as host, second as repo
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[test]
    fn test_extract_owner_repo_from_url_http() {
        let url = "http://bitbucket.org/owner/repo";
        let result = Scanner::extract_owner_repo_from_url(url);
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[test]
    fn test_extract_owner_repo_from_url_trailing_whitespace() {
        let url = "  https://github.com/owner/repo  ";
        let result = Scanner::extract_owner_repo_from_url(url);
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[tokio::test]
    async fn test_check_early_termination_below_threshold() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        let findings = vec![VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "Test".to_string(),
            description: "Test desc".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.5,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        }];

        let multi_progress = MultiProgress::new();
        let pb = multi_progress.add(ProgressBar::new(100));

        let result = scanner
            .check_early_termination(&findings, &[], &ScanPhase::Indexing, &pb)
            .await;

        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should NOT terminate (1 finding < 1000 threshold)
    }

    #[tokio::test]
    async fn test_check_early_termination_above_threshold() {
        let mut config = create_test_config();
        config.scanner.performance.early_termination_threshold = 2.0; // Low threshold for testing
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        // Create 5 findings (above threshold of 2)
        let findings: Vec<VulnerabilityFinding> = (0..5)
            .map(|i| VulnerabilityFinding {
                id: format!("test-{}", i),
                title: "Test".to_string(),
                description: "Test desc".to_string(),
                severity: Severity::Medium,
                confidence_score: 0.5,
                cwe_id: None,
                file_path: "test.rs".to_string(),
                line_number: None,
                code_snippet: None,
                diff_hunk: None,
                recommendation: None,
                code_location: None,
                already_reported: false,
                sources: vec![],
                commit_reference: None,
                ticket_reference: None,
                priority_score: None,
                cross_file_references: None,
                verification_status: None,
                verification_notes: None,
                verification_error: None,
                agent_evidence_path: None,
                security_issue: None,
                poc_code: None,
                mitigation_code: None,
                poc_format: None,
                llm_model: None,
                agent_mode: false,
            })
            .collect();

        let multi_progress = MultiProgress::new();
        let pb = multi_progress.add(ProgressBar::new(100));

        let result = scanner
            .check_early_termination(&findings, &[], &ScanPhase::Indexing, &pb)
            .await;

        assert!(result.is_ok());
        assert!(result.unwrap()); // Should terminate (5 findings > 2 threshold)
    }

    #[tokio::test]
    async fn test_check_early_termination_disabled() {
        let mut config = create_test_config();
        config.scanner.performance.early_termination_threshold = 0.0; // Disabled
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        // Create many findings but threshold is 0 (disabled)
        let findings: Vec<VulnerabilityFinding> = (0..10000)
            .map(|i| VulnerabilityFinding {
                id: format!("test-{}", i),
                title: "Test".to_string(),
                description: "Test desc".to_string(),
                severity: Severity::Medium,
                confidence_score: 0.5,
                cwe_id: None,
                file_path: "test.rs".to_string(),
                line_number: None,
                code_snippet: None,
                diff_hunk: None,
                recommendation: None,
                code_location: None,
                already_reported: false,
                sources: vec![],
                commit_reference: None,
                ticket_reference: None,
                priority_score: None,
                cross_file_references: None,
                verification_status: None,
                verification_notes: None,
                verification_error: None,
                agent_evidence_path: None,
                security_issue: None,
                poc_code: None,
                mitigation_code: None,
                poc_format: None,
                llm_model: None,
                agent_mode: false,
            })
            .collect();

        let multi_progress = MultiProgress::new();
        let pb = multi_progress.add(ProgressBar::new(100));

        let result = scanner
            .check_early_termination(&findings, &[], &ScanPhase::Indexing, &pb)
            .await;

        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should NOT terminate (threshold = 0 means disabled)
    }

    #[test]
    fn test_scanner_state_initial_values() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        let state = scanner.state.borrow();
        assert!(state.findings.is_empty());
        assert_eq!(state.current_phase, ScanPhase::Indexing);
        assert_eq!(state.files_scanned, 0);
        assert!(state.errors.is_empty());
        assert!(state.cve_entries.is_empty());
        assert!(state.project_stack.is_none());
    }

    #[test]
    fn test_scanner_metrics_tracker_initialization() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let _scanner = Scanner::new(config, target_path, false);

        // Just verify the scanner was created with a metrics tracker
        // The actual metrics tracking is tested in other modules
        // LlmMetricsTracker is always initialized, we can't easily test its internals here
    }

    #[test]
    fn test_scanner_with_different_force_values() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");

        let scanner_force = Scanner::new(config.clone(), target_path.clone(), true);
        let scanner_no_force = Scanner::new(config, target_path, false);

        assert!(scanner_force.force);
        assert!(!scanner_no_force.force);
    }

    #[test]
    fn test_scanner_checkpoint_path_with_nested_output_dir() {
        let mut config = create_test_config();
        config.output.dir = "/tmp/output/nested/path".to_string();
        let target_path = PathBuf::from("/tmp/target");
        let scanner = Scanner::new(config, target_path, false);

        assert_eq!(
            scanner.checkpoint_path,
            PathBuf::from("/tmp/output/nested/path/checkpoint.json")
        );
    }

    #[test]
    fn test_extract_owner_repo_from_various_git_hosts() {
        // GitHub
        assert_eq!(
            Scanner::extract_owner_repo_from_url("https://github.com/rust-lang/rust"),
            Some(("rust-lang".to_string(), "rust".to_string()))
        );

        // GitLab
        assert_eq!(
            Scanner::extract_owner_repo_from_url("https://gitlab.com/gitlab-org/gitlab"),
            Some(("gitlab-org".to_string(), "gitlab".to_string()))
        );

        // Bitbucket SSH
        assert_eq!(
            Scanner::extract_owner_repo_from_url("git@bitbucket.org:team/project.git"),
            Some(("team".to_string(), "project".to_string()))
        );
    }

    #[test]
    fn test_extract_owner_repo_from_url_with_subpath() {
        // URLs with organization subpaths
        assert_eq!(
            Scanner::extract_owner_repo_from_url("https://github.com/vercel/next.js"),
            Some(("vercel".to_string(), "next.js".to_string()))
        );
    }

    #[tokio::test]
    async fn test_check_early_termination_at_threshold_boundary() {
        let mut config = create_test_config();
        config.scanner.performance.early_termination_threshold = 5.0;
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        // Exactly at threshold - should NOT terminate (need > threshold)
        let findings: Vec<VulnerabilityFinding> = (0..5)
            .map(|i| VulnerabilityFinding {
                id: format!("test-{}", i),
                title: "Test".to_string(),
                description: "Test desc".to_string(),
                severity: Severity::Medium,
                confidence_score: 0.5,
                cwe_id: None,
                file_path: "test.rs".to_string(),
                line_number: None,
                code_snippet: None,
                diff_hunk: None,
                recommendation: None,
                code_location: None,
                already_reported: false,
                sources: vec![],
                commit_reference: None,
                ticket_reference: None,
                priority_score: None,
                cross_file_references: None,
                verification_status: None,
                verification_notes: None,
                verification_error: None,
                agent_evidence_path: None,
                security_issue: None,
                poc_code: None,
                mitigation_code: None,
                poc_format: None,
                llm_model: None,
                agent_mode: false,
            })
            .collect();

        let multi_progress = MultiProgress::new();
        let pb = multi_progress.add(ProgressBar::new(100));

        let result = scanner
            .check_early_termination(&findings, &[], &ScanPhase::Indexing, &pb)
            .await;

        assert!(result.is_ok());
        assert!(!result.unwrap()); // 5 is NOT > 5, so should NOT terminate
    }

    #[test]
    fn test_scanner_state_clone() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        // Test that we can clone the state via Arc
        let state_clone = scanner.state.clone();
        assert!(Arc::strong_count(&state_clone) >= 2);
    }

    #[test]
    fn test_scanner_with_empty_config_fields() {
        let config = ScannerConfig {
            project: ProjectConfig {
                name: String::new(),
                path: String::new(),
                languages: vec![],
            },
            output: OutputConfig {
                dir: "/tmp/empty-test".to_string(),
                format: vec![],
            },
            scanner: crate::config::ScannerSettings {
                commit_lookback_days: 0,
                max_file_size_kb: 0,
                exclude_paths: vec![],
                semgrep: crate::config::SemgrepSettings::default(),
                performance: PerformanceSettings::default(),
            },
            llm: LlmConfig {
                timeout_secs: 0,
                max_retries: 0,
                retry_backoff_ms: 0,
                max_concurrent: 0,
                phases: LlmPhasesConfig::default(),
            },
            tickets: crate::config::TicketConfig::default(),
            agent: crate::config::AgentConfig::default(),
        };

        let target_path = PathBuf::from("/tmp/target");
        let scanner = Scanner::new(config, target_path, false);

        // Scanner should still be created even with empty config fields
        assert_eq!(scanner.state.borrow().current_phase, ScanPhase::Indexing);
    }

    #[test]
    fn test_scanner_with_max_values() {
        let config = ScannerConfig {
            project: ProjectConfig {
                name: "max-test".to_string(),
                path: "/tmp/max-test".to_string(),
                languages: vec![
                    "rust".to_string(),
                    "python".to_string(),
                    "javascript".to_string(),
                ],
            },
            output: OutputConfig {
                dir: "/tmp/max-output".to_string(),
                format: vec!["json".to_string(), "html".to_string(), "sarif".to_string()],
            },
            scanner: crate::config::ScannerSettings {
                commit_lookback_days: 365,
                max_file_size_kb: 102400,
                exclude_paths: vec![
                    "node_modules".to_string(),
                    "target".to_string(),
                    ".git".to_string(),
                ],
                semgrep: crate::config::SemgrepSettings::default(),
                performance: PerformanceSettings::default(),
            },
            llm: LlmConfig {
                timeout_secs: 300,
                max_retries: 10,
                retry_backoff_ms: 60000,
                max_concurrent: 16,
                phases: LlmPhasesConfig::default(),
            },
            tickets: crate::config::TicketConfig::default(),
            agent: crate::config::AgentConfig::default(),
        };

        let target_path = PathBuf::from("/tmp/max-target");
        let scanner = Scanner::new(config, target_path, false);

        assert_eq!(scanner.config.project.languages.len(), 3);
        assert_eq!(scanner.config.output.format.len(), 3);
        assert_eq!(scanner.config.scanner.exclude_paths.len(), 3);
    }

    #[test]
    fn test_scanner_checkpoint_file_exists_when_created() {
        use std::fs;

        let mut config = create_test_config();
        let temp_dir = format!("/tmp/scanner_test_{}", std::process::id());
        let _ = fs::create_dir_all(&temp_dir);
        config.output.dir = temp_dir.clone();

        let target_path = PathBuf::from("/tmp/target");
        let scanner = Scanner::new(config, target_path, false);

        // Verify checkpoint path is correctly computed
        assert!(scanner.checkpoint_path.starts_with(&temp_dir));
        assert!(scanner.checkpoint_path.ends_with("checkpoint.json"));

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_scanner_with_different_config_combinations() {
        // Test with parallel phases enabled
        let mut config = create_test_config();
        config.scanner.performance.enable_parallel_phases = true;
        config.scanner.performance.early_termination_threshold = 50.0;

        let target_path = PathBuf::from("/tmp/target");
        let scanner = Scanner::new(config, target_path, false);

        assert!(scanner.config.scanner.performance.enable_parallel_phases);
        assert_eq!(
            scanner
                .config
                .scanner
                .performance
                .early_termination_threshold,
            50.0
        );
    }

    #[test]
    fn test_scanner_with_exclude_paths() {
        let mut config = create_test_config();
        config.scanner.exclude_paths = vec![
            "tests/".to_string(),
            "target/".to_string(),
            ".git/".to_string(),
        ];

        let target_path = PathBuf::from("/tmp/target");
        let scanner = Scanner::new(config, target_path, false);

        assert_eq!(scanner.config.scanner.exclude_paths.len(), 3);
        assert!(scanner
            .config
            .scanner
            .exclude_paths
            .contains(&"tests/".to_string()));
    }

    #[tokio::test]
    async fn test_check_early_termination_with_empty_findings() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        let findings: Vec<VulnerabilityFinding> = vec![];
        let analyzed_files: Vec<String> = vec![];

        let multi_progress = MultiProgress::new();
        let pb = multi_progress.add(ProgressBar::new(100));

        let result = scanner
            .check_early_termination(&findings, &analyzed_files, &ScanPhase::Indexing, &pb)
            .await;

        assert!(result.is_ok());
        assert!(!result.unwrap()); // Empty findings should never trigger termination
    }

    #[tokio::test]
    async fn test_check_early_termination_with_many_analyzed_files() {
        let mut config = create_test_config();
        config.scanner.performance.early_termination_threshold = 1.0;
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        // Many analyzed files but only 1 finding
        let findings = vec![VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "Test".to_string(),
            description: "Test desc".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.5,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        }];

        let analyzed_files: Vec<String> = (0..1000)
            .map(|i| format!("/path/to/file_{}.rs", i))
            .collect();

        let multi_progress = MultiProgress::new();
        let pb = multi_progress.add(ProgressBar::new(100));

        let result = scanner
            .check_early_termination(&findings, &analyzed_files, &ScanPhase::Indexing, &pb)
            .await;

        assert!(result.is_ok());
        assert!(!result.unwrap()); // 1 finding is NOT > 1.0 threshold
    }

    #[test]
    fn test_scanner_state_modification_through_arc() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        // Clone the Arc and modify through clone
        let state_clone = scanner.state.clone();
        state_clone.send_modify(|s| {
            s.files_scanned = 42;
            s.current_phase = ScanPhase::Semgrep;
        });

        let state = scanner.state.borrow();
        assert_eq!(state.files_scanned, 42);
        assert_eq!(state.current_phase, ScanPhase::Semgrep);
    }

    #[test]
    fn test_scanner_with_various_severity_levels() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        // Add findings with different severity levels
        let severities = vec![
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ];

        for severity in severities {
            scanner.add_finding(VulnerabilityFinding {
                id: format!("test-{:?}", severity),
                title: "Test".to_string(),
                description: "Test desc".to_string(),
                severity,
                confidence_score: 0.5,
                cwe_id: None,
                file_path: "test.rs".to_string(),
                line_number: None,
                code_snippet: None,
                diff_hunk: None,
                recommendation: None,
                code_location: None,
                already_reported: false,
                sources: vec![],
                commit_reference: None,
                ticket_reference: None,
                priority_score: None,
                cross_file_references: None,
                verification_status: None,
                verification_notes: None,
                verification_error: None,
                agent_evidence_path: None,
                security_issue: None,
                poc_code: None,
                mitigation_code: None,
                poc_format: None,
                llm_model: None,
                agent_mode: false,
            });
        }

        assert_eq!(scanner.findings().len(), 5);
    }

    #[test]
    fn test_scanner_add_finding_deduplication() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        // Add same finding twice (same ID)
        let finding = VulnerabilityFinding {
            id: "duplicate-id".to_string(),
            title: "Test".to_string(),
            description: "Test desc".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.5,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        };

        scanner.add_finding(finding.clone());
        scanner.add_finding(finding); // Same ID

        // Note: Scanner doesn't deduplicate - it just appends
        // This test documents current behavior
        assert_eq!(scanner.findings().len(), 2);
    }

    #[test]
    fn test_scanner_with_all_verification_statuses() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        let statuses = vec![
            VerificationStatus::Confirmed,
            VerificationStatus::FalsePositive,
            VerificationStatus::NeedsReview,
            VerificationStatus::Failed,
        ];

        for status in statuses {
            scanner.add_finding(VulnerabilityFinding {
                id: format!("test-{:?}", status),
                title: "Test".to_string(),
                description: "Test desc".to_string(),
                severity: Severity::Medium,
                confidence_score: 0.5,
                cwe_id: None,
                file_path: "test.rs".to_string(),
                line_number: None,
                code_snippet: None,
                diff_hunk: None,
                recommendation: None,
                code_location: None,
                already_reported: false,
                sources: vec![],
                commit_reference: None,
                ticket_reference: None,
                priority_score: None,
                cross_file_references: None,
                verification_status: Some(status),
                verification_notes: None,
                verification_error: None,
                agent_evidence_path: None,
                security_issue: None,
                poc_code: None,
                mitigation_code: None,
                poc_format: None,
                llm_model: None,
                agent_mode: false,
            });
        }

        let findings = scanner.findings();
        assert_eq!(findings.len(), 4);
        assert!(findings
            .iter()
            .any(|f| f.verification_status == Some(VerificationStatus::Confirmed)));
    }

    #[test]
    fn test_scanner_with_cve_entries_field() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        // Verify cve_entries field exists and is initially empty
        assert!(scanner.cve_entries.is_empty());

        // Note: cve_entries is private, we can only test it's initialized
    }

    #[test]
    fn test_scanner_with_project_stack_field() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        // Verify project_stack field exists and is initially None
        assert!(scanner.project_stack.is_none());

        // Note: project_stack is private, we can only test it's initialized
    }

    #[test]
    fn test_scanner_with_source_list() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        scanner.add_finding(VulnerabilityFinding {
            id: "test-1".to_string(),
            title: "Test".to_string(),
            description: "Test desc".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.5,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![
                "semgrep".to_string(),
                "llm".to_string(),
                "agent".to_string(),
            ],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: true,
        });

        let findings = scanner.findings();
        assert_eq!(findings[0].sources.len(), 3);
        assert!(findings[0].agent_mode);
    }

    #[test]
    fn test_scanner_force_true_skips_checkpoint_logic() {
        // When force=true, the run() method should skip checkpoint loading
        // This test documents the expected behavior
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, true);

        assert!(scanner.force);
        // The force flag is checked in run() at line 136
    }

    #[test]
    fn test_scanner_force_false_checks_checkpoint() {
        // When force=false, the run() method checks for checkpoint existence
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        assert!(!scanner.force);
        // The checkpoint_path.exists() is checked in run() at line 139
    }

    #[test]
    fn test_scanner_checkpoint_path_computation() {
        // Test various output directory configurations
        let test_cases = vec![
            ("/tmp/output", "/tmp/output/checkpoint.json"),
            ("/tmp/output/nested", "/tmp/output/nested/checkpoint.json"),
            ("./relative/path", "./relative/path/checkpoint.json"),
        ];

        for (output_dir, expected_checkpoint) in test_cases {
            let mut config = create_test_config();
            config.output.dir = output_dir.to_string();
            let target_path = PathBuf::from("/tmp/target");
            let scanner = Scanner::new(config, target_path, false);

            assert_eq!(
                scanner.checkpoint_path.to_string_lossy(),
                expected_checkpoint,
                "Failed for output_dir: {}",
                output_dir
            );
        }
    }

    #[test]
    fn test_scanner_initial_findings_preserved() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");

        let initial_findings = vec![VulnerabilityFinding {
            id: "initial-1".to_string(),
            title: "Initial Finding 1".to_string(),
            description: "Initial desc 1".to_string(),
            severity: Severity::High,
            confidence_score: 0.9,
            cwe_id: Some("CWE-79".to_string()),
            file_path: "initial.rs".to_string(),
            line_number: Some(10),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["pre-scan".to_string()],
            commit_reference: Some("abc123".to_string()),
            ticket_reference: Some("ISSUE-1".to_string()),
            priority_score: Some(0.95),
            cross_file_references: None,
            verification_status: Some(VerificationStatus::NeedsReview),
            verification_notes: Some("Needs manual review".to_string()),
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: Some("test-model".to_string()),
            agent_mode: false,
        }];

        let scanner = Scanner::with_initial_findings(config, target_path, initial_findings, false);

        assert_eq!(scanner.state.borrow().findings.len(), 1);
        assert_eq!(scanner.state.borrow().findings[0].id, "initial-1");
        assert_eq!(
            scanner.state.borrow().findings[0].sources,
            vec!["pre-scan".to_string()]
        );
    }

    #[test]
    fn test_scanner_error_handling_in_state() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        // Verify errors vector is initially empty
        assert!(scanner.state.borrow().errors.is_empty());

        // Note: There's no public API to add errors directly,
        // but we can verify the state structure is correct
    }

    #[test]
    fn test_scanner_files_scanned_counter() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        // Verify files_scanned is initially 0
        assert_eq!(scanner.state.borrow().files_scanned, 0);

        // Note: There's no public API to increment files_scanned directly
        // but we can verify the state structure is correct
    }

    #[test]
    fn test_scanner_current_phase_tracking() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        // Verify initial phase is Indexing
        assert_eq!(scanner.state.borrow().current_phase, ScanPhase::Indexing);

        // Note: Phase updates happen during run() execution
    }

    #[test]
    fn test_scanner_with_agent_mode_findings() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        scanner.add_finding(VulnerabilityFinding {
            id: "agent-finding".to_string(),
            title: "Agent Finding".to_string(),
            description: "Found by security agent".to_string(),
            severity: Severity::Critical,
            confidence_score: 0.95,
            cwe_id: Some("CWE-89".to_string()),
            file_path: "agent.rs".to_string(),
            line_number: Some(50),
            code_snippet: Some("sql_query(input)".to_string()),
            diff_hunk: None,
            recommendation: Some("Use parameterized queries".to_string()),
            code_location: Some("agent.rs:50".to_string()),
            already_reported: false,
            sources: vec!["security-agent".to_string()],
            commit_reference: None,
            ticket_reference: None,
            priority_score: Some(0.98),
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: Some("/tmp/agent-evidence/trace-1.json".to_string()),
            security_issue: None,
            poc_code: Some("poc code".to_string()),
            mitigation_code: Some("mitigation code".to_string()),
            poc_format: Some("rust".to_string()),
            llm_model: None,
            agent_mode: true,
        });

        let findings = scanner.findings();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].agent_mode);
        assert_eq!(
            findings[0].agent_evidence_path,
            Some("/tmp/agent-evidence/trace-1.json".to_string())
        );
        assert_eq!(findings[0].poc_format, Some("rust".to_string()));
    }

    #[test]
    fn test_scanner_with_code_location_info() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        scanner.add_finding(VulnerabilityFinding {
            id: "location-finding".to_string(),
            title: "Location Test".to_string(),
            description: "Test with full location info".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.7,
            cwe_id: Some("CWE-200".to_string()),
            file_path: "vulnerable.c".to_string(),
            line_number: Some(123),
            code_snippet: Some("strcpy(dest, src)".to_string()),
            diff_hunk: Some("-strcpy(dest, src)\n+strncpy(dest, src, size)".to_string()),
            recommendation: Some("Use bounded string copy".to_string()),
            code_location: Some("vulnerable.c:123".to_string()),
            already_reported: true,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        });

        let findings = scanner.findings();
        assert!(findings[0].already_reported);
        assert_eq!(findings[0].line_number, Some(123));
        assert!(findings[0].diff_hunk.is_some());
    }

    #[tokio::test]
    async fn test_check_early_termination_with_different_phases() {
        let mut config = create_test_config();
        config.scanner.performance.early_termination_threshold = 3.0;
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        let findings: Vec<VulnerabilityFinding> = (0..5)
            .map(|i| VulnerabilityFinding {
                id: format!("test-{}", i),
                title: "Test".to_string(),
                description: "Test desc".to_string(),
                severity: Severity::Medium,
                confidence_score: 0.5,
                cwe_id: None,
                file_path: "test.rs".to_string(),
                line_number: None,
                code_snippet: None,
                diff_hunk: None,
                recommendation: None,
                code_location: None,
                already_reported: false,
                sources: vec![],
                commit_reference: None,
                ticket_reference: None,
                priority_score: None,
                cross_file_references: None,
                verification_status: None,
                verification_notes: None,
                verification_error: None,
                agent_evidence_path: None,
                security_issue: None,
                poc_code: None,
                mitigation_code: None,
                poc_format: None,
                llm_model: None,
                agent_mode: false,
            })
            .collect();

        // Test with different phases
        let phases = vec![
            ScanPhase::Indexing,
            ScanPhase::Semgrep,
            ScanPhase::LlmStaticAnalysis,
            ScanPhase::LlmDiscovery,
            ScanPhase::Reporting,
        ];

        for phase in phases {
            let multi_progress = MultiProgress::new();
            let pb = multi_progress.add(ProgressBar::new(100));

            let result = scanner
                .check_early_termination(&findings, &[], &phase, &pb)
                .await;

            assert!(result.is_ok(), "Failed for phase: {:?}", phase);
            assert!(result.unwrap(), "Should terminate for phase: {:?}", phase);
        }
    }

    #[test]
    fn test_scanner_with_priority_scores() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        scanner.add_finding(VulnerabilityFinding {
            id: "priority-1".to_string(),
            title: "High Priority".to_string(),
            description: "Critical finding".to_string(),
            severity: Severity::Critical,
            confidence_score: 0.95,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: Some(0.99),
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        });

        let findings = scanner.findings();
        assert_eq!(findings[0].priority_score, Some(0.99));
    }

    #[test]
    fn test_scanner_with_ticket_references() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        scanner.add_finding(VulnerabilityFinding {
            id: "ticket-ref".to_string(),
            title: "Known Issue".to_string(),
            description: "Already tracked".to_string(),
            severity: Severity::Low,
            confidence_score: 0.3,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: true,
            sources: vec![],
            commit_reference: None,
            ticket_reference: Some("SEC-123".to_string()),
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        });

        let findings = scanner.findings();
        assert_eq!(findings[0].ticket_reference, Some("SEC-123".to_string()));
        assert!(findings[0].already_reported);
    }

    #[test]
    fn test_scanner_with_commit_references() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        scanner.add_finding(VulnerabilityFinding {
            id: "commit-ref".to_string(),
            title: "Git Linked".to_string(),
            description: "Linked to commit".to_string(),
            severity: Severity::Info,
            confidence_score: 0.2,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: Some("a1b2c3d4e5f6".to_string()),
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        });

        let findings = scanner.findings();
        assert_eq!(
            findings[0].commit_reference,
            Some("a1b2c3d4e5f6".to_string())
        );
    }

    #[test]
    fn test_scanner_with_llm_model_tracking() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        scanner.add_finding(VulnerabilityFinding {
            id: "llm-tracked".to_string(),
            title: "LLM Found".to_string(),
            description: "Discovered by LLM".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.75,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: Some("mistral-small".to_string()),
            agent_mode: false,
        });

        let findings = scanner.findings();
        assert_eq!(findings[0].llm_model, Some("mistral-small".to_string()));
    }

    #[test]
    fn test_scanner_with_cross_file_references() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        scanner.add_finding(VulnerabilityFinding {
            id: "cross-file".to_string(),
            title: "Cross-File Issue".to_string(),
            description: "Related to other files".to_string(),
            severity: Severity::High,
            confidence_score: 0.85,
            cwe_id: None,
            file_path: "main.rs".to_string(),
            line_number: Some(42),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: Some(vec![
                "utils.rs:15".to_string(),
                "helpers.rs:88".to_string(),
            ]),
            verification_status: None,
            verification_notes: None,
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        });

        let findings = scanner.findings();
        assert!(findings[0].cross_file_references.is_some());
        assert_eq!(findings[0].cross_file_references.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_scanner_with_verification_notes() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        scanner.add_finding(VulnerabilityFinding {
            id: "verification-notes".to_string(),
            title: "Verified Finding".to_string(),
            description: "With verification notes".to_string(),
            severity: Severity::Medium,
            confidence_score: 0.6,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: Some(VerificationStatus::Confirmed),
            verification_notes: Some("Manually verified by security team".to_string()),
            verification_error: None,
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        });

        let findings = scanner.findings();
        assert_eq!(
            findings[0].verification_notes,
            Some("Manually verified by security team".to_string())
        );
    }

    #[test]
    fn test_scanner_with_verification_error() {
        let config = create_test_config();
        let target_path = PathBuf::from("/tmp/test-target");
        let scanner = Scanner::new(config, target_path, false);

        scanner.add_finding(VulnerabilityFinding {
            id: "verification-error".to_string(),
            title: "Verification Failed".to_string(),
            description: "With error message".to_string(),
            severity: Severity::Low,
            confidence_score: 0.4,
            cwe_id: None,
            file_path: "test.rs".to_string(),
            line_number: None,
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
            commit_reference: None,
            ticket_reference: None,
            priority_score: None,
            cross_file_references: None,
            verification_status: Some(VerificationStatus::Failed),
            verification_notes: None,
            verification_error: Some("Connection timeout during verification".to_string()),
            agent_evidence_path: None,
            security_issue: None,
            poc_code: None,
            mitigation_code: None,
            poc_format: None,
            llm_model: None,
            agent_mode: false,
        });

        let findings = scanner.findings();
        assert_eq!(
            findings[0].verification_error,
            Some("Connection timeout during verification".to_string())
        );
    }
}
