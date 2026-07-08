//! Scanner orchestration - main run() method with parallel/sequential phase execution

use crate::checkpoint::ScanPhase;
use crate::findings::VulnerabilityFinding;
use crate::scanner::checkpoint::{load_checkpoint_findings, save_checkpoint};

use indicatif::{ProgressBar, ProgressStyle};

use std::time::Instant;

/// Type alias for phase result
type PhaseResult = Result<(Vec<VulnerabilityFinding>, Vec<String>), String>;

/// Execute parallel phases (Indexing, Semgrep, LlmStaticAnalysis)
async fn run_parallel_phases(
    scanner: &super::Scanner,
    pb: &ProgressBar,
    mut findings: Vec<VulnerabilityFinding>,
    mut analyzed_files: Vec<String>,
    completed_phases: &[ScanPhase],
) -> Result<(Vec<VulnerabilityFinding>, Vec<String>), String> {
    let is_phase_completed = |phase: &ScanPhase| completed_phases.contains(phase);

    tracing::info!(
        "\u{1B}[34m[SCANNER]\u{1B}[0m Starting parallel phases: Indexing, Semgrep, LLM Static Analysis..."
    );

    pb.set_draw_target(indicatif::ProgressDrawTarget::stderr());
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb.set_message("Running parallel phases (Indexing, Semgrep, LLM Static)...");

    let findings_for_parallel = findings.clone();
    tracing::info!(
        "\u{1B}[34m[SCANNER]\u{1B}[0m Findings cloned: {} items",
        findings_for_parallel.len()
    );

    let indexing_handle = if !is_phase_completed(&ScanPhase::Indexing) {
        let this = scanner;
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
        let this = scanner;
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
        load_checkpoint_findings(&scanner.checkpoint_path, &ScanPhase::LlmStaticAnalysis).await
    } else {
        Vec::new()
    };

    let has_valid_findings = !checkpoint_findings.is_empty()
        && checkpoint_findings
            .iter()
            .any(|f| !f.description.is_empty());

    let llm_static_handle =
        if !is_phase_completed(&ScanPhase::LlmStaticAnalysis) || !has_valid_findings {
            if !is_phase_completed(&ScanPhase::LlmStaticAnalysis) {
                tracing::info!("[LLM] Running LLM Static Analysis phase");
            } else {
                tracing::warn!(
                "[LLM] Checkpoint has {} findings but all have empty descriptions - forcing re-run",
                checkpoint_findings.len()
            );
            }
            let this = scanner;
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

    scanner.state.send_modify(|s| {
        s.current_phase = ScanPhase::LlmStaticAnalysis;
        s.findings = findings.clone();
    });

    // Check for early termination after parallel phases
    let threshold = scanner
        .config
        .scanner
        .performance
        .early_termination_threshold;
    if threshold > 0.0 && findings.len() as f32 > threshold {
        tracing::warn!(
            "Early termination triggered after parallel phases: {} findings > threshold {}",
            findings.len(),
            threshold
        );
        if let Err(e) = save_checkpoint(
            &scanner.checkpoint_path,
            &scanner.config,
            &findings,
            &analyzed_files,
            &ScanPhase::LlmStaticAnalysis,
            &scanner.metrics_tracker,
        )
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
        return Ok((findings, analyzed_files));
    }

    if let Err(e) = save_checkpoint(
        &scanner.checkpoint_path,
        &scanner.config,
        &findings,
        &analyzed_files,
        &ScanPhase::LlmStaticAnalysis,
        &scanner.metrics_tracker,
    )
    .await
    {
        tracing::warn!("Failed to save checkpoint after parallel phases: {}", e);
    }

    // Re-enable progress bar and show completion
    pb.set_draw_target(indicatif::ProgressDrawTarget::stdout());
    pb.set_message("Parallel phases complete, running sequential phases...");
    pb.set_position(300);

    Ok((findings, analyzed_files))
}

/// Execute sequential phases
async fn run_sequential_phases(
    scanner: &super::Scanner,
    pb: &ProgressBar,
    mut findings: Vec<VulnerabilityFinding>,
    mut analyzed_files: Vec<String>,
    completed_phases: &[ScanPhase],
    start_position: u64,
) -> Result<(Vec<VulnerabilityFinding>, Vec<String>), String> {
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

    let is_phase_completed = |phase: &ScanPhase| completed_phases.contains(phase);

    for (i, phase) in sequential_phases.iter().enumerate() {
        let phase_num = 4 + i;
        pb.set_position(start_position + (i as u64) * 100);

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
                phase_num,
                sequential_phases.len() + 3
            ),
            ScanPhase::LlmVerification => format!(
                "Phase {}/{}: LLM verification (validating findings)...",
                phase_num,
                sequential_phases.len() + 3
            ),
            ScanPhase::SecurityAgentVerification => format!(
                "Phase {}/{}: SecurityAgent verification (tool-based validation)...",
                phase_num,
                sequential_phases.len() + 3
            ),
            ScanPhase::TicketCrossRef => format!(
                "Phase {}/{}: Searching ticket systems for references...",
                phase_num,
                sequential_phases.len() + 3
            ),
            ScanPhase::GitAnalysis => format!(
                "Phase {}/{}: Analyzing Git history for related commits...",
                phase_num,
                sequential_phases.len() + 3
            ),
            ScanPhase::CrossFileAnalysis => format!(
                "Phase {}/{}: Cross-file dependency analysis...",
                phase_num,
                sequential_phases.len() + 3
            ),
            ScanPhase::ConfidenceScoring => format!(
                "Phase {}/{}: Calculating confidence scores...",
                phase_num,
                sequential_phases.len() + 3
            ),
            ScanPhase::AiAggregation => format!(
                "Phase {}/{}: AI aggregation (generating executive summary)...",
                phase_num,
                sequential_phases.len() + 3
            ),
            ScanPhase::Reporting => format!(
                "Phase {}/{}: Generating reports (JSON/HTML/SARIF)...",
                phase_num,
                sequential_phases.len() + 3
            ),
            ScanPhase::ThreatModeling => format!(
                "Phase {}/{}: Threat modeling (STRIDE analysis)...",
                phase_num,
                sequential_phases.len() + 3
            ),
            ScanPhase::RootCauseDedup => format!(
                "Phase {}/{}: Root cause deduplication...",
                phase_num,
                sequential_phases.len() + 3
            ),
            ScanPhase::MultiVerifier => format!(
                "Phase {}/{}: Multi-verifier voting...",
                phase_num,
                sequential_phases.len() + 3
            ),
            ScanPhase::AutoPatching => format!(
                "Phase {}/{}: Auto-patching with staging validation...",
                phase_num,
                sequential_phases.len() + 3
            ),
            ScanPhase::CveBootstrap => {
                format!(
                    "Phase {}/{}: CVE bootstrap...",
                    phase_num,
                    sequential_phases.len() + 3
                )
            }
            ScanPhase::PocCompiler => format!(
                "Phase {}/{}: PoC compilation check...",
                phase_num,
                sequential_phases.len() + 3
            ),
            ScanPhase::VariantSearch => {
                format!(
                    "Phase {}/{}: Variant search...",
                    phase_num,
                    sequential_phases.len() + 3
                )
            }
            _ => format!(
                "Phase {}/{}: {:?}",
                phase_num,
                sequential_phases.len() + 3,
                phase
            ),
        };
        pb.set_message(phase_msg);

        let phase_start = Instant::now();

        (findings, analyzed_files) = scanner
            .run_phase(phase, findings, pb, &analyzed_files)
            .await?;
        let phase_duration = phase_start.elapsed();
        tracing::info!("Phase {:?} completed in {:?}", phase, phase_duration);

        scanner.state.send_modify(|s| {
            s.current_phase = phase.clone();
            s.findings = findings.clone();
        });

        // Check for early termination
        let threshold = scanner
            .config
            .scanner
            .performance
            .early_termination_threshold;
        if threshold > 0.0 && findings.len() as f32 > threshold {
            tracing::warn!(
                "Early termination triggered after phase {:?}: {} findings > threshold {}",
                phase,
                findings.len(),
                threshold
            );
            if let Err(e) = save_checkpoint(
                &scanner.checkpoint_path,
                &scanner.config,
                &findings,
                &analyzed_files,
                phase,
                &scanner.metrics_tracker,
            )
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
            return Ok((findings, analyzed_files));
        }

        if let Err(e) = save_checkpoint(
            &scanner.checkpoint_path,
            &scanner.config,
            &findings,
            &analyzed_files,
            phase,
            &scanner.metrics_tracker,
        )
        .await
        {
            tracing::warn!("Failed to save checkpoint after {:?}: {}", phase, e);
        }
    }

    Ok((findings, analyzed_files))
}

/// Main scanner orchestration - coordinates parallel and sequential phase execution
pub(super) async fn run_scanner(
    scanner: &super::Scanner,
) -> Result<Vec<VulnerabilityFinding>, String> {
    let (mut findings, completed_phases, mut analyzed_files) = if scanner.force {
        tracing::info!("Force flag set - starting fresh, ignoring checkpoint");
        (Vec::new(), Vec::new(), Vec::new())
    } else if scanner.checkpoint_path.exists() {
        use crate::checkpoint::Checkpoint;
        match Checkpoint::load(&scanner.checkpoint_path.to_string_lossy()) {
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

    let enable_parallel = true;
    let sequential_phase_count = 16; // Including v3 features
    let total_phases = 3 + sequential_phase_count;

    let pb = scanner
        .progress
        .add(ProgressBar::new(total_phases as u64 * 100));
    tracing::debug!("Total phases: {}", total_phases);

    let style = ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {msg}")
        .unwrap()
        .progress_chars("=>-");
    pb.set_style(style);
    pb.set_message("Initializing BACO security scan...");

    if enable_parallel {
        tracing::info!("\u{1B}[34m[SCANNER]\u{1B}[0m Parallel mode ENABLED");

        (findings, analyzed_files) =
            run_parallel_phases(scanner, &pb, findings, analyzed_files, &completed_phases).await?;
    } else {
        // Sequential execution for backward compatibility
        tracing::info!(
            "\u{1B}[34m[SCANNER]\u{1B}[0m Starting SERIAL phases (parallel disabled)..."
        );
        // TODO: Implement sequential parallel phases if needed
    }

    let start_position = if enable_parallel { 300 } else { 0 };
    let (findings, _analyzed_files) = run_sequential_phases(
        scanner,
        &pb,
        findings,
        analyzed_files,
        &completed_phases,
        start_position,
    )
    .await?;

    pb.set_message("Scan complete!");
    pb.finish();

    scanner.state.send_modify(|s| {
        s.current_phase = ScanPhase::Reporting;
        s.findings = findings.clone();
    });

    Ok(findings)
}
