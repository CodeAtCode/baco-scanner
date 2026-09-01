//! Scanner orchestration - main run() method with parallel/sequential phase execution

use crate::checkpoint::ScanPhase;
use crate::findings::VulnerabilityFinding;
use crate::scanner::checkpoint::{load_checkpoint_findings, save_checkpoint};
use crate::scanner::helpers::log_and_aggregate_llm_results;

use indicatif::{ProgressBar, ProgressStyle};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::Semaphore;

use std::time::Instant;

/// Structural deduplication: group findings by (file, cwe_id), cluster by
/// line proximity (consecutive lines within ±2 chain into one cluster),
/// keep highest-sources/highest-confidence, merge sources.
pub fn structural_dedup(findings: &mut Vec<VulnerabilityFinding>) -> usize {
    let before = findings.len();

    #[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
    struct GroupKey {
        file_path: String,
        cwe_id: Option<String>,
    }

    // BTreeMap for deterministic grouping; original order is restored on rebuild
    let mut groups: BTreeMap<GroupKey, Vec<usize>> = BTreeMap::new();

    for (i, finding) in findings.iter().enumerate() {
        let key = GroupKey {
            file_path: finding.file_path.clone(),
            cwe_id: finding.cwe_id.clone(),
        };
        groups.entry(key).or_default().push(i);
    }

    // Fixed-width line buckets cannot honor a ±2 tolerance (boundary pairs
    // split), so clusters grow while consecutive lines stay within ±2
    let mut clusters: Vec<Vec<usize>> = Vec::new();
    for (_, mut indices) in groups {
        indices.sort_by_key(|&i| findings[i].line_number.unwrap_or(0));
        let mut current: Vec<usize> = Vec::new();
        let mut prev_line: Option<u32> = None;
        for idx in indices {
            let line = findings[idx].line_number.unwrap_or(0);
            let starts_new_cluster = prev_line.is_some_and(|p| line.saturating_sub(p) > 2);
            if starts_new_cluster {
                clusters.push(std::mem::take(&mut current));
            }
            current.push(idx);
            prev_line = Some(line);
        }
        if !current.is_empty() {
            clusters.push(current);
        }
    }

    // Process each cluster
    let mut kept_indices = std::collections::HashSet::new();
    let mut merged_count = 0;

    for indices in clusters {
        if indices.len() == 1 {
            // Single finding in cluster - keep it
            kept_indices.insert(indices[0]);
            continue;
        }

        // Multiple findings - keep the one with most sources, or highest confidence on tie
        let mut best_idx = indices[0];
        let mut best_sources = findings[best_idx].sources.len();
        let mut best_confidence = findings[best_idx].confidence_score;

        for &idx in indices.iter().skip(1) {
            let num_sources = findings[idx].sources.len();
            let confidence = findings[idx].confidence_score;

            if num_sources > best_sources
                || (num_sources == best_sources && confidence > best_confidence)
            {
                best_idx = idx;
                best_sources = num_sources;
                best_confidence = confidence;
            }
        }

        // Merge sources from all other findings into the best one
        // First, collect all unique sources to avoid borrow issues
        let mut all_sources: Vec<String> = Vec::new();
        for &idx in &indices {
            for source in &findings[idx].sources {
                if !all_sources.contains(source) {
                    all_sources.push(source.clone());
                }
            }
        }
        findings[best_idx].sources = all_sources;
        merged_count += indices.len() - 1;

        kept_indices.insert(best_idx);
    }

    // Rebuild findings vector with only kept findings (preserving original order)
    let mut new_findings = Vec::with_capacity(kept_indices.len());
    for (i, finding) in findings.drain(..).enumerate() {
        if kept_indices.contains(&i) {
            new_findings.push(finding);
        }
    }
    *findings = new_findings;

    let after = findings.len();
    tracing::info!(
        "Structural dedup: {} findings -> {} ({} merged)",
        before,
        after,
        merged_count
    );

    merged_count
}

/// Execute parallel phases (Indexing, Semgrep, LlmStaticAnalysis)
async fn run_parallel_phases(
    scanner: &super::Scanner,
    pb: &ProgressBar,
    mut findings: Vec<VulnerabilityFinding>,
    mut analyzed_files: Vec<String>,
    completed_phases: &[ScanPhase],
) -> Result<(Vec<VulnerabilityFinding>, Vec<String>), String> {
    let is_phase_completed = |phase: &ScanPhase| completed_phases.contains(phase);

    // Create semaphore for parallel task limiting
    let max_parallel = scanner.config.scanner.performance.max_parallel_tasks;
    let semaphore = Arc::new(Semaphore::new(max_parallel));

    tracing::info!(
        "\u{1B}[34m[SCANNER]\u{1B}[0m Starting parallel phases: Indexing, Semgrep, LLM Static Analysis..."
    );

    pb.set_draw_target(indicatif::ProgressDrawTarget::stderr());
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb.set_message("Running parallel phases (Indexing, Semgrep, LLM Static)...");

    tracing::info!(
        "\u{1B}[34m[SCANNER]\u{1B}[0m Spawning parallel tasks with {} findings",
        findings.len()
    );

    let indexing_handle = if !is_phase_completed(&ScanPhase::Indexing) {
        let this = scanner;
        let pb = pb.clone();
        let initial_findings = findings.clone();
        let sem_perm = semaphore.clone();
        Some(async move {
            let _permit = sem_perm.acquire().await;
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
        let initial_findings = findings.clone();
        let sem_perm = semaphore.clone();
        Some(async move {
            let _permit = sem_perm.acquire().await;
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
            let initial_findings = findings.clone();
            let analyzed_files_clone = analyzed_files.clone();
            let sem_perm = semaphore.clone();
            Some(async move {
                let _permit = sem_perm.acquire().await;
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

    let cpg_slice_handle = if !is_phase_completed(&ScanPhase::CpgSlice) {
        let this = scanner;
        let pb = pb.clone();
        let initial_findings = findings.clone();
        let sem_perm = semaphore.clone();
        Some(async move {
            let _permit = sem_perm.acquire().await;
            this.run_phase(&ScanPhase::CpgSlice, initial_findings, &pb, &[])
                .await
        })
    } else {
        tracing::info!("Skipping CpgSlice phase (already completed in previous run)");
        None
    };

    let start_time = Instant::now();

    // Execute all spawned tasks in true parallel using tokio::join! with 4-tuple match
    let (indexing_result, semgrep_result, llm_static_result, cpg_slice_result) = match (
        indexing_handle,
        semgrep_handle,
        llm_static_handle,
        cpg_slice_handle,
    ) {
        (Some(i), Some(s), Some(l), Some(c)) => {
            let (ir, sr, lr, cr) = tokio::join!(i, s, l, c);
            (Some(ir), Some(sr), Some(lr), Some(cr))
        }
        (Some(i), Some(s), Some(l), None) => {
            let (ir, sr, lr) = tokio::join!(i, s, l);
            (Some(ir), Some(sr), Some(lr), None)
        }
        (Some(i), Some(s), None, Some(c)) => {
            let (ir, sr, cr) = tokio::join!(i, s, c);
            (Some(ir), Some(sr), None, Some(cr))
        }
        (Some(i), Some(s), None, None) => {
            let (ir, sr) = tokio::join!(i, s);
            (Some(ir), Some(sr), None, None)
        }
        (Some(i), None, Some(l), Some(c)) => {
            let (ir, lr, cr) = tokio::join!(i, l, c);
            (Some(ir), None, Some(lr), Some(cr))
        }
        (Some(i), None, Some(l), None) => {
            let (ir, lr) = tokio::join!(i, l);
            (Some(ir), None, Some(lr), None)
        }
        (Some(i), None, None, Some(c)) => {
            let (ir, cr) = tokio::join!(i, c);
            (Some(ir), None, None, Some(cr))
        }
        (Some(i), None, None, None) => {
            let ir = i.await;
            (Some(ir), None, None, None)
        }
        (None, Some(s), Some(l), Some(c)) => {
            let (sr, lr, cr) = tokio::join!(s, l, c);
            (None, Some(sr), Some(lr), Some(cr))
        }
        (None, Some(s), Some(l), None) => {
            let (sr, lr) = tokio::join!(s, l);
            (None, Some(sr), Some(lr), None)
        }
        (None, Some(s), None, Some(c)) => {
            let (sr, cr) = tokio::join!(s, c);
            (None, Some(sr), None, Some(cr))
        }
        (None, Some(s), None, None) => {
            let sr = s.await;
            (None, Some(sr), None, None)
        }
        (None, None, Some(l), Some(c)) => {
            let (lr, cr) = tokio::join!(l, c);
            (None, None, Some(lr), Some(cr))
        }
        (None, None, Some(l), None) => {
            let lr = l.await;
            (None, None, Some(lr), None)
        }
        (None, None, None, Some(c)) => {
            let cr = c.await;
            (None, None, None, Some(cr))
        }
        (None, None, None, None) => (None, None, None, None),
    };

    let parallel_duration = start_time.elapsed();
    tracing::info!("Parallel phases completed in {:?}", parallel_duration);

    if let Some(Ok((mut index_findings, _, _))) = indexing_result {
        findings.append(&mut index_findings);
    }
    if let Some(Ok((mut semgrep_findings, _, _))) = semgrep_result {
        findings.append(&mut semgrep_findings);
    }
    if let Some(Ok((mut cpg_findings, _, _))) = cpg_slice_result {
        findings.append(&mut cpg_findings);
    }
    log_and_aggregate_llm_results(&llm_static_result, &mut findings, &mut analyzed_files);

    tracing::info!("After parallel phases: {} findings total", findings.len());

    // Apply structural deduplication before sequential phases
    structural_dedup(&mut findings);

    scanner.state.send_modify(|s| {
        s.current_phase = ScanPhase::CpgSlice;
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
    pb.set_draw_target(indicatif::ProgressDrawTarget::stderr());
    pb.set_message("Parallel phases complete, running sequential phases...");
    pb.set_position(300);

    Ok((findings, analyzed_files))
}

/// Return the list of sequential scan phases
fn sequential_phases() -> [ScanPhase; 20] {
    [
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
        // v3 features
        ScanPhase::ThreatModeling,
        ScanPhase::RootCauseDedup,
        ScanPhase::MultiVerifier,
        ScanPhase::AutoPatching,
        ScanPhase::CveBootstrap,
        ScanPhase::PocCompiler,
        ScanPhase::ExploitSynth,
        ScanPhase::VariantSearch,
        ScanPhase::Reporting,
    ]
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
    let sequential_phases = sequential_phases();

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
            ScanPhase::CweRouting => format!(
                "Phase {}/{}: CWE routing (routing findings to specialized models)...",
                phase_num,
                sequential_phases.len() + 3
            ),
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

        let (new_findings, new_analyzed_files, rejected_findings) = scanner
            .run_phase(phase, findings, pb, &analyzed_files)
            .await?;

        // Store rejected findings for later use in reporting
        if !rejected_findings.is_empty() {
            scanner.state.send_modify(|s| {
                s.rejected_findings = rejected_findings;
            });
        }

        (findings, analyzed_files) = (new_findings, new_analyzed_files);
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
    let (mut findings, completed_phases, mut analyzed_files) = if !scanner.force
        && scanner.checkpoint_path.exists()
    {
        use crate::checkpoint::Checkpoint;
        match Checkpoint::load(&scanner.checkpoint_path.to_string_lossy()) {
            Ok(cp) => {
                if cp.completed_phases.contains(&ScanPhase::Reporting) {
                    eprintln!(
                        "\u{1B}[32m[SCANNER] Scan already complete: {} phases finished, {} findings loaded.\n         Use --force to start a fresh scan.\u{1B}[0m",
                        cp.completed_phases.len(),
                        cp.findings_so_far.len()
                    );
                    return Ok(cp.findings_so_far);
                }

                let resume_phase =
                    Checkpoint::resume_from(&scanner.checkpoint_path.to_string_lossy())
                        .unwrap_or(ScanPhase::Indexing);
                let phase_idx = crate::scanner::pipeline::orchestrator::phase_index(&resume_phase);
                let total = crate::scanner::pipeline::orchestrator::total_phases();

                eprintln!(
                    "\u{1B}[33m[SCANNER] Resuming scan from phase {:?} ({}/{}) - {} phases already completed, {} findings loaded.\n         Use --force to start a fresh scan.\u{1B}[0m",
                    resume_phase,
                    phase_idx,
                    total,
                    cp.completed_phases.len(),
                    cp.findings_so_far.len()
                );
                tracing::info!(
                    "Loaded checkpoint from phase {:?} with {} findings, {} analyzed files, completed phases: {:?}",
                    cp.current_phase,
                    cp.findings_so_far.len(),
                    cp.analyzed_files.len(),
                    cp.completed_phases
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
    let sequential_phase_count = 20; // 20 sequential phases including Validate
    let total_phases = 4 + sequential_phase_count; // 4 parallel + 20 sequential = 24

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
        // Parallelization not implemented - sequential mode active
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
