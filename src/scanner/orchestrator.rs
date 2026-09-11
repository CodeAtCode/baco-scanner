//! Scanner orchestration - main run() method with parallel/sequential phase execution

use crate::checkpoint::ScanPhase;
use crate::config::ScanPipelineProfile;
use crate::findings::{Severity, VulnerabilityFinding};
use crate::scanner::checkpoint::EarlyTerminationInfo;
use crate::scanner::checkpoint::{load_checkpoint_findings, save_checkpoint};
use crate::scanner::helpers::log_and_aggregate_llm_results;

use futures::future::join_all;
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
    let profile = scanner.config.scanner.profile;

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

    // CpgSlice is experimental - skip it in core profile
    let cpg_slice_handle = if profile == ScanPipelineProfile::Core {
        tracing::info!("profile=core: skipping experimental phase CpgSlice");
        None
    } else if !is_phase_completed(&ScanPhase::CpgSlice) {
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

    // Execute all spawned tasks in true parallel using Vec-of-futures + join_all
    // Box the futures to get a common type
    type PhaseResult = Result<
        (
            Vec<VulnerabilityFinding>,
            Vec<String>,
            Vec<crate::scanner::phases::llm_phases::RejectedFinding>,
        ),
        String,
    >;
    let mut tasks: Vec<(ScanPhase, futures::future::LocalBoxFuture<'_, PhaseResult>)> = Vec::new();

    if let Some(fut) = indexing_handle {
        tasks.push((ScanPhase::Indexing, Box::pin(fut)));
    }
    if let Some(fut) = semgrep_handle {
        tasks.push((ScanPhase::Semgrep, Box::pin(fut)));
    }
    if let Some(fut) = llm_static_handle {
        tasks.push((ScanPhase::LlmStaticAnalysis, Box::pin(fut)));
    }
    if let Some(fut) = cpg_slice_handle {
        tasks.push((ScanPhase::CpgSlice, Box::pin(fut)));
    }

    // Run all tasks in parallel and collect results with their phase tags
    let results = join_all(
        tasks
            .into_iter()
            .map(|(phase, fut)| async move { (phase, fut.await) }),
    )
    .await;

    // Extract results per-phase for backward compatibility with existing logic
    // Results are already awaited by join_all, so we just extract and clone them
    let indexing_result = results
        .iter()
        .find(|(p, _)| *p == ScanPhase::Indexing)
        .map(|(_, r)| r.clone());

    let semgrep_result = results
        .iter()
        .find(|(p, _)| *p == ScanPhase::Semgrep)
        .map(|(_, r)| r.clone());

    let llm_static_result = results
        .iter()
        .find(|(p, _)| *p == ScanPhase::LlmStaticAnalysis)
        .map(|(_, r)| r.clone());

    let cpg_slice_result = results
        .iter()
        .find(|(p, _)| *p == ScanPhase::CpgSlice)
        .map(|(_, r)| r.clone());

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
    // Only count Medium-and-above findings (Critical, High, Medium) toward the threshold
    let medium_plus_count = findings
        .iter()
        .filter(|f| f.severity >= Severity::Medium)
        .count();
    let threshold = scanner
        .config
        .scanner
        .performance
        .early_termination_threshold;
    if threshold > 0.0 && medium_plus_count as f32 > threshold {
        let skipped_phases = vec![
            "RuleSynthesis",
            "LlmDiscovery",
            "LlmVerification",
            "Validate",
            "SecurityAgentVerification",
            "TicketCrossRef",
            "GitAnalysis",
            "CrossFileAnalysis",
            "ConfidenceScoring",
            "AiAggregation",
            "ThreatModeling",
            "RootCauseDedup",
            "MultiVerifier",
            "AutoPatching",
            "CveBootstrap",
            "PocCompiler",
            "ExploitSynth",
            "VariantSearch",
            "Reporting",
        ];
        tracing::warn!(
            "Early termination triggered after parallel phases: {} medium+ findings > threshold {} (total findings: {}), skipping phases: {:?}",
            medium_plus_count,
            threshold,
            findings.len(),
            skipped_phases
        );
        let et_info = EarlyTerminationInfo {
            triggered: true,
            finding_count: medium_plus_count,
            phases_skipped: skipped_phases.iter().map(|s| s.to_string()).collect(),
        };
        if let Err(e) = save_checkpoint(
            &scanner.checkpoint_path,
            &scanner.config,
            &findings,
            &analyzed_files,
            &ScanPhase::LlmStaticAnalysis,
            &scanner.metrics_tracker,
            Some(et_info),
        )
        .await
        {
            tracing::warn!("Failed to save checkpoint before early termination: {}", e);
        }
        pb.set_message(format!(
            "Early termination: {} medium+ findings (threshold: {})",
            medium_plus_count, threshold
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
        None,
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

/// Core phases: the set of phases that constitute a sensible default scan.
/// These are the phases that run under profile="core".
const CORE_PHASES: &[ScanPhase] = &[
    ScanPhase::Indexing,
    ScanPhase::Semgrep,
    ScanPhase::CweRouting,
    ScanPhase::LlmStaticAnalysis,
    ScanPhase::LlmDiscovery,
    ScanPhase::LlmVerification,
    ScanPhase::TicketCrossRef,
    ScanPhase::GitAnalysis,
    ScanPhase::CrossFileAnalysis,
    ScanPhase::ConfidenceScoring,
    ScanPhase::AiAggregation,
    ScanPhase::RootCauseDedup,
    ScanPhase::CveBootstrap,
    ScanPhase::Reporting,
];

/// Experimental phases: phases that are excluded from the core profile.
/// These run only under profile="all" (and still respect individual feature flags).
const EXPERIMENTAL_PHASES: &[ScanPhase] = &[
    ScanPhase::CpgSlice,
    ScanPhase::RuleSynthesis,
    ScanPhase::Validate,
    ScanPhase::SecurityAgentVerification,
    ScanPhase::ThreatModeling,
    ScanPhase::MultiVerifier,
    ScanPhase::AutoPatching,
    ScanPhase::PocCompiler,
    ScanPhase::ExploitSynth,
    ScanPhase::VariantSearch,
];

/// Check if a phase is part of the core profile
fn is_core_phase(phase: &ScanPhase) -> bool {
    CORE_PHASES.contains(phase)
}

/// Get the list of experimental phases as strings for logging
fn experimental_phase_names() -> Vec<String> {
    EXPERIMENTAL_PHASES
        .iter()
        .map(|p| match p {
            ScanPhase::CpgSlice => "CpgSlice".to_string(),
            ScanPhase::RuleSynthesis => "RuleSynthesis".to_string(),
            ScanPhase::Validate => "Validate".to_string(),
            ScanPhase::SecurityAgentVerification => "SecurityAgentVerification".to_string(),
            ScanPhase::ThreatModeling => "ThreatModeling".to_string(),
            ScanPhase::MultiVerifier => "MultiVerifier".to_string(),
            ScanPhase::AutoPatching => "AutoPatching".to_string(),
            ScanPhase::PocCompiler => "PocCompiler".to_string(),
            ScanPhase::ExploitSynth => "ExploitSynth".to_string(),
            ScanPhase::VariantSearch => "VariantSearch".to_string(),
            _ => format!("{:?}", p),
        })
        .collect()
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
    let all_sequential_phases = sequential_phases();
    let profile = scanner.config.scanner.profile;

    let is_phase_completed = |phase: &ScanPhase| completed_phases.contains(phase);

    for (i, phase) in all_sequential_phases.iter().enumerate() {
        let phase_num = 4 + i;
        pb.set_position(start_position + (i as u64) * 100);

        if is_phase_completed(phase) {
            tracing::info!(
                "Skipping {:?} phase (already completed in previous run)",
                phase
            );
            continue;
        }

        // Profile-based skipping: skip experimental phases when profile=core
        if profile == ScanPipelineProfile::Core && !is_core_phase(phase) {
            tracing::info!("profile=core: skipping experimental phase {:?}", phase);
            // Record as completed for checkpoint consistency
            if let Err(e) = save_checkpoint(
                &scanner.checkpoint_path,
                &scanner.config,
                &findings,
                &analyzed_files,
                phase,
                &scanner.metrics_tracker,
                None,
            )
            .await
            {
                tracing::warn!(
                    "Failed to save checkpoint after skipping {:?}: {}",
                    phase,
                    e
                );
            }
            continue;
        }

        let phase_msg = match phase {
            ScanPhase::CweRouting => format!(
                "Phase {}/{}: CWE routing (routing findings to specialized models)...",
                phase_num,
                all_sequential_phases.len() + 3
            ),
            ScanPhase::LlmDiscovery => format!(
                "Phase {}/{}: LLM discovery (enriching findings with context)...",
                phase_num,
                all_sequential_phases.len() + 3
            ),
            ScanPhase::LlmVerification => format!(
                "Phase {}/{}: LLM verification (validating findings)...",
                phase_num,
                all_sequential_phases.len() + 3
            ),
            ScanPhase::SecurityAgentVerification => format!(
                "Phase {}/{}: SecurityAgent verification (tool-based validation)...",
                phase_num,
                all_sequential_phases.len() + 3
            ),
            ScanPhase::TicketCrossRef => format!(
                "Phase {}/{}: Searching ticket systems for references...",
                phase_num,
                all_sequential_phases.len() + 3
            ),
            ScanPhase::GitAnalysis => format!(
                "Phase {}/{}: Analyzing Git history for related commits...",
                phase_num,
                all_sequential_phases.len() + 3
            ),
            ScanPhase::CrossFileAnalysis => format!(
                "Phase {}/{}: Cross-file dependency analysis...",
                phase_num,
                all_sequential_phases.len() + 3
            ),
            ScanPhase::ConfidenceScoring => format!(
                "Phase {}/{}: Calculating confidence scores...",
                phase_num,
                all_sequential_phases.len() + 3
            ),
            ScanPhase::AiAggregation => format!(
                "Phase {}/{}: AI aggregation (generating executive summary)...",
                phase_num,
                all_sequential_phases.len() + 3
            ),
            ScanPhase::Reporting => format!(
                "Phase {}/{}: Generating reports (JSON/HTML/SARIF)...",
                phase_num,
                all_sequential_phases.len() + 3
            ),
            ScanPhase::ThreatModeling => format!(
                "Phase {}/{}: Threat modeling (STRIDE analysis)...",
                phase_num,
                all_sequential_phases.len() + 3
            ),
            ScanPhase::RootCauseDedup => format!(
                "Phase {}/{}: Root cause deduplication...",
                phase_num,
                all_sequential_phases.len() + 3
            ),
            ScanPhase::MultiVerifier => format!(
                "Phase {}/{}: Multi-verifier voting...",
                phase_num,
                all_sequential_phases.len() + 3
            ),
            ScanPhase::AutoPatching => format!(
                "Phase {}/{}: Auto-patching with staging validation...",
                phase_num,
                all_sequential_phases.len() + 3
            ),
            ScanPhase::CveBootstrap => {
                format!(
                    "Phase {}/{}: CVE bootstrap...",
                    phase_num,
                    all_sequential_phases.len() + 3
                )
            }
            ScanPhase::PocCompiler => format!(
                "Phase {}/{}: PoC compilation check...",
                phase_num,
                all_sequential_phases.len() + 3
            ),
            ScanPhase::VariantSearch => {
                format!(
                    "Phase {}/{}: Variant search...",
                    phase_num,
                    all_sequential_phases.len() + 3
                )
            }
            _ => format!(
                "Phase {}/{}: {:?}",
                phase_num,
                all_sequential_phases.len() + 3,
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
        // Only count Medium-and-above findings (Critical, High, Medium) toward the threshold
        let medium_plus_count = findings
            .iter()
            .filter(|f| f.severity >= Severity::Medium)
            .count();
        let threshold = scanner
            .config
            .scanner
            .performance
            .early_termination_threshold;
        if threshold > 0.0 && medium_plus_count as f32 > threshold {
            let remaining_phases: Vec<&str> = all_sequential_phases
                .iter()
                .skip_while(|p| *p != phase)
                .skip(1)
                .map(|p| match p {
                    ScanPhase::CweRouting => "CweRouting",
                    ScanPhase::RuleSynthesis => "RuleSynthesis",
                    ScanPhase::LlmDiscovery => "LlmDiscovery",
                    ScanPhase::LlmVerification => "LlmVerification",
                    ScanPhase::Validate => "Validate",
                    ScanPhase::SecurityAgentVerification => "SecurityAgentVerification",
                    ScanPhase::TicketCrossRef => "TicketCrossRef",
                    ScanPhase::GitAnalysis => "GitAnalysis",
                    ScanPhase::CrossFileAnalysis => "CrossFileAnalysis",
                    ScanPhase::ConfidenceScoring => "ConfidenceScoring",
                    ScanPhase::AiAggregation => "AiAggregation",
                    ScanPhase::ThreatModeling => "ThreatModeling",
                    ScanPhase::RootCauseDedup => "RootCauseDedup",
                    ScanPhase::MultiVerifier => "MultiVerifier",
                    ScanPhase::AutoPatching => "AutoPatching",
                    ScanPhase::CveBootstrap => "CveBootstrap",
                    ScanPhase::PocCompiler => "PocCompiler",
                    ScanPhase::ExploitSynth => "ExploitSynth",
                    ScanPhase::VariantSearch => "VariantSearch",
                    ScanPhase::Reporting => "Reporting",
                    _ => "Unknown",
                })
                .collect();
            tracing::warn!(
                "Early termination triggered after phase {:?}: {} medium+ findings > threshold {} (total findings: {}), skipping phases: {:?}",
                phase,
                medium_plus_count,
                threshold,
                findings.len(),
                remaining_phases
            );
            let et_info = EarlyTerminationInfo {
                triggered: true,
                finding_count: medium_plus_count,
                phases_skipped: remaining_phases.iter().map(|s| s.to_string()).collect(),
            };
            if let Err(e) = save_checkpoint(
                &scanner.checkpoint_path,
                &scanner.config,
                &findings,
                &analyzed_files,
                phase,
                &scanner.metrics_tracker,
                Some(et_info),
            )
            .await
            {
                tracing::warn!("Failed to save checkpoint before early termination: {}", e);
            }
            pb.set_message(format!(
                "Early termination: {} medium+ findings (threshold: {})",
                medium_plus_count, threshold
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
            None,
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

    // Profile handling: log skipped experimental phases for core profile
    let profile = scanner.config.scanner.profile;
    if profile == ScanPipelineProfile::Core {
        let skipped = experimental_phase_names();
        tracing::info!(
            "profile=core: {} experimental phases skipped ({:?})",
            skipped.len(),
            skipped
        );
    } else {
        tracing::info!("profile=all: all phases enabled (individually flag-gated)");
    }

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
    let (findings, analyzed_files) = run_sequential_phases(
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

    // Scan health: what actually ran, surfaced in the console and the final report
    let mut health = crate::scan_health::ScanHealth::new();
    for phase in [
        ScanPhase::Indexing,
        ScanPhase::Semgrep,
        ScanPhase::LlmStaticAnalysis,
        ScanPhase::CpgSlice,
    ] {
        health.record_phase_run(&phase);
    }
    for phase in sequential_phases() {
        health.record_phase_run(&phase);
    }
    health.set_analyzed(analyzed_files.len() as u64);
    let llm_metrics = scanner.metrics_tracker.finalize().await;
    let (ok_calls, failed_calls) =
        crate::scan_health::from_llm_metrics(&llm_metrics, Some(&scanner.config.llm.pricing));
    health.set_llm_counts(ok_calls, failed_calls);
    if ok_calls + failed_calls == 0 {
        eprintln!(
            "\u{1B}[33m[SCAN HEALTH] WARNING: zero LLM calls recorded — LLM phases were skipped or misconfigured (run `baco doctor`)\u{1B}[0m"
        );
    }
    eprintln!("\n{}", health.summary());

    // Re-write the final report with the scan_health section, preserving early-termination info
    let et_info = crate::checkpoint::Checkpoint::load(&scanner.checkpoint_path.to_string_lossy())
        .ok()
        .and_then(|mut cp| cp.early_termination.take());
    let json_path = format!("{}/findings.json", scanner.config.output.dir);
    if let Err(e) = crate::report::json::write_findings_json(
        &findings,
        &[],
        &json_path,
        None,
        None,
        et_info,
        Some(health),
    ) {
        tracing::warn!("Failed to write final report with scan health: {}", e);
    }

    scanner.state.send_modify(|s| {
        s.current_phase = ScanPhase::Reporting;
        s.findings = findings.clone();
    });

    Ok(findings)
}
