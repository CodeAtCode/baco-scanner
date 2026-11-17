use crate::checkpoint::ScanPhase;
use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::scanner::phases::PhaseConfig;
use crate::scanner::progress::progress_position;

/// Run the Validate phase (phase 9/15).
///
/// LLM-as-judge rationale validation implementing the CORRECT paper (arxiv:2504.13474).
/// For each finding, an LLM evaluates the soundness of the reasoning and adjusts
/// confidence: +0.10 for sound reasoning, -0.20 for flawed reasoning.
pub async fn run_validate(
    _scanner: &crate::scanner::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        findings,
        pb,
        analyzed_files,
        metrics_tracker,
        target_path: _,
        config,
        project_stack: _,
    } = cfg;

    if !config.validate.enabled {
        tracing::info!("Validate phase disabled (config.validate.enabled=false); skipping");
        pb.set_position(pb.position() + 100);
        return Ok((findings, analyzed_files.to_vec()));
    }

    let phase_config = &config.llm.phases.verification;
    let Some(api_key) = &phase_config.api_key else {
        tracing::warn!("Validate phase enabled but no LLM API key configured; skipping");
        pb.set_position(pb.position() + 100);
        return Ok((findings, analyzed_files.to_vec()));
    };

    tracing::info!(
        "Running Validate phase (rationale check on {} findings)",
        findings.len()
    );
    let phase_num = crate::scanner::pipeline::orchestrator::phase_index(&ScanPhase::Validate);
    let total = crate::scanner::pipeline::orchestrator::total_phases();
    pb.set_message(format!(
        "Phase {}/{}: Validate (rationale check)...",
        phase_num, total
    ));

    let timeout = phase_config.timeout_secs.unwrap_or(config.llm.timeout_secs);
    let llm_config = crate::llm::LlmConfig {
        base_url: phase_config.base_url.clone(),
        api_key: api_key.clone(),
        model: phase_config.model.clone(),
        models: phase_config.get_models(),
        timeout,
        max_retries: config.llm.max_retries as u32,
        retry_backoff_ms: config.llm.retry_backoff_ms,
        temperature: config.llm.temperature,
        max_reasoning_tokens: config.llm.max_reasoning_tokens,
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 3,
    };
    let client = crate::llm::LlmClient::with_metrics(llm_config, Some(metrics_tracker.clone()));

    let total = findings.len();
    let mut updated: Vec<VulnerabilityFinding> = Vec::with_capacity(total);
    let base = pb.position();

    for (i, finding) in findings.into_iter().enumerate() {
        match crate::llm_verification::rationale_check(&client, &finding).await {
            Ok(verdict) => {
                let mut f = finding;
                f.confidence_score =
                    (f.confidence_score + verdict.confidence_adjustment).clamp(0.0, 1.0);
                f.add_evidence(
                    crate::evidence::EvidenceSource::LlmAnalysis("rationale_validation".into()),
                    0.7,
                    format!("Rationale validation verdict: {:?}", verdict),
                );
                if !verdict.issues.is_empty() {
                    let note = format!(
                        "Rationale check: {}\nIssues: {}",
                        if verdict.is_sound { "sound" } else { "flawed" },
                        verdict.issues.join("; ")
                    );
                    f.verification_notes = Some(match f.verification_notes.take() {
                        Some(existing) => format!("{}\n{}", existing, note),
                        None => note,
                    });
                }
                tracing::debug!(
                    "Validate [{}/{}]: {:?} confidence {:+.2}",
                    i + 1,
                    total,
                    f.title,
                    verdict.confidence_adjustment
                );
                updated.push(f);
            }
            Err(e) => {
                tracing::warn!(
                    "Validate [{}/{}]: rationale_check failed: {}",
                    i + 1,
                    total,
                    e
                );
                updated.push(finding);
            }
        }
        pb.set_position(progress_position(base, i, total));
    }

    pb.set_position(base + 100);
    Ok((updated, analyzed_files.to_vec()))
}

/// Default handler for unknown phases
pub async fn run_default(
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase,
        findings,
        pb: _,
        analyzed_files,
        metrics_tracker: _,
        target_path: _,
        config: _,
        project_stack: _,
    } = cfg;

    tracing::warn!("Unknown phase: {:?}. Skipping.", phase);
    Ok((findings, analyzed_files.to_vec()))
}
