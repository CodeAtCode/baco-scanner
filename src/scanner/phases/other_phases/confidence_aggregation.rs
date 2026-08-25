use std::path::PathBuf;

use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::scanner::phases::PhaseConfig;

/// Run confidence scoring phase (phase 14 of 24).
pub async fn run_confidence_scoring(
    _scanner: &crate::scanner::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        findings,
        pb,
        analyzed_files,
        metrics_tracker: _,
        target_path: _,
        config,
        project_stack: _,
    } = cfg;

    // Skip if disabled via performance settings
    if !config.scanner.performance.enable_confidence_refinement {
        tracing::info!("Confidence refinement phase disabled via config, skipping");
        pb.set_position(pb.position() + 100);
        return Ok((findings, analyzed_files.to_vec()));
    }

    tracing::info!("Running confidence refinement phase...");

    // Load analysis context
    let output_path = PathBuf::from(&config.output.dir);
    let context = if output_path.exists() {
        match crate::analysis_context::AnalysisContext::load(&output_path) {
            Ok(ctx) => ctx,
            Err(e) => {
                tracing::warn!("Failed to load analysis context: {}, using default", e);
                crate::analysis_context::AnalysisContext::default()
            }
        }
    } else {
        crate::analysis_context::AnalysisContext::default()
    };

    // Run confidence refinement
    let refinement = crate::confidence_refinement::ConfidenceRefinementPhase::new();
    let refined_scores = refinement.run(findings.clone(), &context);

    // Apply refined scores to findings
    let mut updated_findings = Vec::new();
    for finding in findings {
        if let Some(refined) = refined_scores.get(&finding.id) {
            let mut updated = finding.clone();
            updated.confidence_score = refined.refined_score;
            updated_findings.push(updated);
        } else {
            updated_findings.push(finding);
        }
    }

    pb.set_position(pb.position() + 100);
    Ok((updated_findings, analyzed_files.to_vec()))
}

/// Run AI aggregation phase (phase 15 of 24).
pub async fn run_ai_aggregation(
    _scanner: &crate::scanner::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        findings,
        pb,
        analyzed_files,
        metrics_tracker: _,
        target_path: _,
        config,
        project_stack: _,
    } = cfg;

    tracing::info!("Running AI aggregation phase...");
    let llm_config = crate::llm::LlmConfig {
        base_url: config.llm.phases.aggregation.base_url.clone(),
        api_key: config
            .llm
            .phases
            .aggregation
            .api_key
            .clone()
            .unwrap_or_default(),
        model: config.llm.phases.aggregation.model.clone(),
        models: config.llm.phases.aggregation.get_models(),
        timeout: config.llm.timeout_secs,
        max_retries: config.llm.max_retries as u32,
        retry_backoff_ms: config.llm.retry_backoff_ms,
        temperature: 0.5,
        max_reasoning_tokens: None,
    };

    let aggregation = crate::report::ai_aggregation::AiAggregationPhase::new(llm_config);

    // Enrich findings with LLM analysis (populates description and recommendation)
    let (enriched_findings, _llm_failed) = aggregation.enrich_findings_with_llm(&findings).await;

    tracing::debug!("AI aggregation complete");
    pb.set_position(pb.position() + 100);
    Ok((enriched_findings, analyzed_files.to_vec()))
}

/// Run reporting phase (phase 24 of 24).
pub async fn run_reporting(
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

    tracing::info!("Running reporting phase to {:?}", config.output.dir);

    // Finalize metrics and get summary
    let llm_metrics = metrics_tracker.finalize().await;

    let json_path = format!("{}/findings.json", config.output.dir);
    if let Err(e) = crate::report::json::write_findings_json(
        &findings,
        json_path.as_str(),
        Some(llm_metrics),
        None,
    ) {
        tracing::warn!("Failed to write JSON report: {}", e);
    }

    let html_path = format!("{}/report.html", config.output.dir);
    if let Err(e) =
        crate::report::html::generate_html_report(&findings, &html_path, Some(config), None)
    {
        tracing::warn!("Failed to write HTML report: {}", e);
    }

    pb.set_position(pb.position() + 100);
    Ok((findings, analyzed_files.to_vec()))
}
