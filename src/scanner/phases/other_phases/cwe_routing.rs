use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::scanner::phases::PhaseConfig;

/// Run CWE routing phase.
pub async fn run_cwe_routing(
    _scanner: &crate::scanner::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        mut findings,
        pb: _,
        analyzed_files,
        metrics_tracker: _,
        target_path: _,
        config,
        project_stack: _,
    } = cfg;

    if !config.router.enabled {
        tracing::info!("CWE router disabled via config, skipping CWE routing phase");
        return Ok((findings, analyzed_files.to_vec()));
    }

    tracing::info!("Running CWE routing phase (routing findings to specialized models)");

    let router = crate::router::CweRouter::from_config(&config.router);
    let mut routed_count = 0usize;

    for finding in &mut findings {
        if let Some(cwe) = finding.cwe_id.as_deref() {
            let route = router.route_cwe(cwe);

            if let Some(model) = route.model_override {
                finding.llm_model = Some(model);
                routed_count += 1;
            }
        }
    }

    tracing::info!(
        "CWE routing complete: {} of {} findings routed to specialized models",
        routed_count,
        findings.len()
    );

    Ok((findings, analyzed_files.to_vec()))
}
