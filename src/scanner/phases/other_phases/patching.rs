use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::scanner::phases::PhaseConfig;

/// Run CVE bootstrap phase.
pub async fn run_cve_bootstrap(
    _scanner: &crate::scanner::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        findings,
        pb: _,
        analyzed_files,
        metrics_tracker: _,
        target_path,
        config,
        project_stack: _,
    } = cfg;

    // Skip if disabled via config
    if !config.scanner.performance.enable_cve_bootstrap {
        tracing::info!("CVE bootstrap phase disabled via config, skipping");
        return Ok((findings, analyzed_files.to_vec()));
    }

    tracing::info!("Running CVE bootstrap phase");

    let bootstrapper =
        crate::cve_bootstrap::CveBootstrapper::new(target_path.to_string_lossy().to_string());

    match bootstrapper.run_cve_enrichment(&findings).await {
        Ok(enriched_findings) => {
            tracing::info!(
                "CVE bootstrap: {} findings enriched",
                enriched_findings.len()
            );
            Ok((enriched_findings, analyzed_files.to_vec()))
        }
        Err(e) => {
            tracing::warn!("CVE bootstrap failed: {}", e);
            Ok((findings, analyzed_files.to_vec()))
        }
    }
}
