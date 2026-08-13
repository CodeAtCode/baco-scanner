use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::scanner::phases::PhaseConfig;

/// Run Semgrep phase (Phase 2/20)
pub async fn run_semgrep(
    _scanner: &crate::scanner::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        mut findings,
        pb,
        analyzed_files,
        metrics_tracker: _,
        target_path,
        config,
        project_stack: _,
    } = cfg;

    tracing::info!("Running Semgrep phase on {:?}", target_path);
    let runner =
        crate::semgrep::SemgrepRunner::new(None, config.scanner.semgrep.exclude_rules.clone());
    pb.set_message("Phase 2/20: Running Semgrep static analysis (scanning for known vulnerability patterns)...");

    // Enable steady tick for progress bar timer
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    match runner
        .run(target_path.to_str().unwrap_or("."), &config.output.dir)
        .await
    {
        Ok(semgrep_findings) => {
            let semgrep_count = semgrep_findings.len();
            findings.extend(semgrep_findings);
            pb.set_message(format!(
                "Phase 2/20: Semgrep complete - {} findings discovered",
                semgrep_count
            ));
            pb.set_position(pb.position() + 100);

            Ok((findings, analyzed_files.to_vec()))
        }
        Err(e) => {
            tracing::warn!("Semgrep failed: {}. Skipping phase.", e);
            pb.set_message("Phase 2/20: Semgrep failed - skipping phase");
            pb.set_position(pb.position() + 100);

            Ok((findings, analyzed_files.to_vec()))
        }
    }
}
