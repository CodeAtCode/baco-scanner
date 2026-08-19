use crate::checkpoint::ScanPhase;
use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::scanner::phases::PhaseConfig;

/// Run Semgrep phase (phase 2 of 24).
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
    let phase_num = crate::scanner::pipeline::orchestrator::phase_index(&ScanPhase::Semgrep);
    let total = crate::scanner::pipeline::orchestrator::total_phases();
    pb.set_message(format!("Phase {}/{}: Running Semgrep static analysis (scanning for known vulnerability patterns)...", phase_num, total));

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
                "Phase {}/{}: Semgrep complete - {} findings discovered",
                phase_num, total, semgrep_count
            ));
            pb.set_position(pb.position() + 100);

            Ok((findings, analyzed_files.to_vec()))
        }
        Err(e) => {
            tracing::warn!("Semgrep failed: {}. Skipping phase.", e);
            pb.set_message(format!(
                "Phase {}/{}: Semgrep failed - skipping phase",
                phase_num, total
            ));
            pb.set_position(pb.position() + 100);

            Ok((findings, analyzed_files.to_vec()))
        }
    }
}
