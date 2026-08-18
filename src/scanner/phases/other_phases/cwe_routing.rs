use crate::cpg::CpgEngine as _;
use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::scanner::phases::PhaseConfig;

/// Run CWE routing phase (Phase 20/20)
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
        let language = crate::report::html::utilities::detect_language(&finding.file_path);
        let spec = router.route(&finding.cwe_id, language);

        if let Some(ref model) = spec.model_override {
            finding.llm_model = Some(model.clone());
            routed_count += 1;
        }
    }

    tracing::info!(
        "CWE routing complete: {} of {} findings routed to specialized models",
        routed_count,
        findings.len()
    );

    Ok((findings, analyzed_files.to_vec()))
}

/// Run CPG slice phase (Phase 3/24)
///
/// Uses Joern to build a Code Property Graph and extract code slices around
/// suspected vulnerabilities, reducing LLM context size (LLMxCPG, Usenix 2025).
/// No-op when `config.cpg.enabled` is false or Joern is unavailable.
pub async fn run_cpg_slice(
    _scanner: &crate::scanner::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        findings,
        pb,
        analyzed_files,
        metrics_tracker: _,
        target_path,
        config,
        project_stack: _,
    } = cfg;

    if !config.cpg.enabled {
        tracing::info!("CPG slice phase disabled (config.cpg.enabled=false); skipping");
        pb.set_position(pb.position() + 100);
        return Ok((findings, analyzed_files.to_vec()));
    }

    let engine = crate::cpg::JoernEngine::new(config.cpg.joern_path.clone());
    if !engine.is_available() {
        tracing::warn!(
            "CPG slice phase enabled but Joern binary not found; skipping. \
             Install Joern or set config.cpg.joern_path"
        );
        pb.set_position(pb.position() + 100);
        return Ok((findings, analyzed_files.to_vec()));
    }

    tracing::info!(
        "Running CPG slice phase on {} findings (budget={} lines)",
        findings.len(),
        config.cpg.slice_budget_lines
    );
    pb.set_message("Phase 3/24: CPG slice (building graph and slicing)");

    let cpg = match engine.build(target_path) {
        Ok(cpg) => cpg,
        Err(e) => {
            tracing::warn!(
                "CPG build failed for {:?}: {}; skipping phase",
                target_path,
                e
            );
            pb.set_position(pb.position() + 100);
            return Ok((findings, analyzed_files.to_vec()));
        }
    };

    let slicer = crate::cpg::slicer::CpgSlicer::new(&engine);
    let total = findings.len();
    for (i, finding) in findings.iter().enumerate() {
        let cwe_hint = finding.cwe_id.as_deref().unwrap_or("CWE-79");
        let entry_point = finding
            .code_location
            .as_deref()
            .and_then(|loc| loc.rsplit("::").next())
            .unwrap_or("main");
        if let Ok(slice) = slicer.slice(&cpg, cwe_hint, entry_point) {
            if !slice.is_empty() {
                tracing::debug!(
                    "CPG slice for finding {} ({}): {} bytes, {} function(s)",
                    finding.id,
                    cwe_hint,
                    slice.source.len(),
                    slice.related_functions.len()
                );
            }
        }
        pb.set_position(pb.position() + (i as u64 * 100 / total.max(1) as u64));
    }

    pb.set_position(pb.position() + 100);
    Ok((findings, analyzed_files.to_vec()))
}
