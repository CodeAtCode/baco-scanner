use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::scanner::phases::PhaseConfig;

/// Run root cause deduplication phase.
pub async fn run_root_cause_dedup(
    _scanner: &crate::scanner::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        findings,
        pb: _,
        analyzed_files,
        metrics_tracker: _,
        target_path: _,
        config,
        project_stack: _,
    } = cfg;

    // Skip if disabled via performance settings
    if !config.scanner.performance.enable_root_cause_dedup {
        tracing::info!("Root cause deduplication phase disabled via config, skipping");
        return Ok((findings, analyzed_files.to_vec()));
    }

    tracing::info!("Running root cause deduplication phase");

    let mut dedup = crate::root_cause_dedup::RootCauseDeduplicator::new();
    let deduped_groups = dedup.deduplicate(findings.clone());

    // Keep one finding per group (the first one encountered), merging evidence from dropped findings
    let mut kept_findings = Vec::new();
    for group in deduped_groups {
        if let Some(finding_id) = group.findings.first() {
            // Find the original finding by ID
            if let Some(kept_finding) = findings.iter().find(|f| f.id == *finding_id) {
                let mut kept = kept_finding.clone();
                // Merge evidence from all dropped findings in this group
                for dropped_id in &group.findings[1..] {
                    if let Some(dropped_finding) = findings.iter().find(|f| f.id == *dropped_id) {
                        kept.evidence.extend(dropped_finding.evidence.clone());
                    }
                }
                kept_findings.push(kept);
            }
        }
    }

    tracing::info!(
        "Deduplicated: {} findings → {} findings",
        findings.len(),
        kept_findings.len()
    );
    Ok((kept_findings, analyzed_files.to_vec()))
}
