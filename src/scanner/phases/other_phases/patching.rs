use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::scanner::phases::PhaseConfig;

/// Run auto patching phase (phase 19 of 24).
pub async fn run_auto_patching(
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

    // Skip if disabled via performance settings
    if !config.scanner.performance.enable_auto_patching {
        tracing::info!("Auto patching phase disabled via config, skipping");
        return Ok((findings, analyzed_files.to_vec()));
    }

    tracing::info!("Running auto patching phase");

    let patcher = crate::staging::AutoPatcher::new(target_path.to_path_buf());
    let patching_config = crate::staging::PatchingConfig::default();

    match patcher.execute_batch_with_vuln_spec(&findings, &patching_config, Some(&config.vuln_spec))
    {
        Ok(patched_findings) => {
            tracing::info!(
                "Auto patching: {} findings processed",
                patched_findings.len()
            );
            Ok((patched_findings, analyzed_files.to_vec()))
        }
        Err(e) => {
            tracing::warn!("Auto patching failed: {}", e);
            Ok((findings, analyzed_files.to_vec()))
        }
    }
}

/// Run CVE bootstrap phase (phase 20 of 24).
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

/// Run PoC compiler phase (phase 21 of 24).
pub async fn run_poc_compiler(
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

    // Skip if disabled via config
    if !config.scanner.performance.enable_poc_compilation {
        tracing::info!("PoC compiler phase disabled via config, skipping");
        return Ok((findings, analyzed_files.to_vec()));
    }

    tracing::info!("Running PoC compiler phase");

    let mut verified_findings = findings.clone();
    for finding in &mut verified_findings {
        if let Some(poc_code) = &finding.poc_code {
            // Use language from poc_format or default to rust
            let language = finding.poc_format.as_deref().unwrap_or("rust");
            let result = crate::poc_compiler::PocCompiler::compile_check(poc_code, language);

            if result.compiles {
                finding.verification_status = Some(crate::findings::VerificationStatus::Confirmed);
            } else {
                finding.verification_status = Some(crate::findings::VerificationStatus::Failed);
                let notes = finding.verification_notes.clone().unwrap_or_default();
                finding.verification_notes = Some(format!(
                    "{}PoC compilation failed: {}",
                    if notes.is_empty() { "" } else { "\n" },
                    result.errors.join(", ")
                ));
            }
        }
    }

    Ok((verified_findings, analyzed_files.to_vec()))
}

/// Run variant search phase (phase 23 of 24).
pub async fn run_variant_search(
    _scanner: &crate::scanner::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        mut findings,
        pb: _,
        analyzed_files,
        metrics_tracker: _,
        target_path,
        config,
        project_stack: _,
    } = cfg;

    // Skip if disabled via config
    if !config.scanner.performance.enable_variant_search {
        tracing::info!("Variant search phase disabled via config, skipping");
        return Ok((findings, analyzed_files.to_vec()));
    }

    tracing::info!("Running variant search phase");

    let searcher =
        crate::variant_search::VariantSearcher::new(target_path.to_string_lossy().to_string());

    match searcher.search_variants() {
        Ok(variant_hits) => {
            let variant_findings: Vec<VulnerabilityFinding> = variant_hits
                .into_iter()
                .map(|hit| {
                    let finding_id = format!("variant-{}:{}", hit.file_path, hit.line_number);
                    VulnerabilityFinding {
                        id: finding_id,
                        title: "Code variant detected".to_string(),
                        description: format!(
                            "Potential vulnerability variant found with similarity score: {:.2}",
                            hit.similarity_score
                        ),
                        severity: crate::findings::Severity::Medium,
                        confidence_score: hit.similarity_score,
                        cwe_id: None,
                        file_path: hit.file_path,
                        line_number: Some(hit.line_number),
                        code_snippet: Some(hit.snippet),
                        diff_hunk: None,
                        recommendation: Some(
                            "Review this code variant for potential vulnerabilities".to_string(),
                        ),
                        code_location: None,
                        already_reported: false,
                        sources: vec!["variant_search".to_string()],
                        commit_reference: None,
                        ticket_reference: None,
                        priority_score: None,
                        cross_file_references: None,
                        verification_status: None,
                        verification_notes: None,
                        verification_error: None,
                        agent_evidence_path: None,
                        security_issue: None,
                        poc_code: None,
                        mitigation_code: None,
                        poc_format: None,
                        llm_model: None,
                        agent_mode: false,
                        statement_range: None,
                        triage_verdict: None,
                        evidence: vec![],
                        verification_tier: None,
                    }
                })
                .collect();

            let count = variant_findings.len();
            findings.extend(variant_findings);
            tracing::info!("Variant search completed: {} variants found", count);
            Ok((findings, analyzed_files.to_vec()))
        }
        Err(e) => {
            tracing::warn!("Variant search failed: {}", e);
            Ok((findings, analyzed_files.to_vec()))
        }
    }
}
