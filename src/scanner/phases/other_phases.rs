use std::path::PathBuf;

use super::PhaseConfig;
use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::git_analysis::GitAnalyzer;

/// Run indexing phase (Phase 1/20)
pub async fn run_indexing(
    _scanner: &super::super::Scanner,
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

    // Index the project with incremental scanning
    tracing::info!("Running indexing phase on {:?}", target_path);

    // Try to load previous hash store for incremental scanning
    let hash_store_path = PathBuf::from(&config.output.dir).join("file_hashes.json");
    let _previous_hash_store = if hash_store_path.exists() {
        match crate::incremental_scan::FileHashStore::load(&hash_store_path.to_string_lossy()) {
            Ok(store) => {
                tracing::info!("Loaded previous hash store with {} entries", store.len());
                Some(store)
            }
            Err(e) => {
                tracing::warn!("Failed to load previous hash store: {}, starting fresh", e);
                None
            }
        }
    } else {
        None
    };

    // Run incremental indexing
    let (index, hash_store) = match crate::indexer::FileIndex::index_project_incremental(
        target_path.to_str().unwrap_or("."),
        &config.project.languages,
        config.scanner.max_file_size_kb * 1024,
        &config.scanner.exclude_paths,
    ) {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!("Indexing failed: {}. Skipping phase.", e);
            return Ok((findings, analyzed_files.to_vec()));
        }
    };

    // Save hash store for future incremental scans
    if let Some(parent) = hash_store_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = hash_store.save(&hash_store_path.to_string_lossy()) {
        tracing::warn!("Failed to save hash store: {}", e);
    } else {
        tracing::info!("Saved hash store with {} entries", hash_store.len());
    }

    // Log statistics about incremental scanning
    if _previous_hash_store.is_some() {
        let unchanged_count = index
            .files
            .iter()
            .filter(|f| f.hash.as_ref().is_some())
            .count();
        tracing::info!(
            "Incremental scan: {} total files, {} unchanged from previous scan",
            index.files.len(),
            unchanged_count
        );
    }

    Ok((findings, analyzed_files.to_vec()))
}

/// Run Semgrep phase (Phase 2/20)
pub async fn run_semgrep(
    _scanner: &super::super::Scanner,
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

/// Run ticket cross-reference phase (Phase 7/20)
pub async fn run_ticket_cross_ref(
    _scanner: &super::super::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        mut findings,
        pb,
        analyzed_files,
        metrics_tracker: _,
        target_path: _,
        config,
        project_stack: _,
    } = cfg;

    tracing::info!("Running ticket cross-reference phase...");

    let mut systems = Vec::new();
    for cfg in &config.tickets.systems {
        let ticket_system = crate::tickets::TicketSystem {
            name: format!("{} ({})", cfg.system_type, cfg.url),
            system_type: cfg.system_type.clone(),
            url: cfg.url.clone(),
            credentials: cfg.api_key.clone(),
        };
        systems.push(ticket_system);
    }

    if !systems.is_empty() {
        let searcher = crate::tickets::TicketSearcher::new(systems);
        for finding in &mut findings {
            let _references = searcher
                .search_for_finding(&finding.title)
                .await
                .unwrap_or_default();
            // Map to ticket_reference string (first match or None)
            if let Some(refs) = _references.first() {
                finding.ticket_reference = Some(format!(
                    "{}:{}:{}", // system:id:title
                    refs.system, refs.ticket_id, refs.title
                ));
            }
        }
    }
    pb.set_position(pb.position() + 100);
    Ok((findings, analyzed_files.to_vec()))
}

/// Run Git analysis phase (Phase 8/20)
pub async fn run_git_analysis(
    _scanner: &super::super::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        mut findings,
        pb,
        analyzed_files,
        metrics_tracker: _,
        target_path,
        config: _,
        project_stack: _,
    } = cfg;

    tracing::info!("Running Git analysis phase...");

    match GitAnalyzer::new(target_path.to_str().unwrap_or(".")) {
        Ok(analysis) => {
            let remote_url =
                super::super::Scanner::get_git_remote_url(target_path.to_str().unwrap_or("."));
            for finding in &mut findings {
                #[allow(deprecated)]
                let _commits = analysis
                    .find_related_commits(&finding.file_path, finding.line_number)
                    .unwrap_or_default();
                if let Some(commit) = _commits.first() {
                    let commit_ref = if let Some(ref url) = remote_url {
                        let owner_repo = super::super::Scanner::extract_owner_repo_from_url(url);
                        if let Some((owner, repo)) = owner_repo {
                            let short_hash = if commit.commit_hash.len() > 7 {
                                &commit.commit_hash[..7]
                            } else {
                                &commit.commit_hash
                            };
                            Some(format!(
                                "https://github.com/{}/{}/commit/{}",
                                owner, repo, short_hash
                            ))
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    if let Some(ref_url) = commit_ref {
                        finding.commit_reference = Some(ref_url);
                    } else {
                        finding.commit_reference = Some(format!(
                            "{}:{}:{}",
                            commit.commit_hash, commit.author, commit.commit_message
                        ));
                    }
                }
            }
        }
        Err(git_err) => {
            tracing::warn!("Git analysis failed: {} - skipping Git phase", git_err);
        }
    }
    pb.set_position(pb.position() + 100);
    Ok((findings, analyzed_files.to_vec()))
}

/// Run cross-file analysis phase (Phase 12/23)
pub async fn run_cross_file_analysis(
    _scanner: &super::super::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        mut findings,
        pb,
        analyzed_files,
        metrics_tracker: _,
        target_path: _,
        config: _,
        project_stack: _,
    } = cfg;

    tracing::info!("Running cross-file analysis phase...");
    findings = crate::crossfile::CrossFileAnalyzer::analyze_cross_file_references(&findings);

    let chains = crate::chain_analysis::ChainAnalyzer::analyze_chains(&findings);
    if !chains.is_empty() {
        tracing::info!(
            "Cross-file analysis detected {} attack chain(s); applying chain verdicts",
            chains.len()
        );
        crate::chain_analysis::apply_chain_verdicts(&mut findings, &chains);
    }

    pb.set_position(pb.position() + 100);
    Ok((findings, analyzed_files.to_vec()))
}

/// Run confidence scoring phase (Phase 10/20)
pub async fn run_confidence_scoring(
    _scanner: &super::super::Scanner,
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

/// Run AI aggregation phase (Phase 11/20)
pub async fn run_ai_aggregation(
    _scanner: &super::super::Scanner,
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
    };

    let aggregation = crate::report::ai_aggregation::AiAggregationPhase::new(llm_config);

    // Enrich findings with LLM analysis (populates description and recommendation)
    let (enriched_findings, _llm_failed) = aggregation.enrich_findings_with_llm(&findings).await;

    tracing::debug!("AI aggregation complete");
    pb.set_position(pb.position() + 100);
    Ok((enriched_findings, analyzed_files.to_vec()))
}

/// Run reporting phase (Phase 12/20)
pub async fn run_reporting(
    _scanner: &super::super::Scanner,
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
    if let Err(e) =
        crate::report::json::write_findings_json(&findings, json_path.as_str(), Some(llm_metrics))
    {
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

/// Run threat modeling phase (Phase 13/20)
pub async fn run_threat_modeling(
    _scanner: &super::super::Scanner,
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

    if !config.scanner.performance.enable_threat_modeling {
        tracing::info!("Threat modeling phase disabled via config, skipping");
        return Ok((findings, analyzed_files.to_vec()));
    }

    tracing::info!("Running threat modeling phase");

    // Load or create analysis context
    let output_path = PathBuf::from(&config.output.dir);
    let context = if output_path.exists() {
        match crate::analysis_context::AnalysisContext::load(&output_path) {
            Ok(ctx) => ctx,
            Err(e) => {
                tracing::warn!("Failed to load analysis context: {}, creating new one", e);
                crate::analysis_context::AnalysisContext::default()
            }
        }
    } else {
        crate::analysis_context::AnalysisContext::default()
    };

    // Run threat modeling
    match crate::threat_model::ThreatModelingPhase::run(&output_path, &context, None).await {
        Ok(threat_model) => {
            // If threat model generated, add it as a finding
            if !threat_model.is_empty() {
                let finding = VulnerabilityFinding {
                    id: format!("threat-model-{}", chrono::Utc::now().format("%Y%m%d%H%M%S")),
                    title: "Threat Model Generated".to_string(),
                    severity: crate::findings::Severity::Medium,
                    confidence_score: 0.9,
                    file_path: "THREAT_MODEL.md".to_string(),
                    line_number: Some(1),
                    code_snippet: Some(threat_model.clone()),
                    description: threat_model,
                    cwe_id: None,
                    verification_status: None,
                    sources: vec!["threat-modeling".to_string()],
                    cross_file_references: None,
                    diff_hunk: None,
                    recommendation: None,
                    code_location: None,
                    already_reported: false,
                    commit_reference: None,
                    ticket_reference: None,
                    priority_score: None,
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
                };
                findings.push(finding);
            }

            Ok((findings, analyzed_files.to_vec()))
        }
        Err(e) => {
            tracing::warn!("Threat modeling phase failed: {}", e);
            Ok((findings, analyzed_files.to_vec()))
        }
    }
}

/// Run root cause deduplication phase (Phase 14/20)
pub async fn run_root_cause_dedup(
    _scanner: &super::super::Scanner,
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

    // Keep one finding per group (the first one encountered)
    let mut kept_findings = Vec::new();
    for group in deduped_groups {
        if let Some(finding_id) = group.findings.first() {
            // Find the original finding by ID
            if let Some(finding) = findings.iter().find(|f| f.id == *finding_id) {
                kept_findings.push(finding.clone());
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

/// Run multi verifier phase (Phase 15/20)
pub async fn run_multi_verifier(
    _scanner: &super::super::Scanner,
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
    if !config.scanner.performance.enable_multi_verifier {
        tracing::info!("Multi verifier phase disabled via config, skipping");
        return Ok((findings, analyzed_files.to_vec()));
    }

    tracing::info!("Running multi verifier phase");

    let config_verifier = crate::multi_verifier::VerifierConfig {
        num_verifiers: 3,
        circuit_breaker_threshold: 0.5,
    };
    let verifier = crate::multi_verifier::MultiVerifier::new(config_verifier);
    let verified_findings = verifier.verify_batch(&findings);

    tracing::info!(
        "Multi verifier: {} findings → {} findings",
        findings.len(),
        verified_findings.len()
    );
    Ok((verified_findings, analyzed_files.to_vec()))
}

/// Run auto patching phase (Phase 16/20)
pub async fn run_auto_patching(
    _scanner: &super::super::Scanner,
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

    match patcher.execute_batch(&findings, &patching_config) {
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

/// Run CVE bootstrap phase (Phase 17/20)
pub async fn run_cve_bootstrap(
    _scanner: &super::super::Scanner,
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

/// Run PoC compiler phase (Phase 18/20)
pub async fn run_poc_compiler(
    _scanner: &super::super::Scanner,
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

/// Run variant search phase (Phase 19/20)
pub async fn run_variant_search(
    _scanner: &super::super::Scanner,
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

/// Run CWE routing phase (Phase 20/20)
pub async fn run_cwe_routing(
    _scanner: &super::super::Scanner,
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

/// Run CPG slice phase (Phase 3/23)
///
/// Uses Joern to build a Code Property Graph and extract code slices around
/// suspected vulnerabilities, reducing LLM context size (LLMxCPG, Usenix 2025).
/// No-op when `config.cpg.enabled` is false or Joern is unavailable.
pub async fn run_cpg_slice(
    _scanner: &super::super::Scanner,
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

    use crate::cpg::CpgEngine as _;
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
    pb.set_message("Phase 3/23: CPG slice (building graph and slicing)");

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

/// Run rule synthesis phase (Phase 6/23)
///
/// Generates semgrep rules from CWE identifiers using LLM synthesis (MoCQ paper).
/// No-op when `config.rulesynth.enabled` is false or no API key is configured.
pub async fn run_rule_synthesis(
    _scanner: &super::super::Scanner,
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

    if !config.rulesynth.enabled {
        tracing::info!("Rule synthesis disabled (config.rulesynth.enabled=false); skipping");
        pb.set_position(pb.position() + 100);
        return Ok((findings, analyzed_files.to_vec()));
    }

    let phase_config = &config.llm.phases.discovery;
    let Some(api_key) = &phase_config.api_key else {
        tracing::warn!("Rule synthesis enabled but no LLM API key configured; skipping phase");
        pb.set_position(pb.position() + 100);
        return Ok((findings, analyzed_files.to_vec()));
    };

    tracing::info!(
        "Running rule synthesis phase (max {} rules/CWE) → {:?}",
        config.rulesynth.max_rules_per_cwe,
        config.rulesynth.output_dir
    );
    pb.set_message("Phase 6/23: Rule synthesis (LLM→semgrep rules)");

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
    };
    let client = crate::llm::LlmClient::with_metrics(llm_config, Some(metrics_tracker.clone()));

    let synthesizer = crate::rulesynth::RuleSynthesizer::new(&client, &config.rulesynth);

    let mut seen_cwes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for finding in &findings {
        if let Some(cwe) = &finding.cwe_id {
            seen_cwes.insert(cwe.clone());
        }
    }

    let total = seen_cwes.len();
    for (i, cwe) in seen_cwes.iter().enumerate() {
        for language in &config.project.languages {
            match synthesizer.generate(cwe, language).await {
                Ok(rules) => {
                    if rules.is_empty() {
                        tracing::debug!(
                            "Rule synthesis: no valid rules for {} ({})",
                            cwe,
                            language
                        );
                    } else {
                        tracing::info!(
                            "Rule synthesis: generated {} valid rule(s) for {} ({})",
                            rules.len(),
                            cwe,
                            language
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("Rule synthesis failed for {} ({}): {}", cwe, language, e);
                }
            }
        }
        pb.set_position(pb.position() + (i as u64 * 100 / total.max(1) as u64));
    }

    pb.set_position(pb.position() + 100);
    Ok((findings, analyzed_files.to_vec()))
}

/// Run exploit synthesis phase (Phase 21/23)
///
/// Generates sandbox-verified exploits for confirmed findings (QRS paper).
/// No-op when `config.exploit.enabled` is false or Docker sandbox unavailable.
pub async fn run_exploit_synth(
    _scanner: &super::super::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        mut findings,
        pb,
        analyzed_files,
        metrics_tracker,
        target_path: _,
        config,
        project_stack: _,
    } = cfg;

    if !config.exploit.enabled {
        tracing::info!("Exploit synthesis disabled (config.exploit.enabled=false); skipping");
        pb.set_position(pb.position() + 100);
        return Ok((findings, analyzed_files.to_vec()));
    }

    let phase_config = &config.llm.phases.discovery;
    let Some(api_key) = &phase_config.api_key else {
        tracing::warn!("Exploit synthesis enabled but no LLM API key configured; skipping phase");
        pb.set_position(pb.position() + 100);
        return Ok((findings, analyzed_files.to_vec()));
    };

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
    };
    let client = crate::llm::LlmClient::with_metrics(llm_config, Some(metrics_tracker.clone()));

    let synth = crate::exploit::ExploitSynthesizer::new(&client, &config.exploit);
    if !synth.is_available() {
        tracing::warn!(
            "Exploit synthesis enabled but sandbox unavailable (Docker not running?); skipping phase"
        );
        pb.set_position(pb.position() + 100);
        return Ok((findings, analyzed_files.to_vec()));
    }

    tracing::info!(
        "Running exploit synthesis on {} findings (max {} exploit(s)/finding, sandbox={})",
        findings.len(),
        config.exploit.max_exploits_per_finding,
        config.exploit.sandbox_image
    );
    pb.set_message("Phase 21/23: Exploit synthesis (sandbox-verified PoCs)");

    let total = findings.len();
    for (i, finding) in findings.iter_mut().enumerate() {
        match synth.synthesize_and_verify(finding).await {
            Ok(result) => {
                if result.confirmed {
                    tracing::info!(
                        "Exploit confirmed for finding {} (exit_code={})",
                        finding.id,
                        result.exit_code
                    );
                    if let Some(verdict) = &mut finding.triage_verdict {
                        let _ = verdict;
                    }
                } else {
                    tracing::debug!(
                        "Exploit not confirmed for finding {} (exit_code={}, matched={})",
                        finding.id,
                        result.exit_code,
                        result.matched_expected
                    );
                }
            }
            Err(crate::exploit::ExploitError::Disabled) => {}
            Err(e) => {
                tracing::warn!("Exploit synthesis failed for finding {}: {}", finding.id, e);
            }
        }
        pb.set_position(pb.position() + (i as u64 * 100 / total.max(1) as u64));
    }

    pb.set_position(pb.position() + 100);
    Ok((findings, analyzed_files.to_vec()))
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
