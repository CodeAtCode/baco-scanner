use crate::agent;
use crate::checkpoint::ScanPhase;
use crate::confidence_refinement::ConfidenceRefinementPhase;
use crate::config;
use crate::context::AnalysisContext;
use crate::cve_bootstrap::CveBootstrapper;
use crate::findings::{VerificationStatus, VulnerabilityFinding};
use crate::git_analysis::GitAnalyzer;
use crate::indexer::FileIndex;
use crate::llm::{self, create_llm_client_with_metrics};
use crate::llm_analysis::LlmAnalyzer;
use crate::llm_metrics::LlmMetricsTracker;
use crate::multi_verifier::{MultiVerifier, VerifierConfig};
use crate::poc_compiler::PocCompiler;
use crate::poc_generation::{PoCFormat, PoCGenerationEngine};
use crate::report::ai_aggregation::AiAggregationPhase;
use crate::report::html::generate_html_report;
use crate::report::json::write_findings_json;
use crate::root_cause_dedup::RootCauseDeduplicator;
use crate::semgrep::SemgrepRunner;
use crate::staging::{AutoPatcher, PatchingConfig};
use crate::threat_model::ThreatModelingPhase;
use crate::tickets::TicketSearcher;
use crate::variant_search::VariantSearcher;

use indicatif::ProgressBar;

use std::path::PathBuf;
use std::sync::Arc;

/// Configuration for run_phase execution
pub struct PhaseConfig<'a> {
    pub phase: &'a ScanPhase,
    pub findings: Vec<VulnerabilityFinding>,
    pub pb: &'a ProgressBar,
    pub analyzed_files: &'a [String],
    pub metrics_tracker: &'a LlmMetricsTracker,
    pub target_path: &'a std::path::Path,
    pub config: &'a config::ScannerConfig,
    pub project_stack: &'a Option<crate::scanner_types::project::ProjectStack>,
}

/// Execute a single scan phase and return updated findings and analyzed files
pub async fn run_phase(
    scanner: &super::Scanner,
    cfg: PhaseConfig<'_>,
) -> Result<(Vec<VulnerabilityFinding>, Vec<String>), String> {
    let PhaseConfig {
        phase,
        mut findings,
        pb,
        analyzed_files,
        metrics_tracker,
        target_path,
        config,
        project_stack,
    } = cfg;
    match phase {
        ScanPhase::Indexing => {
            // Index the project with incremental scanning
            tracing::info!("Running indexing phase on {:?}", target_path);

            // Try to load previous hash store for incremental scanning
            let hash_store_path = PathBuf::from(&config.output.dir).join("file_hashes.json");
            let _previous_hash_store = if hash_store_path.exists() {
                match crate::incremental_scan::FileHashStore::load(
                    &hash_store_path.to_string_lossy(),
                ) {
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
            let (index, hash_store) = match FileIndex::index_project_incremental(
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
        ScanPhase::Semgrep => {
            tracing::info!("Running Semgrep phase on {:?}", target_path);
            let runner = SemgrepRunner::new(None, config.scanner.semgrep.exclude_rules.clone());
            pb.set_message("Phase 2/11: Running Semgrep static analysis (scanning for known vulnerability patterns)...");

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
                        "Phase 2/11: Semgrep complete - {} findings discovered",
                        semgrep_count
                    ));
                    pb.set_position(pb.position() + 100);

                    Ok((findings, analyzed_files.to_vec()))
                }
                Err(e) => {
                    tracing::warn!("Semgrep failed: {}. Skipping phase.", e);
                    pb.set_message("Phase 2/11: Semgrep failed - skipping phase");
                    pb.set_position(pb.position() + 100);

                    Ok((findings, analyzed_files.to_vec()))
                }
            }
        }
        ScanPhase::LlmStaticAnalysis => {
            tracing::info!("Running LLM static analysis on {:?}", target_path);

            // Reset progress bar to 0-100 for this phase
            pb.set_length(100);
            pb.set_position(0);
            pb.set_message(
                "Phase 3/11: LLM static analysis (analyzing files for vulnerabilities)...",
            );

            let index = FileIndex::index_project(
                target_path.to_str().unwrap_or("."),
                &config.project.languages,
                config.scanner.max_file_size_kb * 1024,
                &config.scanner.exclude_paths,
            )
            .unwrap_or(FileIndex {
                files: Vec::new(),
                total_size: 0,
                hash_store: None,
            });

            let files = index.get_files();
            let file_count = files.len();

            // Check for LLM discovery API key (used by LlmStaticAnalysis)
            tracing::info!("[LLM] Phase config check for LlmStaticAnalysis");
            let phase_config = &config.llm.phases.discovery;
            tracing::info!(
                "[LLM] Phase config: base_url={}, api_key={:?}",
                phase_config.base_url,
                phase_config.api_key
            );

            if let Some(api_key) = &phase_config.api_key {
                let discovery_timeout =
                    phase_config.timeout_secs.unwrap_or(config.llm.timeout_secs);

                // Enable steady tick for progress bar timer
                pb.enable_steady_tick(std::time::Duration::from_millis(100));

                let llm_config = llm::LlmConfig {
                    base_url: phase_config.base_url.clone(),
                    api_key: api_key.clone(),
                    model: phase_config.model.clone(),
                    models: phase_config.get_models(),
                    timeout: discovery_timeout,
                    max_retries: config.llm.max_retries as u32,
                    retry_backoff_ms: config.llm.retry_backoff_ms,
                };

                let client = crate::llm::LlmClient::with_metrics(
                    llm_config.clone(),
                    Some(metrics_tracker.clone()),
                );
                let analyzer = LlmAnalyzer::new(
                    client,
                    config.project.languages.clone(),
                    config.scanner.max_file_size_kb as usize,
                    config,
                );

                let mut llm_findings = Vec::new();
                let mut new_analyzed_files: Vec<String> = analyzed_files.to_vec();

                for (i, file_info) in files.iter().enumerate() {
                    let file_path_str = file_info.path.to_string_lossy().to_string();
                    if analyzed_files.contains(&file_path_str) {
                        let progress_pct = ((i as f64 / file_count as f64) * 100.0) as u64;
                        pb.set_position(progress_pct);
                        pb.set_message(format!(
                            "Phase 3/11: Skipping already analyzed [{}]: {}",
                            i + 1,
                            file_info.path.display()
                        ));
                        continue;
                    }
                    let progress_pct = ((i as f64 / file_count as f64) * 100.0) as u64;
                    let pb_msg = pb.clone();
                    let msg = format!(
                        "Phase 3/11: LLM analyzing [{}/{}] ({:.0}%): {}",
                        i + 1,
                        file_count,
                        progress_pct,
                        file_info.path.display()
                    );
                    pb_msg.set_message(msg);
                    pb_msg.set_position(progress_pct);

                    match analyzer.analyze_file(&file_info.path).await {
                        Ok(file_findings) => {
                            llm_findings.extend(file_findings);
                            new_analyzed_files.push(file_path_str);
                            let pb_msg2 = pb.clone();
                            let msg = format!(
                                "Phase 3/11: LLM analyzing [{}/{}] ({:.0}%): {} - {} findings total",
                                i + 1, file_count, progress_pct,
                                file_info.path.display(),
                                llm_findings.len()
                            );
                            pb_msg2.set_message(msg);
                        }
                        Err(e) => {
                            tracing::warn!(
                                "LLM analysis failed for {}: {}",
                                file_info.path.display(),
                                e
                            );
                            let pb_msg3 = pb.clone();
                            let error_lines: Vec<&str> = e.lines().take(3).collect();
                            let error_summary = error_lines.join(" | ");
                            let msg = format!(
                                "Phase 3/11: {} - {} - FAILED: {}",
                                file_info.path.display(),
                                error_summary,
                                if i + 1 < file_count {
                                    format!("({}/{})", i + 1, file_count)
                                } else {
                                    "complete".to_string()
                                }
                            );
                            pb_msg3.set_message(msg);
                        }
                    }

                    // Yield to allow TUI updates
                    tokio::task::yield_now().await;
                }

                // Set position to 100 when complete
                pb.set_position(100);

                findings.extend(llm_findings.clone());
                pb.set_message(format!(
                    "Phase 3/11: LLM static analysis complete - {} findings discovered",
                    llm_findings.len()
                ));

                // Reset for next phase: set length back to show total progress
                pb.set_length(1100);
                pb.set_position(300); // End of phase 3 (3/11 * 100)
            } else {
                tracing::debug!("No API key for LLM analysis, skipping static analysis");
            }

            Ok((findings, analyzed_files.to_vec()))
        }
        ScanPhase::LlmDiscovery => {
            tracing::info!("Running LLM discovery phase...");
            pb.set_length(100);
            pb.set_position(0);
            pb.set_message("Phase 4/11: LLM discovery (enriching vulnerability descriptions with AI context)...");

            // Step 1: Detect project stack and fetch CVEs for threat intelligence
            pb.set_message("Phase 4/11: Detecting project stack and fetching CVE data...");
            let target_path_str = target_path.to_string_lossy().to_string();
            let bootstrapper = CveBootstrapper::new(target_path_str.clone());

            // Detect project stack (languages, frameworks, dependencies)
            let stack = match bootstrapper.detect_project_stack() {
                Ok(s) => {
                    tracing::info!(
                        "Detected project stack: {:?} languages, {:?} frameworks, {} dependencies",
                        s.languages,
                        s.frameworks,
                        s.dependencies.len()
                    );
                    s
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to detect project stack: {}, continuing without CVE enrichment",
                        e
                    );
                    crate::scanner_types::project::ProjectStack::default()
                }
            };

            // Fetch relevant CVEs asynchronously (CISA KEV + NVD)
            let cve_client = crate::cve_client::CveClient::new();
            let mut cve_entries = Vec::new();

            // Fetch KEV catalog (higher priority - known exploited vulnerabilities)
            match cve_client.fetch_kev_catalog().await {
                Ok(kev_cves) => {
                    tracing::info!("Fetched {} CVEs from CISA KEV catalog", kev_cves.len());
                    cve_entries.extend(kev_cves);
                }
                Err(e) => {
                    tracing::warn!("Failed to fetch KEV catalog: {}", e);
                }
            }

            // Fetch NVD CVEs for detected dependencies
            for dep in &stack.dependencies {
                let parts: Vec<&str> = dep.name.split('/').collect();
                let (vendor, product) = if parts.len() >= 2 {
                    (parts[0].to_string(), parts[1].to_string())
                } else {
                    let name = dep.name.split('-').next().unwrap_or(&dep.name).to_string();
                    (name.clone(), dep.name.clone())
                };

                match cve_client.fetch_nvd_cves(&vendor, &product).await {
                    Ok(nvd_cves) => {
                        cve_entries.extend(nvd_cves);
                    }
                    Err(e) => {
                        tracing::debug!("Failed to fetch NVD CVEs for {}: {}", dep.name, e);
                    }
                }
                // Small delay to avoid rate limiting
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }

            // Deduplicate CVE entries (KEV takes priority)
            let kev_entries: Vec<_> = cve_entries
                .iter()
                .filter(|c| c.source == crate::scanner_types::cve::CveSource::KEV)
                .cloned()
                .collect();
            let nvd_entries: Vec<_> = cve_entries
                .iter()
                .filter(|c| c.source != crate::scanner_types::cve::CveSource::KEV)
                .cloned()
                .collect();
            cve_entries = crate::cve_client::CveClient::dedup_cve_entries(kev_entries, nvd_entries);

            tracing::info!(
                "Total unique CVEs after deduplication: {}",
                cve_entries.len()
            );

            // Store CVE entries in scanner state for checkpointing
            // Note: This requires access to scanner state, caller should handle this

            // Step 2: Continue with LLM discovery/enrichment
            if let Some(_api_key) = &config.llm.phases.discovery.api_key {
                tracing::debug!("API key configured, running discovery");

                // Enable steady tick for progress bar timer
                pb.enable_steady_tick(std::time::Duration::from_millis(100));

                let client = create_llm_client_with_metrics(scanner, "discovery")
                    .expect("Failed to create LLM client for discovery phase");

                // Enrich each finding's description
                let total_findings = findings.len();
                let use_agent_mode = config.agent.enabled;

                for (i, finding) in findings.iter_mut().enumerate() {
                    let progress_pct = if total_findings > 0 {
                        ((i as f64 / total_findings as f64) * 100.0) as u64
                    } else {
                        100
                    };
                    pb.set_position(progress_pct);
                    pb.set_message(format!(
                        "Phase 4/11: Enriching findings [{}/{}] - {}",
                        i + 1,
                        total_findings,
                        finding.title
                    ));

                    if use_agent_mode {
                        let progress_cb = Arc::new(move |msg: String| {
                            tracing::debug!("Agent: {}", msg);
                        });
                        let agent_session = agent::AgentSession::new(
                            client.clone(),
                            &config.agent,
                            target_path,
                            progress_cb,
                        );

                        match agent_session.analyze_file(&finding.file_path).await {
                            Ok(agent_finding) => {
                                let converted: crate::findings::VulnerabilityFinding =
                                    agent_finding.into_finding();
                                finding.description = converted.description;
                                finding.severity = converted.severity;
                                finding.cwe_id = converted.cwe_id.or(finding.cwe_id.clone());
                                finding.line_number = converted.line_number.or(finding.line_number);
                                finding.diff_hunk =
                                    converted.diff_hunk.or(finding.diff_hunk.clone());
                                if finding.agent_evidence_path.is_none() {
                                    finding.agent_evidence_path = converted.agent_evidence_path;
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Agent analysis failed for {}: {}",
                                    finding.file_path,
                                    e
                                );
                            }
                        }
                    } else {
                        // Simple mode: also request fix_code in JSON format
                        let messages = vec![
                            llm::ChatMessage::system("You are a security vulnerability analyzer. Output valid JSON only."),
                            llm::ChatMessage::user(&format!(
                                r#"Vulnerability: {}
Location: {}:{}
Current description: {}

Respond with ONLY JSON:
{{
  "description": "Enriched description",
  "fix_code": "The secure version of the code"
}}"#,
                                finding.title,
                                finding.file_path,
                                finding.line_number.unwrap_or(0),
                                finding.description
                            ))
                        ];
                        if let Ok(response_with_model) = client.chat(&messages).await {
                            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(
                                &response_with_model.content,
                            ) {
                                if let Some(desc) =
                                    parsed.get("description").and_then(|v| v.as_str())
                                {
                                    finding.description = desc.to_string();
                                }
                                if let Some(fix) = parsed.get("fix_code").and_then(|v| v.as_str()) {
                                    finding.diff_hunk = Some(fix.to_string());
                                }
                            }
                        }
                    }
                }
                pb.set_position(100);
                pb.set_message(format!(
                    "Phase 4/11: Discovery complete - enriched {} findings",
                    total_findings
                ));

                // Reset for next phase
                pb.set_length(1100);
                pb.set_position(400); // End of phase 4 (4/11 * 100)
            } else {
                tracing::debug!("No API key for discovery, skipping LLM enrichment");
                pb.set_message("Phase 4/11: No API key configured - skipping discovery");
                pb.set_length(1100);
                pb.set_position(400);
            }
            Ok((findings, analyzed_files.to_vec()))
        }
        ScanPhase::LlmVerification => {
            tracing::info!("Running LLM verification phase...");
            pb.set_length(100);
            pb.set_position(0);
            pb.set_message(
                "Phase 5/11: LLM verification (validating findings with AI analysis)...",
            );

            let total_findings = findings.len();
            let use_agent_mode = config.agent.enabled;

            if let Some(_api_key) = &config.llm.phases.verification.api_key {
                pb.enable_steady_tick(std::time::Duration::from_millis(100));

                let client = create_llm_client_with_metrics(scanner, "verification")
                    .expect("Failed to create LLM client for verification phase");

                if use_agent_mode {
                    let progress_cb = Arc::new(move |msg: String| {
                        tracing::debug!("Agent verify: {}", msg);
                    });
                    let agent_session =
                        agent::AgentSession::new(client, &config.agent, target_path, progress_cb);

                    for (i, finding) in findings.iter_mut().enumerate() {
                        let progress_pct = if total_findings > 0 {
                            ((i as f64 / total_findings as f64) * 100.0) as u64
                        } else {
                            100
                        };
                        pb.set_position(progress_pct);
                        pb.set_message(format!(
                            "Phase 5/11: Agent verifying [{}/{}] - {}",
                            i + 1,
                            total_findings,
                            finding.title
                        ));

                        match agent_session
                            .verify_finding(&finding.file_path, finding)
                            .await
                        {
                            Ok(agent_finding) => {
                                let converted: crate::findings::VulnerabilityFinding =
                                    agent_finding.into_finding();
                                finding.verification_status = converted.verification_status;
                                finding.verification_notes = converted
                                    .verification_notes
                                    .or(finding.verification_notes.clone());
                                if finding.agent_evidence_path.is_none() {
                                    finding.agent_evidence_path = converted.agent_evidence_path;
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Agent verification failed for {}: {}",
                                    finding.file_path,
                                    e
                                );
                                finding.verification_status = Some(VerificationStatus::NeedsReview);
                                finding.verification_notes = Some(format!("Agent error: {}", e));
                            }
                        }

                        tokio::task::yield_now().await;
                    }
                } else {
                    // Non-agent mode: use direct LLM verification
                    for (i, finding) in findings.iter_mut().enumerate() {
                        let progress_pct = if total_findings > 0 {
                            ((i as f64 / total_findings as f64) * 100.0) as u64
                        } else {
                            100
                        };
                        pb.set_position(progress_pct);
                        pb.set_message(format!(
                            "Phase 5/11: Verifying findings [{}/{}] - {}",
                            i + 1,
                            total_findings,
                            finding.title
                        ));

                        let messages = vec![
                            llm::ChatMessage::system(
                                "You are a security vulnerability verifier. Analyze the finding and determine if it's a true positive, false positive, or needs review. Return JSON with verification_status (confirmed/false_positive/needs_review) and verification_notes."
                            ),
                            llm::ChatMessage::user(&format!(
                                "Vulnerability: {}\nLocation: {}:{}\nDescription: {}\nSources: {:?}",
                                finding.title,
                                finding.file_path,
                                finding.line_number.unwrap_or(0),
                                finding.description,
                                finding.sources
                            ))
                        ];
                        let result = client.chat(&messages).await;

                        if let Ok(response_with_model) = result {
                            if response_with_model.content.contains("confirmed") {
                                finding.verification_status = Some(VerificationStatus::Confirmed);
                                finding.verification_notes =
                                    Some("LLM verified as true positive".to_string());
                            } else if response_with_model.content.contains("false_positive") {
                                finding.verification_status =
                                    Some(VerificationStatus::FalsePositive);
                                finding.verification_notes =
                                    Some(response_with_model.content.clone());
                            } else {
                                finding.verification_status = Some(VerificationStatus::NeedsReview);
                                finding.verification_notes =
                                    Some(response_with_model.content.clone());
                            }
                        }
                    }
                }
                pb.set_position(100);
                pb.set_message(format!(
                    "Phase 5/11: Verification complete - verified {} findings",
                    total_findings
                ));
            } else {
                tracing::debug!("No API key for verification, skipping LLM verification");
                pb.set_message("Phase 5/11: No API key configured - skipping verification");
            }

            // Step 2: Generate PoCs for high-severity confirmed findings
            pb.set_message("Phase 5/11: Generating PoCs for high-severity findings...");

            let context = crate::context::AnalysisContext::default();
            let poc_engine = PoCGenerationEngine::new();

            // Determine target languages for PoC based on project stack
            let poc_formats = if let Some(ref stack) = project_stack {
                let mut formats = Vec::new();
                for lang in &stack.languages {
                    match lang.to_lowercase().as_str() {
                        "rust" => formats.push(PoCFormat::Rust),
                        "python" => formats.push(PoCFormat::Python),
                        "javascript" | "typescript" => formats.push(PoCFormat::Python), // Default to Python for JS
                        "go" => formats.push(PoCFormat::Go),
                        _ => formats.push(PoCFormat::Python),
                    }
                }
                if formats.is_empty() {
                    formats.push(PoCFormat::Python);
                }
                formats
            } else {
                vec![PoCFormat::Python]
            };

            // Generate PoCs for findings that are confirmed or have high severity
            let high_severity_findings: Vec<_> = findings
                .iter()
                .filter(|f| {
                    matches!(
                        f.verification_status,
                        Some(VerificationStatus::Confirmed) | None
                    ) && f.severity.is_high_or_critical()
                })
                .cloned()
                .collect();

            if !high_severity_findings.is_empty() {
                let poc_result =
                    poc_engine.generate(&high_severity_findings, &context, &poc_formats);
                let poc_count = poc_result.proofs.len();

                for poc in &poc_result.proofs {
                    if let Some(finding) = findings.iter_mut().find(|f| f.id == poc.finding_id) {
                        finding.poc_code = Some(poc.code.clone());
                        finding.poc_format = Some(match poc.format {
                            PoCFormat::Rust => "rust".to_string(),
                            PoCFormat::Python => "python".to_string(),
                            PoCFormat::Shell => "shell".to_string(),
                            PoCFormat::Go => "go".to_string(),
                        });

                        // Step 3: Validate PoC using compiler
                        let lang_str = match poc.format {
                            PoCFormat::Rust => "rust",
                            PoCFormat::Python => "python",
                            PoCFormat::Shell => "shell",
                            PoCFormat::Go => "go",
                        };

                        let compile_result = PocCompiler::compile_check(&poc.code, lang_str);

                        if compile_result.compiles {
                            tracing::debug!("PoC compiled successfully for finding {}", finding.id);
                        } else {
                            tracing::warn!(
                                "PoC compilation failed for finding {}: {:?}",
                                finding.id,
                                compile_result.errors
                            );
                        }
                    }
                }

                // Also generate mitigation code
                for finding in &mut findings.iter_mut().filter(|f| {
                    matches!(
                        f.verification_status,
                        Some(VerificationStatus::Confirmed) | None
                    ) && f.severity.is_high_or_critical()
                }) {
                    if let Some(mitigation) = poc_engine.generate_mitigation(finding) {
                        finding.mitigation_code = Some(mitigation.code);
                    }
                }

                tracing::info!(
                    "Generated {} PoCs for {} high-severity findings",
                    poc_count,
                    high_severity_findings.len()
                );
            }

            pb.set_position(pb.position() + 100);
            Ok((findings, analyzed_files.to_vec()))
        }
        ScanPhase::SecurityAgentVerification => {
            tracing::info!("Running SecurityAgent verification phase...");

            if !config.agent.enabled {
                tracing::debug!("Agent mode disabled, skipping SecurityAgent verification");
                pb.set_message("Phase 6/11: Agent mode disabled - skipping");
                pb.set_length(100);
                pb.set_position(100);
                return Ok((findings, analyzed_files.to_vec()));
            }

            let Some(_api_key) = &config.llm.phases.discovery.api_key else {
                tracing::debug!("No API key for agent, skipping SecurityAgent verification");
                pb.set_message("Phase 6/11: No API key - skipping");
                pb.set_length(100);
                pb.set_position(100);
                return Ok((findings, analyzed_files.to_vec()));
            };

            pb.set_length(100);
            pb.set_position(0);
            pb.set_message("Phase 6/11: SecurityAgent verification (tool-based analysis)...");

            let total_findings = findings.len();

            let client = create_llm_client_with_metrics(scanner, "discovery")
                .expect("Failed to create LLM client for SecurityAgent phase");

            for (i, finding) in findings.iter_mut().enumerate() {
                let progress_pct = if total_findings > 0 {
                    ((i as f64 / total_findings as f64) * 100.0) as u64
                } else {
                    100
                };
                pb.set_position(progress_pct);
                pb.set_message(format!(
                    "Phase 6/11: SecurityAgent verifying [{}/{}] - {}",
                    i + 1,
                    total_findings,
                    finding.title
                ));

                let agent = agent::AgentSession::new(
                    client.clone(),
                    &config.agent,
                    target_path,
                    Arc::new(|msg| tracing::debug!("[AGENT] {}", msg)),
                );

                match agent.verify_finding(&finding.file_path, finding).await {
                    Ok(agent_result) => {
                        // Store evidence path
                        if let Some(ref path) = agent_result.compile_path {
                            finding.agent_evidence_path = Some(path.to_string_lossy().to_string());
                        } else if let Some(ref path) = agent_result.test_source_path {
                            finding.agent_evidence_path = Some(path.to_string_lossy().to_string());
                        } else if agent_result.agent_turns > 0 {
                            finding.agent_evidence_path = Some(format!(
                                "{} turns, {} tools",
                                agent_result.agent_turns,
                                agent_result.tools_used.len()
                            ));
                        }

                        // Store test log
                        if let Some(ref log) = agent_result.test_log {
                            if finding.verification_notes.is_none() {
                                finding.verification_notes = Some(log.clone());
                            }
                        }

                        tracing::debug!(
                            "SecurityAgent verified {}: {:?} - {} turns, {} tools",
                            finding.title,
                            finding.verification_status,
                            agent_result.agent_turns,
                            agent_result.tools_used.len()
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "SecurityAgent verification failed for {}: {}",
                            finding.title,
                            e
                        );
                        finding.verification_status = Some(VerificationStatus::Failed);
                        finding.verification_notes =
                            Some(format!("Agent verification failed: {}", e));
                    }
                }
            }

            pb.set_position(100);
            tracing::info!(
                "SecurityAgent verification complete - {} findings",
                total_findings
            );
            Ok((findings, analyzed_files.to_vec()))
        }
        ScanPhase::TicketCrossRef => {
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
                let searcher = TicketSearcher::new(systems);
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
        ScanPhase::GitAnalysis => {
            tracing::info!("Running Git analysis phase...");

            match GitAnalyzer::new(target_path.to_str().unwrap_or(".")) {
                Ok(analysis) => {
                    let remote_url =
                        super::Scanner::get_git_remote_url(target_path.to_str().unwrap_or("."));
                    for finding in &mut findings {
                        #[allow(deprecated)]
                        let _commits = analysis
                            .find_related_commits(&finding.file_path, finding.line_number)
                            .unwrap_or_default();
                        if let Some(commit) = _commits.first() {
                            let commit_ref = if let Some(ref url) = remote_url {
                                let owner_repo = super::Scanner::extract_owner_repo_from_url(url);
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
        ScanPhase::CrossFileAnalysis => {
            tracing::info!("Running cross-file analysis phase...");
            findings =
                crate::crossfile::CrossFileAnalyzer::analyze_cross_file_references(&findings);
            pb.set_position(pb.position() + 100);
            Ok((findings, analyzed_files.to_vec()))
        }
        ScanPhase::ConfidenceScoring => {
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
                match AnalysisContext::load(&output_path) {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        tracing::warn!("Failed to load analysis context: {}, using default", e);
                        AnalysisContext::default()
                    }
                }
            } else {
                AnalysisContext::default()
            };

            // Run confidence refinement
            let refinement = ConfidenceRefinementPhase::new();
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
        ScanPhase::AiAggregation => {
            tracing::info!("Running AI aggregation phase...");
            let llm_config = llm::LlmConfig {
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
            };

            let aggregation = AiAggregationPhase::new(llm_config);

            // Enrich findings with LLM analysis (populates description and recommendation)
            let (enriched_findings, _llm_failed) =
                aggregation.enrich_findings_with_llm(&findings).await;

            tracing::debug!("AI aggregation complete");
            pb.set_position(pb.position() + 100);
            Ok((enriched_findings, analyzed_files.to_vec()))
        }
        ScanPhase::Reporting => {
            tracing::info!("Running reporting phase to {:?}", config.output.dir);

            // Finalize metrics and get summary
            let llm_metrics = metrics_tracker.finalize().await;

            let json_path = format!("{}/findings.json", config.output.dir);
            if let Err(e) = write_findings_json(&findings, json_path.as_str(), Some(llm_metrics)) {
                tracing::warn!("Failed to write JSON report: {}", e);
            }

            let html_path = format!("{}/report.html", config.output.dir);
            if let Err(e) = generate_html_report(&findings, &html_path, Some(config), None) {
                tracing::warn!("Failed to write HTML report: {}", e);
            }

            pb.set_position(pb.position() + 100);
            Ok((findings, analyzed_files.to_vec()))
        }
        ScanPhase::ThreatModeling => {
            // Skip if disabled via performance settings
            if !config.scanner.performance.enable_threat_modeling {
                tracing::info!("Threat modeling phase disabled via config, skipping");
                return Ok((findings, analyzed_files.to_vec()));
            }

            tracing::info!("Running threat modeling phase");

            // Load or create analysis context
            let output_path = PathBuf::from(&config.output.dir);
            let context = if output_path.exists() {
                match AnalysisContext::load(&output_path) {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        tracing::warn!("Failed to load analysis context: {}, creating new one", e);
                        AnalysisContext::default()
                    }
                }
            } else {
                AnalysisContext::default()
            };

            // Run threat modeling
            match ThreatModelingPhase::run(&output_path, &context, None).await {
                Ok(threat_model) => {
                    // If threat model generated, add it as a finding
                    if !threat_model.is_empty() {
                        let finding = VulnerabilityFinding {
                            id: format!(
                                "threat-model-{}",
                                chrono::Utc::now().format("%Y%m%d%H%M%S")
                            ),
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
        ScanPhase::RootCauseDedup => {
            // Skip if disabled via performance settings
            if !config.scanner.performance.enable_root_cause_dedup {
                tracing::info!("Root cause deduplication phase disabled via config, skipping");
                return Ok((findings, analyzed_files.to_vec()));
            }

            tracing::info!("Running root cause deduplication phase");

            let mut dedup = RootCauseDeduplicator::new();
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
        ScanPhase::MultiVerifier => {
            // Skip if disabled via performance settings
            if !config.scanner.performance.enable_multi_verifier {
                tracing::info!("Multi verifier phase disabled via config, skipping");
                return Ok((findings, analyzed_files.to_vec()));
            }

            tracing::info!("Running multi verifier phase");

            let config_verifier = VerifierConfig {
                num_verifiers: 3,
                circuit_breaker_threshold: 0.5,
            };
            let verifier = MultiVerifier::new(config_verifier);
            let verified_findings = verifier.verify_batch(&findings);

            tracing::info!(
                "Multi verifier: {} findings → {} findings",
                findings.len(),
                verified_findings.len()
            );
            Ok((verified_findings, analyzed_files.to_vec()))
        }
        ScanPhase::AutoPatching => {
            // Skip if disabled via performance settings
            if !config.scanner.performance.enable_auto_patching {
                tracing::info!("Auto patching phase disabled via config, skipping");
                return Ok((findings, analyzed_files.to_vec()));
            }

            tracing::info!("Running auto patching phase");

            let patcher = AutoPatcher::new(target_path.to_path_buf());
            let patching_config = PatchingConfig::default();

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
        ScanPhase::CveBootstrap => {
            // Skip if disabled via config
            if !config.scanner.performance.enable_cve_bootstrap {
                tracing::info!("CVE bootstrap phase disabled via config, skipping");
                return Ok((findings, analyzed_files.to_vec()));
            }

            tracing::info!("Running CVE bootstrap phase");

            let bootstrapper = CveBootstrapper::new(target_path.to_string_lossy().to_string());

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
        ScanPhase::PocCompiler => {
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
                    let result = PocCompiler::compile_check(poc_code, language);

                    if result.compiles {
                        finding.verification_status =
                            Some(crate::findings::VerificationStatus::Confirmed);
                    } else {
                        finding.verification_status =
                            Some(crate::findings::VerificationStatus::Failed);
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
        ScanPhase::VariantSearch => {
            // Skip if disabled via config
            if !config.scanner.performance.enable_variant_search {
                tracing::info!("Variant search phase disabled via config, skipping");
                return Ok((findings, analyzed_files.to_vec()));
            }

            tracing::info!("Running variant search phase");

            let searcher = VariantSearcher::new(target_path.to_string_lossy().to_string());

            // For now, return empty variants (full implementation requires more work)
            match searcher.search_variants() {
                Ok(_hits) => {
                    // Future: convert hits to findings and merge
                    tracing::info!("Variant search completed (stub implementation)");
                    Ok((findings, analyzed_files.to_vec()))
                }
                Err(e) => {
                    tracing::warn!("Variant search failed: {}", e);
                    Ok((findings, analyzed_files.to_vec()))
                }
            }
        }
        _ => {
            tracing::warn!("Unknown phase: {:?}. Skipping.", phase);
            Ok((findings, analyzed_files.to_vec()))
        }
    }
}
