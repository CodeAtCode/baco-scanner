use super::PhaseConfig;
use crate::agent;
use crate::context::callee_walker::extract_call_sites;
use crate::context::pacvd_extractor::{self, AbstractionLevel};
use crate::context::semantic_path;
use crate::context::triple_path::TriplePathContext;
use crate::cve_bootstrap::CveBootstrapper;
use crate::error::ScanResult;
use crate::findings::VerificationStatus;
use crate::findings::VulnerabilityFinding;
use crate::llm;
use crate::llm_analysis::LlmAnalyzer;
use crate::poc_compiler::PocCompiler;
use crate::poc_generation::PoCFormat;
use crate::poc_generation::PoCGenerationEngine;
use crate::retrieval::CweKnowledgeBase;
use regex::Regex;

/// Run LLM static analysis phase (Phase 3/20)
use std::sync::Arc;

/// Detect language from file path
fn detect_language(path: &std::path::Path) -> crate::context::control_path::Language {
    match path.extension().and_then(|e| e.to_str()) {
        Some("c" | "h") => crate::context::control_path::Language::C,
        Some("rs") => crate::context::control_path::Language::Rust,
        Some("py") => crate::context::control_path::Language::Python,
        Some("js" | "jsx" | "ts" | "tsx") => crate::context::control_path::Language::JavaScript,
        _ => crate::context::control_path::Language::C, // Default fallback
    }
}

/// Extract function name from a finding's title or code snippet.
///
/// Looks for patterns like "function X", "def X", "fn X" in the title or code_snippet.
fn extract_function_name_from_finding(finding: &VulnerabilityFinding) -> Option<String> {
    let patterns = [
        r"function\s+([a-zA-Z_][a-zA-Z0-9_]*)",
        r"def\s+([a-zA-Z_][a-zA-Z0-9_]*)",
        r"fn\s+([a-zA-Z_][a-zA-Z0-9_]*)",
        r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",
    ];

    let text_to_search = finding.code_snippet.as_deref().unwrap_or(&finding.title);

    for pattern in &patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(caps) = re.captures(text_to_search) {
                if let Some(matched) = caps.get(1) {
                    let name = matched.as_str().to_string();
                    // Filter out common keywords
                    if !matches!(
                        name.as_str(),
                        "if" | "for" | "while" | "match" | "let" | "const" | "var"
                    ) {
                        return Some(name);
                    }
                }
            }
        }
    }

    None
}

/// Run policy sampling for a single file (VulnLLM-R P2.2)
/// Returns a set of CWE IDs collected from multiple high-temperature samples
async fn run_policy_sampling(
    llm_config: &llm::LlmConfig,
    file_path: &std::path::Path,
    samples: u8,
    language_hint: &str,
) -> Result<std::collections::HashSet<String>, String> {
    use std::collections::HashSet;

    // Create a new client with temperature 0.8 for sampling
    let mut sampling_config = llm_config.clone();
    sampling_config.temperature = 0.8;
    let client = llm::LlmClient::with_metrics(sampling_config, None);

    // Read file content
    let content = std::fs::read_to_string(file_path)
        .map_err(|e| format!("Failed to read file for policy sampling: {}", e))?;

    // Determine language label
    let lang = match language_hint {
        "rust" | "Rust" => "rust",
        "c" | "C" => "c",
        "python" | "Python" => "python",
        "javascript" | "JavaScript" | "typescript" | "TypeScript" => "javascript",
        _ => "plaintext",
    };

    let file_path_str = file_path.to_string_lossy().to_string();
    let mut all_cwes = HashSet::new();

    // Compile regex once outside the loop
    let cwe_re = regex::Regex::new(r"CWE-\d+").map_err(|e| format!("Regex error: {}", e))?;

    // Run sampling loop
    for i in 0..samples {
        let messages = vec![
            llm::ChatMessage::system("You are a vulnerability analyst."),
            llm::ChatMessage::user(&format!(
                "Analyze this file for vulnerabilities. List CWE IDs you suspect.\n\nFile: {}\n```{}\n{}\n```",
                file_path_str, lang, content
            )),
        ];

        match client.chat(&messages).await {
            Ok(response) => {
                // Parse CWE IDs from response using regex
                for cap in cwe_re.find_iter(&response.content) {
                    all_cwes.insert(cap.as_str().to_string());
                }
                tracing::debug!(
                    "Policy sample {}/{}: found {} new CWEs",
                    i + 1,
                    samples,
                    all_cwes.len()
                );
            }
            Err(e) => {
                tracing::debug!("Policy sample {}/{} failed: {}", i + 1, samples, e);
                // Continue to next sample
            }
        }
    }

    Ok(all_cwes)
}

pub async fn run_llm_static_analysis(
    _scanner: &super::super::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        mut findings,
        pb,
        analyzed_files,
        metrics_tracker,
        target_path,
        config,
        project_stack: _,
    } = cfg;

    tracing::info!("Running LLM static analysis on {:?}", target_path);

    // Capture base position for intra-phase progress
    let base = pb.position();
    pb.set_message("Phase 3/20: LLM static analysis (analyzing files for vulnerabilities)...");

    let index = crate::indexer::FileIndex::index_project(
        target_path.to_str().unwrap_or("."),
        &config.project.languages,
        config.scanner.max_file_size_kb * 1024,
        &config.scanner.exclude_paths,
    )
    .unwrap_or(crate::indexer::FileIndex {
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
        let discovery_timeout = phase_config.timeout_secs.unwrap_or(config.llm.timeout_secs);

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
            temperature: 0.5,
            max_reasoning_tokens: config.llm.max_reasoning_tokens,
        };

        let client =
            crate::llm::LlmClient::with_metrics(llm_config.clone(), Some(metrics_tracker.clone()));
        let mut analyzer = LlmAnalyzer::new(
            client.clone(),
            config.project.languages.clone(),
            config.scanner.max_file_size_kb as usize,
            config,
        );

        let mut llm_findings = Vec::new();
        let mut new_analyzed_files: Vec<String> = analyzed_files.to_vec();

        // Load CWE knowledge base for triple-path context
        let cwe_kb = CweKnowledgeBase::load_embedded().ok();

        // Get max_context_tokens for PacVD auto-level selection
        let max_context_tokens = config.llm.max_reasoning_tokens.unwrap_or(32768);

        for (i, file_info) in files.iter().enumerate() {
            let file_path_str = file_info.path.to_string_lossy().to_string();
            if analyzed_files.contains(&file_path_str) {
                let progress_pct = ((i as f64 / file_count as f64) * 100.0) as u64;
                pb.set_position(base + progress_pct);
                pb.set_message(format!(
                    "Phase 3/20: Skipping already analyzed [{}]: {}",
                    i + 1,
                    file_info.path.display()
                ));
                continue;
            }
            let progress_pct = ((i as f64 / file_count as f64) * 100.0) as u64;
            let msg = format!(
                "Phase 3/20: LLM analyzing [{}/{}] ({:.0}%): {}",
                i + 1,
                file_count,
                progress_pct,
                file_info.path.display()
            );
            pb.set_message(msg);
            pb.set_position(base + progress_pct);

            // Build context if enabled
            let context_prefix = if config.vultriage.enabled || config.pacvd.enabled {
                let mut prefix_parts = Vec::new();

                if let Some(ref kb) = cwe_kb {
                    if let Ok(source) = std::fs::read_to_string(&file_info.path) {
                        // Triple path context
                        if config.vultriage.enabled {
                            let lang = detect_language(&file_info.path);
                            if let Ok(triple_ctx) = TriplePathContext::build(&source, lang, kb, 3) {
                                let mut triple_ctx = triple_ctx;
                                if config.vultriage.semantic_path {
                                    match semantic_path::summarize(&source, &client).await {
                                        Ok(sp) => {
                                            triple_ctx = triple_ctx.with_semantic(sp.summary);
                                        }
                                        Err(e) => {
                                            tracing::debug!(
                                                "semantic_path::summarize failed: {}",
                                                e
                                            );
                                        }
                                    }
                                }
                                prefix_parts.push(triple_ctx.to_prompt_section());
                            }
                        }

                        // PacVD context
                        if config.pacvd.enabled {
                            let sites = extract_call_sites(&source);
                            let level = if config.pacvd.auto_level {
                                pacvd_extractor::auto_level(max_context_tokens)
                            } else {
                                match config.pacvd.level {
                                    1 => AbstractionLevel::Primitive,
                                    2 => AbstractionLevel::Typed,
                                    3 => AbstractionLevel::Grouped,
                                    _ => AbstractionLevel::Semantic,
                                }
                            };
                            let av = pacvd_extractor::extract(&sites, level);
                            prefix_parts.push(av.to_prompt_section());
                        }
                    }
                }

                if prefix_parts.is_empty() {
                    None
                } else {
                    Some(prefix_parts.join("\n\n"))
                }
            } else {
                None
            };

            // Policy sampling (VulnLLM-R P2.2) - run before final analysis
            let policy_prefix = if config.policy_sampling.enabled {
                match run_policy_sampling(
                    &llm_config,
                    &file_info.path,
                    config.policy_sampling.samples,
                    &file_info.language,
                )
                .await
                {
                    Ok(policy_cwes) if !policy_cwes.is_empty() => {
                        let cwe_list = policy_cwes
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ");
                        tracing::debug!(
                            "Policy sampling collected {} CWEs: {}",
                            policy_cwes.len(),
                            cwe_list
                        );
                        Some(format!(
                            "Policy sampling suggests these CWEs may be present: {}. Verify carefully.",
                            cwe_list
                        ))
                    }
                    Ok(_) => {
                        tracing::debug!(
                            "Policy sampling found no CWEs, falling through to normal path"
                        );
                        None
                    }
                    Err(e) => {
                        tracing::debug!(
                            "Policy sampling failed: {}, falling through to normal path",
                            e
                        );
                        None
                    }
                }
            } else {
                None
            };

            // Combine existing context_prefix with policy_prefix if both exist
            let final_context_prefix = match (context_prefix, policy_prefix) {
                (Some(base), Some(policy)) => Some(format!("{}\n\n{}", base, policy)),
                (Some(base), None) => Some(base),
                (None, Some(policy)) => Some(policy),
                (None, None) => None,
            };

            // Inject context into analyzer if built
            if let Some(ctx) = final_context_prefix {
                analyzer = analyzer.with_context_prefix(ctx);
            }

            match analyzer.analyze_file(&file_info.path).await {
                Ok(file_findings) => {
                    llm_findings.extend(file_findings);
                    new_analyzed_files.push(file_path_str);
                    let msg = format!(
                        "Phase 3/20: LLM analyzing [{}/{}] ({:.0}%): {} - {} findings total",
                        i + 1,
                        file_count,
                        progress_pct,
                        file_info.path.display(),
                        llm_findings.len()
                    );
                    pb.set_message(msg);
                }
                Err(e) => {
                    tracing::warn!(
                        "LLM analysis failed for {}: {}",
                        file_info.path.display(),
                        e
                    );
                    let error_lines: Vec<&str> = e.lines().take(3).collect();
                    let error_summary = error_lines.join(" | ");
                    let msg = format!(
                        "Phase 3/20: {} - {} - FAILED: {}",
                        file_info.path.display(),
                        error_summary,
                        if i + 1 < file_count {
                            format!("({}/{})", i + 1, file_count)
                        } else {
                            "complete".to_string()
                        }
                    );
                    pb.set_message(msg);
                }
            }

            // Yield to allow TUI updates
            tokio::task::yield_now().await;
        }

        // Set position to base + 100 when complete
        pb.set_position(base + 100);

        findings.extend(llm_findings.clone());
        pb.set_message(format!(
            "Phase 3/20: LLM static analysis complete - {} findings discovered",
            llm_findings.len()
        ));
    } else {
        tracing::debug!("No API key for LLM analysis, skipping static analysis");
    }

    Ok((findings, analyzed_files.to_vec()))
}

/// Run LLM discovery phase (Phase 4/20)
pub async fn run_llm_discovery(
    scanner: &super::super::Scanner,
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

    tracing::info!("Running LLM discovery phase...");
    let base = pb.position();
    pb.set_message(
        "Phase 4/20: LLM discovery (enriching vulnerability descriptions with AI context)...",
    );

    // Step 1: Detect project stack and fetch CVEs for threat intelligence
    pb.set_message("Phase 4/20: Detecting project stack and fetching CVE data...");
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

        let client = crate::llm::create_llm_client_with_metrics(scanner, "discovery")
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
            pb.set_position(base + progress_pct);
            pb.set_message(format!(
                "Phase 4/20: Enriching findings [{}/{}] - {}",
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
                        finding.diff_hunk = converted.diff_hunk.or(finding.diff_hunk.clone());
                        if finding.agent_evidence_path.is_none() {
                            finding.agent_evidence_path = converted.agent_evidence_path;
                        }
                    }
                    Err(e) => {
                        // Silently skip expected errors (placeholder paths, missing files)
                        if !e.starts_with("PLACEHOLDER_PATH:") && !e.starts_with("FILE_NOT_FOUND:")
                        {
                            tracing::warn!(
                                "Agent analysis failed for {}: {}",
                                finding.file_path,
                                e
                            );
                        }
                    }
                }
            } else {
                // Simple mode: also request fix_code in JSON format
                let messages = vec![
                    llm::ChatMessage::system(
                        "You are a security vulnerability analyzer. Output valid JSON only.",
                    ),
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
                    )),
                ];
                if let Ok(response_with_model) = client.chat(&messages).await {
                    if let Ok(parsed) =
                        serde_json::from_str::<serde_json::Value>(&response_with_model.content)
                    {
                        if let Some(desc) = parsed.get("description").and_then(|v| v.as_str()) {
                            finding.description = desc.to_string();
                        }
                        if let Some(fix) = parsed.get("fix_code").and_then(|v| v.as_str()) {
                            finding.diff_hunk = Some(fix.to_string());
                        }
                    }
                }
            }
        }
        pb.set_position(base + 100);
        pb.set_message(format!(
            "Phase 4/20: Discovery complete - enriched {} findings",
            total_findings
        ));
    } else {
        tracing::debug!("No API key for discovery, skipping LLM enrichment");
        pb.set_message("Phase 4/20: No API key configured - skipping discovery");
        pb.set_position(base + 100);
    }
    Ok((findings, analyzed_files.to_vec()))
}

/// Run LLM verification phase (Phase 5/20)
pub async fn run_llm_verification(
    scanner: &super::super::Scanner,
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
        project_stack,
    } = cfg;

    tracing::info!("Running LLM verification phase...");
    let base = pb.position();
    pb.set_message("Phase 5/20: LLM verification (validating findings with AI analysis)...");

    let total_findings = findings.len();
    let use_agent_mode = config.agent.enabled;

    if let Some(_api_key) = &config.llm.phases.verification.api_key {
        pb.enable_steady_tick(std::time::Duration::from_millis(100));

        let client = crate::llm::create_llm_client_with_metrics(scanner, "verification")
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
                pb.set_position(base + progress_pct);
                pb.set_message(format!(
                    "Phase 5/20: Agent verifying [{}/{}] - {}",
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
                pb.set_position(base + progress_pct);
                pb.set_message(format!(
                    "Phase 5/20: Verifying findings [{}/{}] - {}",
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
                        finding.verification_status = Some(VerificationStatus::FalsePositive);
                        finding.verification_notes = Some(response_with_model.content.clone());
                    } else {
                        finding.verification_status = Some(VerificationStatus::NeedsReview);
                        finding.verification_notes = Some(response_with_model.content.clone());
                    }
                }
            }
        }
        pb.set_position(base + 100);
        pb.set_message(format!(
            "Phase 5/20: Verification complete - verified {} findings",
            total_findings
        ));
    } else {
        tracing::debug!("No API key for verification, skipping LLM verification");
        pb.set_message("Phase 5/20: No API key configured - skipping verification");
    }

    // Step 2: Generate PoCs for high-severity confirmed findings
    pb.set_message("Phase 5/20: Generating PoCs for high-severity findings...");

    let context = crate::analysis_context::AnalysisContext::default();
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
        let poc_result = poc_engine.generate(&high_severity_findings, &context, &poc_formats);
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

/// Run Security Agent verification phase (Phase 6/20)
pub async fn run_security_agent_verification(
    scanner: &super::super::Scanner,
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

    tracing::info!("Running Security Agent verification phase...");

    let base = pb.position();

    if !config.agent.enabled {
        tracing::debug!("Agent mode disabled, skipping Security Agent verification");
        pb.set_message("Phase 6/20: Agent mode disabled - skipping");
        pb.set_position(base + 100);
        return Ok((findings, analyzed_files.to_vec()));
    }

    let Some(_api_key) = &config.llm.phases.discovery.api_key else {
        tracing::debug!("No API key for agent, skipping Security Agent verification");
        pb.set_message("Phase 6/20: No API key - skipping");
        pb.set_position(base + 100);
        return Ok((findings, analyzed_files.to_vec()));
    };

    pb.set_message("Phase 6/20: Security Agent verification (tool-based analysis)...");

    let total_findings = findings.len();

    let client = crate::llm::create_llm_client_with_metrics(scanner, "discovery")
        .expect("Failed to create LLM client for Security Agent phase");

    // Agent scaffold context (P2.5) - build once before the findings loop
    let (fn_lookup_opt, call_graph_opt) = if config.agent_scaffold.enabled {
        tracing::info!("Agent scaffold enabled, building function lookup and call graph");

        // Convert config.project.languages (Vec<String>) to Language enum
        let languages: Vec<crate::context::control_path::Language> = config
            .project
            .languages
            .iter()
            .map(|s| match s.to_lowercase().as_str() {
                "c" => crate::context::control_path::Language::C,
                "rust" => crate::context::control_path::Language::Rust,
                "python" => crate::context::control_path::Language::Python,
                "javascript" => crate::context::control_path::Language::JavaScript,
                _ => crate::context::control_path::Language::C, // fallback
            })
            .collect();

        // Build FunctionLookup
        let mut fn_lookup = crate::agent_scaffold::fn_lookup::FunctionLookup::new();
        let max_file_size = (config.scanner.max_file_size_kb * 1024) as usize;
        let exclude_paths = &config.scanner.exclude_paths;

        if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fn_lookup.index_directory(target_path, &languages, max_file_size, exclude_paths);
        })) {
            tracing::warn!("FunctionLookup indexing panicked: {:?}", e);
            (None, None)
        } else {
            // Build CallGraph
            let mut call_graph_builder =
                crate::agent_scaffold::call_graph_paths::CallGraphBuilder::new();

            let build_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // Walk directory and add source files
                for entry in walkdir::WalkDir::new(target_path)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    let path = entry.path();
                    if !path.is_file() {
                        continue;
                    }

                    let path_str = path.to_string_lossy();
                    if exclude_paths.iter().any(|p| path_str.contains(p)) {
                        continue;
                    }

                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        let lang = match ext {
                            "c" | "h" => crate::context::control_path::Language::C,
                            "rs" => crate::context::control_path::Language::Rust,
                            "py" => crate::context::control_path::Language::Python,
                            "js" | "jsx" | "ts" | "tsx" => {
                                crate::context::control_path::Language::JavaScript
                            }
                            _ => continue,
                        };

                        if languages.contains(&lang) {
                            call_graph_builder.add_source_file(path, lang);
                        }
                    }
                }
            }));

            if let Err(e) = build_result {
                tracing::warn!("CallGraph building panicked: {:?}", e);
                (Some(fn_lookup), None)
            } else {
                let call_graph = call_graph_builder.build();
                (Some(fn_lookup), Some(call_graph))
            }
        }
    } else {
        (None, None)
    };

    for (i, finding) in findings.iter_mut().enumerate() {
        let progress_pct = if total_findings > 0 {
            ((i as f64 / total_findings as f64) * 100.0) as u64
        } else {
            100
        };
        pb.set_position(base + progress_pct);
        pb.set_message(format!(
            "Phase 6/20: Security Agent verifying [{}/{}] - {}",
            i + 1,
            total_findings,
            finding.title
        ));

        // Agent scaffold context enrichment (P2.5)
        let scaffold_context: Option<String> = if config.agent_scaffold.enabled {
            // Extract target function name from finding (no function_name field, so extract from title/code_snippet)
            let target_fn = extract_function_name_from_finding(finding);

            if let Some(target_fn_name) = target_fn {
                // Sample call-graph paths
                let paths_str = if let Some(ref call_graph) = call_graph_opt {
                    let paths = call_graph.sample_paths_to(
                        &target_fn_name,
                        config.agent_scaffold.paths_per_target as usize,
                    );
                    if paths.is_empty() {
                        String::new()
                    } else {
                        let mut s = format!("Call graph paths to {}:\n", target_fn_name);
                        for path in &paths {
                            s.push_str(&format!("  {}\n", path.0.join(" -> ")));
                        }
                        s
                    }
                } else {
                    String::new()
                };

                // Look up function source
                let fn_source = if let Some(ref lookup) = fn_lookup_opt {
                    lookup.lookup(&target_fn_name).unwrap_or("")
                } else {
                    ""
                };

                // Build context string
                if !paths_str.is_empty() || !fn_source.is_empty() {
                    let mut ctx = format!("Agent scaffold context for {}:\n\n", target_fn_name);
                    if !paths_str.is_empty() {
                        ctx.push_str("Call graph paths:\n");
                        ctx.push_str(&paths_str);
                        ctx.push('\n');
                    }
                    if !fn_source.is_empty() {
                        ctx.push_str("Target function source:\n");
                        ctx.push_str(fn_source);
                    }
                    Some(ctx)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

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

                // Apply scaffold context if agent didn't set verification_notes
                if scaffold_context.is_some() && finding.verification_notes.is_none() {
                    finding.verification_notes = scaffold_context;
                }

                tracing::debug!(
                    "Security Agent verified {}: {:?} - {} turns, {} tools",
                    finding.title,
                    finding.verification_status,
                    agent_result.agent_turns,
                    agent_result.tools_used.len()
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Security Agent verification failed for {}: {}",
                    finding.title,
                    e
                );
                finding.verification_status = Some(VerificationStatus::Failed);
                // Apply scaffold context on error if no verification_notes set
                if scaffold_context.is_some() && finding.verification_notes.is_none() {
                    finding.verification_notes = scaffold_context;
                } else {
                    finding.verification_notes = Some(format!("Agent verification failed: {}", e));
                }
            }
        }
    }

    // AgentFlow multi-agent harness synthesis (P5)
    if config.agent_flow.enabled {
        tracing::info!("AgentFlow enabled, running harness search loop");
        pb.set_message("Phase 6/20: AgentFlow harness synthesis...");

        for finding in findings.iter_mut() {
            // Build a minimal harness from the finding
            let mut harness = crate::agent_flow::dsl::AgentFlowHarness::new();
            let _analyst = harness.add_agent(crate::agent_flow::dsl::Agent {
                role: format!(
                    "analyst_{}",
                    finding
                        .title
                        .replace(" ", "_")
                        .chars()
                        .take(20)
                        .collect::<String>()
                ),
                prompt: format!(
                    "Analyze vulnerability: {}\nLocation: {}\nDescription: {}",
                    finding.title, finding.file_path, finding.description
                ),
                model: config.llm.phases.discovery.model.clone(),
                tools: std::collections::BTreeSet::new(),
            });

            let mut current_harness = harness;
            let max_iterations = config.agent_flow.max_iterations;

            for iter in 0..max_iterations {
                // Execute the harness
                let execution = match crate::agent_flow::execute(&current_harness, &client).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("AgentFlow execute iter {} failed: {}", iter, e);
                        break;
                    }
                };

                // Build feedback channels from execution result
                let mut feedback_channels = std::collections::BTreeSet::new();
                if execution.is_success() {
                    feedback_channels.insert(crate::agent_flow::dsl::FeedbackChannel::Outcome);
                }

                // Diagnose the result
                let diagnostic = crate::agent_flow::diagnose(
                    &execution,
                    &feedback_channels,
                    if execution.is_success() {
                        vec![crate::agent_flow::diagnoser::FeedbackSignal::Pass]
                    } else {
                        vec![crate::agent_flow::diagnoser::FeedbackSignal::Fail(
                            "some agents failed".to_string(),
                        )]
                    },
                );

                if diagnostic.is_success() {
                    tracing::info!("AgentFlow converged at iter {}", iter);
                    break;
                }

                // Propose a rewrite
                match crate::agent_flow::propose_rewrite(&client, &diagnostic, &current_harness)
                    .await
                {
                    Ok(proposal) => {
                        current_harness =
                            crate::agent_flow::apply_rewrite(&current_harness, &proposal);
                    }
                    Err(e) => {
                        tracing::warn!("AgentFlow propose_rewrite iter {} failed: {}", iter, e);
                        break;
                    }
                }
            }
        }

        pb.set_position(base + 100);
        tracing::info!("AgentFlow harness synthesis complete");
    }

    pb.set_position(base + 100);
    tracing::info!(
        "Security Agent verification complete - {} findings",
        total_findings
    );
    Ok((findings, analyzed_files.to_vec()))
}
