use super::PhaseConfig;
use crate::agent;
use crate::cve_bootstrap::CveBootstrapper;
use crate::error::ScanResult;
use crate::findings::VerificationStatus;
use crate::findings::VulnerabilityFinding;
use crate::llm;
use crate::llm_analysis::LlmAnalyzer;
use crate::poc_compiler::PocCompiler;
use crate::poc_generation::PoCFormat;
use crate::poc_generation::PoCGenerationEngine;

/// Run LLM static analysis phase (Phase 3/20)
use std::sync::Arc;
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
                finding.verification_notes = Some(format!("Agent verification failed: {}", e));
            }
        }
    }

    pb.set_position(base + 100);
    tracing::info!(
        "Security Agent verification complete - {} findings",
        total_findings
    );
    Ok((findings, analyzed_files.to_vec()))
}
