use crate::agent;
use crate::checkpoint::ScanPhase;
use crate::cve_bootstrap::CveBootstrapper;
use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::llm;
use crate::org_context;
use crate::prompt::engine::PromptEngine;
use crate::scanner::phases::PhaseConfig;
use std::sync::Arc;

/// Run LLM discovery phase (phase 7 of 24).
pub async fn run_llm_discovery(
    scanner: &crate::scanner::Scanner,
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
    let phase_num = crate::scanner::pipeline::orchestrator::phase_index(&ScanPhase::LlmDiscovery);
    let total = crate::scanner::pipeline::orchestrator::total_phases();
    pb.set_message(format!(
        "Phase {}/{}: LLM discovery (enriching vulnerability descriptions with AI context)...",
        phase_num, total
    ));

    // Step 1: Detect project stack and fetch CVEs for threat intelligence
    pb.set_message(format!(
        "Phase {}/{}: Detecting project stack and fetching CVE data...",
        phase_num, total
    ));
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

        // Build prior runs skip list if enabled
        let prior_skip_list = if config.prior_runs.enabled {
            let prior_findings = crate::run_store::load_prior_runs(
                std::path::Path::new(&config.output.dir),
                config.prior_runs.max_runs,
            );
            let prior_knowledge = crate::run_store::build_prior_knowledge(&prior_findings);

            if prior_knowledge.skip_keys.is_empty() {
                None
            } else {
                // Cap at 50 entries
                let mut skip_entries: Vec<String> = prior_knowledge
                    .skip_keys
                    .iter()
                    .zip(prior_findings.iter())
                    .take(50)
                    .map(|(key, f)| format!("- {} at {}", key, f.file_path))
                    .collect();

                if prior_knowledge.skip_keys.len() > 50 {
                    let more = prior_knowledge.skip_keys.len() - 50;
                    skip_entries.push(format!("+ {} more", more));
                }

                Some(format!(
                    "KNOWN FINDINGS FROM PRIOR RUNS (do not re-report these; seek NEW distinct issues):\n{}",
                    skip_entries.join("\n")
                ))
            }
        } else {
            None
        };

        // Build hunt prompt context if enabled
        let hunt_context = if config.scanner.performance.enable_hunt_prompts {
            let engine = PromptEngine::new();
            let selected_domains = PromptEngine::select_hunt_domains(&config.project.languages);

            let mut contexts: Vec<String> = Vec::new();
            for domain in selected_domains {
                if let Some(prompt) = engine.get_hunt_prompt(&domain) {
                    contexts.push(format!("\n\n=== HUNT MODULE: {} ===\n{}", domain, prompt));
                }
            }

            if contexts.is_empty() {
                None
            } else {
                Some(contexts.join(""))
            }
        } else {
            None
        };

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
                "Phase {}/{}: Enriching findings [{}/{}] - {}",
                phase_num,
                total,
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
                        finding.add_evidence(
                            crate::evidence::EvidenceSource::LlmAnalysis("discovery".into()),
                            0.6,
                            "LLM discovery refined this finding".into(),
                        );
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
                let mut user_prompt = format!(
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
                );

                // Prepend prior runs skip list if available
                if let Some(ref skip_list) = prior_skip_list {
                    user_prompt = format!("{}\n\n{}", skip_list, user_prompt);
                }

                // Append hunt context if available
                if let Some(ref hunt_ctx) = hunt_context {
                    user_prompt.push_str(hunt_ctx);
                }

                // Append org-context block if available
                if let Some(ref org_ctx) = org_context::render(&config.org_context) {
                    user_prompt.push_str("\n\n");
                    user_prompt.push_str(org_ctx);
                }

                let messages = vec![
                    llm::ChatMessage::system(
                        "You are a security vulnerability analyzer. Output valid JSON only.",
                    ),
                    llm::ChatMessage::user(&user_prompt),
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
                        finding.add_evidence(
                            crate::evidence::EvidenceSource::LlmAnalysis("discovery".into()),
                            0.6,
                            "LLM discovery refined this finding".into(),
                        );
                    }
                }
            }
        }
        pb.set_position(base + 100);
        pb.set_message(format!(
            "Phase {}/{}: Discovery complete - enriched {} findings",
            phase_num, total, total_findings
        ));
    } else {
        tracing::debug!("No API key for discovery, skipping LLM enrichment");
        pb.set_message(format!(
            "Phase {}/{}: No API key configured - skipping discovery",
            phase_num, total
        ));
        pb.set_position(base + 100);
    }
    Ok((findings, analyzed_files.to_vec()))
}
