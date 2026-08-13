use crate::agent;
use crate::cve_bootstrap::CveBootstrapper;
use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::llm;
use crate::scanner::phases::PhaseConfig;
use std::sync::Arc;

/// Run LLM discovery phase (Phase 4/20)
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
