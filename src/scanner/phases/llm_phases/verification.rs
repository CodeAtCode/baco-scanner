use crate::agent;
use crate::error::ScanResult;
use crate::findings::VerificationStatus;
use crate::findings::VulnerabilityFinding;
use crate::llm;
use crate::poc_compiler::PocCompiler;
use crate::poc_generation::{PoCFormat, PoCGenerationEngine};
use crate::prompt::templates::cwe_to_hunt_domain;
use crate::scanner::phases::PhaseConfig;
use std::sync::Arc;

/// Run LLM verification phase (Phase 8/24)
pub async fn run_llm_verification(
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
        project_stack,
    } = cfg;

    tracing::info!("Running LLM verification phase...");
    let base = pb.position();
    pb.set_message("Phase 8/24: LLM verification (validating findings with AI analysis)...");

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
                    "Phase 8/24: Agent verifying [{}/{}] - {}",
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
                    "Phase 8/24: Verifying findings [{}/{}] - {}",
                    i + 1,
                    total_findings,
                    finding.title
                ));

                // Build verification prompt with optional hunt context
                let mut prompt_text = format!(
                    "Vulnerability: {}\nLocation: {}:{}\nDescription: {}\nSources: {:?}",
                    finding.title,
                    finding.file_path,
                    finding.line_number.unwrap_or(0),
                    finding.description,
                    finding.sources
                );

                // Append hunt domain context if CWE maps to a hunt domain
                if let Some(domain) = finding
                    .cwe_id
                    .as_ref()
                    .and_then(|cwe| cwe_to_hunt_domain(cwe))
                {
                    // Note: hunt_prompts would need to be loaded and passed in - for now we add a placeholder
                    // In a full implementation, hunt_prompts would be loaded via load_hunt_prompts()
                    prompt_text.push_str(&format!(
                        "\n\n[Hunt context: {} vulnerability - analyze with domain-specific patterns]",
                        domain
                    ));
                }

                let messages = vec![
                    llm::ChatMessage::system(
                        "You are a security vulnerability verifier. Analyze the finding and determine if it's a true positive, false positive, or needs review. Return JSON with verification_status (confirmed/false_positive/needs_review) and verification_notes."
                    ),
                    llm::ChatMessage::user(&prompt_text)
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
            "Phase 8/24: Verification complete - verified {} findings",
            total_findings
        ));
    } else {
        tracing::debug!("No API key for verification, skipping LLM verification");
        pb.set_message("Phase 8/24: No API key configured - skipping verification");
    }

    // Step 2: Generate PoCs for high-severity confirmed findings
    pb.set_message("Phase 8/24: Generating PoCs for high-severity findings...");

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
