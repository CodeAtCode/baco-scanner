use crate::agent;
use crate::checkpoint::ScanPhase;
use crate::error::ScanResult;
use crate::findings::VerificationStatus;
use crate::findings::VulnerabilityFinding;
use crate::llm;
use crate::org_context;
use crate::poc_compiler::PocCompiler;
use crate::poc_generation::{PoCFormat, PoCGenerationEngine};
use crate::prompt::loader::load_hunt_prompts;
use crate::prompt::templates::cwe_to_hunt_domain;
use crate::scanner::phases::PhaseConfig;
use serde::Deserialize;
use std::fs;
use std::sync::Arc;

/// Rejected finding with its rejection reason.
pub type RejectedFinding = (VulnerabilityFinding, String);

/// Run LLM verification phase (phase 8 of 24).
pub async fn run_llm_verification(
    scanner: &crate::scanner::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>, Vec<RejectedFinding>)> {
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
    let phase_num =
        crate::scanner::pipeline::orchestrator::phase_index(&ScanPhase::LlmVerification);
    let total = crate::scanner::pipeline::orchestrator::total_phases();
    pb.set_message(format!(
        "Phase {}/{}: LLM verification (validating findings with AI analysis)...",
        phase_num, total
    ));

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
                    "Phase {}/{}: Agent verifying [{}/{}] - {}",
                    phase_num,
                    total,
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
                        finding.add_evidence(
                            crate::evidence::EvidenceSource::LlmAnalysis("verification".into()),
                            0.8,
                            format!(
                                "LLM verification verdict: {:?}",
                                finding.verification_status
                            ),
                        );
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
            // Load hunt prompts once for all findings
            let hunt_prompts = load_hunt_prompts(None);

            for (i, finding) in findings.iter_mut().enumerate() {
                let progress_pct = if total_findings > 0 {
                    ((i as f64 / total_findings as f64) * 100.0) as u64
                } else {
                    100
                };
                pb.set_position(base + progress_pct);
                pb.set_message(format!(
                    "Phase {}/{}: Verifying findings [{}/{}] - {}",
                    phase_num,
                    total,
                    i + 1,
                    total_findings,
                    finding.title
                ));

                // Build verification prompt with code context and hunt domain guidance
                let mut prompt_text = format!(
                    "Vulnerability: {}\nLocation: {}:{}\nDescription: {}\nSources: {:?}",
                    finding.title,
                    finding.file_path,
                    finding.line_number.unwrap_or(0),
                    finding.description,
                    finding.sources
                );

                // Add code snippet from finding if available
                if let Some(ref snippet) = finding.code_snippet {
                    prompt_text.push_str(&format!("\n\nVulnerable code:\n```\n{}\n```", snippet));
                }

                // Add surrounding code context from disk (±5 lines)
                if let Some(line_num) = finding.line_number {
                    if let Ok(content) = fs::read_to_string(&finding.file_path) {
                        let lines: Vec<&str> = content.lines().collect();
                        let start = if line_num >= 6 {
                            (line_num - 6) as usize
                        } else {
                            0
                        };
                        let end = std::cmp::min(line_num as usize + 5, lines.len());
                        let context_lines: Vec<String> = (start..end)
                            .map(|i| format!("{:5}: {}", i + 1, lines[i]))
                            .collect();
                        prompt_text.push_str(&format!(
                            "\n\nCode context ({}:{})\n{}",
                            finding.file_path,
                            line_num,
                            context_lines.join("\n")
                        ));
                    }
                }

                // Append hunt domain context if CWE maps to a hunt domain
                if let Some(domain) = finding
                    .cwe_id
                    .as_ref()
                    .and_then(|cwe| cwe_to_hunt_domain(cwe))
                {
                    if let Some(hunt_prompt) = hunt_prompts.get(domain) {
                        if !hunt_prompt.is_empty() {
                            prompt_text.push_str(&format!(
                                "\n\n=== HUNT DOMAIN GUIDANCE ({}) ===\n{}\n=== END HUNT GUIDANCE ===",
                                domain,
                                hunt_prompt
                            ));
                        }
                    }
                }

                // Append org-context block if available
                if let Some(ref org_ctx) = org_context::render(&config.org_context) {
                    prompt_text.push_str("\n\n");
                    prompt_text.push_str(org_ctx);
                }

                let messages = vec![
                    llm::ChatMessage::system(
                        "You are a security vulnerability verifier. Analyze the finding and determine if it's a true positive, false positive, or needs review.\n\nSTRICT OUTPUT FORMAT: Return ONLY valid JSON with no prose outside the JSON object.\n\nJSON schema:\n{\n  \"verification_status\": \"confirmed|false_positive|needs_review\",\n  \"verification_notes\": \"detailed reasoning for the verdict\"\n}\n\nDo NOT include any text before or after the JSON."
                    ),
                    llm::ChatMessage::user(&prompt_text)
                ];
                let result = client.chat(&messages).await;

                if let Ok(response_with_model) = result {
                    let (status, notes) = parse_verification_verdict(&response_with_model.content);
                    finding.verification_status = Some(status);
                    finding.verification_notes = Some(notes);
                    finding.add_evidence(
                        crate::evidence::EvidenceSource::LlmAnalysis("verification".into()),
                        0.8,
                        format!(
                            "LLM verification verdict: {:?}",
                            finding.verification_status
                        ),
                    );
                }
            }
        }
        pb.set_position(base + 100);
        pb.set_message(format!(
            "Phase {}/{}: Verification complete - verified {} findings",
            phase_num, total, total_findings
        ));
    } else {
        tracing::debug!("No API key for verification, skipping LLM verification");
        pb.set_message(format!(
            "Phase {}/{}: No API key configured - skipping verification",
            phase_num, total
        ));
    }

    // Step 2: Generate PoCs for high-severity confirmed findings
    pb.set_message(format!(
        "Phase {}/{}: Generating PoCs for high-severity findings...",
        phase_num, total
    ));

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

    // Separate rejected findings (FalsePositive status) with their reasons
    let mut kept_findings = Vec::new();
    let mut rejected_findings = Vec::new();

    for finding in findings {
        match finding.verification_status {
            Some(VerificationStatus::FalsePositive) => {
                let reason = finding.verification_notes.clone().unwrap_or_else(|| {
                    "Marked as false positive during LLM verification".to_string()
                });
                rejected_findings.push((finding, reason));
            }
            _ => kept_findings.push(finding),
        }
    }

    Ok((kept_findings, analyzed_files.to_vec(), rejected_findings))
}

/// Parse a strict-JSON verification verdict from LLM output.
///
/// Code fences are stripped; if the text does not parse as the verdict
/// object, the finding degrades to `NeedsReview` with the raw response
/// preserved in the notes.
pub fn parse_verification_verdict(content: &str) -> (VerificationStatus, String) {
    #[derive(Deserialize, Debug)]
    struct VerificationVerdict {
        #[serde(rename = "verification_status")]
        status: String,
        #[serde(rename = "verification_notes")]
        notes: Option<String>,
    }

    let cleaned = content
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim_start_matches("json")
        .trim();

    match serde_json::from_str::<VerificationVerdict>(cleaned) {
        Ok(verdict) => {
            let status = match verdict.status.as_str() {
                "confirmed" => VerificationStatus::Confirmed,
                "false_positive" => VerificationStatus::FalsePositive,
                _ => VerificationStatus::NeedsReview,
            };
            let notes = verdict.notes.unwrap_or_default();
            (status, notes)
        }
        Err(_) => (VerificationStatus::NeedsReview, content.to_string()),
    }
}
