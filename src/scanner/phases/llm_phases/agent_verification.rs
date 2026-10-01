use super::helpers::extract_function_name_from_finding;
use crate::agent;
use crate::checkpoint::ScanPhase;
use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::indexer::ExcludeMatcher;
use crate::scanner::phases::PhaseConfig;
use std::sync::Arc;

/// The three agent operations this phase performs, behind a seam.
///
/// The phase is mostly mapping: it hands a finding to an agent, then records
/// what came back. That mapping is the part worth testing, and it is
/// unreachable without a live model, a sandbox and real files. Abstracting
/// only the three calls leaves the rest reachable from a test.
pub trait SecurityAgentRunner {
    fn verify_finding<'a>(
        &'a self,
        file_path: &'a str,
        finding: &'a VulnerabilityFinding,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<agent::AgentFinding, String>> + Send + 'a>,
    >;

    fn run_flow<'a>(
        &'a self,
        harness: &'a crate::agent_flow::AgentFlowHarness,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<crate::agent_flow::ExecutionResult, String>>
                + Send
                + 'a,
        >,
    >;

    fn propose_rewrite<'a>(
        &'a self,
        diagnostic: &'a crate::agent_flow::Diagnostic,
        harness: &'a crate::agent_flow::AgentFlowHarness,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<crate::agent_flow::RewriteProposal, String>>
                + Send
                + 'a,
        >,
    >;
}

/// Production runner: a real [`agent::AgentSession`] and a real model.
pub struct LiveSecurityAgent {
    client: crate::llm::LlmClient,
    agent_config: crate::config::AgentConfig,
    target_path: std::path::PathBuf,
}

impl LiveSecurityAgent {
    pub fn new(
        client: crate::llm::LlmClient,
        agent_config: &crate::config::AgentConfig,
        target_path: &std::path::Path,
    ) -> Self {
        Self {
            client,
            agent_config: agent_config.clone(),
            target_path: target_path.to_path_buf(),
        }
    }
}

impl SecurityAgentRunner for LiveSecurityAgent {
    fn verify_finding<'a>(
        &'a self,
        file_path: &'a str,
        finding: &'a VulnerabilityFinding,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<agent::AgentFinding, String>> + Send + 'a>,
    > {
        Box::pin(async move {
            let session = agent::AgentSession::new(
                self.client.clone(),
                &self.agent_config,
                &self.target_path,
                Arc::new(|msg| tracing::debug!("[AGENT] {}", msg)),
            );
            session.verify_finding(file_path, finding).await
        })
    }

    fn run_flow<'a>(
        &'a self,
        harness: &'a crate::agent_flow::AgentFlowHarness,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<crate::agent_flow::ExecutionResult, String>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move { crate::agent_flow::execute(harness, &self.client).await })
    }

    fn propose_rewrite<'a>(
        &'a self,
        diagnostic: &'a crate::agent_flow::Diagnostic,
        harness: &'a crate::agent_flow::AgentFlowHarness,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<crate::agent_flow::RewriteProposal, String>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            crate::agent_flow::propose_rewrite(&self.client, diagnostic, harness).await
        })
    }
}

/// Record a completed agent verification on the finding.
///
/// A compiled test outranks the test source, which outranks a bare turn count,
/// so the most concrete evidence available wins the evidence path.
pub fn apply_agent_result(
    finding: &mut VulnerabilityFinding,
    result: &agent::AgentFinding,
    scaffold_context: Option<String>,
) {
    if let Some(ref path) = result.compile_path {
        finding.agent_evidence_path = Some(path.to_string_lossy().to_string());
    } else if let Some(ref path) = result.test_source_path {
        finding.agent_evidence_path = Some(path.to_string_lossy().to_string());
    } else if result.agent_turns > 0 {
        finding.agent_evidence_path = Some(format!(
            "{} turns, {} tools",
            result.agent_turns,
            result.tools_used.len()
        ));
    }

    if let Some(ref log) = result.test_log {
        if finding.verification_notes.is_none() {
            finding.verification_notes = Some(log.clone());
        }
    }

    // Scaffold context is the fallback for when the agent said nothing useful.
    if scaffold_context.is_some() && finding.verification_notes.is_none() {
        finding.verification_notes = scaffold_context;
    }

    finding.add_evidence(
        crate::evidence::EvidenceSource::SecurityAgentVerification("agent_verification".into()),
        1.0,
        format!(
            "Agent verification result: {:?}",
            finding.verification_status
        ),
    );

    tracing::debug!(
        "Security Agent verified {}: {:?} - {} turns, {} tools",
        finding.title,
        finding.verification_status,
        result.agent_turns,
        result.tools_used.len()
    );
}

/// Record a failed agent verification on the finding.
///
/// This is called when the agent itself fails (timeout, tool failure, parse error, network).
/// The finding's verification_status is NOT set to Failed, because the agent did not examine
/// the finding. Instead, the error is recorded in verification_error and verification_notes.
pub fn apply_agent_failure(
    finding: &mut VulnerabilityFinding,
    error: &str,
    scaffold_context: Option<String>,
) {
    // Do NOT set verification_status to Failed - the agent did not examine the finding.
    // The error category is recorded in verification_error and verification_notes.
    finding.verification_error = Some(error.to_string());
    if scaffold_context.is_some() && finding.verification_notes.is_none() {
        finding.verification_notes = scaffold_context;
    } else {
        finding.verification_notes = Some(format!("Agent verification failed: {}", error));
    }
    finding.add_evidence(
        crate::evidence::EvidenceSource::SecurityAgentVerification("agent_verification".into()),
        1.0,
        format!("Agent verification error (not examined): {}", error),
    );
}

/// Record the agent flow outcome on the finding.
pub fn apply_flow_outcome(
    finding: &mut VulnerabilityFinding,
    diagnosis: Option<String>,
    rewrite: Option<String>,
) {
    if let Some(ref summary) = diagnosis {
        finding.add_evidence(
            crate::evidence::EvidenceSource::SecurityAgentVerification(
                "agent_flow_diagnosis".into(),
            ),
            1.0,
            format!("AgentFlow diagnosis: {}", summary),
        );
        if finding.verification_notes.is_none() {
            finding.verification_notes = Some(summary.clone());
        }
    }

    if let Some(ref rewrite) = rewrite {
        finding.add_evidence(
            crate::evidence::EvidenceSource::SecurityAgentVerification("agent_flow_rewrite".into()),
            1.0,
            format!("AgentFlow proposed rewrite: {}", rewrite),
        );
    }

    if diagnosis.is_none() && rewrite.is_none() {
        tracing::warn!(
            "AgentFlow produced no output for finding: {}",
            finding.title
        );
    }
}

/// Internal worker that takes an injected runner.
///
/// This holds the body of the phase from scaffold context building through
/// the findings loop and optional AgentFlow execution. The wrapper below
/// handles early-exit guards and constructs the LiveSecurityAgent.
pub async fn run_agent_blocks(
    mut findings: Vec<VulnerabilityFinding>,
    pb: &indicatif::ProgressBar,
    analyzed_files: &[String],
    target_path: &std::path::Path,
    config: &crate::config::ScannerConfig,
    runner: &dyn SecurityAgentRunner,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let phase_num =
        crate::scanner::pipeline::orchestrator::phase_index(&ScanPhase::SecurityAgentVerification);
    let total = crate::scanner::pipeline::orchestrator::total_phases();

    let base = pb.position();

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

            // Build exclusion matcher from config patterns
            let exclude_matcher = ExcludeMatcher::new_or_empty(exclude_paths);

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

                    // Use glob-based exclusion matching
                    let relative_path = path.strip_prefix(target_path).ok();
                    if exclude_matcher.is_excluded(path, relative_path) {
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

    let total_findings = findings.len();

    for (i, finding) in findings.iter_mut().enumerate() {
        let progress_pct = if total_findings > 0 {
            ((i as f64 / total_findings as f64) * 100.0) as u64
        } else {
            100
        };
        pb.set_position(base + progress_pct);
        pb.set_message(format!(
            "Phase {}/{}: Security Agent verifying [{}/{}] - {}",
            phase_num,
            total,
            i + 1,
            total_findings,
            finding.title
        ));

        // Agent scaffold context enrichment (P2.5)
        let scaffold_context: Option<String> = if config.agent_scaffold.enabled {
            // Extract target function name from finding (no function_name field, so extract from title/code_snippet)
            let target_fn = extract_function_name_from_finding(finding);

            if let Some(target_fn_name) = target_fn {
                // Sample call-graph paths (capped at max_rounds)
                let paths_str = if let Some(ref call_graph) = call_graph_opt {
                    let paths = call_graph.sample_paths_to(
                        &target_fn_name,
                        config.agent_scaffold.paths_per_target as usize,
                    );
                    let paths_to_use = paths.len().min(config.agent_scaffold.max_rounds as usize);
                    if paths_to_use < paths.len() {
                        tracing::debug!(
                            "Truncated scaffold rounds to max_rounds={}",
                            config.agent_scaffold.max_rounds
                        );
                    }
                    if paths_to_use == 0 {
                        String::new()
                    } else {
                        let mut s = format!("Call graph paths to {}:\n", target_fn_name);
                        for path in &paths[..paths_to_use] {
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

        match runner.verify_finding(&finding.file_path, finding).await {
            Ok(agent_result) => {
                apply_agent_result(finding, &agent_result, scaffold_context);
            }
            Err(e) => {
                tracing::warn!(
                    "Security Agent verification failed for {}: {}",
                    finding.title,
                    e
                );
                apply_agent_failure(finding, &e, scaffold_context);
            }
        }
    }

    // AgentFlow multi-agent harness synthesis
    if config
        .llm
        .phases
        .security_agent_verification
        .agent_flow
        .enabled
    {
        tracing::debug!("AgentFlow gate enabled for security_agent_verification phase");
        pb.set_message("Phase 10/24: AgentFlow harness synthesis...");

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
            let max_iterations = config
                .llm
                .phases
                .security_agent_verification
                .agent_flow
                .max_iterations;
            let mut diagnosis_summary: Option<String> = None;
            let mut proposed_rewrite: Option<String> = None;

            for iter in 0..max_iterations {
                // Execute the harness
                let execution = match runner.run_flow(&current_harness).await {
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

                // Capture diagnosis summary
                diagnosis_summary = Some(crate::agent_flow::format_diagnostic(&diagnostic));

                if diagnostic.is_success() {
                    tracing::info!("AgentFlow converged at iter {}", iter);
                    break;
                }

                // Propose a rewrite
                match runner.propose_rewrite(&diagnostic, &current_harness).await {
                    Ok(proposal) => {
                        let rationale = proposal.rationale.clone();
                        proposed_rewrite = Some(rationale);
                        current_harness =
                            crate::agent_flow::apply_rewrite(&current_harness, &proposal);
                    }
                    Err(e) => {
                        tracing::warn!("AgentFlow propose_rewrite iter {} failed: {}", iter, e);
                        break;
                    }
                }
            }

            apply_flow_outcome(finding, diagnosis_summary, proposed_rewrite);
        }

        pb.set_position(base + 100);
        tracing::info!("AgentFlow harness synthesis complete");
    } else {
        tracing::debug!(
            "AgentFlow disabled for security_agent_verification phase, skipping harness synthesis"
        );
    }

    pb.set_position(base + 100);
    tracing::info!(
        "Security Agent verification complete - {} findings",
        total_findings
    );
    Ok((findings, analyzed_files.to_vec()))
}

/// Run Security Agent verification phase (Phase 10/24)
pub async fn run_security_agent_verification(
    scanner: &crate::scanner::Scanner,
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

    tracing::info!("Running Security Agent verification phase...");

    let phase_num =
        crate::scanner::pipeline::orchestrator::phase_index(&ScanPhase::SecurityAgentVerification);
    let total = crate::scanner::pipeline::orchestrator::total_phases();

    let base = pb.position();

    if !config.agent.enabled {
        tracing::warn!(
            "Security Agent verification skipped: agent not enabled (set agent.enabled = true in config)"
        );
        pb.set_message(format!(
            "Phase {}/{}: Agent mode disabled - skipping",
            phase_num, total
        ));
        pb.set_position(base + 100);
        // The orchestrator already records this as Skipped via
        // detect_llm_config_skips, which derives the reason from config.llm.phases.
        // Returning an error here would mark the phase Failed and override it.
        return Ok((findings, analyzed_files.to_vec()));
    }

    let Some(_api_key) = &config.llm.phases.security_agent_verification.api_key else {
        tracing::warn!(
            "Security Agent verification skipped: no API key configured (set llm.phases.security_agent_verification.api_key in config)"
        );
        pb.set_message(format!(
            "Phase {}/{}: No API key - skipping",
            phase_num, total
        ));
        pb.set_position(base + 100);
        return Ok((findings, analyzed_files.to_vec()));
    };

    pb.set_message(format!(
        "Phase {}/{}: Security Agent verification (tool-based analysis)...",
        phase_num, total
    ));

    let client = match crate::llm::create_llm_client_with_metrics(
        scanner,
        "security_agent_verification",
    ) {
        Some(client) => client,
        None => {
            tracing::warn!(
                "Security Agent verification skipped: LLM client unavailable (incomplete llm.phases.security_agent_verification config)"
            );
            pb.set_position(base + 100);
            return Ok((findings, analyzed_files.to_vec()));
        }
    };

    let agent = LiveSecurityAgent::new(client, &config.agent, target_path);

    run_agent_blocks(findings, pb, analyzed_files, target_path, config, &agent).await
}
