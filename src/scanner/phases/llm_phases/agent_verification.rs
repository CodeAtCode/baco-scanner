use super::helpers::extract_function_name_from_finding;
use crate::agent;
use crate::error::ScanResult;
use crate::findings::VerificationStatus;
use crate::findings::VulnerabilityFinding;
use crate::scanner::phases::PhaseConfig;
use std::sync::Arc;

/// Run Security Agent verification phase (Phase 10/24)
pub async fn run_security_agent_verification(
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

    tracing::info!("Running Security Agent verification phase...");

    let base = pb.position();

    if !config.agent.enabled {
        tracing::debug!("Agent mode disabled, skipping Security Agent verification");
        pb.set_message("Phase 10/24: Agent mode disabled - skipping");
        pb.set_position(base + 100);
        return Ok((findings, analyzed_files.to_vec()));
    }

    let Some(_api_key) = &config.llm.phases.discovery.api_key else {
        tracing::debug!("No API key for agent, skipping Security Agent verification");
        pb.set_message("Phase 10/24: No API key - skipping");
        pb.set_position(base + 100);
        return Ok((findings, analyzed_files.to_vec()));
    };

    pb.set_message("Phase 10/24: Security Agent verification (tool-based analysis)...");

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
            "Phase 10/24: Security Agent verifying [{}/{}] - {}",
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

    // AgentFlow multi-agent harness synthesis
    if config.agent_flow.enabled {
        // Gate: requires_instrumented_target check
        // When requires_instrumented_target is true, we check for instrumentation signal.
        // Since no per-target instrumentation signal is available in config context,
        // the honest gate is to skip synthesis when the flag is set.
        let enter_agent_flow = if config.agent_flow.requires_instrumented_target {
            tracing::info!("Skipping agent_flow: requires_instrumented_target=true and no instrumentation signal for target");
            false
        } else {
            tracing::info!("AgentFlow enabled, running harness search loop");
            true
        };

        if enter_agent_flow {
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
                let max_iterations = config.agent_flow.max_iterations;

                for iter in 0..max_iterations {
                    // Execute the harness
                    let execution =
                        match crate::agent_flow::execute(&current_harness, &client).await {
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
    }

    pb.set_position(base + 100);
    tracing::info!(
        "Security Agent verification complete - {} findings",
        total_findings
    );
    Ok((findings, analyzed_files.to_vec()))
}
