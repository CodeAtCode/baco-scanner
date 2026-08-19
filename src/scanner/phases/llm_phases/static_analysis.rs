/// Run LLM static analysis phase (phase 4 of 24).
use crate::checkpoint::ScanPhase;
use crate::context::callee_walker::extract_call_sites;
use crate::context::pacvd_extractor::{self, AbstractionLevel};
use crate::context::semantic_path;
use crate::context::triple_path::TriplePathContext;
use crate::scanner::phases::llm_phases::helpers::detect_language;
use crate::scanner::phases::PhaseConfig;

use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::llm;
use crate::llm_analysis::LlmAnalyzer;

use crate::retrieval::CweKnowledgeBase;
use std::collections::HashSet;

/// Run policy sampling for a single file (VulnLLM-R P2.2)
/// Returns a set of CWE IDs collected from multiple high-temperature samples
async fn run_policy_sampling(
    llm_config: &llm::LlmConfig,
    file_path: &std::path::Path,
    samples: u8,
    language_hint: &str,
) -> Result<HashSet<String>, String> {
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
    _scanner: &crate::scanner::Scanner,
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
    let phase_num =
        crate::scanner::pipeline::orchestrator::phase_index(&ScanPhase::LlmStaticAnalysis);
    let total = crate::scanner::pipeline::orchestrator::total_phases();
    pb.set_message(format!(
        "Phase {}/{}: LLM static analysis (analyzing files for vulnerabilities)...",
        phase_num, total
    ));

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
                    "Phase {}/{}: Skipping already analyzed [{}]: {}",
                    phase_num,
                    total,
                    i + 1,
                    file_info.path.display()
                ));
                continue;
            }
            let progress_pct = ((i as f64 / file_count as f64) * 100.0) as u64;
            let msg = format!(
                "Phase {}/{}: LLM analyzing [{}/{}] ({:.0}%): {}",
                phase_num,
                total,
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
                        "Phase {}/{}: LLM analyzing [{}/{}] ({:.0}%): {} - {} findings total",
                        phase_num,
                        total,
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
                        "Phase {}/{}: {} - {} - FAILED: {}",
                        phase_num,
                        total,
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
            "Phase {}/{}: LLM static analysis complete - {} findings discovered",
            phase_num,
            total,
            llm_findings.len()
        ));
    } else {
        tracing::debug!("No API key for LLM analysis, skipping static analysis");
    }

    Ok((findings, analyzed_files.to_vec()))
}
