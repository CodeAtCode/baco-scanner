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

/// Triage decision: files at or above the suspicion threshold go to deep analysis
pub fn should_analyze_file(suspicion: f32, threshold: f32) -> bool {
    suspicion >= threshold
}

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
        config.scanner.performance.enable_file_filtering,
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

    if let Some(_api_key) = &phase_config.api_key {
        let _discovery_timeout = phase_config.timeout_secs.unwrap_or(config.llm.timeout_secs);

        // Enable steady tick for progress bar timer
        pb.enable_steady_tick(std::time::Duration::from_millis(100));

        // Use unified LLM config construction helper (T26)
        let llm_config = llm::phase_llm_config(config, "static_analysis", None);

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

        // Initialize vuln_spec index if enabled
        if config.vuln_spec.enabled {
            crate::vuln_spec::initialize_spec_index(&config.vuln_spec);
        }

        // Load CWE knowledge base for triple-path context
        let cwe_kb = CweKnowledgeBase::load_embedded().ok();

        // Get max_context_tokens for PacVD auto-level selection
        let max_context_tokens = config.llm.max_reasoning_tokens.unwrap_or(32768);

        // Triage cascade (T17): filter files before deep analysis
        let (files_to_analyze, skipped_files) = if config.triage.enabled {
            run_triage_cascade(
                &client,
                &config.triage.model,
                files,
                analyzed_files,
                config.triage.batch_size,
                config.triage.suspicion_threshold,
            )
            .await
        } else {
            (files.iter().collect(), Vec::new())
        };

        if !skipped_files.is_empty() {
            tracing::info!(
                "[Triage] Skipped {} files (suspicion < {} threshold)",
                skipped_files.len(),
                config.triage.suspicion_threshold
            );
            for f in &skipped_files {
                tracing::debug!("[Triage] Skipped: {}", f);
            }
        }

        // Priority scoring (T18): sort files by priority score
        let prioritized_files: Vec<_> = if config.priority.enabled {
            let mut scored: Vec<_> = files_to_analyze
                .iter()
                .map(|f| {
                    let score = compute_file_priority_score(
                        f,
                        config.priority.git_recent_boost,
                        config.priority.entry_point_boost,
                        config.priority.small_file_boost,
                    );
                    (f, score)
                })
                .collect();
            scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            scored.into_iter().map(|(f, _)| *f).collect::<Vec<_>>()
        } else {
            files_to_analyze.to_vec()
        };

        // Budget enforcement (T18): track LLM calls and enforce limits
        let mut llm_call_count = 0;
        let max_calls = if config.budget.enabled {
            config.budget.max_llm_calls
        } else {
            usize::MAX
        };
        let reserve_percent = if config.budget.enabled {
            config.budget.reserve_percent_for_high_risk as f32 / 100.0
        } else {
            0.0
        };
        // Reserve capacity that only high-risk (entry-point) files may consume
        let normal_cap = max_calls.saturating_sub((max_calls as f32 * reserve_percent) as usize);
        let mut high_risk_count = 0;
        let mut skipped_by_budget = Vec::new();

        for (i, file_info) in prioritized_files.iter().enumerate() {
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

            // Budget enforcement (T18): normal files stop at normal_cap;
            // the reserve is only available to high-risk (entry-point) files
            let file_name = file_info
                .path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let is_high_risk = ["main.", "index.", "app.", "server.", "__init__."]
                .iter()
                .any(|p| file_name.contains(p));
            let file_cap = if is_high_risk { max_calls } else { normal_cap };
            if llm_call_count >= file_cap {
                skipped_by_budget.push(file_path_str.clone());
                tracing::debug!(
                    "[Budget] Skipping {} (cap={}, max_llm_calls={})",
                    file_path_str,
                    file_cap,
                    max_calls
                );
                continue;
            }
            if is_high_risk && llm_call_count >= normal_cap {
                high_risk_count += 1;
            }

            match analyzer.analyze_file(&file_info.path).await {
                Ok(file_findings) => {
                    // Wire vuln_spec retriever if enabled
                    let file_findings = if config.vuln_spec.enabled {
                        let mut findings_with_specs = file_findings;
                        for finding in &mut findings_with_specs {
                            // Read relevant code snippet for retrieval
                            if let Ok(code_snippet) = std::fs::read_to_string(&file_info.path) {
                                // Only retrieve specs if CWE ID is present
                                if let Some(cwe_id) = &finding.cwe_id {
                                    let specs =
                                        crate::vuln_spec::retriever::retrieve_relevant_specs(
                                            &code_snippet,
                                            cwe_id,
                                            3,
                                        );
                                    for spec in specs {
                                        finding.add_evidence(
                                            crate::evidence::EvidenceSource::CweSpec(
                                                spec.id.clone(),
                                            ),
                                            0.5,
                                            format!(
                                                "Matched known vulnerability specification: {}",
                                                spec.description
                                            ),
                                        );
                                    }
                                }
                            }
                        }
                        findings_with_specs
                    } else {
                        file_findings
                    };
                    llm_findings.extend(file_findings);
                    new_analyzed_files.push(file_path_str);
                    llm_call_count += 1;
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

        // Log budget summary
        log_budget_summary(
            llm_call_count,
            max_calls,
            &skipped_by_budget,
            high_risk_count,
        );
    } else {
        tracing::debug!("No API key for LLM analysis, skipping static analysis");
    }

    Ok((findings, analyzed_files.to_vec()))
}

/// Triage finding structure for structured output (T17)
#[derive(Debug, serde::Deserialize)]
struct TriageFinding {
    file: String,
    summary_one_line: String,
    suspicion: f32,
    reason: String,
}

/// Triage response wrapper
#[derive(Debug, serde::Deserialize)]
struct TriageResponse {
    findings: Vec<TriageFinding>,
}

/// Run triage cascade to filter files before deep analysis (T17)
async fn run_triage_cascade<'a>(
    client: &crate::llm::LlmClient,
    _triage_model: &str,
    files: &'a [crate::indexer::FileInfo],
    analyzed_files: &[String],
    batch_size: u8,
    suspicion_threshold: f32,
) -> (Vec<&'a crate::indexer::FileInfo>, Vec<String>) {
    use serde::Serialize;

    #[derive(Serialize)]
    struct TriageRequest {
        files: Vec<TriageFile>,
    }

    #[derive(Serialize, Clone)]
    struct TriageFile {
        path: String,
        content_snippet: String,
    }

    let mut files_to_analyze = Vec::new();
    let mut skipped_files = Vec::new();

    // Process files in batches
    let mut batch_start = 0;
    while batch_start < files.len() {
        let batch_end = std::cmp::min(batch_start + batch_size as usize, files.len());
        let batch = &files[batch_start..batch_end];

        // Build batch request
        let batch_files: Vec<TriageFile> = batch
            .iter()
            .filter(|f| !analyzed_files.contains(&f.path.to_string_lossy().to_string()))
            .map(|f| {
                let content = std::fs::read_to_string(&f.path).unwrap_or_default();
                let snippet = content.lines().take(30).collect::<Vec<_>>().join(" ");
                TriageFile {
                    path: f.path.to_string_lossy().to_string(),
                    content_snippet: snippet,
                }
            })
            .collect();

        if batch_files.is_empty() {
            batch_start = batch_end;
            continue;
        }

        // Build triage prompt
        let request = TriageRequest {
            files: batch_files.clone(),
        };

        let prompt = format!(
            r#"Analyze these files for security-relevant patterns. For each file, provide:
- file: the file path
- summary_one_line: one-line summary of what the file does
- suspicion: float 0.0-1.0 indicating likelihood of security issues
- reason: brief explanation of the suspicion score

Respond with JSON in this exact format:
{{"findings": [{{"file": "path", "summary_one_line": "...", "suspicion": 0.5, "reason": "..."}}]}}

Files to analyze:
{}"#,
            serde_json::to_string_pretty(&request).unwrap_or_default()
        );

        let messages = vec![
            crate::llm::ChatMessage::system("You are a security triage assistant. Be conservative - only flag files with clear security relevance."),
            crate::llm::ChatMessage::user(&prompt),
        ];

        match client.chat(&messages).await {
            Ok(response) => {
                // Parse structured response
                let cleaned = response
                    .content
                    .trim()
                    .trim_start_matches("```json")
                    .trim_start_matches("```")
                    .trim_end_matches("```")
                    .trim_end_matches("~~~")
                    .trim();

                match serde_json::from_str::<TriageResponse>(cleaned) {
                    Ok(triage_response) => {
                        for finding in triage_response.findings {
                            if should_analyze_file(finding.suspicion, suspicion_threshold) {
                                // Find the original file info
                                if let Some(file_info) = batch
                                    .iter()
                                    .find(|f| f.path.to_string_lossy() == finding.file)
                                {
                                    files_to_analyze.push(file_info);
                                    tracing::debug!(
                                        "[Triage] File {} passed (suspicion: {}) — {}",
                                        finding.file,
                                        finding.suspicion,
                                        finding.summary_one_line
                                    );
                                }
                            } else {
                                let file_path = finding.file.clone();
                                skipped_files.push(file_path.clone());
                                tracing::debug!(
                                    "[Triage] File {} skipped (suspicion: {} < threshold: {}) — {}",
                                    file_path,
                                    finding.suspicion,
                                    suspicion_threshold,
                                    finding.reason
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse triage response: {}", e);
                        // Fallback: analyze all files in batch
                        for f in batch {
                            if !analyzed_files.contains(&f.path.to_string_lossy().to_string()) {
                                files_to_analyze.push(f);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Triage request failed: {}", e);
                // Fallback: analyze all files in batch
                for f in batch {
                    if !analyzed_files.contains(&f.path.to_string_lossy().to_string()) {
                        files_to_analyze.push(f);
                    }
                }
            }
        }

        batch_start = batch_end;
    }

    (files_to_analyze, skipped_files)
}

/// Compute priority score for a file (T18)
/// Returns a score based on: entry-point status, recent modification, and file size
pub fn compute_file_priority_score(
    file_info: &crate::indexer::FileInfo,
    git_recent_boost: f32,
    entry_point_boost: f32,
    small_file_boost: f32,
) -> f32 {
    let mut score = 1.0;
    let _path_str = file_info.path.to_string_lossy().to_string();
    let filename = file_info
        .path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    // Entry-point boost: main.*, index.*, app.*, server.*, __init__.*
    let entry_point_patterns = [
        "main.",
        "index.",
        "app.",
        "server.",
        "__init__.",
        "__main__.",
    ];
    if entry_point_patterns.iter().any(|p| filename.starts_with(p)) {
        score *= entry_point_boost;
    }

    // Recent modification boost (mtime < 7 days)
    if let Ok(metadata) = std::fs::metadata(&file_info.path) {
        if let Ok(modified) = metadata.modified() {
            let now = std::time::SystemTime::now();
            if let Ok(elapsed) = now.duration_since(modified) {
                if elapsed.as_secs() < 7 * 24 * 60 * 60 {
                    // 7 days
                    score *= git_recent_boost;
                }
            }
        }
    }

    // Small file boost (< 10KB)
    if file_info.size < 10 * 1024 {
        score *= small_file_boost;
    }

    score
}

/// Log budget summary (T18)
fn log_budget_summary(
    llm_call_count: usize,
    max_calls: usize,
    skipped_by_budget: &[String],
    high_risk_protected: usize,
) {
    if !skipped_by_budget.is_empty() || llm_call_count > 0 {
        tracing::info!(
            "[Budget] LLM calls: {}/{} ({} skipped by budget, {} high-risk protected by reserve)",
            llm_call_count,
            max_calls,
            skipped_by_budget.len(),
            high_risk_protected
        );
        for f in skipped_by_budget {
            tracing::debug!("[Budget] Skipped: {}", f);
        }
    }
}
