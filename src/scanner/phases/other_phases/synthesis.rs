use crate::error::ScanResult;
use crate::findings::VulnerabilityFinding;
use crate::scanner::phases::PhaseConfig;

/// Run rule synthesis phase (Phase 6/24)
///
/// Generates semgrep rules from CWE identifiers using LLM synthesis (MoCQ paper).
/// No-op when `config.rulesynth.enabled` is false or no API key is configured.
pub async fn run_rule_synthesis(
    _scanner: &crate::scanner::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        findings,
        pb,
        analyzed_files,
        metrics_tracker,
        target_path: _,
        config,
        project_stack: _,
    } = cfg;

    if !config.rulesynth.enabled {
        tracing::info!("Rule synthesis disabled (config.rulesynth.enabled=false); skipping");
        pb.set_position(pb.position() + 100);
        return Ok((findings, analyzed_files.to_vec()));
    }

    let phase_config = &config.llm.phases.discovery;
    let Some(api_key) = &phase_config.api_key else {
        tracing::warn!("Rule synthesis enabled but no LLM API key configured; skipping phase");
        pb.set_position(pb.position() + 100);
        return Ok((findings, analyzed_files.to_vec()));
    };

    tracing::info!(
        "Running rule synthesis phase (max {} rules/CWE) → {:?}",
        config.rulesynth.max_rules_per_cwe,
        config.rulesynth.output_dir
    );
    pb.set_message("Phase 6/24: Rule synthesis (LLM→semgrep rules)");

    let timeout = phase_config.timeout_secs.unwrap_or(config.llm.timeout_secs);
    let llm_config = crate::llm::LlmConfig {
        base_url: phase_config.base_url.clone(),
        api_key: api_key.clone(),
        model: phase_config.model.clone(),
        models: phase_config.get_models(),
        timeout,
        max_retries: config.llm.max_retries as u32,
        retry_backoff_ms: config.llm.retry_backoff_ms,
        temperature: config.llm.temperature,
        max_reasoning_tokens: config.llm.max_reasoning_tokens,
    };
    let client = crate::llm::LlmClient::with_metrics(llm_config, Some(metrics_tracker.clone()));

    let mut seen_cwes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for finding in &findings {
        if let Some(cwe) = &finding.cwe_id {
            seen_cwes.insert(cwe.clone());
        }
    }

    let total = seen_cwes.len();

    if config.rulesynth.mocq_mode {
        // MoCQ path: use proposer loop with symbolic validation
        use crate::rulesynth::{emitter, proposer::run_proposer_loop};

        // Load traces from corpus_path if configured
        let traces: Vec<crate::rulesynth::symbolic_validator::LabelledTrace> =
            if let Some(ref corpus) = config.rulesynth.corpus_path {
                // Load from directory using load_corpus (one .txt file per trace)
                crate::rulesynth::symbolic_validator::load_corpus(corpus.as_path())
            } else {
                Vec::new()
            };

        for (i, cwe) in seen_cwes.iter().enumerate() {
            match run_proposer_loop(&client, cwe, &traces, config.rulesynth.max_iterations).await {
                Some((pattern, outcome)) => {
                    // Emit the pattern as YAML
                    let yaml = emitter::emit_yaml(&pattern);
                    let output_dir = std::path::PathBuf::from(&config.rulesynth.output_dir);
                    std::fs::create_dir_all(&output_dir).ok();
                    let filename = format!("{}_mocq.yml", cwe);
                    let filepath = output_dir.join(&filename);
                    if let Err(e) = std::fs::write(&filepath, &yaml) {
                        tracing::warn!("MoCQ emit failed for {}: {}", cwe, e);
                    } else {
                        tracing::info!(
                            "MoCQ: emitted pattern for {} to {}",
                            cwe,
                            filepath.display()
                        );
                    }
                    tracing::info!("MoCQ: pattern for {} converged (F1={:.2})", cwe, outcome.f1);
                }
                None => {
                    tracing::warn!("MoCQ: no valid pattern produced for {}", cwe);
                }
            }
            pb.set_position(pb.position() + (i as u64 * 100 / total.max(1) as u64));
        }
    } else {
        // Original path: use old RuleSynthesizer
        let synthesizer = crate::rulesynth::RuleSynthesizer::new(&client, &config.rulesynth);

        for (i, cwe) in seen_cwes.iter().enumerate() {
            for language in &config.project.languages {
                match synthesizer.generate(cwe, language).await {
                    Ok(rules) => {
                        if rules.is_empty() {
                            tracing::debug!(
                                "Rule synthesis: no valid rules for {} ({})",
                                cwe,
                                language
                            );
                        } else {
                            tracing::info!(
                                "Rule synthesis: generated {} valid rule(s) for {} ({})",
                                rules.len(),
                                cwe,
                                language
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Rule synthesis failed for {} ({}): {}", cwe, language, e);
                    }
                }
            }
            pb.set_position(pb.position() + (i as u64 * 100 / total.max(1) as u64));
        }
    }

    pb.set_position(pb.position() + 100);
    Ok((findings, analyzed_files.to_vec()))
}

/// Run exploit synthesis phase (Phase 22/24)
///
/// Generates sandbox-verified exploits for confirmed findings (QRS paper).
/// No-op when `config.exploit.enabled` is false or Docker sandbox unavailable.
pub async fn run_exploit_synth(
    _scanner: &crate::scanner::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        mut findings,
        pb,
        analyzed_files,
        metrics_tracker,
        target_path: _,
        config,
        project_stack: _,
    } = cfg;

    if !config.exploit.enabled {
        tracing::info!("Exploit synthesis disabled (config.exploit.enabled=false); skipping");
        pb.set_position(pb.position() + 100);
        return Ok((findings, analyzed_files.to_vec()));
    }

    let phase_config = &config.llm.phases.discovery;
    let Some(api_key) = &phase_config.api_key else {
        tracing::warn!("Exploit synthesis enabled but no LLM API key configured; skipping phase");
        pb.set_position(pb.position() + 100);
        return Ok((findings, analyzed_files.to_vec()));
    };

    let timeout = phase_config.timeout_secs.unwrap_or(config.llm.timeout_secs);
    let llm_config = crate::llm::LlmConfig {
        base_url: phase_config.base_url.clone(),
        api_key: api_key.clone(),
        model: phase_config.model.clone(),
        models: phase_config.get_models(),
        timeout,
        max_retries: config.llm.max_retries as u32,
        retry_backoff_ms: config.llm.retry_backoff_ms,
        temperature: config.llm.temperature,
        max_reasoning_tokens: config.llm.max_reasoning_tokens,
    };
    let client = crate::llm::LlmClient::with_metrics(llm_config, Some(metrics_tracker.clone()));

    let synth = crate::exploit::ExploitSynthesizer::new(&client, &config.exploit);
    if !synth.is_available() {
        tracing::warn!(
            "Exploit synthesis enabled but sandbox unavailable (Docker not running?); skipping phase"
        );
        pb.set_position(pb.position() + 100);
        return Ok((findings, analyzed_files.to_vec()));
    }

    tracing::info!(
        "Running exploit synthesis on {} findings (max {} exploit(s)/finding, sandbox={})",
        findings.len(),
        config.exploit.max_exploits_per_finding,
        config.exploit.sandbox_image
    );
    pb.set_message("Phase 22/24: Exploit synthesis (sandbox-verified PoCs)");

    let total = findings.len();
    for (i, finding) in findings.iter_mut().enumerate() {
        match synth.synthesize_and_verify(finding).await {
            Ok(result) => {
                if result.confirmed {
                    tracing::info!(
                        "Exploit confirmed for finding {} (exit_code={})",
                        finding.id,
                        result.exit_code
                    );
                    if let Some(verdict) = &mut finding.triage_verdict {
                        let _ = verdict;
                    }
                } else {
                    tracing::debug!(
                        "Exploit not confirmed for finding {} (exit_code={}, matched={})",
                        finding.id,
                        result.exit_code,
                        result.matched_expected
                    );
                }
            }
            Err(crate::exploit::ExploitError::Disabled) => {}
            Err(e) => {
                tracing::warn!("Exploit synthesis failed for finding {}: {}", finding.id, e);
            }
        }
        pb.set_position(pb.position() + (i as u64 * 100 / total.max(1) as u64));
    }

    pb.set_position(pb.position() + 100);
    Ok((findings, analyzed_files.to_vec()))
}

/// Run the Validate phase (phase 9/24).
///
/// LLM-as-judge rationale validation implementing the CORRECT paper (arxiv:2504.13474).
/// For each finding, an LLM evaluates the soundness of the reasoning and adjusts
/// confidence: +0.10 for sound reasoning, -0.20 for flawed reasoning.
pub async fn run_validate(
    _scanner: &crate::scanner::Scanner,
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase: _,
        findings,
        pb,
        analyzed_files,
        metrics_tracker,
        target_path: _,
        config,
        project_stack: _,
    } = cfg;

    if !config.validate.enabled {
        tracing::info!("Validate phase disabled (config.validate.enabled=false); skipping");
        pb.set_position(pb.position() + 100);
        return Ok((findings, analyzed_files.to_vec()));
    }

    let phase_config = &config.llm.phases.verification;
    let Some(api_key) = &phase_config.api_key else {
        tracing::warn!("Validate phase enabled but no LLM API key configured; skipping");
        pb.set_position(pb.position() + 100);
        return Ok((findings, analyzed_files.to_vec()));
    };

    tracing::info!(
        "Running Validate phase (rationale check on {} findings)",
        findings.len()
    );
    pb.set_message("Phase 9/24: Validate (rationale check)");

    let timeout = phase_config.timeout_secs.unwrap_or(config.llm.timeout_secs);
    let llm_config = crate::llm::LlmConfig {
        base_url: phase_config.base_url.clone(),
        api_key: api_key.clone(),
        model: phase_config.model.clone(),
        models: phase_config.get_models(),
        timeout,
        max_retries: config.llm.max_retries as u32,
        retry_backoff_ms: config.llm.retry_backoff_ms,
        temperature: config.llm.temperature,
        max_reasoning_tokens: config.llm.max_reasoning_tokens,
    };
    let client = crate::llm::LlmClient::with_metrics(llm_config, Some(metrics_tracker.clone()));

    let total = findings.len();
    let mut updated: Vec<VulnerabilityFinding> = Vec::with_capacity(total);

    for (i, finding) in findings.into_iter().enumerate() {
        match crate::llm_verification::rationale_check(&client, &finding).await {
            Ok(verdict) => {
                let mut f = finding;
                f.confidence_score =
                    (f.confidence_score + verdict.confidence_adjustment).clamp(0.0, 1.0);
                if !verdict.issues.is_empty() {
                    let note = format!(
                        "Rationale check: {}\nIssues: {}",
                        if verdict.is_sound { "sound" } else { "flawed" },
                        verdict.issues.join("; ")
                    );
                    f.verification_notes = Some(match f.verification_notes.take() {
                        Some(existing) => format!("{}\n{}", existing, note),
                        None => note,
                    });
                }
                tracing::debug!(
                    "Validate [{}/{}]: {:?} confidence {:+.2}",
                    i + 1,
                    total,
                    f.title,
                    verdict.confidence_adjustment
                );
                updated.push(f);
            }
            Err(e) => {
                tracing::warn!(
                    "Validate [{}/{}]: rationale_check failed: {}",
                    i + 1,
                    total,
                    e
                );
                updated.push(finding);
            }
        }
        pb.set_position(pb.position() + ((i as u64 + 1) * 100 / total.max(1) as u64));
    }

    pb.set_position(pb.position() + 100);
    Ok((updated, analyzed_files.to_vec()))
}

/// Default handler for unknown phases
pub async fn run_default(
    cfg: PhaseConfig<'_>,
) -> ScanResult<(Vec<VulnerabilityFinding>, Vec<String>)> {
    let PhaseConfig {
        phase,
        findings,
        pb: _,
        analyzed_files,
        metrics_tracker: _,
        target_path: _,
        config: _,
        project_stack: _,
    } = cfg;

    tracing::warn!("Unknown phase: {:?}. Skipping.", phase);
    Ok((findings, analyzed_files.to_vec()))
}
