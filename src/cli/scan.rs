use crate::config;
use crate::validation;
use std::path::{Path, PathBuf};

#[allow(clippy::too_many_arguments)]
pub async fn run_scan(
    config_path: &Path,
    target: Option<PathBuf>,
    force: bool,
    evidence_gate: bool,
    dry_run: bool,
    preset_overlay: Option<crate::preset::PresetOverlay>,
    diff: Option<String>,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match validation::validate_config(config_path) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!("Validation error: {}", e);
            std::process::exit(2);
        }
    }
    // Layering: defaults → preset → user-file explicit keys (user wins).
    let mut config = config::ScannerConfig::from_file_with_preset(
        config_path.to_str().ok_or("Invalid config path")?,
        preset_overlay,
    )?;

    // Apply env overrides (mirrors run_verify behavior)
    config::apply_env_overrides(&mut config);

    // Apply CLI flag override
    if evidence_gate {
        config.output.evidence_gate = true;
    }

    // Save evidence_gate flag before config is moved into scanner
    let evidence_gate_enabled = config.output.evidence_gate;

    let output_dir = PathBuf::from(&config.output.dir);
    std::fs::create_dir_all(&output_dir)?;

    let target_path = target.unwrap_or_else(|| PathBuf::from(&config.project.path));

    // Dry-run mode: perform indexing + prioritization, print estimate, exit
    if dry_run {
        return run_dry_run(&config, &target_path, quiet);
    }

    if !quiet {
        tracing::info!("Starting BACO security scan on: {}", target_path.display());
        tracing::info!("Config: {}", config_path.display());
        tracing::info!("Running scanner pipeline...");
    }

    // Install Ctrl+C handler before starting scanner
    let checkpoint_path = output_dir.join("checkpoint.json");
    let checkpoint_path_clone = checkpoint_path.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::error!("\nScan interrupted. Progress saved to checkpoint.");
            tracing::error!(
                "Resume with: baco resume --checkpoint {}",
                checkpoint_path_clone.display()
            );
            std::process::exit(130);
        }
    });

    // Check for existing checkpoint and auto-resume if found
    if checkpoint_path.exists() && !quiet {
        tracing::info!(
            "Found existing checkpoint at: {}",
            checkpoint_path.display()
        );
        tracing::info!(
            "Checkpoint exists. Scan will start fresh. Use --resume for continuation or delete checkpoint to start clean."
        );
    }
    // Use a simple message instead of spinner - scanner will show its own progress bar
    crate::ui::Ui::new(quiet).status("Initializing scanner...");

    let project_name = config.project.name.clone();
    let diff_repo = target_path.clone();
    let scanner = crate::scanner::Scanner::new(config, target_path, force);
    let mut findings = scanner.run().await?;

    // Diff scope: keep only findings in files changed in the revspec.
    if let Some(revspec) = diff {
        let changed = crate::tools::diff_analysis::changed_files(
            diff_repo.to_str().unwrap_or("."),
            &revspec,
        )?;
        let before = findings.len();
        findings
            .retain(|f| crate::tools::diff_analysis::matches_changed_set(&f.file_path, &changed));
        tracing::info!(
            "Diff scope '{}': {} files changed, {}/{} findings kept",
            revspec,
            changed.len(),
            findings.len(),
            before
        );
    }

    // Print summary and save reports
    print_scan_summary(
        &findings,
        &output_dir,
        &project_name,
        evidence_gate_enabled,
        quiet,
    )?;

    Ok(())
}

pub async fn run_resume(
    checkpoint_path: &Path,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let checkpoint = validation::validate_checkpoint(checkpoint_path)?;
    if checkpoint.current_phase == crate::checkpoint::ScanPhase::Complete {
        if !quiet {
            tracing::info!("Scan already completed.");
        }
        return Ok(());
    }

    // Display checkpoint UI
    if !quiet {
        tracing::info!("\n══════════════════════════════════════");
        tracing::info!("     CHECKPOINT SCAN INFORMATION");
        tracing::info!("══════════════════════════════════════\n");
        tracing::info!("📁 Checkpoint Path: {}", checkpoint_path.display());
        tracing::info!("🔢 Scan ID: {}", checkpoint.scan_id);
        tracing::info!(
            "📅 Started: {}",
            checkpoint.started_at.format("%Y-%m-%d %H:%M:%S")
        );
        tracing::info!("⏳ Current Phase: {:?}", checkpoint.current_phase);
        tracing::info!("✅ Completed Phases: {}", checkpoint.completed_phases.len());
        for (i, phase) in checkpoint.completed_phases.iter().enumerate() {
            if i < 3 || i >= checkpoint.completed_phases.len().saturating_sub(3) {
                tracing::info!("   • {}", format_phase(phase));
            } else if i == 3 {
                tracing::info!(
                    "   • ... ({} more phases)",
                    checkpoint.completed_phases.len() - 3
                );
            }
        }
        tracing::info!("🎯 Findings Found: {}", checkpoint.findings_so_far.len());
        tracing::info!("📊 Files Analyzed: {}", checkpoint.file_count);
        tracing::info!(
            "📋 Analyzed Files Count: {}",
            checkpoint.analyzed_files.len()
        );
        tracing::info!("══════════════════════════════════════\n");
    }

    // Find all checkpoints in the same directory
    let checkpoint_dir = checkpoint_path.parent().unwrap_or(Path::new("/"));
    let mut other_checkpoints: Vec<PathBuf> = vec![];

    if checkpoint_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(checkpoint_dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.is_file() {
                    let filename = path.file_name().map(|n| n.to_string_lossy().to_string());
                    if filename.map(|n| n.ends_with(".json")).unwrap_or(false)
                        && path != checkpoint_path
                    {
                        other_checkpoints.push(path);
                    }
                }
            }
        }
    }

    if !other_checkpoints.is_empty() && !quiet {
        tracing::warn!("⚠️  Multiple checkpoints found!");
        tracing::info!("Available checkpoints to resume from:");
        for (i, cp) in other_checkpoints.iter().enumerate() {
            tracing::info!("{} {}", if i + 1 == 1 { "🔹" } else { "   " }, cp.display());
        }
    }

    let prev_findings_count = checkpoint.findings_so_far.len();

    // Load config from checkpoint's project path
    let config_path = PathBuf::from(&checkpoint.project_path).join("config.toml");
    let config = if config_path.exists() {
        config::ScannerConfig::from_file(config_path.to_str().ok_or("Invalid config path")?)?
    } else {
        if !quiet {
            tracing::warn!(
                "Warning: Config file not found at {:?}, using default config",
                config_path
            );
        }
        config::ScannerConfig::default()
    };

    let output_dir = PathBuf::from(&config.output.dir);
    std::fs::create_dir_all(&output_dir)?;

    // Create scanner with existing findings from checkpoint
    let target_path = PathBuf::from(&checkpoint.project_path);
    let initial_findings = checkpoint.findings_so_far.clone();
    let scanner = crate::scanner::Scanner::with_initial_findings(
        config,
        target_path,
        initial_findings,
        false,
    );

    let findings = scanner.run().await?;

    // Calculate summary
    let mut severity_counts = std::collections::HashMap::new();
    for finding in &findings {
        *severity_counts
            .entry(finding.severity.to_string())
            .or_insert(0) += 1;
    }
    let new_findings_count = findings.len().saturating_sub(prev_findings_count);

    // Update checkpoint with new findings
    let mut final_checkpoint = checkpoint;
    final_checkpoint.findings_so_far = findings.clone();
    final_checkpoint.save(checkpoint_path.to_str().unwrap())?;

    if !quiet {
        tracing::info!("✅ Resume completed!");
        tracing::info!("══════════════════════════════════════");
    }

    if new_findings_count > 0 && !quiet {
        tracing::info!(
            "🎉 Found {} new finding{}",
            new_findings_count,
            if new_findings_count > 1 { "s" } else { "" }
        );
    }
    tracing::info!("📊 Total findings: {}", findings.len());

    if !severity_counts.is_empty() && !quiet {
        let mut sorted: Vec<_> = severity_counts.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        let mut parts = Vec::new();
        for (severity, count) in sorted {
            parts.push(format!("{}: {}", severity, count));
        }
        tracing::warn!("⚠️  Severity breakdown: {}", parts.join(", "));
    }

    if !quiet {
        tracing::info!("══════════════════════════════════════\n");
    }

    // Save findings to output directory
    let findings_path = output_dir.join("findings.json");
    let json = serde_json::to_string_pretty(&findings)?;
    std::fs::write(&findings_path, json)?;

    if !quiet {
        tracing::info!("💾 Findings saved to {}", findings_path.display());
    }

    Ok(())
}

pub fn format_phase(phase: &crate::checkpoint::ScanPhase) -> String {
    // Delegate to PhaseGraph for data-driven display names
    // This keeps phase numbering in sync with PhaseGraph (single source of truth)
    let phase_graph = crate::scanner::PhaseGraph::new();
    phase_graph.display_name(phase)
}

/// Print scan summary and save reports (quiet-gating via Ui).
pub fn print_scan_summary(
    findings: &[crate::findings::VulnerabilityFinding],
    output_dir: &std::path::Path,
    project_name: &str,
    evidence_gate_enabled: bool,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let ui = crate::ui::Ui::new(quiet);
    ui.line("═══════════════════════════════════════");
    ui.line(format!("Scan complete: {} findings", findings.len()));

    // Count by severity
    let mut severity_counts = std::collections::HashMap::new();
    for finding in findings {
        *severity_counts
            .entry(finding.severity.to_string())
            .or_insert(0) += 1;
    }
    if !severity_counts.is_empty() {
        let mut parts = Vec::new();
        for (severity, count) in severity_counts.iter() {
            parts.push(format!("{} {}", count, severity));
        }
        tracing::info!("Severity breakdown: {}", parts.join(", "));
    }

    // Evidence tier summary when gating is active
    if evidence_gate_enabled {
        let mut tier_counts = (0, 0, 0); // (verified, supported, unverified)
        for finding in findings {
            let tier =
                crate::evidence::classify_finding(&finding.evidence, finding.confidence_score);
            match tier {
                crate::evidence::VerificationTier::Verified => tier_counts.0 += 1,
                crate::evidence::VerificationTier::Supported => tier_counts.1 += 1,
                crate::evidence::VerificationTier::Unverified => tier_counts.2 += 1,
            }
        }
        ui.emit(format!(
            "Evidence gate: {} verified, {} supported, {} unverified (excluded from reports)",
            tier_counts.0, tier_counts.1, tier_counts.2
        ));
    }

    // Save findings to output directory
    let findings_path = output_dir.join("findings.json");
    let json = serde_json::to_string_pretty(&findings)?;
    std::fs::write(&findings_path, json)?;

    // Write markdown report alongside JSON
    let markdown_path = output_dir.join("findings.md");
    let md_content = crate::report::markdown::generate_markdown_report(findings, project_name);
    std::fs::write(&markdown_path, md_content)?;

    tracing::info!("Results saved to:");
    tracing::info!("  - Findings: {}", findings_path.display());
    tracing::info!("  - Markdown report: {}", markdown_path.display());
    tracing::info!("  - HTML report: {}/report.html", output_dir.display());
    tracing::info!("═══════════════════════════════════════");

    Ok(())
}

/// Run dry-run mode: index + prioritize + estimate, then exit
pub fn run_dry_run(
    config: &crate::config::ScannerConfig,
    target_path: &std::path::Path,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::indexer::FileIndex;
    use crate::scanner::phases::llm_phases::static_analysis::compute_file_priority_score;

    let ui = crate::ui::Ui::new(quiet);
    tracing::info!("[Dry Run] Indexing project...");

    // Index project
    let index = FileIndex::index_project(
        target_path.to_str().unwrap_or("."),
        &config.project.languages,
        config.scanner.max_file_size_kb * 1024,
        &config.scanner.exclude_paths,
        config.scanner.performance.enable_file_filtering,
    )
    .unwrap_or(FileIndex {
        files: Vec::new(),
        total_size: 0,
        hash_store: None,
    });

    let files = index.get_files();

    // Compute priority scores and count files per language
    let mut files_by_lang: std::collections::HashMap<String, Vec<&crate::indexer::FileInfo>> =
        std::collections::HashMap::new();
    let mut total_priority: f32 = 0.0;

    for file in files {
        let lang = file.language.clone();
        let hook_map = crate::hook_registry::load_hook_map(&crate::hook_registry::hook_map_path(
            std::path::PathBuf::from(&config.output.dir).as_path(),
        ));
        let score = compute_file_priority_score(file, &config.priority, &hook_map);
        total_priority += score;
        files_by_lang.entry(lang).or_default().push(file);
    }

    // Estimate LLM calls respecting budget and triage
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
    let normal_cap = max_calls.saturating_sub((max_calls as f32 * reserve_percent) as usize);

    // Count high-risk files (entry-points)
    let mut high_risk_count = 0;
    let mut normal_count = 0;
    for file in files {
        let file_name = file
            .path
            .file_name()
            .map(|n: &std::ffi::OsStr| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let is_high_risk = ["main.", "index.", "app.", "server.", "__init__."]
            .iter()
            .any(|p| file_name.contains(p));
        if is_high_risk {
            high_risk_count += 1;
        } else {
            normal_count += 1;
        }
    }

    // Estimate planned LLM calls (triage would skip low-suspicion files)
    let planned_calls = if config.triage.enabled {
        // Assume triage filters ~50% of non-high-risk files
        let triaged_normal = normal_count / 2;
        std::cmp::min(normal_cap, triaged_normal)
            + std::cmp::min(max_calls.saturating_sub(normal_cap), high_risk_count)
    } else {
        std::cmp::min(max_calls, files.len())
    };

    // Estimate tokens (~4 chars/token)
    let total_bytes: usize = files.iter().map(|f| f.size as usize).sum();
    let estimated_tokens = total_bytes / 4;

    // Print estimate
    ui.line("\n[Dry Run] Project Estimate");
    ui.line("═══════════════════════════════════════");
    ui.line(format!("Target: {}", target_path.display()));
    ui.line("\nFiles by language:");
    for (lang, lang_files) in &files_by_lang {
        ui.line(format!("  {}: {} files", lang, lang_files.len()));
    }
    ui.line(format!("\nTotal files: {}", files.len()));
    ui.line(format!("Total size: {} bytes", total_bytes));
    ui.line(format!(
        "Estimated tokens (~4 chars/token): {}",
        estimated_tokens
    ));
    ui.line(format!("\nPlanned LLM calls: {}", planned_calls));
    if config.budget.enabled {
        ui.line(format!(
            "  (budget max: {}, normal cap: {}, high-risk: {})",
            max_calls,
            normal_cap,
            max_calls.saturating_sub(normal_cap)
        ));
    }
    ui.line(format!(
        "\nAverage priority score: {:.2}",
        if files.is_empty() {
            0.0
        } else {
            total_priority / files.len() as f32
        }
    ));
    if quiet {
        ui.emit(format!(
            "[Dry Run] {} files, {} tokens, {} planned LLM calls",
            files.len(),
            estimated_tokens,
            planned_calls
        ));
    }
    ui.emit("[Dry Run] No phases executed, no findings produced.");

    Ok(())
}
