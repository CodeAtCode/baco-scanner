use baco::config;
use baco::doctor;
use baco::preset;
use baco::validation;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use tracing::info;

#[derive(Parser)]
#[command(name = "baco")]
#[command(about = "BACO - CLI Security Vulnerability Scanner")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[arg(short, long, global = true, help = "Suppress all non-essential output")]
    quiet: bool,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long, short)]
        force: bool,
        #[arg(long, help = "Only independently reproduced findings reach reports")]
        evidence_gate: bool,
        #[arg(long, help = "Print estimate and exit before LLM/semgrep phases")]
        dry_run: bool,
        #[arg(long, help = "Preset name (not yet available)")]
        preset: Option<String>,
    },
    Resume {
        #[arg(short, long)]
        checkpoint: PathBuf,
    },
    Report {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long, default_value = "html")]
        format: String,
    },
    Verify {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long, help = "Config file path")]
        config: Option<PathBuf>,
    },
    Eval {
        #[arg(long, help = "Target directory to evaluate")]
        target: PathBuf,
        #[arg(long, help = "Path to ground truth oracle JSON")]
        ground_truth: PathBuf,
        #[arg(
            long,
            help = "Path to findings JSON to score (optional - if omitted, runs scanner first)"
        )]
        findings: Option<PathBuf>,
    },
    Preset {
        #[command(subcommand)]
        action: PresetCommands,
    },
    Doctor {
        #[arg(short, long, help = "Config file path")]
        config: Option<PathBuf>,
        #[arg(long, help = "Output directory path")]
        output_dir: Option<PathBuf>,
        #[arg(long, help = "Output results as JSON")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum PresetCommands {
    List {
        #[arg(long, help = "Show full TOML for each preset")]
        verbose: bool,
    },
    Show {
        #[arg(help = "Preset name to display")]
        name: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logging - respect quiet mode but still set up logger
    let log_level = match cli.verbose {
        0 if !cli.quiet => "warn",
        0 if cli.quiet => "error",
        1 if !cli.quiet => "info",
        1 if cli.quiet => "warn",
        2 => "debug",
        _ => "trace",
    };

    let env_filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| log_level.into());

    // Initialize logger with the determined level
    let logger = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(!cli.quiet);

    if cli.quiet {
        logger.without_time().init();
    } else {
        logger.init();
    }

    // Exit early if quiet mode suppresses everything else
    if cli.quiet {
        // Only show errors via tracing's error! macro
    }

    match cli.command {
        Commands::Scan {
            config,
            target,
            force,
            evidence_gate,
            dry_run,
            preset,
        } => {
            info!("Starting scan with config: {:?}", config);

            // Load preset if specified
            let preset_overlay = if let Some(preset_name) = &preset {
                match preset::load_preset(preset_name) {
                    Ok(overlay) => Some(overlay),
                    Err(e) => {
                        tracing::error!("{}", e);
                        std::process::exit(2);
                    }
                }
            } else {
                None
            };

            run_scan(
                &config,
                target,
                force,
                evidence_gate,
                dry_run,
                preset_overlay,
                cli.quiet,
            )
            .await
            .unwrap_or_else(|e| {
                tracing::error!("Scan failed: {}", e);
                std::process::exit(1);
            });
        }
        Commands::Resume { checkpoint } => {
            info!("Resuming from checkpoint: {:?}", checkpoint);
            run_resume(&checkpoint, cli.quiet)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!("Resume failed: {}", e);
                    std::process::exit(1);
                });
        }
        Commands::Report { input, format } => {
            info!("Generating {} report from: {:?}", format, input);
            run_report(&input, &format, cli.quiet).unwrap_or_else(|e| {
                tracing::error!("Report generation failed: {}", e);
                std::process::exit(1);
            });
        }
        Commands::Verify { input, config } => {
            info!("Verifying findings from: {:?}", input);
            run_verify(&input, config, cli.quiet)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!("Verification failed: {}", e);
                    std::process::exit(1);
                });
        }
        Commands::Eval {
            target,
            ground_truth,
            findings,
        } => {
            info!("Running eval on target: {:?}", target);
            run_eval(&target, &ground_truth, findings, cli.quiet).unwrap_or_else(|e| {
                tracing::error!("Eval failed: {}", e);
                std::process::exit(1);
            });
        }
        Commands::Preset { action } => run_preset_command(action, cli.quiet),
        Commands::Doctor {
            config,
            output_dir,
            json,
        } => {
            run_doctor(config.as_deref(), output_dir.as_deref(), json, cli.quiet);
        }
    }
}

async fn run_scan(
    config_path: &Path,
    target: Option<PathBuf>,
    force: bool,
    evidence_gate: bool,
    dry_run: bool,
    preset_overlay: Option<baco::preset::PresetOverlay>,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match validation::validate_config(config_path) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!("Validation error: {}", e);
            std::process::exit(2);
        }
    }
    let mut config =
        config::ScannerConfig::from_file(config_path.to_str().ok_or("Invalid config path")?)?;

    // Apply preset overlay before user config
    if let Some(preset) = preset_overlay {
        preset.merge_into(&mut config);
    }

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
            "Auto-resuming from last phase. Use 'baco resume --checkpoint {}' for manual control.",
            checkpoint_path.display()
        );
    }

    if !quiet {
        tracing::info!("Running scanner pipeline...");
    }

    // Use a simple message instead of spinner - scanner will show its own progress bar
    if !quiet {
        eprintln!("Initializing scanner...");
    }

    let project_name = config.project.name.clone();
    let scanner = baco::scanner::Scanner::new(config, target_path, force);
    let findings = scanner.run().await?;

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

async fn run_resume(checkpoint_path: &Path, quiet: bool) -> Result<(), Box<dyn std::error::Error>> {
    let checkpoint = validation::validate_checkpoint(checkpoint_path)?;
    if checkpoint.current_phase == baco::checkpoint::ScanPhase::Complete {
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
    let scanner =
        baco::scanner::Scanner::with_initial_findings(config, target_path, initial_findings, false);

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

fn format_phase(phase: &baco::checkpoint::ScanPhase) -> String {
    // Delegate to PhaseGraph for data-driven display names
    // This keeps phase numbering in sync with PhaseGraph (single source of truth)
    let phase_graph = baco::scanner::PhaseGraph::new();
    phase_graph.display_name(phase)
}

/// Print scan summary and save reports (shared by quiet and normal branches)
fn print_scan_summary(
    findings: &[baco::findings::VulnerabilityFinding],
    output_dir: &std::path::Path,
    project_name: &str,
    evidence_gate_enabled: bool,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !quiet {
        tracing::info!("═══════════════════════════════════════");
        tracing::info!("Scan complete: {} findings", findings.len());

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
                    baco::evidence::classify_finding(&finding.evidence, finding.confidence_score);
                match tier {
                    baco::evidence::VerificationTier::Verified => tier_counts.0 += 1,
                    baco::evidence::VerificationTier::Supported => tier_counts.1 += 1,
                    baco::evidence::VerificationTier::Unverified => tier_counts.2 += 1,
                }
            }
            println!(
                "Evidence gate: {} verified, {} supported, {} unverified (excluded from reports)",
                tier_counts.0, tier_counts.1, tier_counts.2
            );
        }

        // Save findings to output directory
        let findings_path = output_dir.join("findings.json");
        let json = serde_json::to_string_pretty(&findings)?;
        std::fs::write(&findings_path, json)?;

        // Write markdown report alongside JSON
        let markdown_path = output_dir.join("findings.md");
        let md_content = baco::report::markdown::generate_markdown_report(findings, project_name);
        std::fs::write(&markdown_path, md_content)?;

        tracing::info!("Results saved to:");
        tracing::info!("  - Findings: {}", findings_path.display());
        tracing::info!("  - Markdown report: {}", markdown_path.display());
        tracing::info!("  - HTML report: {}/report.html", output_dir.display());
        tracing::info!("═══════════════════════════════════════");
    } else {
        // Quiet mode: only show summary line when complete
        tracing::info!("Scan complete: {} findings", findings.len());

        // Evidence tier summary when gating is active
        if evidence_gate_enabled {
            let mut tier_counts = (0, 0, 0); // (verified, supported, unverified)
            for finding in findings {
                let tier =
                    baco::evidence::classify_finding(&finding.evidence, finding.confidence_score);
                match tier {
                    baco::evidence::VerificationTier::Verified => tier_counts.0 += 1,
                    baco::evidence::VerificationTier::Supported => tier_counts.1 += 1,
                    baco::evidence::VerificationTier::Unverified => tier_counts.2 += 1,
                }
            }
            println!(
                "Evidence gate: {} verified, {} supported, {} unverified (excluded from reports)",
                tier_counts.0, tier_counts.1, tier_counts.2
            );
        }

        // Save findings to output directory
        let findings_path = output_dir.join("findings.json");
        let json = serde_json::to_string_pretty(&findings)?;
        std::fs::write(&findings_path, json)?;

        // Write markdown report alongside JSON
        let markdown_path = output_dir.join("findings.md");
        let md_content = baco::report::markdown::generate_markdown_report(findings, project_name);
        std::fs::write(&markdown_path, md_content)?;

        // HTML report path
        let _report_path = format!("{}/report.html", output_dir.display());
    }

    Ok(())
}

/// Run dry-run mode: index + prioritize + estimate, then exit
fn run_dry_run(
    config: &baco::config::ScannerConfig,
    target_path: &std::path::Path,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use baco::indexer::FileIndex;
    use baco::scanner::phases::llm_phases::static_analysis::compute_file_priority_score;

    if !quiet {
        tracing::info!("[Dry Run] Indexing project...");
    }

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
    let mut files_by_lang: std::collections::HashMap<String, Vec<&baco::indexer::FileInfo>> =
        std::collections::HashMap::new();
    let mut total_priority: f32 = 0.0;

    for file in files {
        let lang = file.language.clone();
        let hook_map = baco::hook_registry::load_hook_map(&baco::hook_registry::hook_map_path(
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
    if !quiet {
        println!("\n[Dry Run] Project Estimate");
        println!("═══════════════════════════════════════");
        println!("Target: {}", target_path.display());
        println!("\nFiles by language:");
        for (lang, lang_files) in &files_by_lang {
            println!("  {}: {} files", lang, lang_files.len());
        }
        println!("\nTotal files: {}", files.len());
        println!("Total size: {} bytes", total_bytes);
        println!("Estimated tokens (~4 chars/token): {}", estimated_tokens);
        println!("\nPlanned LLM calls: {}", planned_calls);
        if config.budget.enabled {
            println!(
                "  (budget max: {}, normal cap: {}, high-risk: {})",
                max_calls,
                normal_cap,
                max_calls.saturating_sub(normal_cap)
            );
        }
        println!(
            "\nAverage priority score: {:.2}",
            if files.is_empty() {
                0.0
            } else {
                total_priority / files.len() as f32
            }
        );
        println!("\n[Dry Run] No phases executed, no findings produced.");
    } else {
        // Quiet mode: minimal output
        println!(
            "[Dry Run] {} files, {} tokens, {} planned LLM calls",
            files.len(),
            estimated_tokens,
            planned_calls
        );
        println!("[Dry Run] No phases executed, no findings produced.");
    }

    Ok(())
}

fn run_report(input: &Path, format: &str, quiet: bool) -> Result<(), Box<dyn std::error::Error>> {
    let findings = validation::validate_findings(input)?;
    let output_dir = input.parent().ok_or_else(|| {
        format!(
            "Failed to determine output directory from: {}",
            input.display()
        )
    })?;
    let output_path = match format {
        "html" => output_dir.join("report.html"),
        "json" => output_dir.join("findings.json"),
        "sarif" => output_dir.join("report.sarif"),
        _ => output_dir.join(format),
    };

    if !quiet {
        info!("Generating {} report to {:?}", format, output_path);
    }

    match format {
        "html" => {
            use baco::report::html::generate_html_report;
            generate_html_report(&findings, &output_path.to_string_lossy(), None, None)
                .map_err(|e| format!("Failed to generate HTML report: {}", e))?;
        }
        "json" => {
            use baco::report::json::write_findings_json;
            write_findings_json(
                &findings,
                &[],
                &output_path.to_string_lossy(),
                None,
                None,
                None,
                None, // scan_health
            )
            .map_err(|e| format!("Failed to generate JSON report: {}", e))?;
        }
        "sarif" => {
            use baco::report::sarif::generate_sarif_report;
            let sarif_path = output_path.clone();
            let sarif_json = generate_sarif_report(&findings, None)?;
            std::fs::write(&sarif_path, sarif_json)
                .map_err(|e| format!("Failed to write SARIF report: {}", e))?;
            if !quiet {
                info!("Generated SARIF report to {:?}", sarif_path);
            }
        }
        "markdown" => {
            use baco::report::markdown::generate_markdown_report;
            let md_path = output_path.clone();
            let md_content = generate_markdown_report(&findings, "unknown");
            std::fs::write(&md_path, md_content)
                .map_err(|e| format!("Failed to write markdown report: {}", e))?;
            if !quiet {
                info!("Generated markdown report to {:?}", md_path);
            }
        }
        _ => return Err(format!("Unsupported report format: {}", format).into()),
    }

    if !quiet {
        info!("Report generated successfully at {:?}", output_path);
    }
    Ok(())
}

async fn run_verify(
    input: &Path,
    config_path: Option<PathBuf>,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut findings = validation::validate_findings(input)?;
    if findings.is_empty() {
        if !quiet {
            info!("No findings to verify.");
        }
        return Ok(());
    }

    if !quiet {
        tracing::info!("Loaded {} findings to verify", findings.len());
    }

    let config_path =
        config_path.or_else(|| std::env::var("LLM_CONFIG_PATH").map(PathBuf::from).ok());
    let mut config = match &config_path {
        Some(path) => {
            if !path.exists() {
                tracing::error!("Config file not found: {:?}", path);
                return Err("Config file not found".into());
            }
            let path_str = path.to_str().ok_or("Invalid config path")?;
            config::ScannerConfig::from_file(path_str)?
        }
        None => config::ScannerConfig::default(),
    };
    config::apply_env_overrides(&mut config);
    if config.llm.phases.verification.api_key.is_none() {
        tracing::error!("LLM verification API key is not configured.");
        std::process::exit(1);
    }
    let client =
        baco::llm::LlmClient::new(baco::llm::phase_llm_config(&config, "verification", None)?);
    for finding in findings.iter_mut() {
        tracing::info!("Verifying finding: {}", finding.id);
        let messages = vec![
            baco::llm::ChatMessage::system(
                "You are a security expert. Analyze each finding and determine if it is a confirmed vulnerability, false positive, or needs manual review. Return JSON: {\"status\": \"confirmed\"|\"false_positive\"|\"needs_review\", \"reason\": \"explanation\"}",
            ),
            baco::llm::ChatMessage::user(
                format!(
                    "Finding:\n- ID: {}\n- Title: {}\n- Severity: {}\n- File: {}:{}\n- Description: {}\n- CWE: {}\n- Code: {}\n- Recommendation: {}\n\nAnalyze this finding.",
                    finding.id,
                    finding.title,
                    finding.severity,
                    finding.file_path,
                    finding.line_number.unwrap_or(0),
                    finding.description,
                    finding.cwe_id.as_deref().unwrap_or("N/A"),
                    finding.code_snippet.as_deref().unwrap_or(""),
                    finding.recommendation.as_deref().unwrap_or("")
                ).as_str()
            ),
        ];
        match client.chat(&messages).await {
            Ok(response_with_model) => {
                tracing::debug!("LLM response: {}", response_with_model.content);
                finding.verification_notes = Some(response_with_model.content);
            }
            Err(e) => {
                tracing::error!("LLM verification failed for {}: {}", finding.id, e);
                finding.verification_status = Some(baco::findings::VerificationStatus::Failed);
                finding.verification_error = Some(e.to_string());
            }
        }
    }
    let output_path = format!("{}/verified_findings.json", config.output.dir);

    if !quiet {
        tracing::info!(
            "Writing {} verified findings to {:?}",
            findings.len(),
            output_path
        );
    }
    let json = serde_json::to_string_pretty(&findings)
        .map_err(|e| format!("Failed to serialize verified findings: {}", e))?;
    std::fs::write(&output_path, &json)
        .map_err(|e| format!("Failed to write verified findings: {}", e))?;

    if !quiet {
        info!(
            "Verification complete. Results written to {:?}",
            output_path
        );
    }
    Ok(())
}

fn run_preset_command(action: PresetCommands, quiet: bool) {
    match action {
        PresetCommands::List { verbose } => {
            let presets = preset::list_available_presets();
            if presets.is_empty() {
                if !quiet {
                    println!("No presets available.");
                }
                return;
            }

            if verbose {
                for name in &presets {
                    // Extract preset name (strip " (user)" suffix if present)
                    let preset_name = name.split(" (").next().unwrap_or(name.as_str());
                    println!("\n=== {} ===", name);
                    match preset::load_preset(preset_name) {
                        Ok(_) => {
                            // For verbose mode, we'd need to read the raw TOML
                            // For now, just show the name
                            println!("Preset: {}", preset_name);
                        }
                        Err(e) => {
                            println!("Error loading preset: {}", e);
                        }
                    }
                }
            } else {
                println!("Available presets:");
                for name in presets {
                    println!("  - {}", name);
                }
            }
        }
        PresetCommands::Show { name } => {
            // Load preset to verify it exists
            match preset::load_preset(&name) {
                Ok(_) => {
                    // For show, we need to read the raw TOML content
                    // Try bundled first
                    if let Some(content) = preset_content(&name) {
                        println!("{}", content);
                    } else {
                        // Try user directory
                        let user_path = preset::home_dir()
                            .join(".config")
                            .join("baco")
                            .join("presets")
                            .join(format!("{}.toml", name));
                        if user_path.exists() {
                            match std::fs::read_to_string(&user_path) {
                                Ok(content) => println!("{}", content),
                                Err(e) => {
                                    eprintln!("Failed to read preset: {}", e);
                                    std::process::exit(1);
                                }
                            }
                        } else {
                            eprintln!("Preset '{}' not found", name);
                            std::process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}

fn preset_content(name: &str) -> Option<&'static str> {
    match name {
        "wordpress-core" => Some(include_str!("../presets/wordpress-core.toml")),
        "wordpress-plugin" => Some(include_str!("../presets/wordpress-plugin.toml")),
        "litellm" => Some(include_str!("../presets/litellm.toml")),
        "oss-python" => Some(include_str!("../presets/oss-python.toml")),
        "oss-monorepo" => Some(include_str!("../presets/oss-monorepo.toml")),
        _ => None,
    }
}

fn run_eval(
    target: &Path,
    ground_truth: &Path,
    findings_path: Option<PathBuf>,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use baco::eval::{parse_oracle, score_findings};

    // Load ground truth oracle
    if !ground_truth.exists() {
        return Err(format!("Ground truth file not found: {}", ground_truth.display()).into());
    }

    let oracle_json = std::fs::read_to_string(ground_truth)?;
    let oracle = parse_oracle(&oracle_json)?;

    if !quiet {
        tracing::info!("Loaded oracle for target: {}", oracle.target);
        tracing::info!("Expected findings: {}", oracle.expected_findings.len());
        tracing::info!("Expected suppressed: {}", oracle.expected_suppressed.len());
    }

    // Load findings or run scanner
    let findings = if let Some(path) = findings_path {
        if !path.exists() {
            return Err(format!("Findings file not found: {}", path.display()).into());
        }
        baco::validation::validate_findings(&path)?
    } else {
        // Run scanner on target
        if !quiet {
            tracing::info!("Running scanner on target: {}", target.display());
        }

        let mut config = baco::config::ScannerConfig::default();
        config.project.path = target.to_string_lossy().to_string();
        config.project.name = target
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "target".to_string());

        let output_dir = PathBuf::from(&config.output.dir);
        std::fs::create_dir_all(&output_dir)?;

        let scanner = baco::scanner::Scanner::new(config, target.to_path_buf(), false);
        tokio::runtime::Handle::current().block_on(scanner.run())?
    };

    // Score findings against oracle
    let report = score_findings(&oracle, &findings);

    // Print report
    if !quiet {
        println!("\n═══════════════════════════════════════");
        println!("EVALUATION REPORT");
        println!("═══════════════════════════════════════");
        println!("Target: {}", report.target);
        println!("Expected findings: {}", report.expected);
        println!("Matched: {}", report.matched);
        println!("Missed: {}", report.missed.len());
        println!("False flags: {}", report.false_flags);
        println!();
        println!("Metrics:");
        println!("  Recall:  {:.2}", report.recall * 100.0);
        println!("  Precision: {:.2}", report.precision * 100.0);

        // Calculate F1
        let f1 = if report.precision + report.recall > 0.0 {
            2.0 * report.precision * report.recall / (report.precision + report.recall)
        } else {
            0.0
        };
        println!("  F1 Score:  {:.2}", f1 * 100.0);

        if !report.missed.is_empty() {
            println!("\nMissed findings:");
            for missed in &report.missed {
                println!(
                    "  - {}:{} ({})",
                    missed.file_path, missed.line, missed.cwe_id
                );
            }
        }
        println!("═══════════════════════════════════════\n");
    }

    Ok(())
}

fn run_doctor(
    config_path: Option<&Path>,
    output_dir: Option<&Path>,
    json_output: bool,
    quiet: bool,
) {
    let results = doctor::run_doctor_checks(config_path, output_dir);

    if json_output {
        // JSON output
        let json = serde_json::to_string_pretty(&results).unwrap();
        println!("{}", json);
        std::process::exit(results.exit_code());
    }

    // Text output
    if !quiet {
        println!("\n═══════════════════════════════════════");
        println!("       BACO DOCTOR - Pre-flight Check");
        println!("═══════════════════════════════════════\n");

        for check in &results.checks {
            let status_marker = match check.status {
                doctor::CheckStatus::Ok => "✓",
                doctor::CheckStatus::Warn => "⚠",
                doctor::CheckStatus::Fail => "✗",
            };
            let status_text = match check.status {
                doctor::CheckStatus::Ok => "OK",
                doctor::CheckStatus::Warn => "WARN",
                doctor::CheckStatus::Fail => "FAIL",
            };
            println!("{} [{}] {}", status_marker, status_text, check.name);
            println!("    {}", check.detail);
        }

        println!("\n───────────────────────────────────────────");
        let overall_marker = match results.overall_status {
            doctor::CheckStatus::Ok => "✓",
            doctor::CheckStatus::Warn => "⚠",
            doctor::CheckStatus::Fail => "✗",
        };
        let overall_text = match results.overall_status {
            doctor::CheckStatus::Ok => "All checks passed",
            doctor::CheckStatus::Warn => "Passed with warnings",
            doctor::CheckStatus::Fail => "Failed - fix issues before scanning",
        };
        println!("Overall: {} {}", overall_marker, overall_text);
        println!("═══════════════════════════════════════\n");
    } else {
        // Quiet mode: just summary line
        let status = match results.overall_status {
            doctor::CheckStatus::Ok => "passed",
            doctor::CheckStatus::Warn => "passed with warnings",
            doctor::CheckStatus::Fail => "failed",
        };
        println!("Doctor check: {}", status);
    }

    std::process::exit(results.exit_code());
}
