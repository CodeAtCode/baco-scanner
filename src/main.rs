use baco::config;
use baco::validation;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use tracing::info;

#[derive(Parser)]
#[command(name = "baco")]
#[command(about = "BACO - CLI Security Vulnerability Scanner")]
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
        } => {
            info!("Starting scan with config: {:?}", config);
            run_scan(&config, target, force, cli.quiet)
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
        Commands::Verify { input } => {
            info!("Verifying findings from: {:?}", input);
            run_verify(&input, cli.quiet).await.unwrap_or_else(|e| {
                tracing::error!("Verification failed: {}", e);
                std::process::exit(1);
            });
        }
    }
}

async fn run_scan(
    config_path: &Path,
    target: Option<PathBuf>,
    force: bool,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match validation::validate_config(config_path) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!("Validation error: {}", e);
            std::process::exit(2);
        }
    }
    let config =
        config::ScannerConfig::from_file(config_path.to_str().ok_or("Invalid config path")?)?;
    let output_dir = PathBuf::from(&config.output.dir);
    std::fs::create_dir_all(&output_dir)?;

    let target_path = target.unwrap_or_else(|| PathBuf::from(&config.project.path));

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

    let scanner = baco::scanner::Scanner::new(config, target_path, force);
    let findings = scanner.run().await?;

    // Print summary
    if !quiet {
        tracing::info!("═══════════════════════════════════════");
        tracing::info!("Scan complete: {} findings", findings.len());

        // Count by severity
        let mut severity_counts = std::collections::HashMap::new();
        for finding in &findings {
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

        // Save findings to output directory
        let findings_path = output_dir.join("findings.json");
        let json = serde_json::to_string_pretty(&findings)?;
        std::fs::write(&findings_path, json)?;

        tracing::info!("Results saved to:");
        tracing::info!("  - Findings: {}", findings_path.display());
        tracing::info!("  - HTML report: {}/report.html", output_dir.display());
        tracing::info!("═══════════════════════════════════════");
    } else {
        // Quiet mode: only show summary line when complete
        tracing::info!("Scan complete: {} findings", findings.len());

        // Save findings to output directory
        let findings_path = output_dir.join("findings.json");
        let json = serde_json::to_string_pretty(&findings)?;
        std::fs::write(&findings_path, json)?;

        // HTML report path
        let _report_path = format!("{}/report.html", output_dir.display());
    }

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
    let (phase_str, _phase_index) = match phase {
        baco::checkpoint::ScanPhase::Indexing => ("Indexing ⚙️", 0),
        baco::checkpoint::ScanPhase::Semgrep => ("Semgrep 🔍", 1),
        baco::checkpoint::ScanPhase::LlmStaticAnalysis => ("LLM Static Analysis 🧠", 2),
        baco::checkpoint::ScanPhase::LlmDiscovery => ("LLM Discovery 🔎", 3),
        baco::checkpoint::ScanPhase::LlmVerification => ("LLM Verification ✅", 4),
        baco::checkpoint::ScanPhase::TicketCrossRef => ("Ticket Cross-Ref 🎫", 5),
        baco::checkpoint::ScanPhase::GitAnalysis => ("Git Analysis 📊", 6),
        baco::checkpoint::ScanPhase::CrossFileAnalysis => ("Cross-File Analysis 🔗", 7),
        baco::checkpoint::ScanPhase::ConfidenceScoring => ("Confidence Scoring ⚖️", 8),
        baco::checkpoint::ScanPhase::AiAggregation => ("AI Aggregation 🤖", 9),
        baco::checkpoint::ScanPhase::Reporting => ("Reporting 📝", 10),
        baco::checkpoint::ScanPhase::ThreatModeling => ("Threat Modeling 🛡️", 11),
        baco::checkpoint::ScanPhase::RootCauseDedup => ("Root Cause Dedup 🔍", 12),
        baco::checkpoint::ScanPhase::MultiVerifier => ("Multi-Verifier 🗳️", 13),
        baco::checkpoint::ScanPhase::AutoPatching => ("Auto-Patching 🔧", 14),
        baco::checkpoint::ScanPhase::CveBootstrap => ("CVE Bootstrap 📋", 17),
        baco::checkpoint::ScanPhase::PocCompiler => ("PoC Compiler 🛠️", 18),
        baco::checkpoint::ScanPhase::VariantSearch => ("Variant Search 🔎", 19),
        baco::checkpoint::ScanPhase::SecurityAgentVerification => {
            ("SecurityAgent Verification 🤖", 20)
        }
        baco::checkpoint::ScanPhase::Complete => ("Complete ✨", 15),
        baco::checkpoint::ScanPhase::Error => ("Error ❌", 16),
    };
    phase_str.to_string()
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
            write_findings_json(&findings, &output_path.to_string_lossy(), None)
                .map_err(|e| format!("Failed to generate JSON report: {}", e))?;
        }
        "sarif" => {
            use baco::report::sarif::generate_sarif_report;
            let sarif_path = output_path.clone();
            let sarif_json = generate_sarif_report(&findings)?;
            std::fs::write(&sarif_path, sarif_json)
                .map_err(|e| format!("Failed to write SARIF report: {}", e))?;
            if !quiet {
                info!("Generated SARIF report to {:?}", sarif_path);
            }
        }
        "markdown" => return Err("Markdown report not yet implemented".into()),
        _ => return Err(format!("Unsupported report format: {}", format).into()),
    }

    if !quiet {
        info!("Report generated successfully at {:?}", output_path);
    }
    Ok(())
}

async fn run_verify(input: &Path, quiet: bool) -> Result<(), Box<dyn std::error::Error>> {
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

    let config_path = std::env::var("LLM_CONFIG_PATH").map(PathBuf::from).ok();
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
    let client = baco::llm::LlmClient::new(baco::llm::LlmConfig {
        base_url: config.llm.phases.verification.base_url.clone(),
        api_key: config
            .llm
            .phases
            .verification
            .api_key
            .clone()
            .expect("api_key verified non-empty above"),
        model: config.llm.phases.verification.model.clone(),
        models: config.llm.phases.verification.get_models(),
        timeout: config.llm.timeout_secs,
        max_retries: config.llm.max_retries as u32,
        retry_backoff_ms: config.llm.retry_backoff_ms,
    });
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
                finding.verification_error = Some(e);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_cli_parsing_scan() {
        let cli = Cli::parse_from(["baco", "scan", "--config", "/tmp/config.toml"]);
        match cli.command {
            Commands::Scan { config, .. } => assert_eq!(config, PathBuf::from("/tmp/config.toml")),
            _ => panic!("Expected Scan command"),
        }
        // Test quiet flag parsing
        let cli_quiet =
            Cli::parse_from(["baco", "scan", "--config", "/tmp/config.toml", "--quiet"]);
        match cli_quiet.command {
            Commands::Scan { config, .. } => {
                assert_eq!(config, PathBuf::from("/tmp/config.toml"));
                // Check that quiet is set - quiet field is in Cli struct, not Commands
                assert!(cli_quiet.quiet);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn test_cli_parsing_resume() {
        let cli = Cli::parse_from(["baco", "resume", "--checkpoint", "/tmp/checkpoint.json"]);
        match cli.command {
            Commands::Resume { checkpoint } => {
                assert_eq!(checkpoint, PathBuf::from("/tmp/checkpoint.json"))
            }
            _ => panic!("Expected Resume command"),
        }
    }

    #[test]
    fn test_cli_parsing_report() {
        let cli = Cli::parse_from([
            "baco",
            "report",
            "--input",
            "/tmp/findings.json",
            "--format",
            "html",
        ]);
        match cli.command {
            Commands::Report { input, format } => {
                assert_eq!(input, PathBuf::from("/tmp/findings.json"));
                assert_eq!(format, "html");
            }
            _ => panic!("Expected Report command"),
        }
    }

    #[test]
    fn test_cli_parsing_verify() {
        let cli = Cli::parse_from(["baco", "verify", "--input", "/tmp/findings.json"]);
        match cli.command {
            Commands::Verify { input } => assert_eq!(input, PathBuf::from("/tmp/findings.json")),
            _ => panic!("Expected Verify command"),
        }
    }

    #[test]
    fn test_validate_file_exists_nonexistent() {
        let result = validation::validate_file_exists(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not exist"));
    }

    #[test]
    fn test_validate_findings_valid_json() {
        let temp_dir = TempDir::new().unwrap();
        let findings_path = temp_dir.path().join("findings.json");
        let findings_json = r#"[{"id":"test-1","title":"Test","description":"Desc","severity":"high","confidence_score":0.8,"cwe_id":"CWE-79","file_path":"src/test.rs","line_number":10,"code_snippet":"code","recommendation":"fix","already_reported":false,"sources":[]}]"#;
        fs::write(&findings_path, findings_json).unwrap();

        let result = validation::validate_findings(&findings_path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }
}
