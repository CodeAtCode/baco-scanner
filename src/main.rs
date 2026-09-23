use baco::cli;
use baco::init;
use baco::preset;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;

use cli::PresetCommands;
use cli::report::ReportFormat;

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
        #[arg(long, help = "Preset name")]
        preset: Option<String>,
        #[arg(
            long,
            help = "Limit report to files changed in git revspec (e.g. main...HEAD)"
        )]
        diff: Option<String>,
    },
    Resume {
        #[arg(short, long)]
        checkpoint: PathBuf,
    },
    Report {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long, value_enum, default_value_t = ReportFormat::Html)]
        format: ReportFormat,
    },
    Verify {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long, help = "Config file path")]
        config: Option<PathBuf>,
    },
    Eval {
        #[arg(long, help = "Target directory to evaluate")]
        target: Option<PathBuf>,
        #[arg(long, help = "Path to ground truth oracle JSON")]
        ground_truth: Option<PathBuf>,
        #[arg(
            long,
            help = "Path to findings JSON to score (optional - if omitted, runs scanner first)"
        )]
        findings: Option<PathBuf>,
        #[arg(
            long,
            help = "Run the offline eval suite over all bundled targets (no arguments does the same)"
        )]
        all: bool,
        #[arg(long, help = "Path to config file (reads the [eval] section)")]
        config: Option<PathBuf>,
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
    Init {
        #[arg(
            default_value = ".",
            help = "Target directory to initialize (default: current directory)"
        )]
        path: PathBuf,
        #[arg(long, help = "Overwrite existing baco.toml if it exists")]
        force: bool,
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

    match cli.command {
        Commands::Scan {
            config,
            target,
            force,
            evidence_gate,
            dry_run,
            preset,
            diff,
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

            cli::scan::run_scan(
                &config,
                target,
                force,
                evidence_gate,
                dry_run,
                preset_overlay,
                diff,
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
            cli::scan::run_resume(&checkpoint, cli.quiet)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!("Resume failed: {}", e);
                    std::process::exit(1);
                });
        }
        Commands::Report { input, format } => {
            info!("Generating {} report from: {:?}", format, input);
            cli::report::run_report(&input, format, cli.quiet).unwrap_or_else(|e| {
                tracing::error!("Report generation failed: {}", e);
                std::process::exit(1);
            });
        }
        Commands::Verify { input, config } => {
            info!("Verifying findings from: {:?}", input);
            cli::verify::run_verify(&input, config, cli.quiet)
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
            all,
            config,
        } => {
            if all && (target.is_some() || ground_truth.is_some() || findings.is_some()) {
                tracing::error!(
                    "--all cannot be combined with --target, --ground-truth, or --findings"
                );
                std::process::exit(1);
            }

            let app_config = match config.as_deref() {
                Some(p) => match baco::config::ScannerConfig::from_file(&p.to_string_lossy()) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!("Failed to load config {}: {}", p.display(), e);
                        std::process::exit(1);
                    }
                },
                None => baco::config::ScannerConfig::default(),
            };

            let suite_mode =
                all || (target.is_none() && ground_truth.is_none() && findings.is_none());
            if suite_mode {
                let root = cli::eval::default_eval_root();
                info!("Running eval suite over: {:?}", root);
                cli::eval::run_eval_suite(&root, cli.quiet, app_config.eval.floor).unwrap_or_else(
                    |e| {
                        tracing::error!("Eval suite failed: {}", e);
                        std::process::exit(1);
                    },
                );
            } else {
                let (Some(target), Some(ground_truth)) = (target, ground_truth) else {
                    tracing::error!(
                        "eval requires both --target and --ground-truth (or no arguments / --all for suite mode)"
                    );
                    std::process::exit(1);
                };
                info!("Running eval on target: {:?}", target);
                cli::eval::run_eval(&target, &ground_truth, findings, cli.quiet)
                    .await
                    .unwrap_or_else(|e| {
                        tracing::error!("Eval failed: {}", e);
                        std::process::exit(1);
                    });
            }
        }
        Commands::Preset { action } => cli::preset::run_preset_command(action, cli.quiet),
        Commands::Doctor {
            config,
            output_dir,
            json,
        } => {
            cli::doctor::run_doctor(config.as_deref(), output_dir.as_deref(), json, cli.quiet);
        }
        Commands::Init { path, force } => {
            let init_cmd = init::InitCommand { path, force };
            match init::run_init(&init_cmd, cli.quiet) {
                Ok(()) => {}
                Err(e) => {
                    tracing::error!("{}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
