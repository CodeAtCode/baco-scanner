/// Resolve the eval suite root: `./eval` when present, else the compile-time crate root.
use std::path::{Path, PathBuf};

pub fn default_eval_root() -> PathBuf {
    let local = PathBuf::from("eval");
    if local.is_dir() {
        return local;
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("eval")
}

/// Run the offline eval suite: score every bundled target's findings fixture against
/// its oracle, print per-target pass-rates plus the aggregate, and fail when the
/// aggregate does not exceed the floor (BACO_EVAL_FLOOR, default 0.70).
pub fn run_eval_suite(
    eval_root: &Path,
    quiet: bool,
    config_floor: f32,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::eval::{eval_floor, run_suite};

    let ui = crate::ui::Ui::new(quiet);

    let suite = run_suite(eval_root)?;
    let (floor, source) = eval_floor(config_floor)?;

    ui.line("\n═══════════════════════════════════════");
    ui.line(format!("EVAL SUITE ({} targets)", suite.targets.len()));
    ui.line("═══════════════════════════════════════");
    ui.line(format!(
        "{:<18} {:>8} {:>8} {:>7} {:>6} {:>9} {:>9}",
        "Target", "Expected", "Matched", "Missed", "Flags", "Pass-rate", "Silence"
    ));
    for t in &suite.targets {
        ui.line(format!(
            "{:<18} {:>8} {:>8} {:>7} {:>6} {:>8.2}% {:>8.2}%",
            t.report.target,
            t.report.expected,
            t.report.matched,
            t.report.missed.len(),
            t.report.false_flags,
            t.pass_rate * 100.0,
            t.report.silence_rate * 100.0
        ));
    }
    ui.line("───────────────────────────────────────");
    ui.line(format!(
        "Aggregate pass-rate: {:.2}% ({}/{} findings matched)",
        suite.aggregate * 100.0,
        suite.total_matched,
        suite.total_expected
    ));
    ui.line(format!(
        "Aggregate silence: {:.2}% ({}/{} suppressed twins clean, {} false flags)",
        suite.silence * 100.0,
        suite.total_suppressed_clean,
        suite.total_suppressed,
        suite.total_false_flags
    ));
    ui.line(format!("Floor: {:.2} ({})", floor, source));
    ui.line("═══════════════════════════════════════\n");

    if suite.aggregate > floor {
        ui.line(format!(
            "SUITE PASS: aggregate {:.2}% exceeds floor {:.2}",
            suite.aggregate * 100.0,
            floor
        ));
        Ok(())
    } else {
        Err(format!(
            "SUITE FAIL: aggregate pass-rate {:.2}% does not exceed floor {:.2} ({})",
            suite.aggregate * 100.0,
            floor,
            source
        )
        .into())
    }
}

pub async fn run_eval(
    target: &Path,
    ground_truth: &Path,
    findings_path: Option<PathBuf>,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::eval::{parse_oracle, score_findings};

    let ui = crate::ui::Ui::new(quiet);

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
        crate::validation::validate_findings(&path)?
    } else {
        // Run scanner on target
        if !quiet {
            tracing::info!("Running scanner on target: {}", target.display());
        }

        let mut config = crate::config::ScannerConfig::default();
        config.project.path = target.to_string_lossy().to_string();
        config.project.name = target
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "target".to_string());

        let output_dir = PathBuf::from(&config.output.dir);
        std::fs::create_dir_all(&output_dir)?;

        let scanner = crate::scanner::Scanner::new(config, target.to_path_buf(), false);
        scanner.run().await?
    };

    // Score findings against oracle
    let report = score_findings(&oracle, &findings);

    // Print report
    ui.line("\n═══════════════════════════════════════");
    ui.line("EVALUATION REPORT");
    ui.line("═══════════════════════════════════════");
    ui.line(format!("Target: {}", report.target));
    ui.line(format!("Expected findings: {}", report.expected));
    ui.line(format!("Matched: {}", report.matched));
    ui.line(format!("Missed: {}", report.missed.len()));
    ui.line(format!("False flags: {}", report.false_flags));
    ui.line("");
    ui.line("Metrics:");
    ui.line(format!("  Recall:  {:.2}", report.recall * 100.0));
    ui.line(format!("  Precision: {:.2}", report.precision * 100.0));

    // Calculate F1
    let f1 = if report.precision + report.recall > 0.0 {
        2.0 * report.precision * report.recall / (report.precision + report.recall)
    } else {
        0.0
    };
    ui.line(format!("  F1 Score:  {:.2}", f1 * 100.0));
    ui.line(format!("  Silence:  {:.2}", report.silence_rate * 100.0));

    if !report.missed.is_empty() {
        ui.line("\nMissed findings:");
        for missed in &report.missed {
            ui.line(format!(
                "  - {}:{} ({})",
                missed.file_path, missed.line, missed.cwe_id
            ));
        }
    }
    ui.line("═══════════════════════════════════════\n");

    Ok(())
}
