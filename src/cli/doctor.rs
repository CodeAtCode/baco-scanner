use crate::doctor;
use crate::ui::Ui;
use std::path::Path;

pub fn run_doctor(
    config_path: Option<&Path>,
    output_dir: Option<&Path>,
    json_output: bool,
    quiet: bool,
) {
    let results = doctor::run_doctor_checks(config_path, output_dir);
    let ui = Ui::new(quiet);

    if json_output {
        // JSON output
        let json = serde_json::to_string_pretty(&results).unwrap();
        ui.emit(json);
        std::process::exit(results.exit_code());
    }

    // Text output (Ui suppresses decorative lines in quiet mode).
    ui.line("\n═══════════════════════════════════════");
    ui.line("       BACO DOCTOR - Pre-flight Check");
    ui.line("═══════════════════════════════════════\n");

    for check in &results.checks {
        let (status_marker, status_text) = match check.status {
            doctor::CheckStatus::Ok => ("✓", "OK"),
            doctor::CheckStatus::Warn => ("⚠", "WARN"),
            doctor::CheckStatus::Fail => ("✗", "FAIL"),
        };
        ui.line(format!(
            "{} [{}] {}",
            status_marker, status_text, check.name
        ));
        ui.line(format!("    {}", check.detail));
    }

    ui.line("\n───────────────────────────────────────────");
    let (overall_marker, overall_text) = match results.overall_status {
        doctor::CheckStatus::Ok => ("✓", "All checks passed"),
        doctor::CheckStatus::Warn => ("⚠", "Passed with warnings"),
        doctor::CheckStatus::Fail => ("✗", "Failed - fix issues before scanning"),
    };
    ui.line(format!("Overall: {} {}", overall_marker, overall_text));
    ui.line("═══════════════════════════════════════\n");
    if quiet {
        ui.emit(format!(
            "Doctor check: {}",
            match results.overall_status {
                doctor::CheckStatus::Ok => "passed",
                doctor::CheckStatus::Warn => "passed with warnings",
                doctor::CheckStatus::Fail => "failed",
            }
        ));
    }

    std::process::exit(results.exit_code());
}
