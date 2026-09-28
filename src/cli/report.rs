use crate::validation;
use std::path::Path;
use tracing::info;

/// Output format for `baco report`, validated by clap at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ReportFormat {
    Html,
    Json,
    Sarif,
    Markdown,
}

impl std::fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            ReportFormat::Html => "html",
            ReportFormat::Json => "json",
            ReportFormat::Sarif => "sarif",
            ReportFormat::Markdown => "markdown",
        };
        write!(f, "{name}")
    }
}

pub fn run_report(
    input: &Path,
    format: ReportFormat,
    config_path: Option<&Path>,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let findings = validation::validate_findings(input)?;
    let output_dir = input.parent().ok_or_else(|| {
        format!(
            "Failed to determine output directory from: {}",
            input.display()
        )
    })?;
    let output_path = match format {
        ReportFormat::Html => output_dir.join("report.html"),
        ReportFormat::Json => output_dir.join("findings.json"),
        ReportFormat::Sarif => output_dir.join("report.sarif"),
        ReportFormat::Markdown => output_dir.join("report.md"),
    };

    // Load config if provided
    let config = if let Some(cfg_path) = config_path {
        Some(crate::config::ScannerConfig::from_file(
            cfg_path.to_string_lossy().as_ref(),
        )?)
    } else {
        None
    };

    if !quiet {
        info!("Generating {} report to {:?}", format, output_path);
    }

    match format {
        ReportFormat::Html => {
            use crate::report::html::generate_html_report;
            generate_html_report(
                &findings,
                &output_path.to_string_lossy(),
                config.as_ref(),
                None,
            )
            .map_err(|e| format!("Failed to generate HTML report: {}", e))?;
        }
        ReportFormat::Json => {
            use crate::report::json::write_findings_json;
            write_findings_json(
                &findings,
                &[],
                &output_path.to_string_lossy(),
                None,
                config.as_ref(),
                None,
                None, // scan_health
            )
            .map_err(|e| format!("Failed to generate JSON report: {}", e))?;
        }
        ReportFormat::Sarif => {
            use crate::report::sarif::generate_sarif_report;
            let sarif_path = output_path.clone();
            let sarif_json = generate_sarif_report(&findings, config.as_ref())?;
            std::fs::write(&sarif_path, sarif_json)
                .map_err(|e| format!("Failed to write SARIF report: {}", e))?;
            if !quiet {
                info!("Generated SARIF report to {:?}", sarif_path);
            }
        }
        ReportFormat::Markdown => {
            use crate::report::markdown::generate_markdown_report;
            let md_path = output_path.clone();
            // Derive project name from input directory name
            let project_name = input
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            // Markdown does not take config, so use pre-filtered slice
            let gated_findings = if config.as_ref().is_some_and(|c| c.output.evidence_gate) {
                crate::report::apply_evidence_gate(&findings, config.as_ref())
            } else {
                findings.clone()
            };
            let md_content = generate_markdown_report(&gated_findings, &project_name);
            std::fs::write(&md_path, md_content)
                .map_err(|e| format!("Failed to write markdown report: {}", e))?;
            if !quiet {
                info!("Generated markdown report to {:?}", md_path);
            }
        }
    }

    if !quiet {
        info!("Report generated successfully at {:?}", output_path);
    }
    Ok(())
}
