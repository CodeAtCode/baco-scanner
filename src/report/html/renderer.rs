use crate::config::ScannerConfig;
use crate::error::ScanError;
use crate::evidence::classify_finding;
pub use crate::findings::VulnerabilityFinding;
use chrono::Utc;
use minijinja::{Environment, context};
use std::collections::HashMap;
use std::fs;

use super::finding_renderer::render_finding_with_id;
use super::utilities::{
    build_empty_state_message, build_filter_buttons, build_summary_cards, calculate_severity_stats,
};

/// Embedded HTML template for the report.
const REPORT_TEMPLATE: &str = include_str!("templates/report.j2");

pub fn generate_html_report(
    findings: &[VulnerabilityFinding],
    output_path: &str,
    config: Option<&ScannerConfig>,
    rejected_findings: Option<&[(crate::findings::VulnerabilityFinding, String)]>,
) -> Result<(), ScanError> {
    let gate_enabled = config.map(|c| c.output.evidence_gate).unwrap_or(false);

    let filtered_findings: Vec<VulnerabilityFinding> =
        crate::report::apply_evidence_gate(findings, config);

    let unverified_findings: Vec<&VulnerabilityFinding> = if gate_enabled {
        findings
            .iter()
            .filter(|f| {
                let tier = classify_finding(&f.evidence, f.confidence_score);
                matches!(tier, crate::evidence::VerificationTier::Unverified)
            })
            .collect()
    } else {
        vec![]
    };

    let scan_date = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let total_findings = filtered_findings.len();

    let mut languages: std::collections::HashSet<String> = std::collections::HashSet::new();
    for finding in findings {
        let lang = super::presenter::detect_language(&finding.file_path);
        if !lang.is_empty() {
            languages.insert(lang.to_string());
        }
        if finding.diff_hunk.is_some() {
            languages.insert("diff".to_string());
        }
    }

    let prism_core_js = include_str!("assets/prism-core.min.js").to_string();
    let prism_css = include_str!("assets/prism-tomorrow.min.css").to_string();

    let prism_language_scripts: String = languages
        .iter()
        .filter_map(|lang| match lang.as_str() {
            "python" => Some(include_str!("assets/prism-python.min.js").to_string()),
            "javascript" => Some(include_str!("assets/prism-javascript.min.js").to_string()),
            "typescript" => Some(include_str!("assets/prism-typescript.min.js").to_string()),
            "rust" => Some(include_str!("assets/prism-rust.min.js").to_string()),
            "go" => Some(include_str!("assets/prism-go.min.js").to_string()),
            "java" => Some(include_str!("assets/prism-java.min.js").to_string()),
            "c" => Some(include_str!("assets/prism-c.min.js").to_string()),
            "cpp" => Some(include_str!("assets/prism-cpp.min.js").to_string()),
            "sql" => Some(include_str!("assets/prism-sql.min.js").to_string()),
            "yaml" => Some(include_str!("assets/prism-yaml.min.js").to_string()),
            "json" => Some(include_str!("assets/prism-json.min.js").to_string()),
            "bash" | "sh" => Some(include_str!("assets/prism-bash.min.js").to_string()),
            "diff" => Some(include_str!("assets/prism-diff.min.js").to_string()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n    ");

    let models_html = if let Some(cfg) = config {
        let discovery_models = cfg.llm.phases.discovery.get_models();
        let verification_models = cfg.llm.phases.verification.get_models();
        let aggregation_models = cfg.llm.phases.aggregation.get_models();

        let discovery_html = if discovery_models.is_empty() {
            "Not configured".to_string()
        } else {
            discovery_models.join(", ")
        };

        let verification_html = if verification_models.is_empty() {
            "Not configured".to_string()
        } else {
            verification_models.join(", ")
        };

        let aggregation_html = if aggregation_models.is_empty() {
            "Not configured".to_string()
        } else {
            aggregation_models.join(", ")
        };

        format!(
            r#"<div class="metadata-item"><div class="metadata-label">Discovery Models</div><div class="metadata-value">{}</div></div>
                <div class="metadata-item"><div class="metadata-label">Verification Models</div><div class="metadata-value">{}</div></div>
                <div class="metadata-item"><div class="metadata-label">Aggregation Models</div><div class="metadata-value">{}</div></div>"#,
            discovery_html, verification_html, aggregation_html
        )
    } else {
        r#"<div class="metadata-item"><div class="metadata-label">AI Models</div><div class="metadata-value">Not configured</div></div>"#.to_string()
    };

    let stats = calculate_severity_stats(findings);
    let filter_buttons_html = build_filter_buttons(&stats);
    let summary_cards_html = build_summary_cards(&stats);

    let avg_confidence = if findings.is_empty() {
        0.0
    } else {
        findings
            .iter()
            .map(|f| f.confidence_score as f64)
            .sum::<f64>()
            / findings.len() as f64
    };

    let verified = findings
        .iter()
        .filter(|f| f.verification_status.is_some())
        .count();
    let already_reported = findings.iter().filter(|f| f.already_reported).count();

    let empty_state = if total_findings == 0 {
        build_empty_state_message()
    } else {
        String::new()
    };

    // Build findings HTML
    let mut findings_html = String::new();

    if total_findings > 0 {
        // Priority findings section
        let priority_findings: Vec<&VulnerabilityFinding> = filtered_findings
            .iter()
            .filter(|f| {
                matches!(
                    f.severity,
                    crate::findings::Severity::Critical | crate::findings::Severity::High
                )
            })
            .collect();

        if !priority_findings.is_empty() {
            findings_html.push_str(r#"<div class="priority-section">"#);
            findings_html.push_str(r#"<h2>🚨 Priority Findings (Critical & High)</h2>"#);

            let mut sorted_priority = priority_findings;
            sorted_priority.sort_by_key(|a| std::cmp::Reverse(a.severity));

            for (idx, finding) in sorted_priority.iter().enumerate() {
                let global_id = format!("priority-{}", idx);
                findings_html.push_str(&render_finding_with_id(finding, &global_id));
            }
            findings_html.push_str("</div>");
        }

        // File grouping
        let mut findings_by_file: HashMap<String, Vec<&VulnerabilityFinding>> = HashMap::new();
        for finding in &filtered_findings {
            findings_by_file
                .entry(finding.file_path.clone())
                .or_default()
                .push(finding);
        }

        let mut sorted_files: Vec<_> = findings_by_file.into_iter().collect();
        sorted_files.sort_by_key(|a| std::cmp::Reverse(a.1.len()));

        findings_html.push_str(r#"<div class="findings-by-file">"#);
        for (file_path, file_findings) in sorted_files {
            findings_html.push_str(&format!(
                r#"<details class="file-group"><summary class="file-group-summary">📄 {} ({}) findings</summary>"#,
                html_escape::encode_text(&file_path),
                file_findings.len()
            ));

            let mut sorted_findings = file_findings;
            sorted_findings.sort_by_key(|a| std::cmp::Reverse(a.severity));

            for (finding_id, finding) in sorted_findings.iter().enumerate() {
                let global_id = format!(
                    "{}-{}",
                    html_escape::encode_text(&file_path).replace('/', "-"),
                    finding_id
                );
                findings_html.push_str(&render_finding_with_id(finding, &global_id));
            }

            findings_html.push_str("</details>");
        }
        findings_html.push_str("</div>");
    }

    // Build appendix HTML
    let mut appendix_html = String::new();

    let include_rejected = config.map(|c| c.output.include_rejected).unwrap_or(false);

    if gate_enabled && !unverified_findings.is_empty() {
        appendix_html.push_str(r#"<section class="unverified-appendix">"#);
        appendix_html.push_str(&format!(
            r#"<h2>Appendix: Unverified Findings</h2>
<p class="finding-count">{} unverified findings excluded from main report</p>"#,
            unverified_findings.len()
        ));

        for f in &unverified_findings {
            let evidence_detail = f
                .evidence
                .first()
                .map(|e| e.detail.as_str())
                .unwrap_or("No evidence detail available");
            let line = f
                .line_number
                .map(|l| l.to_string())
                .unwrap_or("N/A".to_string());
            appendix_html.push_str(&format!(
                r#"<div class="finding unverified">
<div class="finding-header">
<h3>{}</h3>
<span class="severity unverified">Unverified</span>
</div>
<div class="meta">
<strong>File:</strong> {} | <strong>Line:</strong> {}
</div>
<div class="finding-details">
<p><strong>Reason:</strong> {}</p>
</div>
</div>"#,
                html_escape::encode_text(&f.title),
                html_escape::encode_text(&f.file_path),
                line,
                html_escape::encode_text(evidence_detail)
            ));
        }
        appendix_html.push_str("</section>");
    }

    if include_rejected {
        if let Some(rejected) = rejected_findings {
            if !rejected.is_empty() {
                appendix_html.push_str(r#"<section class="rejected-appendix">"#);
                appendix_html.push_str(&format!(
                    r#"<h2>Investigated & Dismissed</h2>
<p class="finding-count">{} findings were investigated and dismissed</p>"#,
                    rejected.len()
                ));

                for (f, reason) in rejected {
                    let line = f
                        .line_number
                        .map(|l| l.to_string())
                        .unwrap_or("N/A".to_string());
                    appendix_html.push_str(&format!(
                        r#"<div class="finding rejected">
<div class="finding-header">
<h3>{}</h3>
<span class="severity rejected">Dismissed</span>
</div>
<div class="meta">
<strong>File:</strong> {} | <strong>Line:</strong> {}
</div>
<div class="finding-details">
<p><strong>Rejection Reason:</strong> {}</p>
</div>
</div>"#,
                        html_escape::encode_text(&f.title),
                        html_escape::encode_text(&f.file_path),
                        line,
                        html_escape::encode_text(reason)
                    ));
                }
                appendix_html.push_str("</section>");
            }
        }
    }

    let unique_files = filtered_findings
        .iter()
        .map(|f| &f.file_path)
        .collect::<std::collections::HashSet<_>>()
        .len();

    // Create minijinja environment and render
    let mut env = Environment::new();

    // Add a custom filter to preserve HTML (similar to | safe in Jinja2)
    fn identity_filter(value: minijinja::Value) -> minijinja::Value {
        value
    }
    env.add_filter("safe", identity_filter);
    env.add_filter("format", |value: f64, pattern: &str| match pattern {
        "%.1" => format!("{:.1}", value),
        _ => value.to_string(),
    });

    env.add_template("report", REPORT_TEMPLATE)
        .map_err(|e| ScanError::Parse {
            message: format!("Template compilation error: {}", e),
            source: None,
        })?;

    let html = env
        .render_named_str(
            "report",
            REPORT_TEMPLATE,
            context! {
                scan_date => scan_date,
                total_findings => total_findings,
                stats_critical => stats.critical,
                stats_high => stats.high,
                models_html => models_html,
                avg_confidence => format!("{:.1}", avg_confidence * 100.0),
                verified => verified,
                already_reported => already_reported,
                unique_files => unique_files,
                summary_cards_html => summary_cards_html,
                empty_state => empty_state,
                filter_buttons_html => filter_buttons_html,
                findings_html => findings_html,
                appendix_html => appendix_html,
                version => env!("CARGO_PKG_VERSION"),
                filtered_findings_count => filtered_findings.len(),
                prism_css => prism_css,
                prism_core_js => prism_core_js,
                prism_language_scripts => prism_language_scripts,
            },
        )
        .map_err(|e| ScanError::Parse {
            message: format!("Template rendering error: {}", e),
            source: None,
        })?;

    if let Some(parent) = std::path::Path::new(output_path).parent() {
        std::fs::create_dir_all(parent).map_err(ScanError::IoError)?;
    }

    fs::write(output_path, html).map_err(ScanError::IoError)?;
    Ok(())
}
