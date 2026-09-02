//! Markdown report generation for BACO security findings.
//!
//! This module generates diffable markdown summaries suitable for CI/PR contexts,
//! with severity-grouped tables and verification-tier breakdowns.

use crate::evidence::{classify_finding, VerificationTier};
use crate::findings::{Severity, VulnerabilityFinding};
use chrono::Utc;

/// Generate a markdown-formatted security report.
///
/// The report includes:
/// - H1 title with scan metadata
/// - Executive summary table (counts by severity × verification tier)
/// - Findings grouped by severity (Critical→Low)
/// - Unverified findings appendix (when evidence tiers present)
/// - Footer with tool version
pub fn generate_markdown_report(findings: &[VulnerabilityFinding], project_name: &str) -> String {
    let scan_date = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    let version = env!("CARGO_PKG_VERSION");

    let mut md = String::new();

    // H1 Title
    md.push_str("# 🔒 BACO Security Vulnerability Report\n\n");
    md.push_str(&format!(
        "**Project:** {} | **Scan Date:** {} | **Total Findings:** {}\n\n",
        project_name,
        scan_date,
        findings.len()
    ));

    // Executive Summary Table
    md.push_str("## Executive Summary\n\n");
    md.push_str("| Severity | Verified | Supported | Unverified | Total |\n");
    md.push_str("|----------|----------|-----------|------------|-------|\n");

    let mut severity_rows = Vec::new();
    for &severity in &[
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let verified = findings
            .iter()
            .filter(|f| {
                f.severity == severity
                    && matches!(
                        classify_finding(&f.evidence, f.confidence_score),
                        VerificationTier::Verified
                    )
            })
            .count();
        let supported = findings
            .iter()
            .filter(|f| {
                f.severity == severity
                    && matches!(
                        classify_finding(&f.evidence, f.confidence_score),
                        VerificationTier::Supported
                    )
            })
            .count();
        let unverified = findings
            .iter()
            .filter(|f| {
                f.severity == severity
                    && matches!(
                        classify_finding(&f.evidence, f.confidence_score),
                        VerificationTier::Unverified
                    )
            })
            .count();
        let total = verified + supported + unverified;

        severity_rows.push(format!(
            "| **{:?}** | {} | {} | {} | {} |",
            severity, verified, supported, unverified, total
        ));
    }
    md.push_str(&severity_rows.join("\n"));
    md.push_str("\n\n");

    // Overall totals
    let total_verified = findings
        .iter()
        .filter(|f| {
            matches!(
                classify_finding(&f.evidence, f.confidence_score),
                VerificationTier::Verified
            )
        })
        .count();
    let total_supported = findings
        .iter()
        .filter(|f| {
            matches!(
                classify_finding(&f.evidence, f.confidence_score),
                VerificationTier::Supported
            )
        })
        .count();
    let total_unverified = findings
        .iter()
        .filter(|f| {
            matches!(
                classify_finding(&f.evidence, f.confidence_score),
                VerificationTier::Unverified
            )
        })
        .count();

    md.push_str(&format!(
        "**Totals:** {} verified | {} supported | {} unverified\n\n",
        total_verified, total_supported, total_unverified
    ));

    // Group findings by severity
    let mut findings_by_severity: std::collections::BTreeMap<Severity, Vec<&VulnerabilityFinding>> =
        std::collections::BTreeMap::new();
    for finding in findings {
        findings_by_severity
            .entry(finding.severity)
            .or_default()
            .push(finding);
    }

    // Output sections in order: Critical, High, Medium, Low, Info
    let severity_order = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    let mut has_findings = false;
    for &severity in &severity_order {
        if let Some(sev_findings) = findings_by_severity.get(&severity) {
            if sev_findings.is_empty() {
                continue;
            }
            has_findings = true;

            md.push_str(&format!(
                "## {:?} Findings ({})\n\n",
                severity,
                sev_findings.len()
            ));

            for finding in sev_findings {
                md.push_str(&render_finding(finding));
                md.push('\n');
            }
        }
    }

    if !has_findings {
        md.push_str("## No Findings\n\n");
        md.push_str("No security issues detected.\n\n");
    }

    // Unverified findings appendix
    let unverified_findings: Vec<&VulnerabilityFinding> = findings
        .iter()
        .filter(|f| {
            matches!(
                classify_finding(&f.evidence, f.confidence_score),
                VerificationTier::Unverified
            )
        })
        .collect();

    if !unverified_findings.is_empty() {
        md.push_str("## Appendix: Unverified Findings\n\n");
        md.push_str(
            "The following findings lack sufficient evidence for inclusion in the main report.\n\n",
        );

        for finding in &unverified_findings {
            md.push_str(&render_finding(finding));
            md.push('\n');
        }
    }

    // Footer
    md.push_str(&format!(
        "---\n\n*Generated by BACO Security Scanner v{}*",
        version
    ));

    md
}

/// Render a single finding to markdown.
fn render_finding(finding: &VulnerabilityFinding) -> String {
    let mut md = String::new();

    // Title with CWE
    let cwe_str = finding
        .cwe_id
        .as_ref()
        .map(|cwe| format!(" ({})", cwe))
        .unwrap_or_default();
    md.push_str(&format!(
        "### [{}] {}{}\n\n",
        finding.severity, finding.title, cwe_str
    ));

    // Location
    let line_str = finding
        .line_number
        .map(|l| format!(":{}", l))
        .unwrap_or_default();
    md.push_str(&format!(
        "**Location:** `{}`{}\n\n",
        finding.file_path, line_str
    ));

    // Description
    md.push_str(&format!("**Description:** {}\n\n", finding.description));

    // Confidence score
    md.push_str(&format!(
        "**Confidence:** {:.1}%\n\n",
        finding.confidence_score * 100.0
    ));

    // Evidence tier
    let tier = classify_finding(&finding.evidence, finding.confidence_score);
    md.push_str(&format!("**Evidence Tier:** {:?}\n\n", tier));

    // Code snippet if present
    if let Some(snippet) = &finding.code_snippet {
        md.push_str("**Code:**\n\n");
        md.push_str("```text\n");
        md.push_str(snippet);
        md.push_str("\n```\n\n");
    }

    // Diff hunk if present
    if let Some(hunk) = &finding.diff_hunk {
        md.push_str("**Diff:**\n\n");
        md.push_str("```diff\n");
        md.push_str(hunk);
        md.push_str("\n```\n\n");
    }

    // Recommendation
    if let Some(rec) = &finding.recommendation {
        md.push_str("**Recommendation:**\n\n");
        md.push_str(rec);
        md.push_str("\n\n");
    }

    // Mitigation code if present
    if let Some(mitigation) = &finding.mitigation_code {
        md.push_str("**Mitigation:**\n\n");
        // Detect language from file extension
        let lang = detect_language(&finding.file_path);
        md.push_str(&format!("```{}\n", lang));
        md.push_str(mitigation);
        md.push_str("\n```\n\n");
    }

    // PoC code if present
    if let Some(poc) = &finding.poc_code {
        md.push_str("**Proof of Concept:**\n\n");
        let poc_lang = finding.poc_format.as_deref().unwrap_or("text");
        md.push_str(&format!("```{}\n", poc_lang));
        md.push_str(poc);
        md.push_str("\n```\n\n");
    }

    // Sources
    if !finding.sources.is_empty() {
        md.push_str(&format!("**Sources:** {}\n\n", finding.sources.join(", ")));
    }

    // Already reported status
    if finding.already_reported {
        md.push_str("**Status:** Already reported in existing tracker\n\n");
    }

    md
}

/// Detect programming language from file extension.
fn detect_language(file_path: &str) -> &'static str {
    if let Some(ext) = std::path::Path::new(file_path).extension() {
        match ext.to_str().unwrap_or("") {
            "py" => "python",
            "js" => "javascript",
            "ts" => "typescript",
            "tsx" => "typescript",
            "rs" => "rust",
            "go" => "go",
            "java" => "java",
            "c" => "c",
            "cc" | "cpp" | "cxx" => "cpp",
            "h" | "hpp" => "cpp",
            "sql" => "sql",
            "yaml" | "yml" => "yaml",
            "json" => "json",
            "sh" | "bash" => "bash",
            "rb" => "ruby",
            "php" => "php",
            "cs" => "csharp",
            "swift" => "swift",
            "kt" => "kotlin",
            "scala" => "scala",
            "pl" | "pm" => "perl",
            "lua" => "lua",
            "sol" => "solidity",
            _ => "text",
        }
    } else {
        "text"
    }
}
