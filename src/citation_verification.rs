//! Citation verification gate for baco security scanner.
//!
//! Validates that LLM-generated finding citations (file paths and line numbers)
//! actually exist in the scanned project tree before rendering reports.

use std::fs;
use std::path::Path;

use crate::findings::VulnerabilityFinding;

/// Report summarizing citation verification results.
#[derive(Debug, Default)]
pub struct CitationReport {
    /// Total number of citations checked.
    pub checked: usize,
    /// Number of citations that passed validation.
    pub passed: usize,
    /// Number of citations that failed validation.
    pub failed: usize,
}

/// Verify that all citation references in findings are valid.
///
/// For each finding:
/// - Resolves `project_path.join(&finding.file_path)` — file must exist
/// - If `line_number` is Some(n), reads the file and requires n <= total line count
///
/// On failure:
/// - `confidence_score *= 0.5`
/// - Appends to `verification_notes`: "citation verification failed: <reason>"
///
/// Returns a summary report with counts.
pub fn verify_citations(
    findings: &mut [VulnerabilityFinding],
    project_path: &Path,
) -> CitationReport {
    let mut report = CitationReport::default();

    for finding in findings.iter_mut() {
        report.checked += 1;

        let file_path = project_path.join(&finding.file_path);

        // Check if file exists and is readable
        let file_content = match fs::read_to_string(&file_path) {
            Ok(content) => content,
            Err(_) => {
                finding.confidence_score *= 0.5;
                let note = format!(
                    "citation verification failed: file not found or unreadable: {}",
                    finding.file_path
                );
                append_verification_note(&mut finding.verification_notes, &note);
                report.failed += 1;
                continue;
            }
        };

        // Check line number if present
        if let Some(line_num) = finding.line_number {
            let line_count = file_content.lines().count();

            if line_num as usize > line_count {
                finding.confidence_score *= 0.5;
                let note = format!(
                    "citation verification failed: line {} out of range (file has {} lines): {}",
                    line_num, line_count, finding.file_path
                );
                append_verification_note(&mut finding.verification_notes, &note);
                report.failed += 1;
                continue;
            }
        }

        // Citation is valid
        report.passed += 1;
    }

    tracing::info!(
        "Citation verification complete: {}/{} passed, {} failed",
        report.passed,
        report.checked,
        report.failed
    );

    report
}

/// Append a note to the verification_notes field, initializing it if needed.
fn append_verification_note(notes: &mut Option<String>, new_note: &str) {
    let combined = match notes.as_ref() {
        Some(existing) => format!("{}\n{}", existing, new_note),
        None => new_note.to_string(),
    };
    *notes = Some(combined);
}
