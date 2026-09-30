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
/// - `verification_status = Failed`
/// - Appends to `verification_notes`: "citation verification failed: reason" (where reason is the failure cause)
///
/// The finding is kept, not dropped. Two reasons: `include_rejected` exists so a
/// user can ask to see everything, and deleting here would be a second filter
/// that does not respect it. The status is the signal, and whether it is
/// filtered is `apply_evidence_gate`'s decision.
///
/// Confidence is deliberately left alone. `classify_finding` tiers on it, so
/// scaling it by a constant corrupts the model's own estimate with a number
/// that says nothing about how wrong the finding is.
///
/// Returns a summary report with counts.
pub fn verify_citations(
    findings: &mut [VulnerabilityFinding],
    project_path: &Path,
) -> CitationReport {
    let mut report = CitationReport::default();

    for finding in findings.iter_mut() {
        report.checked += 1;

        // Tolerate legacy aggregate findings that used the sentinel path
        if finding.file_path.is_empty() || finding.file_path == "multiple_files" {
            // Count as checked but not passed/failed — skip verification
            continue;
        }

        let file_path = project_path.join(&finding.file_path);

        // Reject absolute paths and path traversal attempts
        if finding.file_path.starts_with('/') || finding.file_path.contains("..") {
            finding.verification_status = Some(crate::findings::VerificationStatus::Failed);
            let note = format!(
                "citation verification failed: path traversal rejected: {}",
                finding.file_path
            );
            append_verification_note(&mut finding.verification_notes, &note);
            report.failed += 1;
            continue;
        }

        // Check if file exists and is readable
        let file_content = match fs::read_to_string(&file_path) {
            Ok(content) => content,
            Err(_) => {
                finding.verification_status = Some(crate::findings::VerificationStatus::Failed);
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
            // Line 0 is invalid (lines are 1-indexed)
            if line_num == 0 {
                finding.verification_status = Some(crate::findings::VerificationStatus::Failed);
                let note = format!(
                    "citation verification failed: line 0 is invalid (1-indexed): {}",
                    finding.file_path
                );
                append_verification_note(&mut finding.verification_notes, &note);
                report.failed += 1;
                continue;
            }

            let line_count = file_content.lines().count();

            if line_num as usize > line_count {
                finding.verification_status = Some(crate::findings::VerificationStatus::Failed);
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
