/// Cost estimation for dry-run mode.
///
/// Provides functions to estimate:
/// - Files per language
/// - Planned LLM calls (respecting budget and triage)
/// - Estimated input tokens (~4 chars/token)
/// - Estimated cost (if price is known)
use crate::indexer::FileInfo;
use std::collections::HashMap;

/// Estimated scan costs and metrics.
#[derive(Debug, Clone)]
pub struct ScanEstimate {
    /// Files grouped by language
    pub files_by_language: HashMap<String, usize>,
    /// Total number of files
    pub total_files: usize,
    /// Total size in bytes
    pub total_bytes: usize,
    /// Estimated tokens (~4 chars per token)
    pub estimated_tokens: usize,
    /// Planned LLM calls after budget/triage enforcement
    pub planned_llm_calls: usize,
    /// Maximum LLM calls allowed by budget
    pub max_llm_calls: usize,
    /// Average priority score across files
    pub avg_priority_score: f32,
}

/// Estimate token count from bytes (~4 chars per token).
pub fn bytes_to_tokens(bytes: usize) -> usize {
    bytes / 4
}

/// Estimate LLM calls based on budget and triage configuration.
///
/// - If triage is enabled: assumes ~50% of non-high-risk files pass triage
/// - High-risk files (entry-points) are protected by budget reserve
pub fn estimate_llm_calls(
    total_files: usize,
    high_risk_count: usize,
    max_calls: usize,
    reserve_percent: f32,
    triage_enabled: bool,
) -> usize {
    let normal_cap = max_calls.saturating_sub((max_calls as f32 * reserve_percent) as usize);
    let normal_count = total_files.saturating_sub(high_risk_count);

    if triage_enabled {
        // Assume triage filters ~50% of non-high-risk files
        let triaged_normal = normal_count / 2;
        let normal_calls = std::cmp::min(normal_cap, triaged_normal);
        // High-risk files always fit in the remaining budget (reserve + unused normal share)
        let high_risk_calls =
            std::cmp::min(high_risk_count, max_calls.saturating_sub(normal_calls));
        normal_calls + high_risk_calls
    } else {
        std::cmp::min(max_calls, total_files)
    }
}

/// Count high-risk files (entry-points like main.*, index.*, etc.)
pub fn count_high_risk_files(files: &[FileInfo]) -> usize {
    files
        .iter()
        .filter(|f| {
            let file_name = f
                .path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            ["main.", "index.", "app.", "server.", "__init__."]
                .iter()
                .any(|p| file_name.contains(p))
        })
        .count()
}

/// Compute a simple estimate from indexed files and budget config.
pub fn compute_estimate(
    files: &[FileInfo],
    max_llm_calls: usize,
    reserve_percent: f32,
    triage_enabled: bool,
    priority_scores: &[f32],
) -> ScanEstimate {
    let mut files_by_lang: HashMap<String, usize> = HashMap::new();
    let mut total_bytes: usize = 0;
    let mut total_priority: f32 = 0.0;

    for (i, file) in files.iter().enumerate() {
        *files_by_lang.entry(file.language.clone()).or_default() += 1;
        total_bytes += file.size as usize;
        if i < priority_scores.len() {
            total_priority += priority_scores[i];
        }
    }

    let high_risk_count = count_high_risk_files(files);
    let planned_calls = estimate_llm_calls(
        files.len(),
        high_risk_count,
        max_llm_calls,
        reserve_percent,
        triage_enabled,
    );

    let avg_priority = if files.is_empty() {
        0.0
    } else {
        total_priority / files.len() as f32
    };

    ScanEstimate {
        files_by_language: files_by_lang,
        total_files: files.len(),
        total_bytes,
        estimated_tokens: bytes_to_tokens(total_bytes),
        planned_llm_calls: planned_calls,
        max_llm_calls,
        avg_priority_score: avg_priority,
    }
}
