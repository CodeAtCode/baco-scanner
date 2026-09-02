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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_file(path: &str, size: u64, language: &str) -> FileInfo {
        FileInfo {
            path: PathBuf::from(path),
            size,
            language: language.to_string(),
            hash: None,
        }
    }

    #[test]
    fn test_bytes_to_tokens() {
        // ~4 chars per token
        assert_eq!(bytes_to_tokens(400), 100);
        assert_eq!(bytes_to_tokens(800), 200);
        assert_eq!(bytes_to_tokens(1000), 250);
        assert_eq!(bytes_to_tokens(3), 0); // Less than 4 chars = 0 tokens
    }

    #[test]
    fn test_estimate_llm_calls_no_budget() {
        // No budget limit - returns total files
        let calls = estimate_llm_calls(100, 10, usize::MAX, 0.0, false);
        assert_eq!(calls, 100); // All files considered
    }

    #[test]
    fn test_estimate_llm_calls_with_budget_no_triage() {
        // Budget enforced, no triage
        let calls = estimate_llm_calls(100, 10, 50, 0.2, false);
        // normal_cap = 50 - (50 * 0.2) = 40
        // All 100 files considered, capped at 50
        assert_eq!(calls, 50);
    }

    #[test]
    fn test_estimate_llm_calls_with_budget_and_triage() {
        // Budget enforced, triage enabled
        let calls = estimate_llm_calls(100, 10, 50, 0.2, true);
        // normal_cap = 50 - (50 * 0.2) = 40
        // triaged_normal = 90 / 2 = 45, capped at 40
        // high_risk = 10, capped at 10 (50 - 40)
        assert_eq!(calls, 50);
    }

    #[test]
    fn test_count_high_risk_files() {
        let files = vec![
            make_file("src/main.rs", 1000, "rust"),
            make_file("src/lib.rs", 500, "rust"),
            make_file("src/index.ts", 800, "typescript"),
            make_file("src/app.py", 600, "python"),
            make_file("src/server.js", 700, "javascript"),
            make_file("src/__init__.py", 200, "python"),
            make_file("src/utils.rs", 400, "rust"),
        ];

        let count = count_high_risk_files(&files);
        assert_eq!(count, 5); // main, index, app, server, __init__
    }

    #[test]
    fn test_compute_estimate_basic() {
        let files = vec![
            make_file("src/main.rs", 1000, "rust"),
            make_file("src/lib.rs", 2000, "rust"),
            make_file("src/index.ts", 1500, "typescript"),
        ];

        let estimate = compute_estimate(&files, 100, 0.2, false, &[1.0, 1.0, 1.0]);

        assert_eq!(estimate.total_files, 3);
        assert_eq!(estimate.total_bytes, 4500);
        assert_eq!(estimate.estimated_tokens, 1125); // 4500 / 4
        assert_eq!(estimate.planned_llm_calls, 3); // min(100, 3)
        assert_eq!(estimate.files_by_language.get("rust").unwrap(), &2);
        assert_eq!(estimate.files_by_language.get("typescript").unwrap(), &1);
    }

    #[test]
    fn test_compute_estimate_budget_capped() {
        let files: Vec<FileInfo> = (0..200)
            .map(|i| make_file(&format!("src/file{}.rs", i), 100, "rust"))
            .collect();

        let estimate = compute_estimate(&files, 50, 0.0, false, &[1.0; 200]);

        assert_eq!(estimate.total_files, 200);
        assert_eq!(estimate.planned_llm_calls, 50); // Capped at budget
    }

    #[test]
    fn test_compute_estimate_with_triage() {
        let files: Vec<FileInfo> = (0..100)
            .map(|i| make_file(&format!("src/file{}.rs", i), 100, "rust"))
            .collect();

        let estimate = compute_estimate(&files, 100, 0.0, true, &[1.0; 100]);

        // With triage, ~50% pass: 100 / 2 = 50
        assert_eq!(estimate.planned_llm_calls, 50);
    }
}
