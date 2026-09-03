//! Unit tests for cost estimation module.

use baco::cost_estimate::*;
use baco::indexer::FileInfo;
use std::path::PathBuf;

fn make_file(path: &str, size: u64, language: &str) -> FileInfo {
    FileInfo {
        path: PathBuf::from(path),
        size,
        language: language.to_string(),
        hash: None,
    }
}

// ============================================================================
// Migrated inline tests from src/cost_estimate.rs (8 tests)
// ============================================================================

#[test]
fn test_bytes_to_tokens_inline_migrated() {
    // ~4 chars per token
    assert_eq!(bytes_to_tokens(400), 100);
    assert_eq!(bytes_to_tokens(800), 200);
    assert_eq!(bytes_to_tokens(1000), 250);
    assert_eq!(bytes_to_tokens(3), 0); // Less than 4 chars = 0 tokens
}

#[test]
fn test_estimate_llm_calls_no_budget_inline_migrated() {
    // No budget limit - returns total files
    let calls = estimate_llm_calls(100, 10, usize::MAX, 0.0, false);
    assert_eq!(calls, 100); // All files considered
}

#[test]
fn test_estimate_llm_calls_with_budget_no_triage_inline_migrated() {
    // Budget enforced, no triage
    let calls = estimate_llm_calls(100, 10, 50, 0.2, false);
    // normal_cap = 50 - (50 * 0.2) = 40
    // All 100 files considered, capped at 50
    assert_eq!(calls, 50);
}

#[test]
fn test_estimate_llm_calls_with_budget_and_triage_inline_migrated() {
    // Budget enforced, triage enabled
    let calls = estimate_llm_calls(100, 10, 50, 0.2, true);
    // normal_cap = 50 - (50 * 0.2) = 40
    // triaged_normal = 90 / 2 = 45, capped at 40
    // high_risk = 10, capped at 10 (50 - 40)
    assert_eq!(calls, 50);
}

#[test]
fn test_count_high_risk_files_inline_migrated() {
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
fn test_compute_estimate_basic_inline_migrated() {
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
fn test_compute_estimate_budget_capped_inline_migrated() {
    let files: Vec<FileInfo> = (0..200)
        .map(|i| make_file(&format!("src/file{}.rs", i), 100, "rust"))
        .collect();

    let estimate = compute_estimate(&files, 50, 0.0, false, &[1.0; 200]);

    assert_eq!(estimate.total_files, 200);
    assert_eq!(estimate.planned_llm_calls, 50); // Capped at budget
}

#[test]
fn test_compute_estimate_with_triage_inline_migrated() {
    let files: Vec<FileInfo> = (0..100)
        .map(|i| make_file(&format!("src/file{}.rs", i), 100, "rust"))
        .collect();

    let estimate = compute_estimate(&files, 100, 0.0, true, &[1.0; 100]);

    // With triage, ~50% pass: 100 / 2 = 50
    assert_eq!(estimate.planned_llm_calls, 50);
}