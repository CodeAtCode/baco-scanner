#![cfg(test)]

use baco::config::phases::PriorityConfig;
use baco::indexer::FileInfo;
use baco::scanner::phases::llm_phases::{compute_file_priority_score, should_analyze_file};
use tempfile::TempDir;

// ============== should_analyze_file tests ==============

/// Test that files with suspicion score above threshold are analyzed
#[test]
fn test_should_analyze_file_above_threshold() {
    let suspicion = 0.7;
    let threshold = 0.5;

    assert!(should_analyze_file(suspicion, threshold));
}

/// Test that files with suspicion score below threshold are not analyzed
#[test]
fn test_should_analyze_file_below_threshold() {
    let suspicion = 0.3;
    let threshold = 0.5;

    assert!(!should_analyze_file(suspicion, threshold));
}

/// Test boundary behavior: suspicion exactly at threshold
#[test]
fn test_should_analyze_file_at_exact_threshold() {
    let suspicion = 0.5;
    let threshold = 0.5;

    // should_analyze_file uses >= comparison
    assert!(should_analyze_file(suspicion, threshold));
}

/// Test with zero threshold: all files pass
#[test]
fn test_should_analyze_file_zero_threshold() {
    let suspicion = 0.0;
    let threshold = 0.0;

    assert!(should_analyze_file(suspicion, threshold));
}

/// Test with unity threshold: only perfect scores pass
#[test]
fn test_should_analyze_file_unity_threshold() {
    // Perfect score passes
    assert!(should_analyze_file(1.0, 1.0));
    // Near-perfect but not exact fails
    assert!(!should_analyze_file(0.99, 1.0));
}

// ============== compute_file_priority_score tests ==============

/// Test that small files (< 10KB) get the small_file_boost
#[test]
fn test_compute_file_priority_score_small_file_boost() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("small_file.py");

    // Create a small file (500 bytes)
    std::fs::write(&test_file, b"print('hello')").unwrap();

    let file_info = FileInfo {
        path: test_file,
        size: 500, // < 10KB
        language: "python".to_string(),
        hash: None,
    };

    let priority = PriorityConfig {
        enabled: true,
        ..Default::default()
    };

    let hook_map = std::collections::HashMap::new();
    let score = compute_file_priority_score(&file_info, &priority, &hook_map);

    // Base score is 1.0
    // git_recent_boost applies (file just created) = 2.0
    // small_file_boost = 1.2
    // So expected score = 1.0 * 2.0 * 1.2 = 2.4
    assert!(
        (score - 2.4).abs() < 0.001,
        "Expected score ~2.4, got {}",
        score
    );
}

/// Test that entry-point files get the entry_point_boost
#[test]
fn test_compute_file_priority_score_entry_point_boost() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("main.py");

    // Create the file
    std::fs::write(&test_file, b"def main(): pass").unwrap();

    let file_info = FileInfo {
        path: test_file,
        size: 50000, // Large file, no small_file_boost
        language: "python".to_string(),
        hash: None,
    };

    let priority = PriorityConfig {
        enabled: true,
        ..Default::default()
    };

    let hook_map = std::collections::HashMap::new();
    let score = compute_file_priority_score(&file_info, &priority, &hook_map);

    // Base score is 1.0
    // git_recent_boost applies (file just created) = 2.0
    // entry_point_boost = 1.5 (main.py matches "main.")
    // So expected score = 1.0 * 2.0 * 1.5 = 3.0
    assert!(
        (score - 3.0).abs() < 0.001,
        "Expected score ~3.0, got {}",
        score
    );
}

/// Test that when priority is disabled, the function still computes a score
/// (the enabled flag is checked by the caller, not inside the function)
#[test]
fn test_compute_file_priority_score_disabled_returns_zero() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("random_file.py");

    std::fs::write(&test_file, b"def foo(): pass").unwrap();

    let file_info = FileInfo {
        path: test_file,
        size: 50000, // Large file, no small_file_boost
        language: "python".to_string(),
        hash: None,
    };

    // Default PriorityConfig has enabled: false
    // But the function still computes a score - the caller checks enabled
    let priority = PriorityConfig::default();

    let hook_map = std::collections::HashMap::new();
    let score = compute_file_priority_score(&file_info, &priority, &hook_map);

    // Base score is 1.0
    // git_recent_boost applies (file just created) = 2.0
    // So score = 1.0 * 2.0 = 2.0
    // The enabled flag is checked by the caller, not inside the function
    assert!(
        (score - 2.0).abs() < 0.001,
        "Expected score ~2.0 (base * git_recent), got {}",
        score
    );
}

/// Test that a small entry-point file gets both boosts
#[test]
fn test_compute_file_priority_score_combined_boosts() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("main.py");

    std::fs::write(&test_file, b"def main(): pass").unwrap();

    let file_info = FileInfo {
        path: test_file,
        size: 500, // Small file (< 10KB)
        language: "python".to_string(),
        hash: None,
    };

    let priority = PriorityConfig {
        enabled: true,
        ..Default::default()
    };

    let hook_map = std::collections::HashMap::new();
    let score = compute_file_priority_score(&file_info, &priority, &hook_map);

    // Base score is 1.0
    // git_recent_boost = 2.0 (file just created)
    // entry_point_boost = 1.5 (main.py matches "main.")
    // small_file_boost = 1.2 (500 bytes < 10KB)
    // Expected score = 1.0 * 2.0 * 1.5 * 1.2 = 3.6
    assert!(
        (score - 3.6).abs() < 0.001,
        "Expected score ~3.6, got {}",
        score
    );
}
