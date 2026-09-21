//! Coverage tests for static orchestrator functions
//!
//! Tests for:
//! - structural_dedup: clustering and deduplication logic
//! - compute_file_priority_score: file prioritization scoring
//! - should_analyze_file: triage decision (boundary cases not in other test files)

use baco::findings::{Severity, VulnerabilityFinding};
use baco::indexer::FileInfo;
use baco::scanner::phases::llm_phases::compute_file_priority_score;
use baco::scanner::structural_dedup;
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::TempDir;

// ============================================================================
// Test fixtures
// ============================================================================

fn make_finding(
    id: &str,
    file_path: &str,
    line_number: u32,
    cwe_id: Option<&str>,
    sources: Vec<&str>,
    confidence: f32,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: format!("Test finding {}", id),
        description: "Test finding description".to_string(),
        severity: Severity::Medium,
        confidence_score: confidence,
        cwe_id: cwe_id.map(|s| s.to_string()),
        file_path: file_path.to_string(),
        line_number: Some(line_number),
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: sources.into_iter().map(|s| s.to_string()).collect(),
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status: None,
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
        statement_range: None,
        triage_verdict: None,
        evidence: vec![],
        verification_tier: None,
    }
}

fn make_priority_config() -> baco::config::PriorityConfig {
    baco::config::PriorityConfig {
        enabled: true,
        git_recent_boost: 1.5,
        entry_point_boost: 2.0,
        small_file_boost: 1.3,
        entry_point_patterns: vec![],
        sink_patterns: vec![],
    }
}

// ============================================================================
// structural_dedup tests
// ============================================================================

#[test]
fn test_structural_dedup_empty_input() {
    let mut findings: Vec<VulnerabilityFinding> = vec![];

    let removed = structural_dedup(&mut findings);

    assert_eq!(findings.len(), 0);
    assert_eq!(removed, 0);
}

#[test]
fn test_structural_dedup_single_finding() {
    let mut findings = vec![make_finding("1", "src/test.rs", 42, Some("CWE-79"), vec!["scanner1"], 0.8)];

    let removed = structural_dedup(&mut findings);

    assert_eq!(findings.len(), 1);
    assert_eq!(removed, 0);
    assert_eq!(findings[0].id, "1");
}

#[test]
fn test_structural_dedup_exact_duplicates_same_file_line() {
    let mut findings = vec![
        make_finding("1", "src/test.rs", 42, Some("CWE-79"), vec!["scanner1"], 0.8),
        make_finding("2", "src/test.rs", 42, Some("CWE-79"), vec!["scanner2"], 0.7),
        make_finding("3", "src/test.rs", 42, Some("CWE-79"), vec!["scanner3"], 0.9),
    ];

    let removed = structural_dedup(&mut findings);

    assert_eq!(findings.len(), 1);
    assert_eq!(removed, 2);
    // Should keep the one with highest confidence (finding 3)
    assert_eq!(findings[0].id, "3");
    assert_eq!(findings[0].confidence_score, 0.9);
}

#[test]
fn test_structural_dedup_near_duplicates_same_file_consecutive_lines() {
    let mut findings = vec![
        make_finding("1", "src/test.rs", 42, Some("CWE-79"), vec!["scanner1"], 0.8),
        make_finding("2", "src/test.rs", 43, Some("CWE-79"), vec!["scanner2"], 0.7),
        make_finding("3", "src/test.rs", 44, Some("CWE-79"), vec!["scanner3"], 0.9),
    ];

    let removed = structural_dedup(&mut findings);

    // Lines 42, 43, 44 are within ±2, so they form one cluster
    assert_eq!(findings.len(), 1);
    assert_eq!(removed, 2);
    assert_eq!(findings[0].id, "3");
}

#[test]
fn test_structural_dedup_near_duplicates_different_clusters() {
    let mut findings = vec![
        make_finding("1", "src/test.rs", 42, Some("CWE-79"), vec!["scanner1"], 0.8),
        make_finding("2", "src/test.rs", 43, Some("CWE-79"), vec!["scanner2"], 0.7),
        make_finding("3", "src/test.rs", 50, Some("CWE-79"), vec!["scanner3"], 0.9),
        make_finding("4", "src/test.rs", 51, Some("CWE-79"), vec!["scanner4"], 0.6),
    ];

    let removed = structural_dedup(&mut findings);

    // Lines 42-43 form cluster 1, lines 50-51 form cluster 2
    assert_eq!(findings.len(), 2);
    assert_eq!(removed, 2);
}

#[test]
fn test_structural_dedup_cross_file_duplicates_different_cwe() {
    let mut findings = vec![
        make_finding("1", "src/test1.rs", 42, Some("CWE-79"), vec!["scanner1"], 0.8),
        make_finding("2", "src/test2.rs", 42, Some("CWE-79"), vec!["scanner2"], 0.7),
        make_finding("3", "src/test1.rs", 42, Some("CWE-89"), vec!["scanner3"], 0.9),
    ];

    let removed = structural_dedup(&mut findings);

    // Different files or different CWE IDs are separate groups
    // test1.rs + CWE-79: 1 finding
    // test2.rs + CWE-79: 1 finding
    // test1.rs + CWE-89: 1 finding
    assert_eq!(findings.len(), 3);
    assert_eq!(removed, 0);
}

#[test]
fn test_structural_dedup_cross_file_same_cwe() {
    let mut findings = vec![
        make_finding("1", "src/test1.rs", 42, Some("CWE-79"), vec!["scanner1"], 0.8),
        make_finding("2", "src/test2.rs", 42, Some("CWE-79"), vec!["scanner2"], 0.7),
    ];

    let removed = structural_dedup(&mut findings);

    // Different files = different groups, no dedup
    assert_eq!(findings.len(), 2);
    assert_eq!(removed, 0);
}

#[test]
fn test_structural_dedup_large_cluster_keeps_best() {
    let mut findings = vec![
        make_finding("1", "src/test.rs", 40, Some("CWE-79"), vec!["scanner1"], 0.5),
        make_finding("2", "src/test.rs", 41, Some("CWE-79"), vec!["scanner2"], 0.6),
        make_finding("3", "src/test.rs", 42, Some("CWE-79"), vec!["scanner1", "scanner2"], 0.7),
        make_finding("4", "src/test.rs", 43, Some("CWE-79"), vec!["scanner3"], 0.8),
        make_finding("5", "src/test.rs", 44, Some("CWE-79"), vec!["scanner4"], 0.4),
    ];

    let removed = structural_dedup(&mut findings);

    // All lines within ±2 form one cluster, keep highest sources then confidence
    assert_eq!(findings.len(), 1);
    assert_eq!(removed, 4);
    // Finding 3 has 2 sources, which is the most
    assert_eq!(findings[0].id, "3");
    assert_eq!(findings[0].sources.len(), 2);
}

#[test]
fn test_structural_dedup_preserves_original_order() {
    let mut findings = vec![
        make_finding("1", "src/a.rs", 10, Some("CWE-79"), vec!["scanner1"], 0.8),
        make_finding("2", "src/b.rs", 20, Some("CWE-89"), vec!["scanner2"], 0.7),
        make_finding("3", "src/a.rs", 11, Some("CWE-79"), vec!["scanner3"], 0.9),
        make_finding("4", "src/c.rs", 30, Some("CWE-90"), vec!["scanner4"], 0.6),
    ];

    let removed = structural_dedup(&mut findings);

    // Finding 1 and 3 are in the same group (a.rs, CWE-79), cluster kept is 3
    // Order should be: 2, 3, 4 (original order of kept findings)
    assert_eq!(findings.len(), 3);
    assert_eq!(removed, 1);
    assert_eq!(findings[0].id, "2");
    assert_eq!(findings[1].id, "3");
    assert_eq!(findings[2].id, "4");
}

#[test]
fn test_structural_dedup_sources_merged_into_best() {
    let mut findings = vec![
        make_finding("1", "src/test.rs", 42, Some("CWE-79"), vec!["scanner1", "scanner2"], 0.8),
        make_finding("2", "src/test.rs", 43, Some("CWE-79"), vec!["scanner3", "scanner4"], 0.9),
    ];

    let removed = structural_dedup(&mut findings);

    assert_eq!(findings.len(), 1);
    assert_eq!(removed, 1);
    // Finding 2 has higher confidence, so it's kept
    assert_eq!(findings[0].id, "2");
    // Sources from both should be merged
    assert_eq!(findings[0].sources.len(), 4);
    assert!(findings[0].sources.contains(&"scanner1".to_string()));
    assert!(findings[0].sources.contains(&"scanner2".to_string()));
    assert!(findings[0].sources.contains(&"scanner3".to_string()));
    assert!(findings[0].sources.contains(&"scanner4".to_string()));
}

#[test]
fn test_structural_dedup_tiebreaker_by_sources_then_confidence() {
    let mut findings = vec![
        make_finding("1", "src/test.rs", 42, Some("CWE-79"), vec!["scanner1"], 0.9),
        make_finding("2", "src/test.rs", 43, Some("CWE-79"), vec!["scanner2", "scanner3"], 0.8),
    ];

    let removed = structural_dedup(&mut findings);

    assert_eq!(findings.len(), 1);
    // Finding 2 has more sources (2 vs 1), so it wins despite lower confidence
    assert_eq!(findings[0].id, "2");
    assert_eq!(findings[0].sources.len(), 2);
}

// ============================================================================
// compute_file_priority_score tests
// ============================================================================

#[test]
fn test_compute_file_priority_score_entry_point_boost() {
    let tmp_dir = TempDir::new().unwrap();
    let main_file = tmp_dir.path().join("main.rs");
    std::fs::write(&main_file, "fn main() {}").unwrap();

    let file_info = FileInfo {
        path: main_file,
        size: 100,
        language: "rust".to_string(),
        hash: None,
    };

    let priority = make_priority_config();
    let hook_map: HashMap<String, Vec<String>> = HashMap::new();

    let score = compute_file_priority_score(&file_info, &priority, &hook_map);

    // Entry point boost: 1.0 * 2.0 (entry_point_boost) * 1.3 (small_file_boost) = 2.6
    assert!((score - 2.6).abs() < 0.01);
}

#[test]
fn test_compute_file_priority_score_small_file_boost() {
    let tmp_dir = TempDir::new().unwrap();
    let small_file = tmp_dir.path().join("utils.rs");
    std::fs::write(&small_file, "fn helper() {}").unwrap();

    let file_info = FileInfo {
        path: small_file,
        size: 5000, // < 10KB
        language: "rust".to_string(),
        hash: None,
    };

    let priority = make_priority_config();
    let hook_map: HashMap<String, Vec<String>> = HashMap::new();

    let score = compute_file_priority_score(&file_info, &priority, &hook_map);

    // Small file boost: 1.0 * 1.3 = 1.3
    assert!((score - 1.3).abs() < 0.01);
}

#[test]
fn test_compute_file_priority_score_hook_map_boost() {
    let tmp_dir = TempDir::new().unwrap();
    let hook_file = tmp_dir.path().join("hooks.php");
    std::fs::write(&hook_file, "add_action('init', ...);").unwrap();

    let file_info = FileInfo {
        path: hook_file.clone(),
        size: 1000,
        language: "php".to_string(),
        hash: None,
    };

    let priority = make_priority_config();
    let mut hook_map: HashMap<String, Vec<String>> = HashMap::new();
    hook_map.insert(hook_file.to_string_lossy().to_string(), vec!["hook1".to_string()]);

    let score = compute_file_priority_score(&file_info, &priority, &hook_map);

    // Hook map boost: 1.0 * 2.0 (entry_point_boost) * 1.3 (small_file_boost) = 2.6
    assert!((score - 2.6).abs() < 0.01);
}

// ============================================================================
// should_analyze_file tests (boundary cases)
// ============================================================================

#[test]
fn test_should_analyze_file_high_suspicion_low_threshold() {
    let result = baco::scanner::phases::llm_phases::should_analyze_file(0.95, 0.3);

    assert!(result);
}

#[test]
fn test_should_analyze_file_low_suspicion_high_threshold() {
    let result = baco::scanner::phases::llm_phases::should_analyze_file(0.1, 0.8);

    assert!(!result);
}

#[test]
fn test_should_analyze_file_extreme_values() {
    // Edge case: both suspicion and threshold at extremes
    let result1 = baco::scanner::phases::llm_phases::should_analyze_file(0.0, 0.0);
    assert!(result1); // 0.0 >= 0.0 is true

    let result2 = baco::scanner::phases::llm_phases::should_analyze_file(1.0, 1.0);
    assert!(result2); // 1.0 >= 1.0 is true

    let result3 = baco::scanner::phases::llm_phases::should_analyze_file(0.0, 1.0);
    assert!(!result3); // 0.0 >= 1.0 is false
}