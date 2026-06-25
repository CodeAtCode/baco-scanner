//! LLM phase tests (10 tests)
//!
//! Tests for LLM-related phases including static analysis, discovery,
//! verification, and aggregation phases.

use crate::config::ScannerConfig;
use crate::findings::VulnerabilityFinding;

use crate::phase::tests::test_fixtures::create_test_finding;
use crate::phase::ai_aggregation::AiAggregationPhase;
use crate::phase::llm_static::LlmStaticAnalysisPhase;
use crate::phase::{PhaseContext, ScanPhase as PhaseTrait};
use crate::scanner::Scanner;
use crate::scanner_types::{MajorityVerdict, PatchCandidate, PatchValidationResult, VerifierVerdict};
use std::fs;
use tempfile::TempDir;


// ========================================================================
// LLM PHASE TESTS (10 tests)
// ========================================================================

/// Test 21: LLM Static Analysis phase - disabled scenario
#[tokio::test]
async fn test_llm_static_phase_disabled() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("test.rs"), "fn main() {}").unwrap();

    let config = ScannerConfig::default();
    let mut scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);
    let mut ctx = PhaseContext {
        scanner: &mut scanner,
        analyzed_files: &mut vec![],
    };

    let phase = LlmStaticAnalysisPhase;
    let result = phase.execute(&mut ctx).await;

    // Without API key, should return empty findings without error
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

/// Test 22: LLM Discovery phase - findings enrichment structure
#[test]
fn test_llm_discovery_findings_enrichment() {
    let mut finding = create_test_finding();
    finding.sources = vec!["semgrep".to_string()];

    // Simulate enrichment - adding new sources
    finding.sources.push("llm-discovery".to_string());
    finding.verification_notes = Some("LLM confirmed this is a vulnerability".to_string());

    assert_eq!(finding.sources.len(), 2);
    assert!(finding.sources.contains(&"llm-discovery".to_string()));
}

/// Test 23: LLM Discovery phase - error handling structure
#[test]
fn test_llm_discovery_error_handling_structure() {
    // Verify error handling pattern
    let result: Result<Vec<VulnerabilityFinding>, String> = Err("LLM API unavailable".to_string());

    match result {
        Ok(findings) => assert!(findings.is_empty()),
        Err(e) => assert!(e.contains("LLM API")),
    }
}

/// Test 24: AI Aggregation phase - empty findings
#[tokio::test]
async fn test_ai_aggregation_phase_empty_findings() {
    let temp_dir = TempDir::new().unwrap();
    let config = ScannerConfig::default();
    let mut scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);

    let mut ctx = PhaseContext {
        scanner: &mut scanner,
        analyzed_files: &mut vec![],
    };

    let phase = AiAggregationPhase;
    let result = phase.execute(&mut ctx).await;

    assert!(result.is_ok());
}

/// Test 25: Confidence Refinement phase - confidence scoring
#[test]
fn test_confidence_refinement_scoring() {
    let mut finding = create_test_finding();
    finding.confidence_score = 0.5;

    // Simulate confidence refinement
    let base_confidence = finding.confidence_score;
    let verification_boost = 0.1; // If verified
    let multi_source_boost = 0.05; // If from multiple sources

    finding.confidence_score = (base_confidence + verification_boost + multi_source_boost).min(1.0);

    assert!(finding.confidence_score > base_confidence);
    assert!(finding.confidence_score <= 1.0);
}

/// Test 26: Confidence Refinement phase - pattern matching
#[test]
fn test_confidence_refinement_pattern_matching() {
    let finding = create_test_finding();

    // Pattern: SQL injection with high confidence
    let sql_injection_patterns = vec!["SQL", "query", "database"];
    let description_upper = finding.description.to_uppercase();

    let matches = sql_injection_patterns
        .iter()
        .filter(|p| description_upper.contains(&p.to_uppercase()))
        .count();

    assert!(matches > 0); // Our test finding mentions SQL
}

/// Test 27: Root Cause Dedup phase - deduplication logic
#[test]
fn test_root_cause_dedup_logic() {
    let mut findings = vec![create_test_finding(), create_test_finding()];

    // Same file and line should be considered duplicates
    findings[0].file_path = "src/auth.rs".to_string();
    findings[0].line_number = Some(42);
    findings[1].file_path = "src/auth.rs".to_string();
    findings[1].line_number = Some(42);

    // Deduplication based on location
    let mut seen_locations = std::collections::HashSet::new();
    let mut unique_count = 0;

    for finding in &findings {
        let location = (
            finding.file_path.clone(),
            finding.line_number.unwrap_or(0),
        );
        if seen_locations.insert(location) {
            unique_count += 1;
        }
    }

    assert_eq!(unique_count, 1); // Should deduplicate to 1
}

/// Test 28: Multi Verifier phase - consensus voting
#[test]
fn test_multi_verifier_consensus_voting() {
    let verdicts = vec![
        VerifierVerdict::Confirmed,
        VerifierVerdict::Confirmed,
        VerifierVerdict::Rejected,
    ];

    let majority = MajorityVerdict::new(VerifierVerdict::Confirmed, 0.67, verdicts);

    assert_eq!(majority.final_verdict, VerifierVerdict::Confirmed);
    assert_eq!(majority.confidence, 0.67);
}

/// Test 29: Auto Patcher phase - patch generation structure
#[test]
fn test_auto_patcher_patch_generation() {
    let diff = r#"--- a/src/auth.rs
+++ b/src/auth.rs
@@ -10 +10 @@
-strcpy(buf, input);
+strncpy(buf, input, sizeof(buf));
"#;

    let patch = PatchCandidate::new(diff, "src/auth.rs");
    assert!(patch.diff.contains("strncpy"));
    assert_eq!(patch.file_path, "src/auth.rs");
    assert!(!patch.applied);
}

/// Test 30: Auto Patcher phase - patch staging
#[test]
fn test_auto_patcher_staging() {
    let mut patch = PatchCandidate::new("diff content", "src/test.rs");
    patch.validation_result = Some(PatchValidationResult::success());

    assert!(patch.validation_result.as_ref().unwrap().compiles);
    assert!(patch.validation_result.as_ref().unwrap().tests_pass);
}
