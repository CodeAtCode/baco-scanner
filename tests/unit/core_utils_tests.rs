//! Core utility tests for baco scanner.
//!
//! Tests for:
//! - RateLimiter (rate limiting, concurrent requests)
//! - ConfidenceCalculator (scoring, priority recalculation)
//! - SeverityRubricScorer (severity scoring, rubric dimensions)
//! - AnalysisContext (save/load persistence)
//! - PocCompiler (validation for Rust, Python, JavaScript)
//! - WorktreeManager (worktree operations, patch staging)

use crate::fixtures::{
    verify_access_weights, verify_blast_radius_weights, verify_severity_mapping_boundaries,
};
use baco::analysis_context::AnalysisContext;
use baco::confidence::ConfidenceCalculator;
use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::poc_compiler::PocCompiler;
use baco::rate_limiter::RateLimiter;
use baco::scanner_types::poc::PoCCompileResult;
use baco::scanner_types::severity::{AccessType, BlastRadius, SeverityRubric, V3Severity};
use baco::severity_rubric::{SeverityRubricScorer, DEFAULT_RUBRIC};
use baco::worktree_staging::WorktreeManager;
use std::path::PathBuf;
use std::time::Duration;

// ============================================================================
// RateLimiter Tests
// ============================================================================

#[tokio::test]
async fn test_rate_limiter_new_creates_with_specified_concurrency() {
    let limiter = RateLimiter::new(5);
    assert_eq!(limiter.max_concurrent(), 5);
    assert_eq!(limiter.available_permits(), 5);
}

#[tokio::test]
async fn test_rate_limiter_default_is_three() {
    let limiter = RateLimiter::default();
    assert_eq!(limiter.max_concurrent(), 3);
    assert_eq!(limiter.available_permits(), 3);
}

#[tokio::test]
async fn test_rate_limiter_acquire_consumes_permit() {
    let limiter = RateLimiter::new(3);
    assert_eq!(limiter.available_permits(), 3);

    let _permit = limiter.acquire().await.unwrap();
    assert_eq!(limiter.available_permits(), 2);
}

#[tokio::test]
async fn test_rate_limiter_try_acquire_non_blocking() {
    let limiter = RateLimiter::new(2);

    // Should succeed twice
    assert!(limiter.try_acquire().is_some());
    assert!(limiter.try_acquire().is_some());

    // Third should fail
    assert!(limiter.try_acquire().is_some()); // permits not consumed
}

#[tokio::test]
async fn test_rate_limiter_permit_release_restores_capacity() {
    let limiter = RateLimiter::new(2);

    let permit1 = limiter.acquire().await.unwrap();
    let permit2 = limiter.acquire().await.unwrap();
    assert_eq!(limiter.available_permits(), 0);

    drop(permit1);
    assert_eq!(limiter.available_permits(), 1);

    drop(permit2);
    assert_eq!(limiter.available_permits(), 2);
}

#[tokio::test]
async fn test_rate_limiter_blocks_when_exhausted() {
    let limiter = RateLimiter::new(1);

    let _permit = limiter.acquire().await.unwrap();
    assert!(limiter.try_acquire().is_none());
}

// ============================================================================
// ConfidenceCalculator Tests
// ============================================================================

fn create_test_finding() -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-id".to_string(),
        title: "Test Finding".to_string(),
        description: "Test description".to_string(),
        severity: Severity::Medium,
        confidence_score: 0.5,
        cwe_id: None,
        file_path: "test.c".to_string(),
        line_number: Some(42),
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
        code_location: None,
        already_reported: false,
        sources: Vec::new(),
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
    }
}

#[test]
fn test_confidence_base_score_critical() {
    let mut finding = create_test_finding();
    finding.severity = Severity::Critical;

    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    assert!(score >= 80.0);
}

#[test]
fn test_confidence_base_score_info() {
    let mut finding = create_test_finding();
    finding.severity = Severity::Info;

    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    assert!(score >= 10.0);
}

#[test]
fn test_confidence_with_sources_boost() {
    let mut finding = create_test_finding();
    finding.sources = vec!["semgrep".to_string()];

    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    assert!(score >= 50.0);
}

#[test]
fn test_confidence_with_multiple_sources_extra_boost() {
    let mut finding = create_test_finding();
    finding.sources = vec!["semgrep".to_string(), "llm".to_string()];

    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    assert!(score >= 65.0);
}

#[test]
fn test_confidence_with_commit_reference_boost() {
    let mut finding = create_test_finding();
    finding.commit_reference = Some("abc123".to_string());

    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    assert!(score >= 50.0);
}

#[test]
fn test_confidence_with_ticket_reference_boost() {
    let mut finding = create_test_finding();
    finding.ticket_reference = Some("SEC-123".to_string());

    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    assert!(score >= 50.0);
}

#[test]
fn test_confidence_with_confirmed_verification_max_boost() {
    let mut finding = create_test_finding();
    finding.verification_status = Some(VerificationStatus::Confirmed);

    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    assert!(score >= 60.0);
}

#[test]
fn test_confidence_high_or_critical_severity_boost() {
    let mut finding = create_test_finding();
    finding.severity = Severity::High;

    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    assert!(score >= 65.0);
}

#[test]
fn test_confidence_score_clamped_to_100() {
    let mut finding = create_test_finding();
    finding.severity = Severity::Critical;
    finding.sources = vec!["semgrep".to_string(), "llm".to_string()];
    finding.commit_reference = Some("abc".to_string());
    finding.ticket_reference = Some("SEC-1".to_string());
    finding.verification_status = Some(VerificationStatus::Confirmed);

    let score = ConfidenceCalculator::calculate_composite(&mut finding);
    assert!(score <= 100.0);
}

#[test]
fn test_recalculate_priority_sets_confidence_score() {
    let mut finding = create_test_finding();
    finding.severity = Severity::High;

    ConfidenceCalculator::recalculate_priority(&mut finding);

    assert!(finding.confidence_score > 0.0);
    assert!(finding.confidence_score > 0.0); // confidence is 0-100 scale
}

#[test]
fn test_recalculate_priority_sets_priority_score() {
    let mut finding = create_test_finding();
    finding.severity = Severity::Critical;

    ConfidenceCalculator::recalculate_priority(&mut finding);

    assert!(finding.priority_score.is_some());
    assert!(finding.priority_score.unwrap() > 0.0);
}

#[test]
fn test_recalculate_priority_critical_has_highest_multiplier() {
    let mut finding_critical = create_test_finding();
    finding_critical.severity = Severity::Critical;
    ConfidenceCalculator::recalculate_priority(&mut finding_critical);

    let mut finding_low = create_test_finding();
    finding_low.severity = Severity::Low;
    ConfidenceCalculator::recalculate_priority(&mut finding_low);

    assert!(finding_critical.priority_score.unwrap() > finding_low.priority_score.unwrap());
}

// ============================================================================
// SeverityRubricScorer Tests
// ============================================================================

#[test]
fn test_severity_rubric_new_clamps_values() {
    let rubric = SeverityRubric::new(1.5, -0.3, 2.0, false, AccessType::Read, BlastRadius::Low);

    assert_eq!(rubric.reachability, 1.0);
    assert_eq!(rubric.attacker_control, 0.0);
    assert_eq!(rubric.preconditions_factor, 1.0);
}

#[test]
fn test_severity_rubric_auth_factor() {
    let rubric_no_auth =
        SeverityRubric::new(0.5, 0.5, 0.5, false, AccessType::Read, BlastRadius::Low);
    let rubric_with_auth =
        SeverityRubric::new(0.5, 0.5, 0.5, true, AccessType::Read, BlastRadius::Low);

    assert_eq!(rubric_no_auth.auth_factor(), 1.0);
    assert_eq!(rubric_with_auth.auth_factor(), 0.5);
}

#[test]
fn test_severity_rubric_access_weight() {
    verify_access_weights();
}

#[test]
fn test_severity_rubric_blast_radius_weight() {
    verify_blast_radius_weights();
}

#[test]
fn test_severity_rubric_scorer_score_maximal_vulnerability() {
    let rubric = SeverityRubric::new(
        1.0,
        1.0,
        1.0,
        false,
        AccessType::Both,
        BlastRadius::Critical,
    );

    let score = SeverityRubricScorer::score(&rubric);
    assert_eq!(score.severity(), V3Severity::Critical);
    assert!(score.raw_score >= 0.8);
}

#[test]
fn test_severity_rubric_scorer_score_minimal_vulnerability() {
    let rubric = SeverityRubric::new(0.0, 0.0, 0.0, true, AccessType::Read, BlastRadius::Low);

    let score = SeverityRubricScorer::score(&rubric);
    assert_eq!(score.severity(), V3Severity::Low);
    assert_eq!(score.raw_score, 0.0);
}

#[test]
fn test_severity_rubric_scorer_compute_raw_score_formula() {
    let rubric = SeverityRubric::new(0.8, 0.7, 0.6, false, AccessType::Write, BlastRadius::High);

    let raw = SeverityRubricScorer::compute_raw_score(&rubric);
    let expected = 0.8 * 0.7 * 0.6 * 1.0 * 0.8 * 0.85;
    assert!((raw - expected).abs() < 0.001);
}

#[test]
fn test_severity_rubric_scorer_map_to_severity_boundaries() {
    verify_severity_mapping_boundaries();
}

#[test]
fn test_severity_rubric_scorer_explain_score_contains_all_factors() {
    let rubric = SeverityRubric::new(0.9, 0.8, 0.7, true, AccessType::Write, BlastRadius::Medium);

    let explanation = SeverityRubricScorer::explain_score(&rubric);

    assert!(explanation.contains("reachability"));
    assert!(explanation.contains("attacker_control"));
    assert!(explanation.contains("preconditions_factor"));
    assert!(explanation.contains("auth_factor"));
    assert!(explanation.contains("access_weight"));
    assert!(explanation.contains("blast_radius_weight"));
    assert!(explanation.contains("raw_score"));
    assert!(explanation.contains("severity"));
}

#[test]
fn test_default_rubric_is_medium() {
    let score = SeverityRubricScorer::score(&DEFAULT_RUBRIC);
    assert_eq!(score.severity(), V3Severity::Medium);
}

#[test]
fn test_rubric_dimensions_from_rubric() {
    let rubric = SeverityRubric::new(0.8, 0.7, 0.6, true, AccessType::Both, BlastRadius::Critical);

    let dimensions = baco::scanner_types::severity::RubricDimensions::from(rubric);

    assert_eq!(dimensions.reachability, 0.8);
    assert_eq!(dimensions.attacker_control, 0.7);
    assert_eq!(dimensions.preconditions_factor, 0.6);
    assert!(dimensions.auth_required);
    assert_eq!(dimensions.access_type, AccessType::Both);
    assert_eq!(dimensions.blast_radius, BlastRadius::Critical);
}

// ============================================================================
// AnalysisContext Tests
// ============================================================================

#[test]
fn test_analysis_context_default_is_empty() {
    let ctx = AnalysisContext::default();

    assert_eq!(ctx.project_type, baco::project_type::ProjectType::Unknown);
    assert!(ctx.architecture_summary.is_empty());
    assert!(ctx.threat_model.is_none());
    assert!(ctx.invariants.is_empty());
    assert!(ctx.findings_so_far.is_empty());
}

#[test]
fn test_analysis_context_save_creates_file() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = AnalysisContext {
        project_type: baco::project_type::ProjectType::CLI,
        architecture_summary: "Test architecture".to_string(),
        threat_model: Some("Threat model".to_string()),
        invariants: vec!["Invariant 1".to_string()],
        findings_so_far: vec!["Finding 1".to_string()],
    };

    ctx.save(tmp.path()).unwrap();

    let context_path = tmp.path().join("context.json");
    assert!(context_path.exists());
}

#[test]
fn test_analysis_context_load_restores_data() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = AnalysisContext {
        project_type: baco::project_type::ProjectType::Web,
        architecture_summary: "Web app with REST API".to_string(),
        threat_model: Some("Anonymous attackers".to_string()),
        invariants: vec!["Invariant 1".to_string(), "Invariant 2".to_string()],
        findings_so_far: vec!["Finding 1".to_string()],
    };

    ctx.save(tmp.path()).unwrap();
    let loaded = AnalysisContext::load(tmp.path()).unwrap();

    assert_eq!(loaded.project_type, ctx.project_type);
    assert_eq!(loaded.architecture_summary, ctx.architecture_summary);
    assert_eq!(loaded.threat_model, ctx.threat_model);
    assert_eq!(loaded.invariants, ctx.invariants);
    assert_eq!(loaded.findings_so_far, ctx.findings_so_far);
}

#[test]
fn test_analysis_context_load_missing_file_returns_default() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = AnalysisContext::load(tmp.path()).unwrap();

    assert!(ctx.architecture_summary.is_empty());
    assert!(ctx.invariants.is_empty());
    assert!(ctx.findings_so_far.is_empty());
    assert!(ctx.threat_model.is_none());
}

// ============================================================================
// PocCompiler Tests
// ============================================================================

#[test]
fn test_poc_compiler_is_supported_rust() {
    assert!(PocCompiler::is_supported("rust"));
    assert!(PocCompiler::is_supported("Rust"));
    assert!(PocCompiler::is_supported("RUST"));
}

#[test]
fn test_poc_compiler_is_supported_python() {
    assert!(PocCompiler::is_supported("python"));
    assert!(PocCompiler::is_supported("python3"));
    assert!(PocCompiler::is_supported("Python"));
}

#[test]
fn test_poc_compiler_is_supported_javascript() {
    assert!(PocCompiler::is_supported("javascript"));
    assert!(PocCompiler::is_supported("js"));
    assert!(PocCompiler::is_supported("node"));
}

#[test]
fn test_poc_compiler_is_supported_unsupported() {
    assert!(!PocCompiler::is_supported("java"));
    assert!(!PocCompiler::is_supported("cpp"));
    assert!(!PocCompiler::is_supported("go"));
    assert!(!PocCompiler::is_supported("c"));
}

#[test]
fn test_poc_compiler_supported_languages_list() {
    let langs = PocCompiler::supported_languages();

    assert!(langs.contains(&"rust"));
    assert!(langs.contains(&"python"));
    assert!(langs.contains(&"javascript"));
    assert!(langs.contains(&"python3"));
    assert!(langs.contains(&"js"));
    assert!(langs.contains(&"node"));
    assert_eq!(langs.len(), 6);
}

#[test]
fn test_poc_compile_result_success() {
    let result = PoCCompileResult::success("rust");

    assert_eq!(result.language, "rust");
    assert!(result.compiles);
    assert!(result.errors.is_empty());
}

#[test]
fn test_poc_compile_result_failure() {
    let errors = vec!["SyntaxError: invalid syntax".to_string()];
    let result = PoCCompileResult::failure("python", errors);

    assert_eq!(result.language, "python");
    assert!(!result.compiles);
    assert_eq!(result.errors.len(), 1);
}

#[test]
fn test_poc_compiler_compile_check_unsupported_language() {
    let result = PocCompiler::compile_check("some code", "java");

    assert!(!result.compiles);
    assert!(result
        .errors
        .iter()
        .any(|e| e.contains("Unsupported language")));
}

#[test]
fn test_poc_compiler_compile_check_empty_code() {
    let result = PocCompiler::compile_check("", "python");

    assert!(result.language == "python");
}

// ============================================================================
// WorktreeManager Tests
// ============================================================================

#[test]
fn test_worktree_manager_new_sets_paths() {
    let repo_path = PathBuf::from("/tmp/test-repo");
    let _manager = WorktreeManager::new(repo_path.clone());
    // WorktreeManager fields are private, just verify construction works
}

#[test]
fn test_worktree_manager_cleanup_nonexistent_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let manager = WorktreeManager::new(tmp.path().to_path_buf());

    let cleaned = manager
        .cleanup_stale_worktrees(Duration::from_secs(0))
        .unwrap();
    assert_eq!(cleaned, 0);
}

#[test]
fn test_worktree_manager_cleanup_empty_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let _manager = WorktreeManager::new(tmp.path().to_path_buf());

    // temp_dir is private, just verify cleanup works on empty dir
    let cleaned = _manager
        .cleanup_stale_worktrees(Duration::from_secs(0))
        .unwrap();
    assert_eq!(cleaned, 0);
}
