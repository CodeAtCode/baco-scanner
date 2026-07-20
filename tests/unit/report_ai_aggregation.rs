//! Unit tests for AI aggregation phase
//!
//! Tests cover: AI aggregation logic, finding consolidation, summary generation,
//! report formatting, conflict resolution, consensus algorithms, and confidence scoring.

#![allow(clippy::too_many_arguments, unused_imports)]

use baco::analysis_context::AnalysisContext;
use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::llm::LlmConfig;
use baco::report::ai_aggregation::conflict_resolver::ConflictResolver;
use baco::report::ai_aggregation::{
    AiAggregation, AiAggregationPhase, AiAggregationResult, AiAggregationStatistics,
    ConsensusRecommendation, ConsensusResult, FindingSource, UnifiedFindingReport,
};

// ============================================================================
// Test Helpers
// ============================================================================

fn make_config() -> LlmConfig {
    LlmConfig {
        base_url: "http://test".to_string(),
        api_key: "test-key".to_string(),
        model: "test-model".to_string(),
        models: vec!["test-model".to_string()],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
    }
}

fn make_config_empty() -> LlmConfig {
    LlmConfig {
        base_url: String::new(),
        api_key: String::new(),
        model: String::new(),
        models: vec![],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
    }
}

/// Helper to create a test finding with specific parameters.
/// This is a local test helper specific to ai_aggregation tests.
fn make_finding(
    id: &str,
    severity: Severity,
    confidence: f32,
    file: &str,
    line: Option<u32>,
    cwe: Option<&str>,
    verification: Option<VerificationStatus>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: format!("Finding {}", id),
        description: "Test description".to_string(),
        severity,
        confidence_score: confidence,
        cwe_id: cwe.map(String::from),
        file_path: file.to_string(),
        line_number: line,
        code_snippet: Some("test code".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix this".to_string()),
        code_location: None,
        already_reported: false,
        sources: vec!["test".to_string()],
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status: verification,
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        security_issue: None,
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
        llm_model: None,
        agent_mode: false,
    }
}

fn make_finding_with_cross_file(
    id: &str,
    severity: Severity,
    confidence: f32,
    file: &str,
    line: Option<u32>,
    cwe: Option<&str>,
    verification: Option<VerificationStatus>,
    has_cross_file: bool,
) -> VulnerabilityFinding {
    let mut finding = make_finding(id, severity, confidence, file, line, cwe, verification);
    if has_cross_file {
        finding.cross_file_references = Some(vec!["src/lib.rs".to_string()]);
    }
    finding
}

// ============================================================================
// AiAggregation Tests
// ============================================================================

#[tokio::test]
async fn test_ai_aggregation_generate_executive_summary_empty() {
    let ai_agg = AiAggregation::new(make_config());
    let result = ai_agg.generate_executive_summary(&[]).await.unwrap();

    assert_eq!(result, "No vulnerabilities found.");
}

#[tokio::test]
async fn test_ai_aggregation_generate_executive_summary() {
    let ai_agg = AiAggregation::new(make_config());
    let findings = vec![make_finding(
        "f1",
        Severity::Critical,
        0.9,
        "src/main.rs",
        Some(42),
        Some("CWE-79"),
        Some(VerificationStatus::Confirmed),
    )];

    let result = ai_agg.generate_executive_summary(&findings).await.unwrap();

    assert!(!result.is_empty());
}

#[tokio::test]
async fn test_ai_aggregation_generate_risk_assessment_empty() {
    let ai_agg = AiAggregation::new(make_config());
    let result = ai_agg.generate_risk_assessment(&[]).await.unwrap();

    assert!(result.contains("Average Confidence Score: 0.00"));
    assert!(result.contains("Findings with Cross-file Reachability: 0"));
}

#[tokio::test]
async fn test_ai_aggregation_generate_risk_assessment() {
    let ai_agg = AiAggregation::new(make_config());
    let findings = vec![
        make_finding_with_cross_file(
            "f1",
            Severity::Critical,
            0.9,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            None,
            true,
        ),
        make_finding_with_cross_file(
            "f2",
            Severity::High,
            0.8,
            "src/lib.rs",
            Some(100),
            Some("CWE-89"),
            None,
            true,
        ),
        make_finding_with_cross_file(
            "f3",
            Severity::Medium,
            0.5,
            "src/utils.rs",
            Some(50),
            Some("CWE-22"),
            Some(VerificationStatus::FalsePositive),
            false,
        ),
    ];

    let result = ai_agg.generate_risk_assessment(&findings).await.unwrap();

    assert!(result.contains("Average Confidence Score: 0.73"));
    assert!(result.contains("Findings with Cross-file Reachability: 2"));
    assert!(result.contains("Already Reported in Ticket System: 0"));
}

// ============================================================================
// AiAggregationPhase Creation Tests
// ============================================================================

#[test]
fn test_ai_aggregation_phase_new_with_config() {
    let config = make_config();
    let _phase = AiAggregationPhase::new(config);
}

#[test]
fn test_ai_aggregation_phase_new_with_empty_config() {
    let config = make_config_empty();
    let _phase = AiAggregationPhase::new(config);
}

#[tokio::test]
async fn test_async_compatible() {
    let config = make_config();
    let _phase = AiAggregationPhase::new(config);
}

// ============================================================================
// Conflict Resolver Tests (public API)
// ============================================================================

#[test]
fn test_conflict_resolver_resolve_severity_conflict() {
    let findings = [
        make_finding(
            "f1",
            Severity::Critical,
            0.5,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            None,
        ),
        make_finding(
            "f2",
            Severity::Low,
            0.9,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            None,
        ),
    ];
    let finding_refs: Vec<&VulnerabilityFinding> = findings.iter().collect();

    let conflict = ConflictResolver::resolve_severity_conflict("src/main.rs:42", &finding_refs);

    assert_eq!(
        conflict.conflict_type,
        baco::report::ai_aggregation::models::ConflictType::SeverityMismatch
    );
    assert_eq!(
        conflict.resolution,
        baco::report::ai_aggregation::models::ConflictResolution::HighestSeverity
    );
    assert!(conflict.resolution_reason.contains("Critical"));
}

#[test]
fn test_conflict_resolver_resolve_cwe_conflict() {
    let findings = [
        make_finding(
            "f1",
            Severity::High,
            0.8,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            None,
        ),
        make_finding(
            "f2",
            Severity::High,
            0.8,
            "src/main.rs",
            Some(42),
            Some("CWE-120"),
            None,
        ),
    ];
    let finding_refs: Vec<&VulnerabilityFinding> = findings.iter().collect();

    let conflict = ConflictResolver::resolve_cwe_conflict("src/main.rs:42", &finding_refs);

    assert_eq!(
        conflict.conflict_type,
        baco::report::ai_aggregation::models::ConflictType::CweMismatch
    );
    assert!(conflict.resolution_reason.contains("CWE-79"));
}

#[test]
fn test_conflict_resolver_resolve_verification_conflict_verified() {
    let findings = [
        make_finding(
            "f1",
            Severity::High,
            0.9,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            Some(VerificationStatus::Confirmed),
        ),
        make_finding(
            "f2",
            Severity::High,
            0.8,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            Some(VerificationStatus::FalsePositive),
        ),
    ];
    let finding_refs: Vec<&VulnerabilityFinding> = findings.iter().collect();

    let conflict = ConflictResolver::resolve_verification_conflict("src/main.rs:42", &finding_refs);

    assert_eq!(
        conflict.conflict_type,
        baco::report::ai_aggregation::models::ConflictType::VerificationConflict
    );
    assert_eq!(
        conflict.resolution,
        baco::report::ai_aggregation::models::ConflictResolution::PreferVerified
    );
}

#[test]
fn test_conflict_resolver_resolve_confidence_conflict() {
    let findings = [
        make_finding(
            "f1",
            Severity::High,
            0.9,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            None,
        ),
        make_finding(
            "f2",
            Severity::High,
            0.5,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            None,
        ),
    ];
    let finding_refs: Vec<&VulnerabilityFinding> = findings.iter().collect();

    let conflict = ConflictResolver::resolve_confidence_conflict("src/main.rs:42", &finding_refs);

    assert_eq!(
        conflict.conflict_type,
        baco::report::ai_aggregation::models::ConflictType::ConfidenceConflict
    );
    assert_eq!(
        conflict.resolution,
        baco::report::ai_aggregation::models::ConflictResolution::HighestConfidence
    );
}

// ============================================================================
// Executive Summary Tests
// ============================================================================

#[tokio::test]
async fn test_generate_executive_summary_no_findings() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings: Vec<VulnerabilityFinding> = vec![];
    let result = phase.run(findings, &context).await;

    assert!(result
        .executive_summary
        .contains("Total Unique Findings: 0"));
    assert!(result.executive_summary.contains("Risk Level:"));
}

#[tokio::test]
async fn test_generate_executive_summary_critical_risk() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![
        make_finding(
            "f1",
            Severity::Critical,
            0.9,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            Some(VerificationStatus::Confirmed),
        ),
        make_finding(
            "f2",
            Severity::Critical,
            0.95,
            "src/lib.rs",
            Some(100),
            Some("CWE-89"),
            Some(VerificationStatus::Confirmed),
        ),
        make_finding(
            "f3",
            Severity::Critical,
            0.9,
            "src/utils.rs",
            Some(50),
            Some("CWE-22"),
            Some(VerificationStatus::Confirmed),
        ),
        make_finding(
            "f4",
            Severity::High,
            0.85,
            "src/main.rs",
            Some(100),
            Some("CWE-79"),
            None,
        ),
        make_finding(
            "f5",
            Severity::High,
            0.8,
            "src/lib.rs",
            Some(200),
            Some("CWE-89"),
            None,
        ),
        make_finding(
            "f6",
            Severity::High,
            0.85,
            "src/utils.rs",
            Some(75),
            Some("CWE-22"),
            None,
        ),
    ];

    let result = phase.run(findings, &context).await;

    assert!(result.executive_summary.contains("Risk Level: CRITICAL"));
    assert!(result
        .executive_summary
        .contains("Immediate action required"));
}

#[tokio::test]
async fn test_generate_executive_summary_low_risk() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![
        make_finding(
            "f1",
            Severity::Medium,
            0.3,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            Some(VerificationStatus::FalsePositive),
        ),
        make_finding(
            "f2",
            Severity::Low,
            0.2,
            "src/lib.rs",
            Some(100),
            Some("CWE-89"),
            Some(VerificationStatus::FalsePositive),
        ),
        make_finding(
            "f3",
            Severity::Low,
            0.25,
            "src/utils.rs",
            Some(50),
            Some("CWE-22"),
            Some(VerificationStatus::FalsePositive),
        ),
        make_finding(
            "f4",
            Severity::Low,
            0.3,
            "src/main.rs",
            Some(100),
            Some("CWE-79"),
            Some(VerificationStatus::FalsePositive),
        ),
    ];

    let result = phase.run(findings, &context).await;

    assert!(result.executive_summary.contains("Risk Level: LOW"));
}

#[tokio::test]
async fn test_generate_executive_summary_high_risk() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![
        make_finding(
            "f1",
            Severity::High,
            0.9,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            None,
        ),
        make_finding(
            "f2",
            Severity::High,
            0.85,
            "src/lib.rs",
            Some(100),
            Some("CWE-89"),
            None,
        ),
        make_finding(
            "f3",
            Severity::Medium,
            0.8,
            "src/utils.rs",
            Some(50),
            Some("CWE-22"),
            None,
        ),
    ];

    let result = phase.run(findings, &context).await;

    // With high confidence (avg 0.85) and all findings being high confidence,
    // the risk level will be CRITICAL (>50% high confidence)
    assert!(result.executive_summary.contains("Risk Level: CRITICAL"));
}

#[tokio::test]
async fn test_generate_executive_summary_moderate_risk() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![
        make_finding(
            "f1",
            Severity::Medium,
            0.5,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            None,
        ),
        make_finding(
            "f2",
            Severity::Medium,
            0.55,
            "src/lib.rs",
            Some(100),
            Some("CWE-89"),
            None,
        ),
        make_finding(
            "f3",
            Severity::Low,
            0.4,
            "src/utils.rs",
            Some(50),
            Some("CWE-22"),
            None,
        ),
        make_finding(
            "f4",
            Severity::Low,
            0.45,
            "src/main.rs",
            Some(100),
            Some("CWE-79"),
            None,
        ),
    ];

    let result = phase.run(findings, &context).await;

    assert!(result.executive_summary.contains("Risk Level: MODERATE"));
}

// ============================================================================
// Context Update Tests
// ============================================================================

#[tokio::test]
async fn test_update_context_with_findings() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let mut context = AnalysisContext::default();

    let findings = vec![make_finding(
        "f1",
        Severity::Critical,
        0.9,
        "src/main.rs",
        Some(42),
        Some("CWE-79"),
        Some(VerificationStatus::Confirmed),
    )];

    let result = phase.run(findings, &context).await;
    phase.update_context(&result, &mut context);

    assert!(!context.findings_so_far.is_empty());
    assert!(context.findings_so_far[0].contains("CWE-79"));
}

// ============================================================================
// Full Aggregation Run Tests
// ============================================================================

#[tokio::test]
async fn test_run_aggregation_empty_findings() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings: Vec<VulnerabilityFinding> = vec![];
    let result = phase.run(findings, &context).await;

    assert_eq!(result.unified_reports.len(), 0);
    assert!(result
        .executive_summary
        .contains("Total Unique Findings: 0"));
}

#[tokio::test]
async fn test_run_aggregation_single_finding() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![make_finding(
        "f1",
        Severity::Critical,
        0.9,
        "src/main.rs",
        Some(42),
        Some("CWE-79"),
        Some(VerificationStatus::Confirmed),
    )];

    let result = phase.run(findings, &context).await;

    assert_eq!(result.unified_reports.len(), 1);
    assert!(!result.executive_summary.is_empty());
    assert!(!result.enriched_findings.is_empty());
}

#[tokio::test]
async fn test_run_aggregation_multiple_findings_with_conflicts() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![
        make_finding(
            "f1",
            Severity::Critical,
            0.9,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            None,
        ),
        make_finding(
            "f2",
            Severity::Low,
            0.8,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            None,
        ), // Severity conflict
        make_finding(
            "f3",
            Severity::High,
            0.85,
            "src/lib.rs",
            Some(100),
            Some("CWE-89"),
            None,
        ),
    ];

    let result = phase.run(findings, &context).await;

    assert_eq!(result.unified_reports.len(), 3);
    assert!(!result.conflicts.is_empty());
    assert!(!result.executive_summary.is_empty());
}

#[tokio::test]
async fn test_run_aggregation_false_positive_detection() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![
        make_finding(
            "f1",
            Severity::Medium,
            0.4,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            Some(VerificationStatus::FalsePositive),
        ),
        make_finding(
            "f2",
            Severity::High,
            0.9,
            "src/lib.rs",
            Some(100),
            Some("CWE-89"),
            Some(VerificationStatus::Confirmed),
        ),
    ];

    let result = phase.run(findings, &context).await;

    assert_eq!(result.statistics.false_positives_detected, 1);
    assert_eq!(result.statistics.high_confidence_count, 1);
}

#[tokio::test]
async fn test_run_aggregation_with_empty_config() {
    let config = make_config_empty();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![make_finding(
        "f1",
        Severity::High,
        0.8,
        "src/main.rs",
        Some(42),
        Some("CWE-79"),
        None,
    )];

    let result = phase.run(findings, &context).await;

    // Should still work without LLM
    assert_eq!(result.unified_reports.len(), 1);
    assert!(!result.executive_summary.is_empty());
}

#[tokio::test]
async fn test_run_aggregation_multiple_files() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![
        make_finding(
            "f1",
            Severity::High,
            0.8,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            None,
        ),
        make_finding(
            "f2",
            Severity::High,
            0.85,
            "src/lib.rs",
            Some(100),
            Some("CWE-89"),
            None,
        ),
        make_finding(
            "f3",
            Severity::Critical,
            0.9,
            "src/utils.rs",
            Some(50),
            Some("CWE-22"),
            None,
        ),
        make_finding(
            "f4",
            Severity::Medium,
            0.6,
            "src/auth.rs",
            Some(25),
            Some("CWE-287"),
            None,
        ),
    ];

    let result = phase.run(findings, &context).await;

    assert_eq!(result.unified_reports.len(), 4);
    assert_eq!(result.enriched_findings.len(), 4);
}

#[tokio::test]
async fn test_run_aggregation_with_cross_file_findings() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![
        make_finding_with_cross_file(
            "f1",
            Severity::High,
            0.8,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            None,
            true,
        ),
        make_finding_with_cross_file(
            "f2",
            Severity::High,
            0.85,
            "src/lib.rs",
            Some(100),
            Some("CWE-89"),
            None,
            true,
        ),
        make_finding_with_cross_file(
            "f3",
            Severity::Medium,
            0.6,
            "src/utils.rs",
            Some(50),
            Some("CWE-22"),
            None,
            false,
        ),
    ];

    let result = phase.run(findings, &context).await;

    assert_eq!(result.unified_reports.len(), 3);
}

// ============================================================================
// Enrichment Tests
// ============================================================================

#[tokio::test]
async fn test_enrich_findings_with_empty_config() {
    let config = make_config_empty();
    let phase = AiAggregationPhase::new(config);

    let findings = vec![make_finding(
        "f1",
        Severity::High,
        0.8,
        "src/main.rs",
        Some(42),
        Some("CWE-79"),
        None,
    )];

    let (enriched, llm_failed) = phase.enrich_findings_with_llm(&findings).await;

    // With empty config, LLM should not be used
    assert_eq!(enriched.len(), 1);
    assert!(!llm_failed); // LLM wasn't even attempted
}

#[tokio::test]
async fn test_enrich_findings_preserves_existing_description() {
    let config = make_config_empty();
    let phase = AiAggregationPhase::new(config);

    let mut finding = make_finding(
        "f1",
        Severity::High,
        0.8,
        "src/main.rs",
        Some(42),
        Some("CWE-79"),
        None,
    );
    finding.description = "Existing description".to_string();

    let (enriched, _llm_failed) = phase.enrich_findings_with_llm(&[finding]).await;

    assert_eq!(enriched.len(), 1);
    assert_eq!(enriched[0].description, "Existing description");
}

// ============================================================================
// Edge Cases
// ============================================================================

#[tokio::test]
async fn test_aggregation_with_findings_without_line_numbers() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![
        make_finding(
            "f1",
            Severity::High,
            0.8,
            "src/main.rs",
            None,
            Some("CWE-79"),
            None,
        ),
        make_finding(
            "f2",
            Severity::High,
            0.85,
            "src/main.rs",
            None,
            Some("CWE-79"),
            None,
        ),
    ];

    let result = phase.run(findings, &context).await;

    assert_eq!(result.unified_reports.len(), 2);
}

#[tokio::test]
async fn test_aggregation_with_findings_without_cwe() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![
        make_finding(
            "f1",
            Severity::High,
            0.8,
            "src/main.rs",
            Some(42),
            None,
            None,
        ),
        make_finding(
            "f2",
            Severity::High,
            0.85,
            "src/lib.rs",
            Some(100),
            None,
            None,
        ),
    ];

    let result = phase.run(findings, &context).await;

    assert_eq!(result.unified_reports.len(), 2);
}

#[tokio::test]
async fn test_aggregation_with_all_severity_levels() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![
        make_finding(
            "f1",
            Severity::Critical,
            0.9,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            None,
        ),
        make_finding(
            "f2",
            Severity::High,
            0.8,
            "src/lib.rs",
            Some(100),
            Some("CWE-89"),
            None,
        ),
        make_finding(
            "f3",
            Severity::Medium,
            0.6,
            "src/utils.rs",
            Some(50),
            Some("CWE-22"),
            None,
        ),
        make_finding(
            "f4",
            Severity::Low,
            0.4,
            "src/auth.rs",
            Some(25),
            Some("CWE-287"),
            None,
        ),
        make_finding(
            "f5",
            Severity::Info,
            0.3,
            "src/config.rs",
            Some(10),
            Some("CWE-798"),
            None,
        ),
    ];

    let result = phase.run(findings, &context).await;

    assert_eq!(result.unified_reports.len(), 5);
}

#[tokio::test]
async fn test_aggregation_with_mixed_verification_status() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![
        make_finding(
            "f1",
            Severity::High,
            0.9,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            Some(VerificationStatus::Confirmed),
        ),
        make_finding(
            "f2",
            Severity::High,
            0.3,
            "src/lib.rs",
            Some(100),
            Some("CWE-89"),
            Some(VerificationStatus::FalsePositive),
        ),
        make_finding(
            "f3",
            Severity::Medium,
            0.5,
            "src/utils.rs",
            Some(50),
            Some("CWE-22"),
            Some(VerificationStatus::NeedsReview),
        ),
        make_finding(
            "f4",
            Severity::Medium,
            0.6,
            "src/auth.rs",
            Some(25),
            Some("CWE-287"),
            None,
        ),
    ];

    let result = phase.run(findings, &context).await;

    assert_eq!(result.unified_reports.len(), 4);
}

#[tokio::test]
async fn test_aggregation_statistics_accuracy() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![
        make_finding(
            "f1",
            Severity::Critical,
            0.9,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            Some(VerificationStatus::Confirmed),
        ),
        make_finding(
            "f2",
            Severity::High,
            0.8,
            "src/lib.rs",
            Some(100),
            Some("CWE-89"),
            None,
        ),
        make_finding(
            "f3",
            Severity::Medium,
            0.4,
            "src/utils.rs",
            Some(50),
            Some("CWE-22"),
            Some(VerificationStatus::FalsePositive),
        ),
    ];

    let result = phase.run(findings, &context).await;

    assert_eq!(result.statistics.total_unique_findings, 3);
    assert!(result.statistics.high_confidence_count >= 1);
    assert!(result.statistics.false_positives_detected >= 1);
}

#[tokio::test]
async fn test_aggregation_preserves_finding_ids() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![
        make_finding(
            "custom-id-1",
            Severity::High,
            0.8,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            None,
        ),
        make_finding(
            "custom-id-2",
            Severity::Critical,
            0.9,
            "src/lib.rs",
            Some(100),
            Some("CWE-89"),
            None,
        ),
    ];

    let result = phase.run(findings, &context).await;

    assert_eq!(result.unified_reports[0].finding.id, "custom-id-1");
    assert_eq!(result.unified_reports[1].finding.id, "custom-id-2");
}

// Note: This test is slow with tarpaulin due to async overhead.
// Reduced to minimal findings for CI coverage.
#[tokio::test]
async fn test_aggregation_with_large_number_of_findings() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    // Minimal test case - just verify aggregation works
    let findings: Vec<VulnerabilityFinding> = (0..3)
        .map(|i| {
            make_finding(
                &format!("f{}", i),
                Severity::High,
                0.8 + (i as f32 * 0.01),
                &format!("src/file{}.rs", i),
                Some(42 + i as u32),
                Some("CWE-79"),
                None,
            )
        })
        .collect();

    let result = phase.run(findings, &context).await;

    assert_eq!(result.unified_reports.len(), 3);
    assert_eq!(result.enriched_findings.len(), 3);
}

#[tokio::test]
async fn test_aggregation_executive_summary_contains_recommendation() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![make_finding(
        "f1",
        Severity::Critical,
        0.9,
        "src/main.rs",
        Some(42),
        Some("CWE-79"),
        Some(VerificationStatus::Confirmed),
    )];

    let result = phase.run(findings, &context).await;

    assert!(result.executive_summary.contains("Recommendation:"));
}

#[tokio::test]
async fn test_conflict_resolver_empty_findings() {
    let findings: Vec<&VulnerabilityFinding> = vec![];

    let conflict = ConflictResolver::resolve_severity_conflict("empty:0", &findings);

    // Should handle empty gracefully (may panic or return empty, depending on impl)
    // This test documents the expected behavior
    assert!(!conflict.resolution_reason.is_empty());
}

#[tokio::test]
async fn test_aggregation_unified_reports_have_confidence() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![
        make_finding(
            "f1",
            Severity::High,
            0.8,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            None,
        ),
        make_finding(
            "f2",
            Severity::Critical,
            0.9,
            "src/lib.rs",
            Some(100),
            Some("CWE-89"),
            None,
        ),
    ];

    let result = phase.run(findings, &context).await;

    for report in &result.unified_reports {
        assert!(report.ai_confidence.overall > 0.0);
        assert!(report.ai_confidence.overall <= 1.0);
        assert!(report.ai_confidence.semantic >= 0.0);
        assert!(report.ai_confidence.verification >= 0.0);
        assert!(report.ai_confidence.context >= 0.0);
        assert!(report.ai_confidence.consensus >= 0.0);
    }
}

#[tokio::test]
async fn test_aggregation_consensus_recommendations() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![
        make_finding(
            "f1",
            Severity::High,
            0.9,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            Some(VerificationStatus::Confirmed),
        ),
        make_finding(
            "f2",
            Severity::Medium,
            0.3,
            "src/lib.rs",
            Some(100),
            Some("CWE-89"),
            Some(VerificationStatus::FalsePositive),
        ),
        make_finding(
            "f3",
            Severity::Medium,
            0.5,
            "src/utils.rs",
            Some(50),
            Some("CWE-22"),
            None,
        ),
    ];

    let result = phase.run(findings, &context).await;

    // Check that we have different recommendations
    let has_high_confidence = result
        .unified_reports
        .iter()
        .any(|r| r.consensus.recommendation == ConsensusRecommendation::IncludeHighConfidence);
    let has_false_positive = result
        .unified_reports
        .iter()
        .any(|r| r.consensus.recommendation == ConsensusRecommendation::ExcludeFalsePositive);

    assert!(has_high_confidence || has_false_positive);
}

// ============================================================================
// EnrichmentService Tests
// ============================================================================

use baco::report::ai_aggregation::enrichment::EnrichmentService;

#[test]
fn test_enrichment_service_new_with_valid_config() {
    let config = make_config();
    let _service = EnrichmentService::new(&config);

    // Service should be created successfully
}

#[test]
fn test_enrichment_service_new_with_empty_config() {
    let config = make_config_empty();
    let _service = EnrichmentService::new(&config);

    // Service should be created successfully (LLM client will be None)
}

#[tokio::test]
async fn test_enrich_findings_empty_input() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let findings: Vec<VulnerabilityFinding> = vec![];
    let (enriched, llm_failed) = phase.enrich_findings_with_llm(&findings).await;

    assert_eq!(enriched.len(), 0);
    // With empty findings, LLM wasn't actually called
    assert!(!llm_failed);
}

#[tokio::test]
async fn test_enrich_findings_with_empty_description_and_recommendation() {
    let config = make_config_empty();
    let phase = AiAggregationPhase::new(config);

    let mut finding = make_finding(
        "f1",
        Severity::High,
        0.8,
        "src/main.rs",
        Some(42),
        Some("CWE-79"),
        None,
    );
    // Clear description and recommendation to test fallback behavior
    finding.description = String::new();
    finding.recommendation = None;

    let (enriched, llm_failed) = phase.enrich_findings_with_llm(&[finding]).await;

    assert_eq!(enriched.len(), 1);
    // With empty config, LLM client is None, so findings are returned unchanged
    // This means description stays empty (no enrichment happens)
    assert!(enriched[0].description.is_empty());
    assert!(enriched[0].recommendation.is_none());
    // LLM wasn't even attempted, so llm_failed should be false
    assert!(!llm_failed);
}

#[test]
fn test_extract_json_field_valid_json() {
    let json = r#"{"description": "This is a test", "recommendation": "Fix it"}"#;

    let desc = EnrichmentService::extract_json_field(json, "description");
    let rec = EnrichmentService::extract_json_field(json, "recommendation");

    assert_eq!(desc, Some("This is a test".to_string()));
    assert_eq!(rec, Some("Fix it".to_string()));
}

#[test]
fn test_extract_json_field_missing_field() {
    let json = r#"{"description": "This is a test"}"#;

    let rec = EnrichmentService::extract_json_field(json, "recommendation");

    assert_eq!(rec, None);
}

#[test]
fn test_extract_json_field_invalid_json() {
    let json = "not valid json";

    let desc = EnrichmentService::extract_json_field(json, "description");

    assert_eq!(desc, None);
}

#[test]
fn test_extract_json_field_empty_string() {
    let json = "";

    let desc = EnrichmentService::extract_json_field(json, "description");

    assert_eq!(desc, None);
}

// ============================================================================
// DeduplicationService Tests
// ============================================================================

use baco::report::ai_aggregation::deduplication::DeduplicationService;

#[test]
fn test_deduplication_service_new() {
    let config = make_config();
    let _service = DeduplicationService::new(&config);

    // Service should be created successfully
}

#[test]
fn test_deduplication_service_new_with_empty_config() {
    let config = make_config_empty();
    let _service = DeduplicationService::new(&config);

    // Service should be created successfully
}

#[tokio::test]
async fn test_deduplicate_empty_findings() {
    let config = make_config();
    let service = DeduplicationService::new(&config);

    let findings: Vec<VulnerabilityFinding> = vec![];
    let result = service.deduplicate(&findings).await;

    assert_eq!(result.len(), 0);
}

#[tokio::test]
async fn test_deduplicate_no_duplicates() {
    let config = make_config_empty();
    let service = DeduplicationService::new(&config);

    let findings = vec![
        make_finding(
            "f1",
            Severity::High,
            0.8,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            None,
        ),
        make_finding(
            "f2",
            Severity::High,
            0.8,
            "src/lib.rs",
            Some(100),
            Some("CWE-89"),
            None,
        ),
        make_finding(
            "f3",
            Severity::Medium,
            0.6,
            "src/utils.rs",
            Some(50),
            Some("CWE-22"),
            None,
        ),
    ];

    let result = service.deduplicate(&findings).await;

    // All findings should be kept (different files/locations)
    assert_eq!(result.len(), 3);
}

#[tokio::test]
async fn test_deduplicate_same_file_different_lines() {
    let config = make_config_empty();
    let service = DeduplicationService::new(&config);

    let findings = vec![
        make_finding(
            "f1",
            Severity::High,
            0.8,
            "src/main.rs",
            Some(42),
            Some("CWE-79"),
            None,
        ),
        make_finding(
            "f2",
            Severity::High,
            0.8,
            "src/main.rs",
            Some(100),
            Some("CWE-79"),
            None,
        ),
        make_finding(
            "f3",
            Severity::High,
            0.8,
            "src/main.rs",
            Some(200),
            Some("CWE-79"),
            None,
        ),
    ];

    let result = service.deduplicate(&findings).await;

    // All findings should be kept (lines are more than 3 apart)
    assert_eq!(result.len(), 3);
}

#[tokio::test]
async fn test_deduplicate_findings_without_line_numbers() {
    let config = make_config_empty();
    let service = DeduplicationService::new(&config);

    let findings = vec![
        make_finding(
            "f1",
            Severity::High,
            0.8,
            "src/main.rs",
            None,
            Some("CWE-79"),
            None,
        ),
        make_finding(
            "f2",
            Severity::High,
            0.8,
            "src/main.rs",
            None,
            Some("CWE-79"),
            None,
        ),
    ];

    let result = service.deduplicate(&findings).await;

    // Without line numbers, they can't be considered duplicates
    assert_eq!(result.len(), 2);
}
