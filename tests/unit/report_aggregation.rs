//! Unit tests for ReportAggregationPhase
//!
//! Tests cover:
//! - Deduplication logic
//! - Statistics calculation
//! - Executive summary generation
//! - Finding prioritization
//! - Full aggregation workflow

use baco::analysis_context::AnalysisContext;
use baco::findings::{IssueCategory, SecurityIssue, Severity, VerificationStatus, VulnerabilityFinding};
use baco::report::aggregation::{
    AggregateStatistics, AggregationResult, ExecutiveSummary, PrioritizedFinding,
    ReportAggregationPhase,
};

use crate::fixtures::make_finding_report_agg;

/// Helper to create a test finding with custom parameters.
fn create_finding(
    id: &str,
    title: &str,
    file_path: &str,
    line_number: Option<u32>,
    cwe_id: Option<&str>,
    severity: Severity,
) -> VulnerabilityFinding {
    make_finding_report_agg(id, title, file_path, line_number, cwe_id, severity)
}

/// Helper to create a finding with a security issue category.
fn create_finding_with_category(
    id: &str,
    title: &str,
    file_path: &str,
    category: IssueCategory,
    severity: Severity,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test finding".to_string(),
        severity,
        confidence_score: 0.8,
        cwe_id: None,
        file_path: file_path.to_string(),
        line_number: Some(10),
        code_snippet: Some("test".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix it".to_string()),
        code_location: None,
        already_reported: false,
        sources: Vec::new(),
        commit_reference: None,
        ticket_reference: None,
        priority_score: None,
        cross_file_references: None,
        verification_status: Some(VerificationStatus::NeedsReview),
        verification_notes: None,
        verification_error: None,
        agent_evidence_path: None,
        agent_mode: false,
        llm_model: None,
        security_issue: Some(SecurityIssue {
            category,
            cwe_id: None,
            owasp_category: None,
            mitre_attack: None,
            custom_tags: Vec::new(),
        }),
        poc_code: None,
        mitigation_code: None,
        poc_format: None,
    }
}

// ============================================================================
// Deduplication Tests
// ============================================================================

#[test]
fn test_deduplicate_same_location_same_cwe() {
    let phase = ReportAggregationPhase::new();

    // Same file, line, and CWE - should deduplicate to 1
    let findings = vec![
        create_finding("f1", "Finding 1", "src/test.rs", Some(10), Some("CWE-79"), Severity::High),
        create_finding("f2", "Finding 2", "src/test.rs", Some(10), Some("CWE-79"), Severity::High),
        create_finding("f3", "Finding 3", "src/test.rs", Some(10), Some("CWE-79"), Severity::Critical),
    ];

    let unique = phase.deduplicate_findings(findings);
    assert_eq!(unique.len(), 1);
}

#[test]
fn test_deduplicate_different_locations() {
    let phase = ReportAggregationPhase::new();

    // Same CWE but different locations - should keep all
    let findings = vec![
        create_finding("f1", "Finding 1", "src/test.rs", Some(10), Some("CWE-79"), Severity::High),
        create_finding("f2", "Finding 2", "src/test.rs", Some(20), Some("CWE-79"), Severity::High),
        create_finding("f3", "Finding 3", "src/other.rs", Some(10), Some("CWE-79"), Severity::High),
    ];

    let unique = phase.deduplicate_findings(findings);
    assert_eq!(unique.len(), 3);
}

#[test]
fn test_deduplicate_different_cwe_same_location() {
    let phase = ReportAggregationPhase::new();

    // Same location but different CWE - should keep all
    let findings = vec![
        create_finding("f1", "Finding 1", "src/test.rs", Some(10), Some("CWE-79"), Severity::High),
        create_finding("f2", "Finding 2", "src/test.rs", Some(10), Some("CWE-89"), Severity::High),
        create_finding("f3", "Finding 3", "src/test.rs", Some(10), Some("CWE-200"), Severity::High),
    ];

    let unique = phase.deduplicate_findings(findings);
    assert_eq!(unique.len(), 3);
}

#[test]
fn test_deduplicate_empty_input() {
    let phase = ReportAggregationPhase::new();
    let findings: Vec<VulnerabilityFinding> = Vec::new();
    let unique = phase.deduplicate_findings(findings);
    assert_eq!(unique.len(), 0);
}

#[test]
fn test_deduplicate_preserves_first_occurrence() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "First Finding", "src/test.rs", Some(10), Some("CWE-79"), Severity::Low),
        create_finding("f2", "Second Finding", "src/test.rs", Some(10), Some("CWE-79"), Severity::Critical),
    ];

    let unique = phase.deduplicate_findings(findings);
    assert_eq!(unique.len(), 1);
    assert_eq!(unique[0].title, "First Finding");
    assert_eq!(unique[0].severity, Severity::Low);
}

// ============================================================================
// Statistics Calculation Tests
// ============================================================================

#[test]
fn test_calculate_statistics_empty_findings() {
    let phase = ReportAggregationPhase::new();
    let findings: Vec<VulnerabilityFinding> = Vec::new();
    let stats = phase.calculate_statistics(&findings);

    assert_eq!(stats.total_findings, 0);
    assert_eq!(stats.critical_count, 0);
    assert_eq!(stats.high_count, 0);
    assert_eq!(stats.medium_count, 0);
    assert_eq!(stats.low_count, 0);
    assert_eq!(stats.info_count, 0);
    assert_eq!(stats.average_confidence, 0.0);
    assert_eq!(stats.unique_files_affected, 0);
}

#[test]
fn test_calculate_statistics_severity_counts() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Critical", "src/a.rs", Some(1), None, Severity::Critical),
        create_finding("f2", "High", "src/b.rs", Some(2), None, Severity::High),
        create_finding("f3", "Medium", "src/c.rs", Some(3), None, Severity::Medium),
        create_finding("f4", "Low", "src/d.rs", Some(4), None, Severity::Low),
        create_finding("f5", "Info", "src/e.rs", Some(5), None, Severity::Info),
    ];

    let stats = phase.calculate_statistics(&findings);

    assert_eq!(stats.total_findings, 5);
    assert_eq!(stats.critical_count, 1);
    assert_eq!(stats.high_count, 1);
    assert_eq!(stats.medium_count, 1);
    assert_eq!(stats.low_count, 1);
    assert_eq!(stats.info_count, 1);
}

#[test]
fn test_calculate_statistics_verification_status() {
    let phase = ReportAggregationPhase::new();

    let mut finding1 = create_finding("f1", "Confirmed", "src/a.rs", Some(1), None, Severity::High);
    finding1.verification_status = Some(VerificationStatus::Confirmed);

    let mut finding2 = create_finding("f2", "False Positive", "src/b.rs", Some(2), None, Severity::High);
    finding2.verification_status = Some(VerificationStatus::FalsePositive);

    let mut finding3 = create_finding("f3", "Needs Review", "src/c.rs", Some(3), None, Severity::High);
    finding3.verification_status = Some(VerificationStatus::NeedsReview);

    let findings = vec![finding1, finding2, finding3];
    let stats = phase.calculate_statistics(&findings);

    assert_eq!(stats.verified_count, 1);
    assert_eq!(stats.false_positive_count, 1);
    assert_eq!(stats.needs_review_count, 1);
}

#[test]
fn test_calculate_statistics_average_confidence() {
    let phase = ReportAggregationPhase::new();

    let mut finding1 = create_finding("f1", "Finding 1", "src/a.rs", Some(1), None, Severity::High);
    finding1.confidence_score = 1.0;

    let mut finding2 = create_finding("f2", "Finding 2", "src/b.rs", Some(2), None, Severity::High);
    finding2.confidence_score = 0.5;

    let findings = vec![finding1, finding2];
    let stats = phase.calculate_statistics(&findings);

    assert!((stats.average_confidence - 0.75).abs() < 0.001);
}

#[test]
fn test_calculate_statistics_unique_files() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Finding 1", "src/a.rs", Some(1), None, Severity::High),
        create_finding("f2", "Finding 2", "src/b.rs", Some(2), None, Severity::High),
        create_finding("f3", "Finding 3", "src/a.rs", Some(3), None, Severity::High), // Same file as f1
        create_finding("f4", "Finding 4", "src/c.rs", Some(4), None, Severity::High),
    ];

    let stats = phase.calculate_statistics(&findings);
    assert_eq!(stats.unique_files_affected, 3);
}

#[test]
fn test_calculate_statistics_cross_file_findings() {
    let phase = ReportAggregationPhase::new();

    let mut finding1 = create_finding("f1", "Finding 1", "src/a.rs", Some(1), None, Severity::High);
    finding1.cross_file_references = Some(vec!["src/b.rs".to_string()]);

    let finding2 = create_finding("f2", "Finding 2", "src/b.rs", Some(2), None, Severity::High);

    let findings = vec![finding1, finding2];
    let stats = phase.calculate_statistics(&findings);

    assert_eq!(stats.cross_file_findings, 1);
}

#[test]
fn test_calculate_statistics_categories() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding_with_category("f1", "Injection 1", "src/a.rs", IssueCategory::Injection, Severity::High),
        create_finding_with_category("f2", "Injection 2", "src/b.rs", IssueCategory::Injection, Severity::High),
        create_finding_with_category("f3", "Memory 1", "src/c.rs", IssueCategory::MemoryCorruption, Severity::Critical),
    ];

    let stats = phase.calculate_statistics(&findings);

    assert_eq!(stats.findings_by_category.get("injection"), Some(&2));
    assert_eq!(stats.findings_by_category.get("memory_corruption"), Some(&1));
}

// ============================================================================
// Executive Summary Tests
// ============================================================================

#[test]
fn test_executive_summary_risk_level_critical() {
    let phase = ReportAggregationPhase::new();
    let stats = AggregateStatistics {
        critical_count: 1,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        total_findings: 1,
        average_confidence: 0.8,
        verified_count: 0,
        false_positive_count: 0,
        needs_review_count: 1,
        unique_files_affected: 1,
        cross_file_findings: 0,
        findings_by_category: std::collections::HashMap::new(),
    };

    let summary = phase.generate_executive_summary(&stats, &[], &AnalysisContext::default());
    assert_eq!(summary.risk_level, "CRITICAL");
}

#[test]
fn test_executive_summary_risk_level_high() {
    let phase = ReportAggregationPhase::new();
    let stats = AggregateStatistics {
        critical_count: 0,
        high_count: 2,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        total_findings: 2,
        average_confidence: 0.8,
        verified_count: 0,
        false_positive_count: 0,
        needs_review_count: 2,
        unique_files_affected: 1,
        cross_file_findings: 0,
        findings_by_category: std::collections::HashMap::new(),
    };

    let summary = phase.generate_executive_summary(&stats, &[], &AnalysisContext::default());
    assert_eq!(summary.risk_level, "HIGH");
}

#[test]
fn test_executive_summary_risk_level_moderate() {
    let phase = ReportAggregationPhase::new();
    let stats = AggregateStatistics {
        critical_count: 0,
        high_count: 0,
        medium_count: 3,
        low_count: 0,
        info_count: 0,
        total_findings: 3,
        average_confidence: 0.8,
        verified_count: 0,
        false_positive_count: 0,
        needs_review_count: 3,
        unique_files_affected: 1,
        cross_file_findings: 0,
        findings_by_category: std::collections::HashMap::new(),
    };

    let summary = phase.generate_executive_summary(&stats, &[], &AnalysisContext::default());
    assert_eq!(summary.risk_level, "MODERATE");
}

#[test]
fn test_executive_summary_risk_level_low() {
    let phase = ReportAggregationPhase::new();
    let stats = AggregateStatistics {
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 2,
        info_count: 0,
        total_findings: 2,
        average_confidence: 0.8,
        verified_count: 0,
        false_positive_count: 0,
        needs_review_count: 2,
        unique_files_affected: 1,
        cross_file_findings: 0,
        findings_by_category: std::collections::HashMap::new(),
    };

    let summary = phase.generate_executive_summary(&stats, &[], &AnalysisContext::default());
    assert_eq!(summary.risk_level, "LOW");
}

#[test]
fn test_executive_summary_risk_level_minimal() {
    let phase = ReportAggregationPhase::new();
    let stats = AggregateStatistics {
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        info_count: 1,
        total_findings: 1,
        average_confidence: 0.8,
        verified_count: 0,
        false_positive_count: 0,
        needs_review_count: 1,
        unique_files_affected: 1,
        cross_file_findings: 0,
        findings_by_category: std::collections::HashMap::new(),
    };

    let summary = phase.generate_executive_summary(&stats, &[], &AnalysisContext::default());
    assert_eq!(summary.risk_level, "MINIMAL");
}

#[test]
fn test_executive_summary_recommendations_for_critical() {
    let phase = ReportAggregationPhase::new();
    let stats = AggregateStatistics {
        critical_count: 3,
        ..Default::default()
    };

    let summary = phase.generate_executive_summary(&stats, &[], &AnalysisContext::default());

    assert!(summary.recommendations.iter().any(|r| r.contains("URGENT")));
    assert!(summary.recommendations.iter().any(|r| r.contains("3")));
}

#[test]
fn test_executive_summary_recommendations_for_cross_file() {
    let phase = ReportAggregationPhase::new();
    let stats = AggregateStatistics {
        cross_file_findings: 5,
        ..Default::default()
    };

    let summary = phase.generate_executive_summary(&stats, &[], &AnalysisContext::default());

    assert!(summary.recommendations.iter().any(|r| r.contains("cross-file")));
}

#[test]
fn test_executive_summary_priority_files() {
    let phase = ReportAggregationPhase::new();
    let stats = AggregateStatistics::default();

    let findings = vec![
        create_finding("f1", "Critical", "src/critical.rs", Some(1), None, Severity::Critical),
        create_finding("f2", "High", "src/high.rs", Some(2), None, Severity::High),
        create_finding("f3", "Low", "src/low.rs", Some(3), None, Severity::Low),
    ];

    let summary = phase.generate_executive_summary(&stats, &findings, &AnalysisContext::default());

    // Priority files should include the files with critical/high findings
    assert!(!summary.priority_files.is_empty());
    assert!(summary.priority_files.iter().any(|f| f.contains("critical.rs")));
}

// ============================================================================
// Prioritization Tests
// ============================================================================

#[test]
fn test_prioritize_findings_severity_order() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Low", "src/a.rs", Some(1), None, Severity::Low),
        create_finding("f2", "Critical", "src/b.rs", Some(2), None, Severity::Critical),
        create_finding("f3", "Medium", "src/c.rs", Some(3), None, Severity::Medium),
        create_finding("f4", "High", "src/d.rs", Some(4), None, Severity::High),
        create_finding("f5", "Info", "src/e.rs", Some(5), None, Severity::Info),
    ];

    let prioritized = phase.prioritize_findings(&findings);

    assert_eq!(prioritized[0].finding.severity, Severity::Critical);
    assert_eq!(prioritized[1].finding.severity, Severity::High);
    assert_eq!(prioritized[2].finding.severity, Severity::Medium);
    assert_eq!(prioritized[3].finding.severity, Severity::Low);
    assert_eq!(prioritized[4].finding.severity, Severity::Info);
}

#[test]
fn test_prioritize_findings_ranks_are_sequential() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Finding 1", "src/a.rs", Some(1), None, Severity::High),
        create_finding("f2", "Finding 2", "src/b.rs", Some(2), None, Severity::Critical),
        create_finding("f3", "Finding 3", "src/c.rs", Some(3), None, Severity::Medium),
    ];

    let prioritized = phase.prioritize_findings(&findings);

    assert_eq!(prioritized[0].rank, 1);
    assert_eq!(prioritized[1].rank, 2);
    assert_eq!(prioritized[2].rank, 3);
}

#[test]
fn test_prioritize_findings_cross_file_boost() {
    let phase = ReportAggregationPhase::new();

    let mut finding1 = create_finding("f1", "With Cross-File", "src/a.rs", Some(1), None, Severity::High);
    finding1.cross_file_references = Some(vec!["src/b.rs".to_string()]);

    let finding2 = create_finding("f2", "Without Cross-File", "src/c.rs", Some(2), None, Severity::High);

    let findings = vec![finding1, finding2];
    let prioritized = phase.prioritize_findings(&findings);

    // Both are High severity, but finding1 should have higher score due to cross-file boost
    assert!(prioritized[0].priority_score > prioritized[1].priority_score);
}

#[test]
fn test_prioritize_findings_already_reported_reduction() {
    let phase = ReportAggregationPhase::new();

    let mut finding1 = create_finding("f1", "Known Issue", "src/a.rs", Some(1), None, Severity::High);
    finding1.already_reported = true;

    let finding2 = create_finding("f2", "New Issue", "src/b.rs", Some(2), None, Severity::High);

    let findings = vec![finding1, finding2];
    let prioritized = phase.prioritize_findings(&findings);

    // finding2 should have higher score because finding1 is already reported
    assert!(prioritized[0].finding.title == "New Issue");
}

#[test]
fn test_prioritize_findings_empty_input() {
    let phase = ReportAggregationPhase::new();
    let findings: Vec<VulnerabilityFinding> = Vec::new();
    let prioritized = phase.prioritize_findings(&findings);
    assert_eq!(prioritized.len(), 0);
}

#[test]
fn test_prioritize_findings_priority_scores_in_range() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Finding 1", "src/a.rs", Some(1), None, Severity::Critical),
        create_finding("f2", "Finding 2", "src/b.rs", Some(2), None, Severity::Info),
    ];

    let prioritized = phase.prioritize_findings(&findings);

    for pf in &prioritized {
        assert!(pf.priority_score >= 0.0 && pf.priority_score <= 1.0);
    }
}

// ============================================================================
// Full Aggregation Workflow Tests
// ============================================================================

#[test]
fn test_run_aggregation_full_workflow() {
    let phase = ReportAggregationPhase::new();
    let context = AnalysisContext::default();

    let findings = vec![
        create_finding("f1", "Critical Finding", "src/a.rs", Some(1), Some("CWE-79"), Severity::Critical),
        create_finding("f2", "High Finding", "src/b.rs", Some(2), Some("CWE-89"), Severity::High),
        create_finding("f3", "Medium Finding", "src/c.rs", Some(3), Some("CWE-200"), Severity::Medium),
    ];

    let result = phase.run(findings, &context);

    assert_eq!(result.statistics.total_findings, 3);
    assert_eq!(result.statistics.critical_count, 1);
    assert_eq!(result.statistics.high_count, 1);
    assert_eq!(result.statistics.medium_count, 1);
    assert_eq!(result.summary.risk_level, "CRITICAL");
    assert_eq!(result.prioritized_findings.len(), 3);
    assert_eq!(result.prioritized_findings[0].finding.severity, Severity::Critical);
}

#[test]
fn test_run_aggregation_with_deduplication() {
    let phase = ReportAggregationPhase::new();
    let context = AnalysisContext::default();

    // These should be deduplicated to 1
    let findings = vec![
        create_finding("f1", "Finding 1", "src/a.rs", Some(1), Some("CWE-79"), Severity::Critical),
        create_finding("f2", "Finding 2", "src/a.rs", Some(1), Some("CWE-79"), Severity::High),
        create_finding("f3", "Finding 3", "src/a.rs", Some(1), Some("CWE-79"), Severity::Medium),
    ];

    let result = phase.run(findings, &context);

    assert_eq!(result.statistics.total_findings, 1);
    assert_eq!(result.unique_findings.len(), 1);
    assert_eq!(result.prioritized_findings.len(), 1);
}

#[test]
fn test_run_aggregation_updates_context() {
    let phase = ReportAggregationPhase::new();
    let mut context = AnalysisContext::default();

    let findings = vec![
        create_finding("f1", "Critical", "src/a.rs", Some(1), Some("CWE-79"), Severity::Critical),
        create_finding("f2", "High", "src/b.rs", Some(2), Some("CWE-89"), Severity::High),
    ];

    let result = phase.run(findings, &context);
    phase.update_context(&result, &mut context);

    assert_eq!(context.findings_so_far.len(), 2);
}

// ============================================================================
// Edge Cases and Special Scenarios
// ============================================================================

#[test]
fn test_aggregation_with_no_cwe_ids() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Finding 1", "src/a.rs", Some(1), None, Severity::High),
        create_finding("f2", "Finding 2", "src/b.rs", Some(2), None, Severity::Medium),
    ];

    let result = phase.run(findings, &AnalysisContext::default());

    assert_eq!(result.statistics.total_findings, 2);
    // Should categorize as "unknown" when no CWE and no security_issue
    assert!(result.statistics.findings_by_category.contains_key("unknown"));
}

#[test]
fn test_aggregation_mixed_cwe_and_security_issue() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "With CWE", "src/a.rs", Some(1), Some("CWE-79"), Severity::High),
        create_finding_with_category("f2", "With Category", "src/b.rs", IssueCategory::Injection, Severity::High),
    ];

    let result = phase.run(findings, &AnalysisContext::default());

    assert_eq!(result.statistics.total_findings, 2);
    assert!(result.statistics.findings_by_category.contains_key("CWE-79"));
    assert!(result.statistics.findings_by_category.contains_key("injection"));
}

#[test]
fn test_empty_aggregation_result() {
    let phase = ReportAggregationPhase::new();
    let context = AnalysisContext::default();
    let findings: Vec<VulnerabilityFinding> = Vec::new();

    let result = phase.run(findings, &context);

    assert_eq!(result.statistics.total_findings, 0);
    assert_eq!(result.summary.risk_level, "MINIMAL");
    assert!(result.prioritized_findings.is_empty());
    assert!(result.unique_findings.is_empty());
}

#[test]
fn test_default_creation() {
    let phase = ReportAggregationPhase::default();
    assert!(true); // Just test that it compiles and creates
}

#[test]
fn test_serialization_of_aggregate_statistics() {
    let stats = AggregateStatistics {
        total_findings: 10,
        critical_count: 2,
        high_count: 3,
        medium_count: 2,
        low_count: 2,
        info_count: 1,
        average_confidence: 0.75,
        verified_count: 5,
        false_positive_count: 2,
        needs_review_count: 3,
        unique_files_affected: 8,
        cross_file_findings: 4,
        findings_by_category: std::collections::HashMap::new(),
    };

    let serialized = serde_json::to_string(&stats).unwrap();
    let deserialized: AggregateStatistics = serde_json::from_str(&serialized).unwrap();

    assert_eq!(stats.total_findings, deserialized.total_findings);
    assert_eq!(stats.critical_count, deserialized.critical_count);
    assert_eq!(stats.average_confidence, deserialized.average_confidence);
}

#[test]
fn test_serialization_of_executive_summary() {
    let summary = ExecutiveSummary {
        risk_level: "HIGH".to_string(),
        findings_summary: "Test summary".to_string(),
        recommendations: vec!["Recommendation 1".to_string(), "Recommendation 2".to_string()],
        priority_files: vec!["src/main.rs".to_string()],
        total_findings: 5,
    };

    let serialized = serde_json::to_string(&summary).unwrap();
    let deserialized: ExecutiveSummary = serde_json::from_str(&serialized).unwrap();

    assert_eq!(summary.risk_level, deserialized.risk_level);
    assert_eq!(summary.recommendations, deserialized.recommendations);
}
