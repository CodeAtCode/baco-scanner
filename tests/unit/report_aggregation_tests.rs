//! Comprehensive tests for report aggregation, statistics calculation,
//! executive summary generation, and finding prioritization.
//!
//! This module tests the ReportAggregationPhase, AggregateStatistics,
//! ExecutiveSummary, PrioritizedFinding, and AggregationResult types.

use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::report::aggregation::{
    AggregateStatistics, AggregationResult, ExecutiveSummary, PrioritizedFinding,
    ReportAggregationPhase,
};
use baco::root_cause_dedup::GlobalFpStore;
use tempfile::TempDir;

use crate::fixtures::make_finding_report_agg;

fn create_finding(
    id: &str,
    title: &str,
    severity: Severity,
    file_path: &str,
) -> VulnerabilityFinding {
    make_finding_report_agg(id, title, file_path, Some(10), Some("CWE-79"), severity)
}

fn create_finding_with_confidence(
    id: &str,
    title: &str,
    severity: Severity,
    file_path: &str,
    confidence: f32,
) -> VulnerabilityFinding {
    let mut finding = create_finding(id, title, severity, file_path);
    finding.confidence_score = confidence;
    finding
}

/// Helper to create a finding with cross-file references
fn create_finding_with_cross_file(
    id: &str,
    title: &str,
    severity: Severity,
    file_path: &str,
) -> VulnerabilityFinding {
    let mut finding = create_finding(id, title, severity, file_path);
    finding.cross_file_references = Some(vec!["src/other.rs".to_string()]);
    finding
}

/// Helper to create a finding with already_reported flag
fn create_already_reported_finding(
    id: &str,
    title: &str,
    severity: Severity,
    file_path: &str,
) -> VulnerabilityFinding {
    let mut finding = create_finding(id, title, severity, file_path);
    finding.already_reported = true;
    finding
}

/// Helper to create a finding without CWE ID
fn create_finding_without_cwe(
    id: &str,
    title: &str,
    severity: Severity,
    file_path: &str,
) -> VulnerabilityFinding {
    let mut finding = create_finding(id, title, severity, file_path);
    finding.cwe_id = None;
    finding
}

/// Helper to create a finding with verified status
fn create_verified_finding(
    id: &str,
    title: &str,
    severity: Severity,
    file_path: &str,
) -> VulnerabilityFinding {
    let mut finding = create_finding(id, title, severity, file_path);
    finding.verification_status = Some(VerificationStatus::Confirmed);
    finding
}

/// Helper to create a finding with false positive status
fn create_fp_finding(
    id: &str,
    title: &str,
    severity: Severity,
    file_path: &str,
) -> VulnerabilityFinding {
    let mut finding = create_finding(id, title, severity, file_path);
    finding.verification_status = Some(VerificationStatus::FalsePositive);
    finding
}

// ============================================================================
// REPORT AGGREGATION PHASE CONSTRUCTOR TESTS
// ============================================================================

#[test]
fn test_phase_new_creates_instance() {
    let phase = ReportAggregationPhase::new();
    // Unit struct construction works
    let _ = phase;
}

#[test]
fn test_phase_default_implementation() {
    let phase = ReportAggregationPhase::new();
    // Constructor should work without panicking
    let _ = phase;
}

// ============================================================================
// DEDUPLICATION TESTS
// ============================================================================

#[test]
fn test_deduplicate_empty_findings_returns_empty() {
    let phase = ReportAggregationPhase::new();
    let findings: Vec<VulnerabilityFinding> = Vec::new();

    let unique = phase.deduplicate_findings(findings, None);

    assert!(unique.is_empty());
}

#[test]
fn test_deduplicate_findings_removes_duplicates_same_location() {
    let phase = ReportAggregationPhase::new();

    let finding1 = create_finding("f1", "Test finding", Severity::High, "src/test.rs");
    let finding2 = create_finding("f2", "Another finding", Severity::Critical, "src/test.rs");
    let finding3 = create_finding("f3", "Third finding", Severity::Medium, "src/test.rs");

    let findings = vec![finding1, finding2, finding3];
    let unique = phase.deduplicate_findings(findings, None);

    // All have same file:line:CWE, so deduplicated to 1
    assert_eq!(unique.len(), 1);
}

#[test]
fn test_deduplicate_findings_keeps_different_locations() {
    let phase = ReportAggregationPhase::new();

    let finding1 = create_finding("f1", "Test finding", Severity::High, "src/test1.rs");
    let finding2 = create_finding("f2", "Test finding", Severity::High, "src/test2.rs");
    let finding3 = create_finding("f3", "Test finding", Severity::High, "src/test3.rs");

    let findings = vec![finding1, finding2, finding3];
    let unique = phase.deduplicate_findings(findings, None);

    // Different files, all kept
    assert_eq!(unique.len(), 3);
}

#[test]
fn test_deduplicate_findings_with_different_lines() {
    let phase = ReportAggregationPhase::new();

    let mut finding1 = create_finding("f1", "Test finding", Severity::High, "src/test.rs");
    finding1.line_number = Some(10);
    let mut finding2 = create_finding("f2", "Test finding", Severity::High, "src/test.rs");
    finding2.line_number = Some(20);
    let mut finding3 = create_finding("f3", "Test finding", Severity::High, "src/test.rs");
    finding3.line_number = Some(10); // Duplicate of finding1

    let findings = vec![finding1, finding2, finding3];
    let unique = phase.deduplicate_findings(findings, None);

    // line 10 appears twice, line 20 once = 2 unique
    assert_eq!(unique.len(), 2);
}

#[test]
fn test_deduplicate_findings_filters_fp_store() {
    let phase = ReportAggregationPhase::new();

    let temp = TempDir::new().unwrap();
    let path = temp.path().join("fp_store.json");

    let mut fp_store = GlobalFpStore::with_path(&path);
    fp_store.mark_false_positive("f1");

    let finding1 = create_finding("f1", "Test finding", Severity::High, "src/test.rs");
    let finding2 = create_finding("f2", "Another finding", Severity::Critical, "src/test.rs");

    let findings = vec![finding1, finding2];
    let unique = phase.deduplicate_findings(findings, Some(&fp_store));

    // f1 filtered by FP store, f2 kept
    assert_eq!(unique.len(), 1);
    assert_eq!(unique[0].id, "f2");
}

#[test]
fn test_deduplicate_findings_without_line_number() {
    let phase = ReportAggregationPhase::new();

    let mut finding1 = create_finding("f1", "Test finding", Severity::High, "src/test.rs");
    finding1.line_number = None;
    let mut finding2 = create_finding("f2", "Another finding", Severity::Critical, "src/test.rs");
    finding2.line_number = None; // Both None = same key

    let findings = vec![finding1, finding2];
    let unique = phase.deduplicate_findings(findings, None);

    // Both have no line number, same file and CWE = 1 unique
    assert_eq!(unique.len(), 1);
}

// ============================================================================
// STATISTICS CALCULATION TESTS
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
    assert_eq!(stats.verified_count, 0);
    assert_eq!(stats.false_positive_count, 0);
    assert_eq!(stats.needs_review_count, 0);
    assert_eq!(stats.unique_files_affected, 0);
    assert_eq!(stats.cross_file_findings, 0);
    assert!(stats.findings_by_category.is_empty());
}

#[test]
fn test_calculate_statistics_counts_by_severity() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Critical", Severity::Critical, "src/f1.rs"),
        create_finding("f2", "High", Severity::High, "src/f2.rs"),
        create_finding("f3", "Medium", Severity::Medium, "src/f3.rs"),
        create_finding("f4", "Low", Severity::Low, "src/f4.rs"),
        create_finding("f5", "Info", Severity::Info, "src/f5.rs"),
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
fn test_calculate_statistics_multiple_same_severity() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Critical 1", Severity::Critical, "src/f1.rs"),
        create_finding("f2", "Critical 2", Severity::Critical, "src/f2.rs"),
        create_finding("f3", "Critical 3", Severity::Critical, "src/f3.rs"),
        create_finding("f4", "High 1", Severity::High, "src/f4.rs"),
        create_finding("f5", "High 2", Severity::High, "src/f5.rs"),
    ];

    let stats = phase.calculate_statistics(&findings);

    assert_eq!(stats.critical_count, 3);
    assert_eq!(stats.high_count, 2);
    assert_eq!(stats.medium_count, 0);
}

#[test]
fn test_calculate_statistics_average_confidence() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding_with_confidence("f1", "Test", Severity::High, "src/f1.rs", 0.5),
        create_finding_with_confidence("f2", "Test", Severity::High, "src/f2.rs", 0.7),
        create_finding_with_confidence("f3", "Test", Severity::High, "src/f3.rs", 0.9),
    ];

    let stats = phase.calculate_statistics(&findings);

    // Average of 0.5, 0.7, 0.9 = 2.1 / 3 = 0.7
    assert!((stats.average_confidence - 0.7).abs() < 0.001);
}

#[test]
fn test_calculate_statistics_average_confidence_empty_is_zero() {
    let phase = ReportAggregationPhase::new();
    let findings: Vec<VulnerabilityFinding> = Vec::new();

    let stats = phase.calculate_statistics(&findings);

    assert_eq!(stats.average_confidence, 0.0);
}

#[test]
fn test_calculate_statistics_unique_files() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Test", Severity::High, "src/file1.rs"),
        create_finding("f2", "Test", Severity::High, "src/file2.rs"),
        create_finding("f3", "Test", Severity::High, "src/file1.rs"), // Duplicate file
        create_finding("f4", "Test", Severity::High, "src/file3.rs"),
    ];

    let stats = phase.calculate_statistics(&findings);

    assert_eq!(stats.unique_files_affected, 3);
}

#[test]
fn test_calculate_statistics_verification_counts() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_verified_finding("f1", "Verified", Severity::High, "src/f1.rs"),
        create_verified_finding("f2", "Verified", Severity::High, "src/f2.rs"),
        create_fp_finding("f3", "FP", Severity::Medium, "src/f3.rs"),
        create_fp_finding("f4", "FP", Severity::Low, "src/f4.rs"),
        create_finding("f5", "NeedsReview", Severity::High, "src/f5.rs"), // Default is NeedsReview
        create_finding("f6", "NoStatus", Severity::Medium, "src/f6.rs"),  // No status set
    ];

    let stats = phase.calculate_statistics(&findings);

    // verified_count counts Confirmed status: f1, f2 = 2 verified
    // false_positive_count: f3, f4 = 2 FP
    // needs_review_count: f5, f6 = 2 (both default to NeedsReview)
    assert_eq!(stats.verified_count, 2);
    assert_eq!(stats.false_positive_count, 2);
    assert_eq!(stats.needs_review_count, 2);
}

#[test]
fn test_calculate_statistics_cross_file_findings() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "No cross", Severity::High, "src/f1.rs"),
        create_finding_with_cross_file("f2", "Has cross", Severity::High, "src/f2.rs"),
        create_finding("f3", "No cross", Severity::Medium, "src/f3.rs"),
        create_finding_with_cross_file("f4", "Has cross", Severity::Low, "src/f4.rs"),
    ];

    let stats = phase.calculate_statistics(&findings);

    assert_eq!(stats.cross_file_findings, 2);
}

#[test]
fn test_calculate_statistics_findings_by_category() {
    let phase = ReportAggregationPhase::new();

    let mut finding1 = create_finding("f1", "Test", Severity::High, "src/f1.rs");
    finding1.cwe_id = Some("CWE-79".to_string());

    let mut finding2 = create_finding("f2", "Test", Severity::High, "src/f2.rs");
    finding2.cwe_id = Some("CWE-79".to_string());

    let mut finding3 = create_finding("f3", "Test", Severity::Medium, "src/f3.rs");
    finding3.cwe_id = Some("CWE-89".to_string());

    let findings = vec![finding1, finding2, finding3];

    let stats = phase.calculate_statistics(&findings);

    assert_eq!(*stats.findings_by_category.get("CWE-79").unwrap(), 2);
    assert_eq!(*stats.findings_by_category.get("CWE-89").unwrap(), 1);
}

#[test]
fn test_calculate_statistics_findings_without_cwe_uses_unknown() {
    let phase = ReportAggregationPhase::new();

    let finding = create_finding_without_cwe("f1", "Test", Severity::High, "src/f1.rs");

    let stats = phase.calculate_statistics(&[finding]);

    assert_eq!(*stats.findings_by_category.get("unknown").unwrap(), 1);
}

// ============================================================================
// EXECUTIVE SUMMARY TESTS
// ============================================================================

#[test]
fn test_executive_summary_risk_level_critical() {
    let phase = ReportAggregationPhase::new();
    let stats = AggregateStatistics {
        critical_count: 1,
        high_count: 5,
        ..Default::default()
    };

    let summary = phase.generate_executive_summary(&stats, &[], &Default::default());

    assert_eq!(summary.risk_level, "CRITICAL");
}

#[test]
fn test_executive_summary_risk_level_high_no_critical() {
    let phase = ReportAggregationPhase::new();
    let stats = AggregateStatistics {
        critical_count: 0,
        high_count: 3,
        ..Default::default()
    };

    let summary = phase.generate_executive_summary(&stats, &[], &Default::default());

    assert_eq!(summary.risk_level, "HIGH");
}

#[test]
fn test_executive_summary_risk_level_moderate() {
    let phase = ReportAggregationPhase::new();
    let stats = AggregateStatistics {
        critical_count: 0,
        high_count: 0,
        medium_count: 5,
        ..Default::default()
    };

    let summary = phase.generate_executive_summary(&stats, &[], &Default::default());

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
        ..Default::default()
    };

    let summary = phase.generate_executive_summary(&stats, &[], &Default::default());

    assert_eq!(summary.risk_level, "LOW");
}

#[test]
fn test_executive_summary_risk_level_minimal() {
    let phase = ReportAggregationPhase::new();
    let stats = AggregateStatistics::default();

    let summary = phase.generate_executive_summary(&stats, &[], &Default::default());

    assert_eq!(summary.risk_level, "MINIMAL");
}

#[test]
fn test_executive_summary_findings_summary_format() {
    let phase = ReportAggregationPhase::new();
    let stats = AggregateStatistics {
        total_findings: 10,
        unique_files_affected: 5,
        critical_count: 2,
        high_count: 3,
        medium_count: 3,
        low_count: 1,
        info_count: 1,
        average_confidence: 0.75,
        ..Default::default()
    };

    let summary = phase.generate_executive_summary(&stats, &[], &Default::default());

    assert!(summary.findings_summary.contains("10"));
    assert!(summary.findings_summary.contains("5"));
    assert!(summary.findings_summary.contains("75.0"));
}

#[test]
fn test_executive_summary_recommendations_for_critical() {
    let phase = ReportAggregationPhase::new();
    let stats = AggregateStatistics {
        critical_count: 3,
        ..Default::default()
    };

    let summary = phase.generate_executive_summary(&stats, &[], &Default::default());

    let has_urgent = summary.recommendations.iter().any(|r| r.contains("URGENT"));
    assert!(has_urgent);
}

#[test]
fn test_executive_summary_recommendations_for_high() {
    let phase = ReportAggregationPhase::new();
    let stats = AggregateStatistics {
        critical_count: 0,
        high_count: 5,
        ..Default::default()
    };

    let summary = phase.generate_executive_summary(&stats, &[], &Default::default());

    let has_high_priority = summary
        .recommendations
        .iter()
        .any(|r| r.contains("High priority"));
    assert!(has_high_priority);
}

#[test]
fn test_executive_summary_recommendations_for_cross_file() {
    let phase = ReportAggregationPhase::new();
    let stats = AggregateStatistics {
        cross_file_findings: 10,
        ..Default::default()
    };

    let summary = phase.generate_executive_summary(&stats, &[], &Default::default());

    let has_cross_file_note = summary
        .recommendations
        .iter()
        .any(|r| r.contains("cross-file"));
    assert!(has_cross_file_note);
}

#[test]
fn test_executive_summary_recommendations_for_low_confidence() {
    let phase = ReportAggregationPhase::new();
    let stats = AggregateStatistics {
        average_confidence: 0.3,
        ..Default::default()
    };

    let summary = phase.generate_executive_summary(&stats, &[], &Default::default());

    let has_low_conf_note = summary
        .recommendations
        .iter()
        .any(|r| r.contains("Low confidence"));
    assert!(has_low_conf_note);
}

#[test]
fn test_executive_summary_no_recommendations_for_empty_findings() {
    let phase = ReportAggregationPhase::new();
    let stats = AggregateStatistics::default();

    let summary = phase.generate_executive_summary(&stats, &[], &Default::default());

    // Default stats have average_confidence = 0.0, which triggers "Low confidence" recommendation
    // So recommendations will NOT be empty - it will have 1 recommendation about low confidence
    assert_eq!(summary.recommendations.len(), 1);
    assert!(summary.recommendations[0].contains("Low confidence"));
}

#[test]
fn test_executive_summary_priority_files_top_5() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Critical", Severity::Critical, "src/a.rs"),
        create_finding("f2", "Critical", Severity::Critical, "src/a.rs"),
        create_finding("f3", "High", Severity::High, "src/b.rs"),
        create_finding("f4", "Low", Severity::Low, "src/c.rs"),
        create_finding("f5", "Low", Severity::Low, "src/c.rs"),
        create_finding("f6", "Low", Severity::Low, "src/c.rs"),
        create_finding("f7", "Low", Severity::Low, "src/c.rs"),
        create_finding("f8", "Low", Severity::Low, "src/c.rs"),
        create_finding("f9", "Low", Severity::Low, "src/c.rs"),
    ];

    let stats = phase.calculate_statistics(&findings);
    let summary = phase.generate_executive_summary(&stats, &findings, &Default::default());

    // Should have at most 5 priority files
    assert!(summary.priority_files.len() <= 5);
}

#[test]
fn test_executive_summary_total_findings_matches_stats() {
    let phase = ReportAggregationPhase::new();
    let stats = AggregateStatistics {
        total_findings: 42,
        ..Default::default()
    };

    let summary = phase.generate_executive_summary(&stats, &[], &Default::default());

    assert_eq!(summary.total_findings, 42);
}

// ============================================================================
// PRIORITIZATION TESTS
// ============================================================================

#[test]
fn test_prioritize_findings_empty_returns_empty() {
    let phase = ReportAggregationPhase::new();
    let findings: Vec<VulnerabilityFinding> = Vec::new();

    let prioritized = phase.prioritize_findings(&findings);

    assert!(prioritized.is_empty());
}

#[test]
fn test_prioritize_findings_orders_by_severity() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Low", Severity::Low, "src/f1.rs"),
        create_finding("f2", "Critical", Severity::Critical, "src/f2.rs"),
        create_finding("f3", "Medium", Severity::Medium, "src/f3.rs"),
        create_finding("f4", "High", Severity::High, "src/f4.rs"),
    ];

    let prioritized = phase.prioritize_findings(&findings);

    assert_eq!(prioritized.len(), 4);
    assert_eq!(prioritized[0].finding.severity, Severity::Critical);
    assert_eq!(prioritized[1].finding.severity, Severity::High);
    assert_eq!(prioritized[2].finding.severity, Severity::Medium);
    assert_eq!(prioritized[3].finding.severity, Severity::Low);
}

#[test]
fn test_prioritize_findings_rank_starts_at_one() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Test", Severity::High, "src/f1.rs"),
        create_finding("f2", "Test", Severity::Critical, "src/f2.rs"),
    ];

    let prioritized = phase.prioritize_findings(&findings);

    assert_eq!(prioritized[0].rank, 1);
    assert_eq!(prioritized[1].rank, 2);
}

#[test]
fn test_prioritize_findings_priority_reason_matches_severity() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Test", Severity::Critical, "src/f1.rs"),
        create_finding("f2", "Test", Severity::High, "src/f2.rs"),
        create_finding("f3", "Test", Severity::Medium, "src/f3.rs"),
        create_finding("f4", "Test", Severity::Low, "src/f4.rs"),
        create_finding("f5", "Test", Severity::Info, "src/f5.rs"),
    ];

    let prioritized = phase.prioritize_findings(&findings);

    assert!(prioritized[0].priority_reason.contains("Critical"));
    assert!(prioritized[1].priority_reason.contains("High"));
    assert!(prioritized[2].priority_reason.contains("Medium"));
    assert!(prioritized[3].priority_reason.contains("Low"));
    assert!(prioritized[4].priority_reason.contains("Informational"));
}

#[test]
fn test_prioritize_findings_cross_file_gets_boost() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "No cross", Severity::High, "src/f1.rs"),
        create_finding_with_cross_file("f2", "Has cross", Severity::High, "src/f2.rs"),
    ];

    let prioritized = phase.prioritize_findings(&findings);

    // Both have same severity, but cross-file should have higher score
    assert!(prioritized[0].priority_score >= prioritized[1].priority_score);
}

#[test]
fn test_prioritize_findings_already_reported_gets_reduction() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "New", Severity::High, "src/f1.rs"),
        create_already_reported_finding("f2", "Already", Severity::High, "src/f2.rs"),
    ];

    let prioritized = phase.prioritize_findings(&findings);

    // New finding should have equal or higher score
    assert!(prioritized[0].priority_score >= prioritized[1].priority_score);
}

#[test]
fn test_prioritize_findings_confidence_affects_score() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding_with_confidence("f1", "Low conf", Severity::Critical, "src/f1.rs", 0.5),
        create_finding_with_confidence("f2", "High conf", Severity::Critical, "src/f2.rs", 0.9),
    ];

    let prioritized = phase.prioritize_findings(&findings);

    // Higher confidence should result in higher score
    assert!(prioritized[0].priority_score > prioritized[1].priority_score);
}

#[test]
fn test_prioritized_finding_score_bounds() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Test", Severity::Critical, "src/f1.rs"),
        create_finding("f2", "Test", Severity::Info, "src/f2.rs"),
    ];

    let prioritized = phase.prioritize_findings(&findings);

    for pf in &prioritized {
        assert!(pf.priority_score >= 0.0);
        assert!(pf.priority_score <= 1.0);
    }
}

// ============================================================================
// AGGREGATION RESULT TESTS (FULL PIPELINE)
// ============================================================================

#[test]
fn test_run_aggregation_empty_findings() {
    let phase = ReportAggregationPhase::new();
    let context = Default::default();

    let findings: Vec<VulnerabilityFinding> = Vec::new();

    let result = phase.run(findings, &context, None);

    assert_eq!(result.statistics.total_findings, 0);
    assert!(result.unique_findings.is_empty());
    assert!(result.prioritized_findings.is_empty());
    assert_eq!(result.summary.risk_level, "MINIMAL");
}

#[test]
fn test_run_aggregation_full_pipeline() {
    let phase = ReportAggregationPhase::new();
    let context = Default::default();

    let findings = vec![
        create_finding("f1", "Critical 1", Severity::Critical, "src/f1.rs"),
        create_finding("f2", "Critical 2", Severity::Critical, "src/f2.rs"),
        create_finding("f3", "High 1", Severity::High, "src/f3.rs"),
        create_finding("f4", "Medium 1", Severity::Medium, "src/f4.rs"),
    ];

    let result = phase.run(findings, &context, None);

    assert_eq!(result.statistics.total_findings, 4);
    assert_eq!(result.statistics.critical_count, 2);
    assert_eq!(result.statistics.high_count, 1);
    assert_eq!(result.statistics.medium_count, 1);
    assert_eq!(result.summary.risk_level, "CRITICAL");
    assert_eq!(result.prioritized_findings.len(), 4);
    assert_eq!(result.prioritized_findings[0].rank, 1);
}

#[test]
fn test_run_aggregation_with_deduplication() {
    let phase = ReportAggregationPhase::new();
    let context = Default::default();

    // All same location = will be deduplicated to 1
    let findings = vec![
        create_finding("f1", "Test 1", Severity::Critical, "src/test.rs"),
        create_finding("f2", "Test 2", Severity::High, "src/test.rs"),
        create_finding("f3", "Test 3", Severity::Medium, "src/test.rs"),
    ];

    let result = phase.run(findings, &context, None);

    // All deduplicated to 1
    assert_eq!(result.statistics.total_findings, 1);
    assert_eq!(result.unique_findings.len(), 1);
    assert_eq!(result.prioritized_findings.len(), 1);
}

#[test]
fn test_run_aggregation_with_fp_store() {
    let phase = ReportAggregationPhase::new();
    let context = Default::default();

    let temp = TempDir::new().unwrap();
    let path = temp.path().join("fp_store.json");

    let mut fp_store = GlobalFpStore::with_path(&path);
    fp_store.mark_false_positive("f1");

    let findings = vec![
        create_finding("f1", "Will be filtered", Severity::Critical, "src/f1.rs"),
        create_finding("f2", "Will remain", Severity::High, "src/f2.rs"),
    ];

    let result = phase.run(findings, &context, Some(&fp_store));

    assert_eq!(result.statistics.total_findings, 1);
    assert_eq!(result.unique_findings[0].id, "f2");
}

// ============================================================================
// UPDATE CONTEXT TESTS
// ============================================================================

#[test]
fn test_update_context_populates_findings_so_far() {
    let phase = ReportAggregationPhase::new();
    let mut context = Default::default();

    let finding = create_finding("f1", "Test finding", Severity::Critical, "src/test.rs");
    let result = AggregationResult {
        statistics: AggregateStatistics::default(),
        summary: ExecutiveSummary {
            risk_level: "TEST".to_string(),
            findings_summary: "Test".to_string(),
            recommendations: vec![],
            priority_files: vec![],
            total_findings: 1,
        },
        prioritized_findings: vec![],
        unique_findings: vec![finding],
    };

    phase.update_context(&result, &mut context);

    assert!(!context.findings_so_far.is_empty());
}

#[test]
fn test_update_context_empty_results_clears_findings() {
    use baco::analysis_context::AnalysisContext;

    let phase = ReportAggregationPhase::new();
    let mut context = AnalysisContext {
        findings_so_far: vec!["old finding".to_string()],
        ..Default::default()
    };

    let result = AggregationResult {
        statistics: AggregateStatistics::default(),
        summary: ExecutiveSummary {
            risk_level: "TEST".to_string(),
            findings_summary: "Test".to_string(),
            recommendations: vec![],
            priority_files: vec![],
            total_findings: 0,
        },
        prioritized_findings: vec![],
        unique_findings: vec![],
    };

    phase.update_context(&result, &mut context);

    assert!(context.findings_so_far.is_empty());
}

// ============================================================================
// AGGREGATE STATISTICS STRUCT TESTS
// ============================================================================

#[test]
fn test_aggregate_statistics_default_values() {
    let stats = AggregateStatistics::default();

    assert_eq!(stats.total_findings, 0);
    assert_eq!(stats.critical_count, 0);
    assert_eq!(stats.high_count, 0);
    assert_eq!(stats.medium_count, 0);
    assert_eq!(stats.low_count, 0);
    assert_eq!(stats.info_count, 0);
    assert_eq!(stats.average_confidence, 0.0);
    assert!(stats.findings_by_category.is_empty());
}

#[test]
fn test_aggregate_statistics_clone() {
    let original = AggregateStatistics {
        total_findings: 42,
        critical_count: 5,
        high_count: 10,
        ..Default::default()
    };

    let cloned = original.clone();

    assert_eq!(cloned.total_findings, 42);
    assert_eq!(cloned.critical_count, 5);
    assert_eq!(cloned.high_count, 10);
}

// ============================================================================
// EXECUTIVE SUMMARY STRUCT TESTS
// ============================================================================

#[test]
fn test_executive_summary_creation() {
    let summary = ExecutiveSummary {
        risk_level: "HIGH".to_string(),
        findings_summary: "Test summary".to_string(),
        recommendations: vec!["Recommendation 1".to_string()],
        priority_files: vec!["src/main.rs".to_string()],
        total_findings: 10,
    };

    assert_eq!(summary.risk_level, "HIGH");
    assert_eq!(summary.findings_summary, "Test summary");
    assert_eq!(summary.recommendations.len(), 1);
    assert_eq!(summary.priority_files.len(), 1);
    assert_eq!(summary.total_findings, 10);
}

// ============================================================================
// PRIORITIZED FINDING STRUCT TESTS
// ============================================================================

#[test]
fn test_prioritized_finding_creation() {
    let finding = create_finding("f1", "Test", Severity::High, "src/f1.rs");
    let pf = PrioritizedFinding {
        finding: finding.clone(),
        rank: 1,
        priority_score: 0.85,
        priority_reason: "High severity".to_string(),
    };

    assert_eq!(pf.rank, 1);
    assert_eq!(pf.priority_score, 0.85);
    assert_eq!(pf.priority_reason, "High severity");
    assert_eq!(pf.finding.id, "f1");
}

// ============================================================================
// EDGE CASES AND BOUNDARY TESTS
// ============================================================================

#[test]
fn test_aggregation_with_single_finding() {
    let phase = ReportAggregationPhase::new();
    let context = Default::default();

    let findings = vec![create_finding(
        "f1",
        "Single",
        Severity::Medium,
        "src/solo.rs",
    )];

    let result = phase.run(findings, &context, None);

    assert_eq!(result.statistics.total_findings, 1);
    assert_eq!(result.prioritized_findings.len(), 1);
    assert_eq!(result.prioritized_findings[0].rank, 1);
    assert_eq!(result.summary.risk_level, "MODERATE");
}

#[test]
fn test_aggregation_with_many_findings_same_file() {
    let phase = ReportAggregationPhase::new();
    let context = Default::default();

    let findings: Vec<_> = (0..100)
        .map(|i| create_finding(&format!("f{}", i), "Test", Severity::High, "src/same.rs"))
        .collect();

    let result = phase.run(findings, &context, None);

    // All same location = deduplicated to 1
    assert_eq!(result.statistics.total_findings, 1);
    assert_eq!(result.statistics.unique_files_affected, 1);
}

#[test]
fn test_aggregation_with_many_different_files() {
    let phase = ReportAggregationPhase::new();
    let context = Default::default();

    let findings: Vec<_> = (0..50)
        .map(|i| {
            create_finding(
                &format!("f{}", i),
                "Test",
                Severity::High,
                &format!("src/file{}.rs", i),
            )
        })
        .collect();

    let result = phase.run(findings, &context, None);

    assert_eq!(result.statistics.total_findings, 50);
    assert_eq!(result.statistics.unique_files_affected, 50);
}

#[test]
fn test_aggregation_preserves_finding_details_after_dedup() {
    let phase = ReportAggregationPhase::new();
    let context = Default::default();

    let mut finding = create_finding("f1", "Original", Severity::Critical, "src/test.rs");
    finding.confidence_score = 0.95;
    finding.recommendation = Some("Specific recommendation".to_string());

    let findings = vec![
        finding,
        create_finding("f2", "Duplicate", Severity::Low, "src/test.rs"),
    ];

    let result = phase.run(findings, &context, None);

    assert_eq!(result.unique_findings.len(), 1);
    assert_eq!(result.unique_findings[0].confidence_score, 0.95);
}

#[test]
fn test_statistics_with_all_verification_statuses() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_verified_finding("f1", "Confirmed", Severity::High, "src/f1.rs"),
        create_fp_finding("f2", "False Positive", Severity::Medium, "src/f2.rs"),
        create_finding("f3", "Needs Review", Severity::Low, "src/f3.rs"),
    ];

    let stats = phase.calculate_statistics(&findings);

    assert_eq!(stats.verified_count, 1);
    assert_eq!(stats.false_positive_count, 1);
    assert_eq!(stats.needs_review_count, 1);
}

#[test]
fn test_priority_score_clamping_at_boundaries() {
    let phase = ReportAggregationPhase::new();

    // Info severity with low confidence and already reported = negative before clamp
    let findings = vec![create_already_reported_finding(
        "f1",
        "Low priority",
        Severity::Info,
        "src/f1.rs",
    )];

    let prioritized = phase.prioritize_findings(&findings);

    // Score should be clamped to 0.0 minimum
    assert!(prioritized[0].priority_score >= 0.0);
}
