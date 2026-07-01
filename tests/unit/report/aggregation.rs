//! Tests for report aggregation phase

use baco::context::AnalysisContext;
use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::report::aggregation::{
    AggregationResult, ExecutiveSummary, PrioritizedFinding, ReportAggregationPhase,
};

fn create_finding(
    id: &str,
    title: &str,
    severity: Severity,
    file: &str,
    line: Option<u32>,
    cwe: Option<&str>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: "Test finding".to_string(),
        severity,
        confidence_score: 0.8,
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
    }
}

#[test]
fn test_report_aggregation_phase_new() {
    let phase = ReportAggregationPhase::new();
    assert!(phase != ReportAggregationPhase::default());
}

#[test]
fn test_default_trait() {
    let _phase = ReportAggregationPhase::default();
}

#[test]
fn test_deduplicate_findings_same_location() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Finding 1", Severity::High, "src/test.rs", Some(10), Some("CWE-79")),
        create_finding("f2", "Finding 2", Severity::Critical, "src/test.rs", Some(10), Some("CWE-79")),
        create_finding("f3", "Finding 3", Severity::Low, "src/test.rs", Some(10), Some("CWE-79")),
    ];

    let unique = phase.deduplicate_findings(findings);

    // All have same file/line/CWE - should deduplicate to 1
    assert_eq!(unique.len(), 1);
}

#[test]
fn test_deduplicate_findings_different_locations() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Finding 1", Severity::High, "src/test.rs", Some(10), Some("CWE-79")),
        create_finding("f2", "Finding 2", Severity::High, "src/test.rs", Some(20), Some("CWE-79")),
        create_finding("f3", "Finding 3", Severity::High, "src/lib.rs", Some(10), Some("CWE-79")),
    ];

    let unique = phase.deduplicate_findings(findings);

    // All different locations - should keep all 3
    assert_eq!(unique.len(), 3);
}

#[test]
fn test_deduplicate_findings_different_cwe() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Finding 1", Severity::High, "src/test.rs", Some(10), Some("CWE-79")),
        create_finding("f2", "Finding 2", Severity::High, "src/test.rs", Some(10), Some("CWE-89")),
    ];

    let unique = phase.deduplicate_findings(findings);

    // Same location but different CWE - should keep both
    assert_eq!(unique.len(), 2);
}

#[test]
fn test_deduplicate_findings_empty() {
    let phase = ReportAggregationPhase::new();
    let unique = phase.deduplicate_findings(vec![]);
    assert_eq!(unique.len(), 0);
}

#[test]
fn test_calculate_statistics_basic() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Critical", Severity::Critical, "src/a.rs", Some(1), Some("CWE-1")),
        create_finding("f2", "High", Severity::High, "src/b.rs", Some(2), Some("CWE-2")),
        create_finding("f3", "Medium", Severity::Medium, "src/c.rs", Some(3), Some("CWE-3")),
        create_finding("f4", "Low", Severity::Low, "src/d.rs", Some(4), Some("CWE-4")),
        create_finding("f5", "Info", Severity::Info, "src/e.rs", Some(5), Some("CWE-5")),
    ];

    let stats = phase.calculate_statistics(&findings);

    assert_eq!(stats.total_findings, 5);
    assert_eq!(stats.critical_count, 1);
    assert_eq!(stats.high_count, 1);
    assert_eq!(stats.medium_count, 1);
    assert_eq!(stats.low_count, 1);
    assert_eq!(stats.info_count, 1);
    assert_eq!(stats.unique_files_affected, 5);
}

#[test]
fn test_calculate_statistics_verification() {
    let phase = ReportAggregationPhase::new();

    let mut finding = create_finding("f1", "Test", Severity::High, "src/test.rs", Some(1), Some("CWE-79"));
    finding.verification_status = Some(VerificationStatus::Confirmed);

    let mut finding2 = create_finding("f2", "Test2", Severity::High, "src/test.rs", Some(2), Some("CWE-79"));
    finding2.verification_status = Some(VerificationStatus::FalsePositive);

    let findings = vec![finding, finding2];
    let stats = phase.calculate_statistics(&findings);

    assert_eq!(stats.verified_count, 1);
    assert_eq!(stats.false_positive_count, 1);
}

#[test]
fn test_calculate_statistics_empty() {
    let phase = ReportAggregationPhase::new();
    let stats = phase.calculate_statistics(&[]);

    assert_eq!(stats.total_findings, 0);
    assert_eq!(stats.average_confidence, 0.0);
}

#[test]
fn test_calculate_statistics_cross_file() {
    let phase = ReportAggregationPhase::new();

    let mut finding = create_finding("f1", "Test", Severity::High, "src/test.rs", Some(1), Some("CWE-79"));
    finding.cross_file_references = Some(vec!["cross-file ref".to_string()]);

    let findings = vec![finding];
    let stats = phase.calculate_statistics(&findings);

    assert_eq!(stats.cross_file_findings, 1);
}

#[test]
fn test_generate_executive_summary_critical() {
    let phase = ReportAggregationPhase::new();
    let stats = baco::report::aggregation::AggregateStatistics {
        critical_count: 5,
        total_findings: 10,
        ..Default::default()
    };
    let context = AnalysisContext::default();

    let summary = phase.generate_executive_summary(&stats, &[], &context);

    assert_eq!(summary.risk_level, "CRITICAL");
    assert!(summary.recommendations.iter().any(|r| r.contains("URGENT")));
}

#[test]
fn test_generate_executive_summary_high() {
    let phase = ReportAggregationPhase::new();
    let stats = baco::report::aggregation::AggregateStatistics {
        critical_count: 0,
        high_count: 3,
        ..Default::default()
    };
    let context = AnalysisContext::default();

    let summary = phase.generate_executive_summary(&stats, &[], &context);

    assert_eq!(summary.risk_level, "HIGH");
}

#[test]
fn test_generate_executive_summary_low_confidence() {
    let phase = ReportAggregationPhase::new();
    let stats = baco::report::aggregation::AggregateStatistics {
        average_confidence: 0.3,
        ..Default::default()
    };
    let context = AnalysisContext::default();

    let summary = phase.generate_executive_summary(&stats, &[], &context);

    assert!(summary.recommendations.iter().any(|r| r.contains("manual verification")));
}

#[test]
fn test_generate_executive_summary_empty() {
    let phase = ReportAggregationPhase::new();
    let stats = crate::aggregation::AggregateStatistics::default();
    let context = AnalysisContext::default();

    let summary = phase.generate_executive_summary(&stats, &[], &context);

    assert_eq!(summary.risk_level, "MINIMAL");
}

#[test]
fn test_prioritize_findings_order() {
    let phase = ReportAggregationPhase::new();

    let findings = vec![
        create_finding("f1", "Low", Severity::Low, "src/a.rs", Some(1), Some("CWE-1")),
        create_finding("f2", "Critical", Severity::Critical, "src/b.rs", Some(2), Some("CWE-2")),
        create_finding("f3", "Medium", Severity::Medium, "src/c.rs", Some(3), Some("CWE-3")),
    ];

    let prioritized = phase.prioritize_findings(&findings);

    assert_eq!(prioritized.len(), 3);
    assert_eq!(prioritized[0].rank, 1);
    assert_eq!(prioritized[0].finding.severity, Severity::Critical);
    assert_eq!(prioritized[1].finding.severity, Severity::Medium);
    assert_eq!(prioritized[2].finding.severity, Severity::Low);
}

#[test]
fn test_prioritize_findings_cross_file_boost() {
    let phase = ReportAggregationPhase::new();

    let mut finding1 = create_finding("f1", "High", Severity::High, "src/a.rs", Some(1), Some("CWE-1"));
    finding1.cross_file_references = Some(vec!["ref".to_string()]);

    let finding2 = create_finding("f2", "High", Severity::High, "src/b.rs", Some(2), Some("CWE-1"));

    let findings = vec![finding1, finding2];
    let prioritized = phase.prioritize_findings(&findings);

    // Cross-file finding should have higher score
    assert!(prioritized[0].priority_score > prioritized[1].priority_score);
}

#[test]
fn test_prioritize_findings_already_reported_reduction() {
    let phase = ReportAggregationPhase::new();

    let mut finding1 = create_finding("f1", "High", Severity::High, "src/a.rs", Some(1), Some("CWE-1"));
    finding1.already_reported = true;

    let finding2 = create_finding("f2", "High", Severity::High, "src/b.rs", Some(2), Some("CWE-1"));

    let findings = vec![finding1, finding2];
    let prioritized = phase.prioritize_findings(&findings);

    // Already reported should have slightly lower score
    assert!(prioritized[1].priority_score > prioritized[0].priority_score);
}

#[test]
fn test_prioritize_findings_empty() {
    let phase = ReportAggregationPhase::new();
    let prioritized = phase.prioritize_findings(&[]);
    assert_eq!(prioritized.len(), 0);
}

#[tokio::test]
async fn test_run_aggregation_full_flow() {
    let phase = ReportAggregationPhase::new();
    let context = AnalysisContext::default();

    let findings = vec![
        create_finding("f1", "Critical", Severity::Critical, "src/a.rs", Some(1), Some("CWE-1")),
        create_finding("f2", "High", Severity::High, "src/b.rs", Some(2), Some("CWE-2")),
    ];

    let result = phase.run(findings, &context);

    assert_eq!(result.statistics.total_findings, 2);
    assert_eq!(result.summary.risk_level, "CRITICAL");
    assert_eq!(result.prioritized_findings.len(), 2);
    assert_eq!(result.unique_findings.len(), 2);
}

#[test]
fn test_update_context() {
    let phase = ReportAggregationPhase::new();
    let mut context = AnalysisContext::default();

    let finding = create_finding("f1", "Test", Severity::Critical, "src/test.rs", Some(1), Some("CWE-79"));
    let result = AggregationResult {
        statistics: crate::aggregation::AggregateStatistics::default(),
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
fn test_aggregation_result_debug() {
    let finding = create_finding("f1", "Test", Severity::High, "src/test.rs", Some(1), Some("CWE-79"));
    let result = AggregationResult {
        statistics: crate::aggregation::AggregateStatistics::default(),
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

    // Should compile and work with Debug
    let _debug_str = format!("{:?}", result);
}

#[test]
fn test_prioritized_finding_debug() {
    let finding = create_finding("f1", "Test", Severity::High, "src/test.rs", Some(1), Some("CWE-79"));
    let pf = PrioritizedFinding {
        finding,
        rank: 1,
        priority_score: 0.8,
        priority_reason: "Test reason".to_string(),
    };

    let _debug_str = format!("{:?}", pf);
}
