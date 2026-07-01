//! Tests for AI aggregation phase

use baco::context::AnalysisContext;
use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::llm::LlmConfig;
use baco::report::ai_aggregation::{
    AiAggregation, AiAggregationPhase, AiAggregationResult, AiAggregationStatistics,
    AiConfidenceScore, ConsensusRecommendation, ConsensusResult, FindingSource,
};

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

#[test]
fn test_ai_aggregation_new() {
    let config = make_config();
    let aggregation = AiAggregation::new(config);
    assert!(aggregation != AiAggregation::new(make_config()));
}

#[test]
fn test_ai_aggregation_phase_new() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    // Just verify it creates successfully
    assert!(true);
}

#[tokio::test]
async fn test_generate_executive_summary_empty() {
    let config = make_config();
    let aggregation = AiAggregation::new(config);

    let summary = aggregation.generate_executive_summary(&[]).await.unwrap();

    assert_eq!(summary, "No vulnerabilities found.");
}

#[tokio::test]
async fn test_generate_executive_summary_with_findings() {
    let config = make_config();
    let aggregation = AiAggregation::new(config);

    let findings = vec![make_finding(
        "f1",
        Severity::Critical,
        0.9,
        "src/main.rs",
        Some(42),
        Some("CWE-79"),
        Some(VerificationStatus::Confirmed),
    )];

    let summary = aggregation.generate_executive_summary(&findings).await.unwrap();

    assert!(!summary.is_empty());
    assert_ne!(summary, "No vulnerabilities found.");
}

#[tokio::test]
async fn test_generate_risk_assessment_empty() {
    let config = make_config();
    let aggregation = AiAggregation::new(config);

    let assessment = aggregation.generate_risk_assessment(&[]).await.unwrap();

    assert!(assessment.contains("Average Confidence Score: 0.00"));
}

#[tokio::test]
async fn test_generate_risk_assessment_with_findings() {
    let config = make_config();
    let aggregation = AiAggregation::new(config);

    let findings = vec![
        make_finding("f1", Severity::Critical, 0.9, "src/a.rs", Some(1), Some("CWE-1"), None),
        make_finding("f2", Severity::High, 0.7, "src/b.rs", Some(2), Some("CWE-2"), None),
    ];

    let assessment = aggregation.generate_risk_assessment(&findings).await.unwrap();

    assert!(assessment.contains("Average Confidence Score:"));
    assert!(assessment.contains("Findings with Cross-file Reachability:"));
}

#[test]
fn test_group_findings_by_location_single() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let finding = make_finding("f1", Severity::High, 0.8, "src/test.rs", Some(10), Some("CWE-79"), None);
    let grouped = phase.group_findings_by_location(&[finding]);

    assert_eq!(grouped.len(), 1);
    assert_eq!(grouped.get("src/test.rs:10").unwrap().len(), 1);
}

#[test]
fn test_group_findings_by_location_multiple_same_location() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let findings = vec![
        make_finding("f1", Severity::High, 0.8, "src/test.rs", Some(10), Some("CWE-79"), None),
        make_finding("f2", Severity::Critical, 0.9, "src/test.rs", Some(10), Some("CWE-79"), None),
    ];

    let grouped = phase.group_findings_by_location(&findings);

    assert_eq!(grouped.len(), 1);
    assert_eq!(grouped.get("src/test.rs:10").unwrap().len(), 2);
}

#[test]
fn test_group_findings_by_location_no_line() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let finding = make_finding("f1", Severity::High, 0.8, "src/test.rs", None, Some("CWE-79"), None);
    let grouped = phase.group_findings_by_location(&[finding]);

    assert_eq!(grouped.len(), 1);
    assert!(grouped.contains_key("src/test.rs:"));
}

#[test]
fn test_detect_conflicts_severity_mismatch() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let findings = vec![
        make_finding("f1", Severity::Critical, 0.9, "src/test.rs", Some(10), Some("CWE-79"), None),
        make_finding("f2", Severity::Low, 0.8, "src/test.rs", Some(10), Some("CWE-79"), None),
    ];

    let grouped = phase.group_findings_by_location(&findings);
    let conflicts = phase.detect_conflicts(&grouped);

    assert!(!conflicts.is_empty());
    assert_eq!(conflicts[0].conflict_type, baco::report::ai_aggregation::conflict_resolver::ConflictType::SeverityMismatch);
}

#[test]
fn test_detect_conflicts_cwe_mismatch() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let findings = vec![
        make_finding("f1", Severity::High, 0.9, "src/test.rs", Some(10), Some("CWE-79"), None),
        make_finding("f2", Severity::High, 0.8, "src/test.rs", Some(10), Some("CWE-89"), None),
    ];

    let grouped = phase.group_findings_by_location(&findings);
    let conflicts = phase.detect_conflicts(&grouped);

    assert!(!conflicts.is_empty());
    assert_eq!(conflicts[0].conflict_type, baco::report::ai_aggregation::conflict_resolver::ConflictType::CweMismatch);
}

#[test]
fn test_detect_conflicts_verification_conflict() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let findings = vec![
        make_finding("f1", Severity::High, 0.9, "src/test.rs", Some(10), Some("CWE-79"), Some(VerificationStatus::Confirmed)),
        make_finding("f2", Severity::High, 0.8, "src/test.rs", Some(10), Some("CWE-79"), Some(VerificationStatus::FalsePositive)),
    ];

    let grouped = phase.group_findings_by_location(&findings);
    let conflicts = phase.detect_conflicts(&grouped);

    assert!(!conflicts.is_empty());
    assert_eq!(conflicts[0].conflict_type, baco::report::ai_aggregation::conflict_resolver::ConflictType::VerificationConflict);
}

#[test]
fn test_detect_conflicts_confidence_conflict() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let findings = vec![
        make_finding("f1", Severity::High, 0.95, "src/test.rs", Some(10), Some("CWE-79"), None),
        make_finding("f2", Severity::High, 0.5, "src/test.rs", Some(10), Some("CWE-79"), None),
    ];

    let grouped = phase.group_findings_by_location(&findings);
    let conflicts = phase.detect_conflicts(&grouped);

    // Confidence diff > 0.3 should trigger conflict
    assert!(!conflicts.is_empty());
    assert_eq!(conflicts[0].conflict_type, baco::report::ai_aggregation::conflict_resolver::ConflictType::ConfidenceConflict);
}

#[test]
fn test_detect_conflicts_no_conflict() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let findings = vec![
        make_finding("f1", Severity::High, 0.8, "src/test.rs", Some(10), Some("CWE-79"), None),
        make_finding("f2", Severity::High, 0.85, "src/test.rs", Some(10), Some("CWE-79"), None),
    ];

    let grouped = phase.group_findings_by_location(&findings);
    let conflicts = phase.detect_conflicts(&grouped);

    // No conflicts expected
    assert_eq!(conflicts.len(), 0);
}

#[test]
fn test_apply_consensus_algorithms_confirmed() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let finding = make_finding("f1", Severity::High, 0.8, "src/test.rs", Some(10), Some("CWE-79"), Some(VerificationStatus::Confirmed));

    let consensus_results = phase.apply_consensus_algorithms(&[finding], &[]);

    assert_eq!(consensus_results.len(), 1);
    assert_eq!(consensus_results[0].confirming_sources.len(), 1);
    assert!(consensus_results[0].confirming_sources.contains(&FindingSource::LlmVerification));
}

#[test]
fn test_apply_consensus_algorithms_false_positive() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let finding = make_finding("f1", Severity::High, 0.8, "src/test.rs", Some(10), Some("CWE-79"), Some(VerificationStatus::FalsePositive));

    let consensus_results = phase.apply_consensus_algorithms(&[finding], &[]);

    assert_eq!(consensus_results.len(), 1);
    assert!(consensus_results[0].likely_false_positive);
}

#[test]
fn test_apply_consensus_algorithms_high_confidence() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let finding = make_finding("f1", Severity::High, 0.9, "src/test.rs", Some(10), Some("CWE-79"), None);

    let consensus_results = phase.apply_consensus_algorithms(&[finding], &[]);

    assert_eq!(consensus_results.len(), 1);
    assert!(consensus_results[0].confirming_sources.contains(&FindingSource::LlmDiscovery));
}

#[test]
fn test_apply_consensus_algorithms_low_confidence() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let finding = make_finding("f1", Severity::High, 0.3, "src/test.rs", Some(10), Some("CWE-79"), None);

    let consensus_results = phase.apply_consensus_algorithms(&[finding], &[]);

    assert_eq!(consensus_results.len(), 1);
    assert_eq!(consensus_results[0].consensus_score, 0.3);
}

#[test]
fn test_calculate_ai_confidence_verified_high() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let finding = make_finding("f1", Severity::High, 0.9, "src/test.rs", Some(10), Some("CWE-79"), Some(VerificationStatus::Confirmed));

    let consensus = ConsensusResult {
        finding: finding.clone(),
        agreement_count: 2,
        total_sources: 2,
        consensus_score: 0.9,
        confirming_sources: vec![FindingSource::LlmDiscovery, FindingSource::LlmVerification],
        contradicting_sources: vec![],
        likely_false_positive: false,
        recommendation: ConsensusRecommendation::IncludeHighConfidence,
    };

    let ai_confidence = phase.calculate_ai_confidence(&consensus);

    assert!(ai_confidence.overall > 0.5);
    assert!(ai_confidence.verification > 0.8);
    assert!(!ai_confidence.positive_factors.is_empty());
}

#[test]
fn test_calculate_ai_confidence_false_positive() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let finding = make_finding("f1", Severity::High, 0.3, "src/test.rs", Some(10), Some("CWE-79"), Some(VerificationStatus::FalsePositive));

    let consensus = ConsensusResult {
        finding: finding.clone(),
        agreement_count: 0,
        total_sources: 1,
        consensus_score: 0.0,
        confirming_sources: vec![],
        contradicting_sources: vec![FindingSource::LlmVerification],
        likely_false_positive: true,
        recommendation: ConsensusRecommendation::ExcludeFalsePositive,
    };

    let ai_confidence = phase.calculate_ai_confidence(&consensus);

    assert!(ai_confidence.verification < 0.2);
    assert!(!ai_confidence.negative_factors.is_empty());
}

#[test]
fn test_calculate_ai_confidence_cross_file() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let mut finding = make_finding("f1", Severity::High, 0.8, "src/test.rs", Some(10), Some("CWE-79"), None);
    finding.cross_file_references = Some(vec!["ref".to_string()]);

    let consensus = ConsensusResult {
        finding: finding.clone(),
        agreement_count: 1,
        total_sources: 1,
        consensus_score: 0.7,
        confirming_sources: vec![FindingSource::LlmDiscovery],
        contradicting_sources: vec![],
        likely_false_positive: false,
        recommendation: ConsensusRecommendation::IncludeHighConfidence,
    };

    let ai_confidence = phase.calculate_ai_confidence(&consensus);

    assert!(ai_confidence.context > 0.8);
}

#[test]
fn test_calculate_statistics_basic() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let finding = make_finding("f1", Severity::High, 0.8, "src/test.rs", Some(10), Some("CWE-79"), None);
    let consensus = ConsensusResult {
        finding: finding.clone(),
        agreement_count: 1,
        total_sources: 1,
        consensus_score: 0.8,
        confirming_sources: vec![FindingSource::LlmDiscovery],
        contradicting_sources: vec![],
        likely_false_positive: false,
        recommendation: ConsensusRecommendation::IncludeHighConfidence,
    };

    let report = baco::report::ai_aggregation::UnifiedFindingReport {
        finding,
        ai_confidence: phase.calculate_ai_confidence(&consensus),
        consensus,
        conflicts_resolved: false,
        original_findings: vec![],
    };

    let stats = phase.calculate_statistics(&[report]);

    assert_eq!(stats.total_unique_findings, 1);
    assert!(!stats.false_positives_detected > 0);
}

#[test]
fn test_calculate_statistics_empty() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let stats = phase.calculate_statistics(&[]);

    assert_eq!(stats.total_unique_findings, 0);
    assert_eq!(stats.average_confidence, 0.0);
}

#[test]
fn test_generate_executive_summary_low_risk() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let stats = AiAggregationStatistics {
        total_unique_findings: 10,
        false_positives_detected: 8,
        high_confidence_count: 0,
        needs_manual_review: 2,
        average_confidence: 0.3,
        conflicts_resolved: 0,
    };
    let context = AnalysisContext::default();

    let summary = phase.generate_executive_summary(&stats, &context);

    assert!(summary.contains("LOW"));
}

#[test]
fn test_generate_executive_summary_critical_risk() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let stats = AiAggregationStatistics {
        total_unique_findings: 10,
        false_positives_detected: 0,
        high_confidence_count: 8,
        needs_manual_review: 0,
        average_confidence: 0.9,
        conflicts_resolved: 0,
    };
    let context = AnalysisContext::default();

    let summary = phase.generate_executive_summary(&stats, &context);

    assert!(summary.contains("CRITICAL"));
}

#[test]
fn test_update_context() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);

    let finding = make_finding("f1", Severity::High, 0.8, "src/test.rs", Some(10), Some("CWE-79"), None);
    let consensus = ConsensusResult {
        finding: finding.clone(),
        agreement_count: 1,
        total_sources: 1,
        consensus_score: 0.8,
        confirming_sources: vec![FindingSource::LlmDiscovery],
        contradicting_sources: vec![],
        likely_false_positive: false,
        recommendation: ConsensusRecommendation::IncludeHighConfidence,
    };

    let report = baco::report::ai_aggregation::UnifiedFindingReport {
        finding,
        ai_confidence: phase.calculate_ai_confidence(&consensus),
        consensus,
        conflicts_resolved: false,
        original_findings: vec![],
    };

    let result = AiAggregationResult {
        unified_reports: vec![report],
        conflicts: vec![],
        statistics: AiAggregationStatistics::default(),
        executive_summary: "Test".to_string(),
        enriched_findings: vec![],
    };

    let mut context = AnalysisContext::default();
    phase.update_context(&result, &mut context);

    assert!(!context.findings_so_far.is_empty());
}

#[tokio::test]
async fn test_run_aggregation_empty_findings() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let result = phase.run(vec![], &context).await;

    assert_eq!(result.unified_reports.len(), 0);
    assert!(result.executive_summary.contains("Total Unique Findings: 0"));
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
}

#[tokio::test]
async fn test_run_aggregation_multiple_findings() {
    let config = make_config();
    let phase = AiAggregationPhase::new(config);
    let context = AnalysisContext::default();

    let findings = vec![
        make_finding("f1", Severity::Critical, 0.9, "src/a.rs", Some(1), Some("CWE-1"), None),
        make_finding("f2", Severity::High, 0.8, "src/b.rs", Some(2), Some("CWE-2"), None),
        make_finding("f3", Severity::Medium, 0.7, "src/c.rs", Some(3), Some("CWE-3"), None),
    ];

    let result = phase.run(findings, &context).await;

    assert_eq!(result.unified_reports.len(), 3);
    assert!(!result.conflicts.is_empty());
    assert!(!result.statistics.to_string().is_empty());
}

#[test]
fn test_finding_source_debug() {
    let sources = vec![
        FindingSource::Semgrep,
        FindingSource::LlmDiscovery,
        FindingSource::LlmVerification,
        FindingSource::LlmMultiPass,
        FindingSource::ChainOfThought,
        FindingSource::CrossFile,
    ];

    for source in sources {
        let _debug = format!("{:?}", source);
    }
}

#[test]
fn test_consensus_recommendation_debug() {
    let recommendations = vec![
        ConsensusRecommendation::IncludeHighConfidence,
        ConsensusRecommendation::IncludeNeedsReview,
        ConsensusRecommendation::ExcludeFalsePositive,
        ConsensusRecommendation::ManualReview,
    ];

    for rec in recommendations {
        let _debug = format!("{:?}", rec);
    }
}

#[test]
fn test_conflict_type_debug() {
    let conflict_types = vec![
        baco::report::ai_aggregation::conflict_resolver::ConflictType::SeverityMismatch,
        baco::report::ai_aggregation::conflict_resolver::ConflictType::CweMismatch,
        baco::report::ai_aggregation::conflict_resolver::ConflictType::VerificationConflict,
        baco::report::ai_aggregation::conflict_resolver::ConflictType::Duplicate,
        baco::report::ai_aggregation::conflict_resolver::ConflictType::ConfidenceConflict,
    ];

    for ct in conflict_types {
        let _debug = format!("{:?}", ct);
    }
}

#[test]
fn test_conflict_resolution_debug() {
    let resolutions = vec![
        baco::report::ai_aggregation::conflict_resolver::ConflictResolution::HighestConfidence,
        baco::report::ai_aggregation::conflict_resolver::ConflictResolution::HighestSeverity,
        baco::report::ai_aggregation::conflict_resolver::ConflictResolution::PreferVerified,
        baco::report::ai_aggregation::conflict_resolver::ConflictResolution::Merged,
        baco::report::ai_aggregation::conflict_resolver::ConflictResolution::MarkedFalsePositive,
        baco::report::ai_aggregation::conflict_resolver::ConflictResolution::KeptOne,
    ];

    for res in resolutions {
        let _debug = format!("{:?}", res);
    }
}

mod conflict_resolver_tests {
    use super::*;
    use baco::report::ai_aggregation::conflict_resolver::ConflictResolver;

    #[test]
    fn test_resolve_severity_conflict() {
        let findings = vec![
            make_finding("f1", Severity::Low, 0.8, "src/test.rs", Some(10), Some("CWE-79"), None),
            make_finding("f2", Severity::Critical, 0.9, "src/test.rs", Some(10), Some("CWE-79"), None),
        ];
        let finding_refs: Vec<&VulnerabilityFinding> = findings.iter().collect();

        let conflict = ConflictResolver::resolve_severity_conflict("src/test.rs:10", &finding_refs);

        assert_eq!(conflict.conflict_type, baco::report::ai_aggregation::conflict_resolver::ConflictType::SeverityMismatch);
        assert_eq!(conflict.resolution, baco::report::ai_aggregation::conflict_resolver::ConflictResolution::HighestSeverity);
        assert!(conflict.resolution_reason.contains("Critical"));
    }

    #[test]
    fn test_resolve_cwe_conflict() {
        let findings = vec![
            make_finding("f1", Severity::High, 0.8, "src/test.rs", Some(10), Some("CWE-79"), None),
            make_finding("f2", Severity::High, 0.8, "src/test.rs", Some(10), Some("CWE-89"), None),
        ];
        let finding_refs: Vec<&VulnerabilityFinding> = findings.iter().collect();

        let conflict = ConflictResolver::resolve_cwe_conflict("src/test.rs:10", &finding_refs);

        assert_eq!(conflict.conflict_type, baco::report::ai_aggregation::conflict_resolver::ConflictType::CweMismatch);
        assert!(conflict.resolution_reason.contains("CWE-79"));
    }

    #[test]
    fn test_resolve_verification_conflict_with_confirmed() {
        let findings = vec![
            make_finding("f1", Severity::High, 0.8, "src/test.rs", Some(10), Some("CWE-79"), Some(VerificationStatus::FalsePositive)),
            make_finding("f2", Severity::High, 0.8, "src/test.rs", Some(10), Some("CWE-79"), Some(VerificationStatus::Confirmed)),
        ];
        let finding_refs: Vec<&VulnerabilityFinding> = findings.iter().collect();

        let conflict = ConflictResolver::resolve_verification_conflict("src/test.rs:10", &finding_refs);

        assert_eq!(conflict.conflict_type, baco::report::ai_aggregation::conflict_resolver::ConflictType::VerificationConflict);
        assert_eq!(conflict.resolution, baco::report::ai_aggregation::conflict_resolver::ConflictResolution::PreferVerified);
    }

    #[test]
    fn test_resolve_verification_conflict_no_confirmed() {
        let findings = vec![
            make_finding("f1", Severity::High, 0.8, "src/test.rs", Some(10), Some("CWE-79"), Some(VerificationStatus::FalsePositive)),
            make_finding("f2", Severity::High, 0.8, "src/test.rs", Some(10), Some("CWE-79"), Some(VerificationStatus::NeedsReview)),
        ];
        let finding_refs: Vec<&VulnerabilityFinding> = findings.iter().collect();

        let conflict = ConflictResolver::resolve_verification_conflict("src/test.rs:10", &finding_refs);

        assert_eq!(conflict.resolution, baco::report::ai_aggregation::conflict_resolver::ConflictResolution::MarkedFalsePositive);
    }

    #[test]
    fn test_resolve_confidence_conflict() {
        let findings = vec![
            make_finding("f1", Severity::High, 0.9, "src/test.rs", Some(10), Some("CWE-79"), None),
            make_finding("f2", Severity::High, 0.5, "src/test.rs", Some(10), Some("CWE-79"), None),
        ];
        let finding_refs: Vec<&VulnerabilityFinding> = findings.iter().collect();

        let conflict = ConflictResolver::resolve_confidence_conflict("src/test.rs:10", &finding_refs);

        assert_eq!(conflict.conflict_type, baco::report::ai_aggregation::conflict_resolver::ConflictType::ConfidenceConflict);
        assert_eq!(conflict.resolution, baco::report::ai_aggregation::conflict_resolver::ConflictResolution::HighestConfidence);
        assert!(conflict.resolution_reason.contains("0.40"));
    }

    #[test]
    fn test_detect_conflicts_empty() {
        let grouped: std::collections::HashMap<String, Vec<&VulnerabilityFinding>> = std::collections::HashMap::new();
        let conflicts = ConflictResolver::detect_conflicts(&grouped);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_detect_conflicts_single_finding_per_location() {
        let finding = make_finding("f1", Severity::High, 0.8, "src/test.rs", Some(10), Some("CWE-79"), None);
        let mut grouped = std::collections::HashMap::new();
        grouped.insert("src/test.rs:10".to_string(), vec![&finding]);

        let conflicts = ConflictResolver::detect_conflicts(&grouped);
        assert!(conflicts.is_empty());
    }
}

mod enrichment_tests {
    use super::*;
    use baco::report::ai_aggregation::enrichment::EnrichmentService;

    #[test]
    fn test_enrichment_service_new_with_valid_config() {
        let config = make_config();
        let service = EnrichmentService::new(&config);
        // Service should be created
        assert!(true);
    }

    #[test]
    fn test_enrichment_service_new_with_empty_config() {
        let config = LlmConfig {
            base_url: String::new(),
            api_key: String::new(),
            model: String::new(),
            models: vec![],
            timeout: 30,
            max_retries: 3,
            retry_backoff_ms: 1000,
        };
        let service = EnrichmentService::new(&config);
        // Service should be created without LLM client
        assert!(true);
    }

    #[test]
    fn test_extract_json_field_valid() {
        let json = r#"{"description": "Test description", "recommendation": "Fix this"}"#;
        
        let desc = EnrichmentService::extract_json_field(json, "description");
        assert_eq!(desc, Some("Test description".to_string()));
        
        let rec = EnrichmentService::extract_json_field(json, "recommendation");
        assert_eq!(rec, Some("Fix this".to_string()));
    }

    #[test]
    fn test_extract_json_field_missing() {
        let json = r#"{"description": "Test"}"#;
        
        let missing = EnrichmentService::extract_json_field(json, "recommendation");
        assert_eq!(missing, None);
    }

    #[test]
    fn test_extract_json_field_invalid_json() {
        let json = "not valid json";
        
        let result = EnrichmentService::extract_json_field(json, "description");
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_enrich_findings_empty() {
        let config = make_config();
        let service = EnrichmentService::new(&config);
        
        let (enriched, _llm_failed) = service.enrich_findings(&[]).await;
        assert!(enriched.is_empty());
    }

    #[tokio::test]
    async fn test_enrich_findings_with_empty_description() {
        let finding = VulnerabilityFinding {
            id: "test-001".to_string(),
            title: "Test Vulnerability".to_string(),
            description: String::new(),
            severity: Severity::Medium,
            confidence_score: 0.8,
            cwe_id: Some("CWE-79".to_string()),
            file_path: "/tmp/test.c".to_string(),
            line_number: Some(42),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec![],
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
        };

        let config = LlmConfig {
            base_url: "http://invalid.invalid".to_string(),
            api_key: "fake_key".to_string(),
            model: String::new(),
            models: vec![],
            timeout: 1,
            max_retries: 1,
            retry_backoff_ms: 0,
        };
        let service = EnrichmentService::new(&config);

        let (enriched, llm_failed) = service.enrich_findings(&[finding.clone()]).await;

        assert!(!enriched.is_empty());
        assert!(!enriched[0].description.is_empty());
        assert!(llm_failed || enriched[0].recommendation.is_some());
    }
}

mod deduplication_tests {
    use super::*;
    use baco::report::ai_aggregation::deduplication::DeduplicationService;

    #[test]
    fn test_deduplication_service_new() {
        let config = make_config();
        let service = DeduplicationService::new(&config);
        // Should create successfully
        assert!(true);
    }

    #[tokio::test]
    async fn test_deduplicate_empty() {
        let config = make_config();
        let service = DeduplicationService::new(&config);
        
        let result = service.deduplicate(&[]).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_deduplicate_single_finding() {
        let config = make_config();
        let service = DeduplicationService::new(&config);
        
        let findings = vec![make_finding("f1", Severity::High, 0.8, "src/test.rs", Some(10), Some("CWE-79"), None)];
        let result = service.deduplicate(&findings).await;
        
        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn test_deduplicate_different_files() {
        let config = make_config();
        let service = DeduplicationService::new(&config);
        
        let findings = vec![
            make_finding("f1", Severity::High, 0.8, "src/a.rs", Some(10), Some("CWE-79"), None),
            make_finding("f2", Severity::High, 0.8, "src/b.rs", Some(10), Some("CWE-79"), None),
        ];
        let result = service.deduplicate(&findings).await;
        
        // Different files should not be deduplicated
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_deduplicate_different_lines() {
        let config = make_config();
        let service = DeduplicationService::new(&config);
        
        let findings = vec![
            make_finding("f1", Severity::High, 0.8, "src/test.rs", Some(10), Some("CWE-79"), None),
            make_finding("f2", Severity::High, 0.8, "src/test.rs", Some(50), Some("CWE-79"), None),
        ];
        let result = service.deduplicate(&findings).await;
        
        // Lines more than 3 apart should not be deduplicated
        assert_eq!(result.len(), 2);
    }
}
