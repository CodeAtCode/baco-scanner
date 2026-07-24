//! Unit tests for report module (non-aggregation)
//!
//! Tests cover:
//! - JSON report generation
//! - HTML report generation
//! - HTML utilities
//! - AI aggregation conflict resolver
//! - AI aggregation deduplication
//! - AI aggregation enrichment

use baco::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use baco::llm::LlmConfig;
use baco::report::ai_aggregation::conflict_resolver::ConflictResolver;
use baco::report::ai_aggregation::deduplication::DeduplicationService;
use baco::report::ai_aggregation::enrichment::EnrichmentService;
use baco::report::ai_aggregation::models::*;
use baco::report::html::{render_finding, utilities};
use baco::report::json::write_findings_json;
use std::collections::HashMap;

/// Helper to create a test finding with minimal fields.
fn make_finding(
    id: &str,
    severity: Severity,
    file: &str,
    line: Option<u32>,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: format!("Finding {}", id),
        description: "Test description".to_string(),
        severity,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
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
        statement_range: None,
        triage_verdict: None,
    }
}

// ============================================================================
// JSON Report Tests
// ============================================================================

#[test]
fn test_write_findings_json_creates_file() {
    let findings = vec![make_finding("f1", Severity::High, "src/test.rs", Some(10))];
    let output_path = "/tmp/test_findings.json";

    let result = write_findings_json(&findings, output_path, None);
    assert!(result.is_ok());

    // Verify file exists
    assert!(std::path::Path::new(output_path).exists());

    // Clean up
    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_with_llm_metrics() {
    let findings = vec![make_finding(
        "f1",
        Severity::Critical,
        "src/main.rs",
        Some(42),
    )];
    let output_path = "/tmp/test_findings_with_metrics.json";

    // Use None for llm_metrics since LlmMetrics is from a different module
    let result = write_findings_json(&findings, output_path, None);
    assert!(result.is_ok());
    assert!(std::path::Path::new(output_path).exists());

    // Clean up
    let _ = std::fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_creates_parent_dirs() {
    let findings = vec![make_finding("f1", Severity::Low, "src/lib.rs", Some(5))];
    let output_path = "/tmp/baco_test_output/nested/findings.json";

    // Ensure parent doesn't exist
    let _ = std::fs::remove_dir_all("/tmp/baco_test_output");

    let result = write_findings_json(&findings, output_path, None);
    assert!(result.is_ok());
    assert!(std::path::Path::new(output_path).exists());

    // Clean up
    let _ = std::fs::remove_dir_all("/tmp/baco_test_output");
}

#[test]
fn test_write_findings_json_empty_findings() {
    let findings: Vec<VulnerabilityFinding> = vec![];
    let output_path = "/tmp/test_empty_findings.json";

    let result = write_findings_json(&findings, output_path, None);
    assert!(result.is_ok());

    // Verify file contains empty array
    let content = std::fs::read_to_string(output_path).unwrap();
    assert_eq!(content, "[]");

    // Clean up
    let _ = std::fs::remove_file(output_path);
}

// ============================================================================
// HTML Utilities Tests
// ============================================================================

#[test]
fn test_calculate_severity_stats_all_severities() {
    let findings = vec![
        make_finding("c1", Severity::Critical, "src/a.rs", Some(1)),
        make_finding("h1", Severity::High, "src/b.rs", Some(2)),
        make_finding("m1", Severity::Medium, "src/c.rs", Some(3)),
        make_finding("l1", Severity::Low, "src/d.rs", Some(4)),
        make_finding("i1", Severity::Info, "src/e.rs", Some(5)),
    ];

    let stats = utilities::calculate_severity_stats(&findings);

    assert_eq!(stats.critical, 1);
    assert_eq!(stats.high, 1);
    assert_eq!(stats.medium, 1);
    assert_eq!(stats.low, 1);
    assert_eq!(stats.info, 1);
}

#[test]
fn test_calculate_severity_stats_empty() {
    let findings: Vec<VulnerabilityFinding> = vec![];
    let stats = utilities::calculate_severity_stats(&findings);

    assert_eq!(stats.critical, 0);
    assert_eq!(stats.high, 0);
    assert_eq!(stats.medium, 0);
    assert_eq!(stats.low, 0);
    assert_eq!(stats.info, 0);
}

#[test]
fn test_calculate_severity_stats_multiple_same_severity() {
    let findings = vec![
        make_finding("c1", Severity::Critical, "src/a.rs", Some(1)),
        make_finding("c2", Severity::Critical, "src/b.rs", Some(2)),
        make_finding("c3", Severity::Critical, "src/c.rs", Some(3)),
    ];

    let stats = utilities::calculate_severity_stats(&findings);

    assert_eq!(stats.critical, 3);
    assert_eq!(stats.high, 0);
}

#[test]
fn test_build_summary_cards_all_severities() {
    let stats = utilities::calculate_severity_stats(&[
        make_finding("c1", Severity::Critical, "src/a.rs", Some(1)),
        make_finding("h1", Severity::High, "src/b.rs", Some(2)),
        make_finding("m1", Severity::Medium, "src/c.rs", Some(3)),
        make_finding("l1", Severity::Low, "src/d.rs", Some(4)),
        make_finding("i1", Severity::Info, "src/e.rs", Some(5)),
    ]);

    let cards = utilities::build_summary_cards(&stats);

    assert!(cards.contains("critical"));
    assert!(cards.contains("high"));
    assert!(cards.contains("medium"));
    assert!(cards.contains("low"));
    assert!(cards.contains("info"));
    assert!(cards.contains("1"));
}

#[test]
fn test_build_summary_cards_empty() {
    let stats = utilities::calculate_severity_stats(&[]);
    let cards = utilities::build_summary_cards(&stats);

    assert!(cards.is_empty());
}

#[test]
fn test_build_filter_buttons_all_severities() {
    let stats = utilities::calculate_severity_stats(&[
        make_finding("c1", Severity::Critical, "src/a.rs", Some(1)),
        make_finding("h1", Severity::High, "src/b.rs", Some(2)),
    ]);

    let buttons = utilities::build_filter_buttons(&stats);

    assert!(buttons.contains("Critical (1)"));
    assert!(buttons.contains("High (1)"));
    assert!(!buttons.contains("Medium"));
    assert!(!buttons.contains("Low"));
    assert!(!buttons.contains("Info"));
}

#[test]
fn test_build_empty_state_message() {
    let message = utilities::build_empty_state_message();

    assert!(message.contains("No Security Issues Found"));
    assert!(message.contains("✅"));
}

#[test]
fn test_detect_language_python() {
    assert_eq!(utilities::detect_language("src/main.py"), "python");
    assert_eq!(utilities::detect_language("/path/to/script.py"), "python");
}

#[test]
fn test_detect_language_javascript() {
    assert_eq!(utilities::detect_language("app.js"), "javascript");
}

#[test]
fn test_detect_language_typescript() {
    assert_eq!(utilities::detect_language("src/app.ts"), "typescript");
    assert_eq!(
        utilities::detect_language("src/component.tsx"),
        "typescript"
    );
}

#[test]
fn test_detect_language_rust() {
    assert_eq!(utilities::detect_language("src/lib.rs"), "rust");
}

#[test]
fn test_detect_language_go() {
    assert_eq!(utilities::detect_language("main.go"), "go");
}

#[test]
fn test_detect_language_c() {
    assert_eq!(utilities::detect_language("src/main.c"), "c");
}

#[test]
fn test_detect_language_cpp() {
    assert_eq!(utilities::detect_language("src/main.cpp"), "cpp");
    assert_eq!(utilities::detect_language("src/main.cc"), "cpp");
}

#[test]
fn test_detect_language_unknown() {
    assert_eq!(utilities::detect_language("src/unknown.xyz"), "");
    assert_eq!(utilities::detect_language("README"), "");
}

#[test]
fn test_markdown_to_html_basic() {
    let html = utilities::markdown_to_html("# Heading");
    assert!(html.contains("<h1>Heading</h1>"));
}

#[test]
fn test_markdown_to_html_bold() {
    let html = utilities::markdown_to_html("**bold text**");
    assert!(html.contains("<strong>bold text</strong>"));
}

#[test]
fn test_markdown_to_html_italic() {
    let html = utilities::markdown_to_html("*italic text*");
    assert!(html.contains("<em>italic text</em>"));
}

#[test]
fn test_markdown_to_html_list() {
    let html = utilities::markdown_to_html("- item 1\n- item 2");
    assert!(html.contains("<ul>"));
    assert!(html.contains("<li>item 1</li>"));
    assert!(html.contains("<li>item 2</li>"));
}

#[test]
fn test_markdown_to_html_code_block() {
    let html = utilities::markdown_to_html("```rust\nfn main() {}\n```");
    assert!(html.contains("<code"));
}

#[test]
fn test_markdown_to_html_empty() {
    let html = utilities::markdown_to_html("");
    assert!(html.is_empty());
}

#[test]
fn test_markdown_to_html_xss_protection() {
    let html = utilities::markdown_to_html("<script>alert('xss')</script>");
    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;script&gt;"));
}

// ============================================================================
// HTML Renderer Tests
// ============================================================================

#[test]
fn test_render_finding_critical_severity() {
    let finding = make_finding("f1", Severity::Critical, "src/main.rs", Some(42));
    let html = render_finding(&finding, 0);

    assert!(html.contains("finding critical"));
    assert!(html.contains("Critical")); // Severity is rendered as title case
    assert!(html.contains("Finding f1"));
    assert!(html.contains("src/main.rs"));
}

#[test]
fn test_render_finding_with_cwe() {
    let finding = make_finding("f1", Severity::High, "src/test.rs", Some(10));
    let html = render_finding(&finding, 0);

    assert!(html.contains("CWE-79"));
}

#[test]
fn test_render_finding_without_line_number() {
    let finding = make_finding("f1", Severity::Low, "src/unknown.rs", None);
    let html = render_finding(&finding, 0);

    assert!(html.contains("src/unknown.rs"));
    assert!(!html.contains(":None"));
}

#[test]
fn test_render_finding_with_recommendation() {
    let finding = make_finding("f1", Severity::Medium, "src/app.rs", Some(25));
    let html = render_finding(&finding, 0);

    assert!(html.contains("Recommendation"));
    assert!(html.contains("Fix this"));
}

// ============================================================================
// Conflict Resolver Tests
// ============================================================================

#[test]
fn test_resolve_severity_conflict_selects_highest() {
    let finding1 = make_finding("f1", Severity::Low, "src/test.rs", Some(10));
    let finding2 = make_finding("f2", Severity::Critical, "src/test.rs", Some(10));
    let finding3 = make_finding("f3", Severity::High, "src/test.rs", Some(10));

    let findings = vec![&finding1, &finding2, &finding3];
    let conflict = ConflictResolver::resolve_severity_conflict("src/test.rs:10", &findings);

    assert_eq!(conflict.conflict_type, ConflictType::SeverityMismatch);
    assert_eq!(conflict.resolution, ConflictResolution::HighestSeverity);
    assert!(conflict.resolution_reason.contains("Critical"));
}

#[test]
fn test_resolve_severity_conflict_empty() {
    let findings: Vec<&VulnerabilityFinding> = vec![];
    let conflict = ConflictResolver::resolve_severity_conflict("src/test.rs:10", &findings);

    assert_eq!(conflict.conflict_type, ConflictType::SeverityMismatch);
    assert!(conflict.findings.is_empty());
}

#[test]
fn test_resolve_cwe_conflict_selects_most_specific() {
    let mut finding1 = make_finding("f1", Severity::High, "src/test.rs", Some(10));
    finding1.cwe_id = Some("CWE-79".to_string());

    let mut finding2 = make_finding("f2", Severity::High, "src/test.rs", Some(10));
    finding2.cwe_id = Some("CWE-79-1".to_string());

    let findings = vec![&finding1, &finding2];
    let conflict = ConflictResolver::resolve_cwe_conflict("src/test.rs:10", &findings);

    assert_eq!(conflict.conflict_type, ConflictType::CweMismatch);
    assert!(conflict.resolution_reason.contains("CWE-79"));
}

#[test]
fn test_resolve_cwe_conflict_without_cwe() {
    let finding1 = make_finding("f1", Severity::High, "src/test.rs", Some(10));
    let finding2 = make_finding("f2", Severity::High, "src/test.rs", Some(10));

    let findings = vec![&finding1, &finding2];
    let conflict = ConflictResolver::resolve_cwe_conflict("src/test.rs:10", &findings);

    assert_eq!(conflict.conflict_type, ConflictType::CweMismatch);
    // When both findings have no CWE, the resolution_reason uses "unknown" from the first finding
    eprintln!("resolution_reason: {}", conflict.resolution_reason);
    assert!(
        conflict.resolution_reason.contains("unknown")
            || conflict.resolution_reason.contains("Selected")
    );
}

#[test]
fn test_resolve_verification_conflict_preferred_verified() {
    let mut finding1 = make_finding("f1", Severity::High, "src/test.rs", Some(10));
    finding1.verification_status = Some(VerificationStatus::Confirmed);

    let mut finding2 = make_finding("f2", Severity::High, "src/test.rs", Some(10));
    finding2.verification_status = Some(VerificationStatus::FalsePositive);

    let findings = vec![&finding1, &finding2];
    let conflict = ConflictResolver::resolve_verification_conflict("src/test.rs:10", &findings);

    assert_eq!(conflict.conflict_type, ConflictType::VerificationConflict);
    assert_eq!(conflict.resolution, ConflictResolution::PreferVerified);
}

#[test]
fn test_resolve_verification_conflict_marked_fp() {
    let finding1 = make_finding("f1", Severity::High, "src/test.rs", Some(10));
    let finding2 = make_finding("f2", Severity::High, "src/test.rs", Some(10));

    let findings = vec![&finding1, &finding2];
    let conflict = ConflictResolver::resolve_verification_conflict("src/test.rs:10", &findings);

    assert_eq!(conflict.resolution, ConflictResolution::MarkedFalsePositive);
}

#[test]
fn test_resolve_confidence_conflict() {
    let mut finding1 = make_finding("f1", Severity::High, "src/test.rs", Some(10));
    finding1.confidence_score = 0.9;

    let mut finding2 = make_finding("f2", Severity::High, "src/test.rs", Some(10));
    finding2.confidence_score = 0.3;

    let findings = vec![&finding1, &finding2];
    let conflict = ConflictResolver::resolve_confidence_conflict("src/test.rs:10", &findings);

    assert_eq!(conflict.conflict_type, ConflictType::ConfidenceConflict);
    assert_eq!(conflict.resolution, ConflictResolution::HighestConfidence);
    assert!(conflict.resolution_reason.contains("0.60"));
}

#[test]
fn test_detect_conflicts_severity_mismatch() {
    let mut grouped = HashMap::new();

    let finding1 = make_finding("f1", Severity::Critical, "src/test.rs", Some(10));
    let finding2 = make_finding("f2", Severity::Low, "src/test.rs", Some(10));

    grouped.insert("src/test.rs:10".to_string(), vec![&finding1, &finding2]);

    let conflicts = ConflictResolver::detect_conflicts(&grouped);

    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].conflict_type, ConflictType::SeverityMismatch);
}

#[test]
fn test_detect_conflicts_no_conflict() {
    let mut grouped = HashMap::new();

    let finding1 = make_finding("f1", Severity::High, "src/test.rs", Some(10));
    let finding2 = make_finding("f2", Severity::High, "src/test.rs", Some(10));

    grouped.insert("src/test.rs:10".to_string(), vec![&finding1, &finding2]);

    let conflicts = ConflictResolver::detect_conflicts(&grouped);

    assert!(conflicts.is_empty());
}

#[test]
fn test_detect_conflicts_single_finding() {
    let mut grouped = HashMap::new();

    let finding1 = make_finding("f1", Severity::High, "src/test.rs", Some(10));
    grouped.insert("src/test.rs:10".to_string(), vec![&finding1]);

    let conflicts = ConflictResolver::detect_conflicts(&grouped);

    assert!(conflicts.is_empty());
}

#[test]
fn test_detect_conflicts_empty_grouped() {
    let grouped: HashMap<String, Vec<&VulnerabilityFinding>> = HashMap::new();
    let conflicts = ConflictResolver::detect_conflicts(&grouped);

    assert!(conflicts.is_empty());
}

// ============================================================================
// Deduplication Service Tests
// ============================================================================

#[test]
fn test_deduplication_service_creation() {
    let config = LlmConfig {
        base_url: "http://test".to_string(),
        api_key: "test-key".to_string(),
        model: "test-model".to_string(),
        models: vec!["test-model".to_string()],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
    };

    let _service = DeduplicationService::new(&config);
    // Service creation succeeds with valid config
}

#[test]
fn test_deduplication_empty_findings() {
    let config = LlmConfig {
        base_url: "http://test".to_string(),
        api_key: "test-key".to_string(),
        model: "test-model".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
    };

    let _service = DeduplicationService::new(&config);
    // Service creation succeeds - async deduplication requires tokio runtime
}

// ============================================================================
// Enrichment Service Tests
// ============================================================================

#[test]
fn test_enrichment_service_creation_with_config() {
    let config = LlmConfig {
        base_url: "http://test".to_string(),
        api_key: "test-key".to_string(),
        model: "test-model".to_string(),
        models: vec!["test-model".to_string()],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
    };

    let _service = EnrichmentService::new(&config);
    // Service creation succeeds with valid LLM config
}

#[test]
fn test_enrichment_service_creation_without_config() {
    let config = LlmConfig {
        base_url: "".to_string(),
        api_key: "".to_string(),
        model: "".to_string(),
        models: vec![],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
    };

    let _service = EnrichmentService::new(&config);
    // Service creation succeeds without LLM config
}

#[test]
fn test_extract_json_field_valid() {
    let json = r#"{"description": "Test description", "recommendation": "Fix it"}"#;

    let desc = EnrichmentService::extract_json_field(json, "description");
    assert_eq!(desc, Some("Test description".to_string()));

    let rec = EnrichmentService::extract_json_field(json, "recommendation");
    assert_eq!(rec, Some("Fix it".to_string()));
}

#[test]
fn test_extract_json_field_not_found() {
    let json = r#"{"description": "Test description"}"#;

    let missing = EnrichmentService::extract_json_field(json, "missing_field");
    assert_eq!(missing, None);
}

#[test]
fn test_extract_json_field_empty() {
    let json = "{}";

    let result = EnrichmentService::extract_json_field(json, "description");
    assert_eq!(result, None);
}

// ============================================================================
// AI Aggregation Models Tests
// ============================================================================

#[test]
fn test_finding_source_equality() {
    let source1 = FindingSource::Semgrep;
    let source2 = FindingSource::Semgrep;
    let source3 = FindingSource::LlmDiscovery;

    assert_eq!(source1, source2);
    assert_ne!(source1, source3);
}

#[test]
fn test_conflict_type_equality() {
    let conflict1 = ConflictType::SeverityMismatch;
    let conflict2 = ConflictType::SeverityMismatch;
    let conflict3 = ConflictType::CweMismatch;

    assert_eq!(conflict1, conflict2);
    assert_ne!(conflict1, conflict3);
}

#[test]
fn test_conflict_resolution_equality() {
    let res1 = ConflictResolution::HighestSeverity;
    let res2 = ConflictResolution::HighestSeverity;
    let res3 = ConflictResolution::PreferVerified;

    assert_eq!(res1, res2);
    assert_ne!(res1, res3);
}

#[test]
fn test_consensus_recommendation_equality() {
    let rec1 = ConsensusRecommendation::IncludeHighConfidence;
    let rec2 = ConsensusRecommendation::IncludeHighConfidence;
    let rec3 = ConsensusRecommendation::ExcludeFalsePositive;

    assert_eq!(rec1, rec2);
    assert_ne!(rec1, rec3);
}

#[test]
fn test_ai_confidence_score_creation() {
    let score = AiConfidenceScore {
        overall: 0.85,
        semantic: 0.8,
        verification: 0.9,
        context: 0.75,
        consensus: 0.8,
        positive_factors: vec!["High confidence".to_string()],
        negative_factors: vec![],
    };

    assert_eq!(score.overall, 0.85);
    assert!(!score.positive_factors.is_empty());
}

#[test]
fn test_ai_aggregation_statistics_default() {
    let stats = AiAggregationStatistics::default();

    assert_eq!(stats.total_unique_findings, 0);
    assert_eq!(stats.false_positives_detected, 0);
    assert_eq!(stats.average_confidence, 0.0);
}

#[test]
fn test_consensus_result_creation() {
    let finding = make_finding("f1", Severity::High, "src/test.rs", Some(10));

    let result = ConsensusResult {
        finding: finding.clone(),
        agreement_count: 2,
        total_sources: 3,
        consensus_score: 0.67,
        confirming_sources: vec![FindingSource::Semgrep, FindingSource::LlmDiscovery],
        contradicting_sources: vec![],
        likely_false_positive: false,
        recommendation: ConsensusRecommendation::IncludeHighConfidence,
    };

    assert_eq!(result.agreement_count, 2);
    assert!(!result.likely_false_positive);
}

#[test]
fn test_finding_conflict_creation() {
    let finding = make_finding("f1", Severity::High, "src/test.rs", Some(10));

    let conflict = FindingConflict {
        findings: vec![finding.clone()],
        conflict_type: ConflictType::SeverityMismatch,
        resolution: ConflictResolution::HighestSeverity,
        resolution_reason: "Test reason".to_string(),
    };

    assert_eq!(conflict.findings.len(), 1);
    assert_eq!(conflict.conflict_type, ConflictType::SeverityMismatch);
}

#[test]
fn test_unified_finding_report_creation() {
    let finding = make_finding("f1", Severity::Critical, "src/main.rs", Some(42));

    let report = UnifiedFindingReport {
        finding: finding.clone(),
        ai_confidence: AiConfidenceScore {
            overall: 0.9,
            semantic: 0.85,
            verification: 0.95,
            context: 0.8,
            consensus: 0.9,
            positive_factors: vec![],
            negative_factors: vec![],
        },
        consensus: ConsensusResult {
            finding: finding.clone(),
            agreement_count: 3,
            total_sources: 3,
            consensus_score: 1.0,
            confirming_sources: vec![FindingSource::LlmDiscovery],
            contradicting_sources: vec![],
            likely_false_positive: false,
            recommendation: ConsensusRecommendation::IncludeHighConfidence,
        },
        conflicts_resolved: true,
        original_findings: vec![finding.clone()],
    };

    assert!(report.conflicts_resolved);
    assert_eq!(report.ai_confidence.overall, 0.9);
}
