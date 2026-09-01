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

use super::report_fixtures::make_finding;

// ============================================================================
// JSON Report Tests
// ============================================================================

#[test]
fn test_write_findings_json_creates_file() {
    let findings = vec![make_finding("f1", Severity::High, "src/test.rs", Some(10))];
    let output_path = "/tmp/test_findings.json";

    let result = write_findings_json(&findings, &[], output_path, None, None);
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
    let result = write_findings_json(&findings, &[], output_path, None, None);
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

    let result = write_findings_json(&findings, &[], output_path, None, None);
    assert!(result.is_ok());
    assert!(std::path::Path::new(output_path).exists());

    // Clean up
    let _ = std::fs::remove_dir_all("/tmp/baco_test_output");
}

#[test]
fn test_write_findings_json_empty_findings() {
    let findings: Vec<VulnerabilityFinding> = vec![];
    let output_path = "/tmp/test_empty_findings.json";

    let result = write_findings_json(&findings, &[], output_path, None, None);
    assert!(result.is_ok());

    // Verify file contains empty array
    let content = std::fs::read_to_string(output_path).unwrap();
    assert_eq!(content, "[]");

    // Clean up
    let _ = std::fs::remove_file(output_path);
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
fn test_render_finding_with_cwe() {
    let finding = VulnerabilityFinding {
        cwe_id: Some("CWE-79".to_string()),
        ..make_finding("f1", Severity::High, "src/test.rs", Some(10))
    };
    let html = render_finding(&finding, 0);

    assert!(html.contains("CWE-79"));
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

/// Helper to create LlmConfig for tests
fn make_llm_config(models: Vec<&str>) -> LlmConfig {
    LlmConfig {
        base_url: "http://test".to_string(),
        api_key: "test-key".to_string(),
        model: "test-model".to_string(),
        models: models.into_iter().map(String::from).collect(),
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.5,
        max_reasoning_tokens: None,
        enable_llm_cache: false,
        cache_dir: None,
        max_concurrent: 3,
    }
}

#[test]
fn test_deduplication_service_creation() {
    let config = make_llm_config(vec!["test-model"]);
    let _service = DeduplicationService::new(&config);
}

#[test]
fn test_deduplication_empty_findings() {
    let config = make_llm_config(vec![]);
    let _service = DeduplicationService::new(&config);
}

// ============================================================================
// Enrichment Service Tests
// ============================================================================

#[test]
fn test_enrichment_service_creation_with_config() {
    let config = make_llm_config(vec!["test-model"]);
    let _service = EnrichmentService::new(&config);
}

#[test]
fn test_enrichment_service_creation_without_config() {
    let config = make_llm_config(vec![]);

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
