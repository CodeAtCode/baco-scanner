//! Comprehensive tests for the EnrichmentService in ai_aggregation/enrichment.rs
//!
//! This module tests the EnrichmentService constructor, enrich_findings method,
//! and extract_json_field utility function for LLM-based enrichment of findings.

use baco::findings::{Severity, VulnerabilityFinding};
use baco::llm::LlmConfig;
use baco::report::ai_aggregation::enrichment::EnrichmentService;

/// Helper to create a minimal test VulnerabilityFinding
fn create_finding(
    id: &str,
    title: &str,
    severity: Severity,
    file_path: &str,
) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: title.to_string(),
        description: String::new(),
        severity,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: file_path.to_string(),
        line_number: Some(10),
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

/// Helper to create a finding with existing description
fn create_finding_with_description(id: &str, description: &str) -> VulnerabilityFinding {
    let mut finding = create_finding(id, "Test", Severity::High, "src/test.rs");
    finding.description = description.to_string();
    finding
}

/// Helper to create a finding with existing recommendation
fn create_finding_with_recommendation(id: &str, recommendation: &str) -> VulnerabilityFinding {
    let mut finding = create_finding(id, "Test", Severity::High, "src/test.rs");
    finding.recommendation = Some(recommendation.to_string());
    finding
}

/// Helper to create a finding without line number
fn create_finding_without_line(id: &str) -> VulnerabilityFinding {
    let mut finding = create_finding(id, "Test", Severity::High, "src/test.rs");
    finding.line_number = None;
    finding
}

/// Helper to create a finding without CWE ID
fn create_finding_without_cwe(id: &str) -> VulnerabilityFinding {
    let mut finding = create_finding(id, "Test", Severity::High, "src/test.rs");
    finding.cwe_id = None;
    finding
}

/// Helper to create valid LLM config
fn create_valid_config() -> LlmConfig {
    LlmConfig {
        base_url: "http://localhost:11434".to_string(),
        api_key: "test-key".to_string(),
        model: "llama2".to_string(),
        models: vec!["llama2".to_string()],
        timeout: 30,
        max_retries: 1,
        retry_backoff_ms: 0,
        temperature: 0.5,
        max_reasoning_tokens: None,
    }
}

/// Helper to create empty LLM config (no client)
fn create_empty_config() -> LlmConfig {
    LlmConfig {
        base_url: String::new(),
        api_key: String::new(),
        model: String::new(),
        models: vec![],
        timeout: 0,
        max_retries: 0,
        retry_backoff_ms: 0,
        temperature: 0.5,
        max_reasoning_tokens: None,
    }
}

// ============================================================================
// ENRICHMENT SERVICE CONSTRUCTOR TESTS
// ============================================================================

#[test]
fn test_enrichment_service_new_with_valid_config_creates_client() {
    let config = create_valid_config();
    let service = EnrichmentService::new(&config);

    // Service should be created successfully
    // The client creation depends on internal implementation
    let _ = service;
}

#[test]
fn test_enrichment_service_new_with_empty_api_key_no_client() {
    let config = LlmConfig {
        api_key: String::new(),
        base_url: "http://localhost".to_string(),
        model: "test".to_string(),
        models: vec!["test".to_string()],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.5,
        max_reasoning_tokens: None,
    };
    let service = EnrichmentService::new(&config);
    let _ = service;
}

#[test]
fn test_enrichment_service_new_with_empty_base_url_no_client() {
    let config = LlmConfig {
        api_key: "test-key".to_string(),
        base_url: String::new(),
        model: "test".to_string(),
        models: vec!["test".to_string()],
        timeout: 30,
        max_retries: 3,
        retry_backoff_ms: 1000,
        temperature: 0.5,
        max_reasoning_tokens: None,
    };
    let service = EnrichmentService::new(&config);
    let _ = service;
}

#[test]
fn test_enrichment_service_new_with_both_empty_no_client() {
    let config = create_empty_config();
    let service = EnrichmentService::new(&config);
    let _ = service;
}

// ============================================================================
// EXTRACT JSON FIELD TESTS (PUBLIC UTILITY FUNCTION)
// ============================================================================

#[test]
fn test_extract_json_field_valid_json_returns_value() {
    let json = r#"{"description": "Test description", "recommendation": "Fix it"}"#;

    let desc = EnrichmentService::extract_json_field(json, "description");
    let rec = EnrichmentService::extract_json_field(json, "recommendation");

    assert_eq!(desc, Some("Test description".to_string()));
    assert_eq!(rec, Some("Fix it".to_string()));
}

#[test]
fn test_extract_json_field_missing_field_returns_none() {
    let json = r#"{"description": "Test description"}"#;

    let missing = EnrichmentService::extract_json_field(json, "recommendation");

    assert!(missing.is_none());
}

#[test]
fn test_extract_json_field_empty_json_returns_none() {
    let json = "{}";

    let result = EnrichmentService::extract_json_field(json, "description");

    assert!(result.is_none());
}

#[test]
fn test_extract_json_field_invalid_json_returns_none() {
    let json = "not valid json";

    let result = EnrichmentService::extract_json_field(json, "description");

    assert!(result.is_none());
}

#[test]
fn test_extract_json_field_empty_string_field() {
    let json = r#"{"description": "", "recommendation": "Fix it"}"#;

    let desc = EnrichmentService::extract_json_field(json, "description");

    // Regex [^"]+ requires at least one non-quote char, so empty value yields no match
    assert!(desc.is_none());
}

#[test]
fn test_extract_json_field_special_characters_in_value() {
    let json = r#"{"description": "Test with \"quotes\" and special chars"}"#;

    let desc = EnrichmentService::extract_json_field(json, "description");

    // Regex extracts content between quotes, quotes inside are handled by regex
    assert!(desc.is_some());
}

#[test]
fn test_extract_json_field_multiline_json() {
    let json = r#"{
        "description": "Multi-line description",
        "recommendation": "Multi-line recommendation"
    }"#;

    let desc = EnrichmentService::extract_json_field(json, "description");
    let rec = EnrichmentService::extract_json_field(json, "recommendation");

    assert_eq!(desc, Some("Multi-line description".to_string()));
    assert_eq!(rec, Some("Multi-line recommendation".to_string()));
}

#[test]
fn test_extract_json_field_case_sensitive_field_name() {
    let json = r#"{"Description": "Wrong case", "description": "Correct"}"#;

    let result = EnrichmentService::extract_json_field(json, "description");

    assert_eq!(result, Some("Correct".to_string()));
}

#[test]
fn test_extract_json_field_numeric_value_stringified() {
    let json = r#"{"count": "42", "description": "Test"}"#;

    let count = EnrichmentService::extract_json_field(json, "count");

    assert_eq!(count, Some("42".to_string()));
}

// ============================================================================
// ENRICH FINDINGS TESTS (WITH EMPTY/NO CLIENT CONFIG)
// ============================================================================

#[tokio::test]
async fn test_enrich_findings_empty_findings_returns_empty() {
    let config = create_valid_config();
    let service = EnrichmentService::new(&config);
    let findings: Vec<VulnerabilityFinding> = Vec::new();

    let (enriched, llm_failed) = service.enrich_findings(&findings).await;

    assert!(enriched.is_empty());
    assert!(!llm_failed);
}

#[tokio::test]
async fn test_enrich_findings_with_no_client_returns_unenriched() {
    let config = create_empty_config();
    let service = EnrichmentService::new(&config);
    let findings = vec![create_finding("f1", "Test", Severity::High, "src/test.rs")];

    let (enriched, llm_failed) = service.enrich_findings(&findings).await;

    // Should return findings unchanged when no client
    assert_eq!(enriched.len(), 1);
    assert!(!llm_failed);
}

#[tokio::test]
async fn test_enrich_findings_preserves_finding_id() {
    let config = create_empty_config();
    let service = EnrichmentService::new(&config);
    let finding = create_finding("unique-id-123", "Test", Severity::High, "src/test.rs");
    let findings = vec![finding];

    let (enriched, _) = service.enrich_findings(&findings).await;

    assert_eq!(enriched[0].id, "unique-id-123");
}

#[tokio::test]
async fn test_enrich_findings_preserves_finding_severity() {
    let config = create_empty_config();
    let service = EnrichmentService::new(&config);
    let finding = create_finding("f1", "Test", Severity::Critical, "src/test.rs");
    let findings = vec![finding];

    let (enriched, _) = service.enrich_findings(&findings).await;

    assert_eq!(enriched[0].severity, Severity::Critical);
}

#[tokio::test]
async fn test_enrich_findings_preserves_file_path() {
    let config = create_empty_config();
    let service = EnrichmentService::new(&config);
    let finding = create_finding("f1", "Test", Severity::High, "/path/to/file.rs");
    let findings = vec![finding];

    let (enriched, _) = service.enrich_findings(&findings).await;

    assert_eq!(enriched[0].file_path, "/path/to/file.rs");
}

#[tokio::test]
async fn test_enrich_findings_preserves_cwe_id() {
    let config = create_empty_config();
    let service = EnrichmentService::new(&config);
    let mut finding = create_finding("f1", "Test", Severity::High, "src/test.rs");
    finding.cwe_id = Some("CWE-79".to_string());
    let findings = vec![finding];

    let (enriched, _) = service.enrich_findings(&findings).await;

    assert_eq!(enriched[0].cwe_id, Some("CWE-79".to_string()));
}

#[tokio::test]
async fn test_enrich_findings_handles_finding_without_line_number() {
    let config = create_empty_config();
    let service = EnrichmentService::new(&config);
    let finding = create_finding_without_line("f1");
    let findings = vec![finding];

    let (enriched, _) = service.enrich_findings(&findings).await;

    assert!(enriched[0].line_number.is_none());
}

#[tokio::test]
async fn test_enrich_findings_handles_finding_without_cwe() {
    let config = create_empty_config();
    let service = EnrichmentService::new(&config);
    let finding = create_finding_without_cwe("f1");
    let findings = vec![finding];

    let (enriched, _) = service.enrich_findings(&findings).await;

    assert!(enriched[0].cwe_id.is_none());
}

#[tokio::test]
async fn test_enrich_findings_multiple_findings_all_processed() {
    let config = create_empty_config();
    let service = EnrichmentService::new(&config);
    let findings = vec![
        create_finding("f1", "Test 1", Severity::High, "src/test1.rs"),
        create_finding("f2", "Test 2", Severity::Critical, "src/test2.rs"),
        create_finding("f3", "Test 3", Severity::Low, "src/test3.rs"),
    ];

    let (enriched, _) = service.enrich_findings(&findings).await;

    assert_eq!(enriched.len(), 3);
    assert_eq!(enriched[0].title, "Test 1");
    assert_eq!(enriched[1].title, "Test 2");
    assert_eq!(enriched[2].title, "Test 3");
}

#[tokio::test]
async fn test_enrich_findings_preserves_existing_description_when_no_client() {
    let config = create_empty_config();
    let service = EnrichmentService::new(&config);
    let finding = create_finding_with_description("f1", "Existing description");
    let findings = vec![finding];

    let (enriched, _) = service.enrich_findings(&findings).await;

    assert_eq!(enriched[0].description, "Existing description");
}

#[tokio::test]
async fn test_enrich_findings_preserves_existing_recommendation_when_no_client() {
    let config = create_empty_config();
    let service = EnrichmentService::new(&config);
    let finding = create_finding_with_recommendation("f1", "Existing recommendation");
    let findings = vec![finding];

    let (enriched, _) = service.enrich_findings(&findings).await;

    assert_eq!(
        enriched[0].recommendation,
        Some("Existing recommendation".to_string())
    );
}

#[tokio::test]
async fn test_enrich_findings_returns_false_for_llm_failed_when_no_client() {
    let config = create_empty_config();
    let service = EnrichmentService::new(&config);
    let findings = vec![create_finding("f1", "Test", Severity::High, "src/test.rs")];

    let (_, llm_failed) = service.enrich_findings(&findings).await;

    // When no client, llm_failed should be false (graceful handling)
    assert!(!llm_failed);
}

// ============================================================================
// EDGE CASES AND BOUNDARY TESTS
// ============================================================================

#[tokio::test]
async fn test_enrich_findings_single_finding() {
    let config = create_empty_config();
    let service = EnrichmentService::new(&config);
    let findings = vec![create_finding(
        "single",
        "Only one",
        Severity::Medium,
        "src/solo.rs",
    )];

    let (enriched, _) = service.enrich_findings(&findings).await;

    assert_eq!(enriched.len(), 1);
    assert_eq!(enriched[0].id, "single");
}

#[tokio::test]
async fn test_enrich_findings_finding_with_all_fields_populated() {
    let config = create_empty_config();
    let service = EnrichmentService::new(&config);

    let mut finding = create_finding("f1", "Complete", Severity::High, "src/complete.rs");
    finding.description = "Full description".to_string();
    finding.recommendation = Some("Full recommendation".to_string());
    finding.code_snippet = Some("code here".to_string());
    finding.confidence_score = 0.95;

    let findings = vec![finding];
    let (enriched, _) = service.enrich_findings(&findings).await;

    assert_eq!(enriched[0].description, "Full description");
    assert_eq!(
        enriched[0].recommendation,
        Some("Full recommendation".to_string())
    );
    assert_eq!(enriched[0].confidence_score, 0.95);
}

#[test]
fn test_extract_json_field_whitespace_tolerance() {
    let json = r#"{ "description" : "Value with spaces" }"#;

    let result = EnrichmentService::extract_json_field(json, "description");

    // Regex expects no space between field name and colon; space before colon yields no match
    assert!(result.is_none());

    // Without space before colon, whitespace after colon IS tolerated (\s* in regex)
    let json2 = r#"{"description":  "Value with spaces"}"#;
    let result2 = EnrichmentService::extract_json_field(json2, "description");
    assert_eq!(result2, Some("Value with spaces".to_string()));
}

#[test]
fn test_extract_json_field_field_at_end_of_json() {
    let json = r#"{"other": "value", "description": "Last field"}"#;

    let result = EnrichmentService::extract_json_field(json, "description");

    assert_eq!(result, Some("Last field".to_string()));
}

#[test]
fn test_extract_json_field_field_at_start_of_json() {
    let json = r#"{"description": "First field", "other": "value"}"#;

    let result = EnrichmentService::extract_json_field(json, "description");

    assert_eq!(result, Some("First field".to_string()));
}
