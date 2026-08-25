//! Tests for statement-level localization in vulnerability findings
//!
//! Paper: SecVulEval — [arxiv:2505.19828](https://arxiv.org/abs/2505.19828)
//! Claim: Function-level findings miss patterns; statement-level needed

use baco::findings::VulnerabilityFinding;
use baco::llm::LlmConfig;
use baco::llm_analysis::LlmAnalyzer;

#[test]
fn test_statement_range_in_finding_struct() {
    // Test that VulnerabilityFinding can be constructed with statement_range
    let finding_with_range = VulnerabilityFinding {
        id: "test-with-range".to_string(),
        title: "Test Finding".to_string(),
        description: "Test description".to_string(),
        severity: baco::findings::Severity::High,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "test.rs".to_string(),
        line_number: Some(42),
        code_snippet: Some("vulnerable_code()".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix it".to_string()),
        code_location: Some("test.rs:42".to_string()),
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
        statement_range: Some((40, 45)),
        triage_verdict: None,
        evidence: vec![],
        verification_tier: None,
    };

    assert_eq!(finding_with_range.statement_range, Some((40, 45)));

    // Test that VulnerabilityFinding can be constructed without statement_range (backward compatible)
    let finding_without_range = VulnerabilityFinding {
        id: "test-without-range".to_string(),
        title: "Test Finding".to_string(),
        description: "Test description".to_string(),
        severity: baco::findings::Severity::High,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "test.rs".to_string(),
        line_number: Some(42),
        code_snippet: Some("vulnerable_code()".to_string()),
        diff_hunk: None,
        recommendation: Some("Fix it".to_string()),
        code_location: Some("test.rs:42".to_string()),
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
        evidence: vec![],
        verification_tier: None,
    };

    assert_eq!(finding_without_range.statement_range, None);
}

#[test]
fn test_statement_range_json_serialization() {
    // Test that statement_range serializes correctly
    let finding = VulnerabilityFinding {
        id: "test-json".to_string(),
        title: "Test".to_string(),
        description: "Test".to_string(),
        severity: baco::findings::Severity::High,
        confidence_score: 0.8,
        cwe_id: None,
        file_path: "test.rs".to_string(),
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
        statement_range: Some((10, 15)),
        triage_verdict: None,
        evidence: vec![],
        verification_tier: None,
    };

    let json = serde_json::to_string(&finding).unwrap();
    assert!(json.contains("\"statement_range\""));
    assert!(json.contains("[10,15]") || json.contains("[10, 15]"));

    // Test deserialization
    let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.statement_range, Some((10, 15)));
}

#[test]
fn test_statement_range_backward_compatible() {
    // Test that findings without statement_range still work (None default)
    let json_without_range = r#"{
        "id": "test-backward",
        "title": "Test",
        "description": "Test",
        "severity": "high",
        "confidence_score": 0.8,
        "file_path": "test.rs",
        "line_number": 42,
        "already_reported": false,
        "sources": [],
        "agent_mode": false
    }"#;

    let finding: VulnerabilityFinding = serde_json::from_str(json_without_range).unwrap();
    assert_eq!(finding.statement_range, None);
}

#[test]
fn test_statement_range_parsed_from_llm() {
    // Test that LLM response with statement_range is parsed correctly
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = baco::config::ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["rust".to_string()], 512, &scanner_config);

    let json_response = r#"[
        {
            "severity": "high",
            "title": "Buffer Overflow",
            "description": "Potential buffer overflow detected",
            "line": 42,
            "cwe_id": "CWE-120",
            "statement_range": [40, 45]
        }
    ]"#;

    let result = analyzer.parse_llm_response(json_response, "test.rs", "test-model");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings.len(), 1);

    let finding = &findings[0];
    assert_eq!(finding.statement_range, Some((40, 45)));
}

#[test]
fn test_statement_range_none_when_missing() {
    // Test that LLM response without statement_range defaults to None
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = baco::config::ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["rust".to_string()], 512, &scanner_config);

    let json_response = r#"[
        {
            "severity": "medium",
            "title": "Unused Variable",
            "description": "Variable declared but not used",
            "line": 10
        }
    ]"#;

    let result = analyzer.parse_llm_response(json_response, "test.rs", "test-model");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings.len(), 1);

    let finding = &findings[0];
    assert_eq!(finding.statement_range, None);
}

#[test]
fn test_statement_range_invalid_format_ignored() {
    // Test that invalid statement_range formats are ignored (default to None)
    let config = LlmConfig::default();
    let client = baco::llm::LlmClient::new(config.clone());
    let scanner_config = baco::config::ScannerConfig::default();
    let analyzer = LlmAnalyzer::new(client, vec!["rust".to_string()], 512, &scanner_config);

    // Wrong number of elements
    let json_response = r#"[
        {
            "severity": "low",
            "title": "Test",
            "description": "Test",
            "line": 5,
            "statement_range": [10]
        }
    ]"#;

    let result = analyzer.parse_llm_response(json_response, "test.rs", "test-model");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].statement_range, None);

    // Non-numeric values
    let json_response = r#"[
        {
            "severity": "low",
            "title": "Test",
            "description": "Test",
            "line": 5,
            "statement_range": ["a", "b"]
        }
    ]"#;

    let result = analyzer.parse_llm_response(json_response, "test.rs", "test-model");
    assert!(result.is_ok());
    let findings = result.unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].statement_range, None);
}
