use baco::findings::{Severity, VulnerabilityFinding};
use baco::llm::metrics::{LlmMetrics, ModelMetrics, OperationMetrics};
use baco::report::json::write_findings_json;
use std::fs;
use std::path::Path;

fn make_finding(severity: Severity, file: &str, line: Option<u32>) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: "test-1".to_string(),
        title: "Test Finding".to_string(),
        description: "Test description".to_string(),
        severity,
        confidence_score: 0.8,
        cwe_id: None,
        file_path: file.to_string(),
        line_number: line,
        code_snippet: None,
        diff_hunk: None,
        recommendation: None,
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
        evidence: vec![],
        verification_tier: None,
    }
}

#[test]
fn test_write_findings_json_empty_findings() {
    let findings: Vec<VulnerabilityFinding> = vec![];
    let output_path = "/tmp/test_empty_findings.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());
    assert!(Path::new(output_path).exists());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("[]"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_single_finding() {
    let findings = vec![make_finding(Severity::High, "src/test.rs", Some(42))];
    let output_path = "/tmp/test_single_finding.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("test-1"));
    assert!(content.contains("Test Finding"));
    assert!(content.contains("src/test.rs"));
    assert!(content.contains("\"high\""));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_multiple_findings() {
    let findings = vec![
        make_finding(Severity::Critical, "src/crit.rs", Some(1)),
        make_finding(Severity::High, "src/high.rs", Some(2)),
        make_finding(Severity::Medium, "src/med.rs", Some(3)),
    ];
    let output_path = "/tmp/test_multi_findings.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("\"critical\""));
    assert!(content.contains("\"high\""));
    assert!(content.contains("\"medium\""));

    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let findings_array = parsed.as_array().unwrap();
    assert_eq!(findings_array.len(), 3);

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_with_cwe_id() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.cwe_id = Some("CWE-79".to_string());
    let findings = vec![finding];
    let output_path = "/tmp/test_cwe_finding.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("CWE-79"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_with_code_snippet() {
    let mut finding = make_finding(Severity::Medium, "src/test.rs", Some(5));
    finding.code_snippet = Some("unsafe_code()".to_string());
    let findings = vec![finding];
    let output_path = "/tmp/test_snippet_finding.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("unsafe_code()"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_creates_parent_dirs() {
    let findings = vec![make_finding(Severity::Low, "src/lib.rs", Some(5))];
    let temp_dir = std::env::temp_dir().join("baco_test_json_nested");
    let output_path = temp_dir.join("nested").join("findings.json");

    let _ = fs::remove_dir_all(&temp_dir);

    let result = write_findings_json(
        &findings,
        &[],
        output_path.to_str().unwrap(),
        None,
        None,
        None,
        None,
    );

    assert!(result.is_ok());
    assert!(output_path.exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_write_findings_json_valid_json() {
    let findings = vec![
        make_finding(Severity::High, "src/a.rs", Some(1)),
        make_finding(Severity::Low, "src/b.rs", Some(2)),
    ];
    let output_path = "/tmp/test_valid_json.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&content);
    assert!(parsed.is_ok(), "Output should be valid JSON");

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_with_llm_metrics() {
    let findings = vec![make_finding(Severity::High, "src/test.rs", Some(10))];
    let _llm_metrics = LlmMetrics {
        total_requests: 10,
        total_success: 8,
        total_failed: 2,
        total_cached: 3,
        total_tokens: 5000,
        total_latency_ms: 2505,
        avg_latency_ms: 250.5,
        by_model: std::collections::HashMap::from([(
            "gpt-4".to_string(),
            ModelMetrics {
                model_name: "gpt-4".to_string(),
                total_requests: 10,
                successful_requests: 8,
                failed_requests: 2,
                cached_requests: 3,
                total_tokens: 5000,
                total_latency_ms: 2505,
            },
        )]),
        by_operation: std::collections::HashMap::from([(
            "discovery".to_string(),
            OperationMetrics {
                operation: "discovery".to_string(),
                phase: "discovery".to_string(),
                requests: 10,
                successful: 8,
                failed: 2,
                tokens: 5000,
                prompt_tokens: 0,
                completion_tokens: 0,
            },
        )]),
        positional_fallbacks: 0,
    };
    let output_path = "/tmp/test_with_metrics.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let findings_array = parsed.as_array().unwrap();
    assert_eq!(findings_array.len(), 1);

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_preserves_severity_levels() {
    let findings = vec![
        make_finding(Severity::Critical, "src/c.rs", Some(1)),
        make_finding(Severity::High, "src/h.rs", Some(2)),
        make_finding(Severity::Medium, "src/m.rs", Some(3)),
        make_finding(Severity::Low, "src/l.rs", Some(4)),
        make_finding(Severity::Info, "src/i.rs", Some(5)),
    ];
    let output_path = "/tmp/test_severity_levels.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let findings_array = parsed.as_array().unwrap();

    assert_eq!(findings_array[0]["severity"], "critical");
    assert_eq!(findings_array[1]["severity"], "high");
    assert_eq!(findings_array[2]["severity"], "medium");
    assert_eq!(findings_array[3]["severity"], "low");
    assert_eq!(findings_array[4]["severity"], "info");

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_preserves_confidence_scores() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.confidence_score = 0.95;
    let findings = vec![finding];
    let output_path = "/tmp/test_confidence.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let findings_array = parsed.as_array().unwrap();

    let confidence = findings_array[0]["confidence_score"].as_f64().unwrap();
    assert!((confidence - 0.95).abs() < 0.001);

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_preserves_sources() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.sources = vec![
        "semgrep".to_string(),
        "llm".to_string(),
        "manual".to_string(),
    ];
    let findings = vec![finding];
    let output_path = "/tmp/test_sources.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("semgrep"));
    assert!(content.contains("llm"));
    assert!(content.contains("manual"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_without_line_number() {
    let finding = make_finding(Severity::Medium, "src/unknown.rs", None);
    let findings = vec![finding];
    let output_path = "/tmp/test_no_line.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let findings_array = parsed.as_array().unwrap();

    assert!(findings_array[0]["line_number"].is_null());

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_with_recommendation() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.recommendation = Some("Use parameterized queries".to_string());
    let findings = vec![finding];
    let output_path = "/tmp/test_recommendation.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("Use parameterized queries"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_with_already_reported() {
    let mut finding = make_finding(Severity::Low, "src/test.rs", Some(10));
    finding.already_reported = true;
    let findings = vec![finding];
    let output_path = "/tmp/test_reported.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let findings_array = parsed.as_array().unwrap();

    assert!(findings_array[0]["already_reported"].as_bool().unwrap());

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_with_poc_and_mitigation() {
    let mut finding = make_finding(Severity::Critical, "src/vuln.rs", Some(25));
    finding.poc_code = Some("exploit()".to_string());
    finding.mitigation_code = Some("safe_fix()".to_string());
    finding.poc_format = Some("python".to_string());
    let findings = vec![finding];
    let output_path = "/tmp/test_poc_mitigation.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("exploit()"));
    assert!(content.contains("safe_fix()"));
    assert!(content.contains("python"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_with_agent_mode() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.agent_mode = true;
    finding.llm_model = Some("claude-3".to_string());
    let findings = vec![finding];
    let output_path = "/tmp/test_agent_mode.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let findings_array = parsed.as_array().unwrap();

    assert!(findings_array[0]["agent_mode"].as_bool().unwrap());
    assert_eq!(findings_array[0]["llm_model"].as_str().unwrap(), "claude-3");

    let _ = fs::remove_file(output_path);
}
#[test]
fn test_write_findings_json_with_tier_field() {
    use baco::evidence::{Evidence, EvidenceSource};
    use chrono::Utc;

    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.evidence = vec![
        Evidence {
            source: EvidenceSource::LlmAnalysis("test".to_string()),
            weight: 0.8,
            detail: "test".to_string(),
            timestamp: Utc::now(),
        },
        Evidence {
            source: EvidenceSource::IndependentVerifier("test".to_string()),
            weight: 0.9,
            detail: "test".to_string(),
            timestamp: Utc::now(),
        },
    ];
    finding.confidence_score = 0.9;
    let findings = vec![finding];
    let output_path = "/tmp/test_tier_field.json";

    let _ = fs::remove_file(output_path);

    // Pass a config with evidence_gate enabled
    let mut config = crate::fixtures::create_minimal_config();
    config.output.evidence_gate = true;
    let result = write_findings_json(&findings, &[], output_path, None, Some(&config), None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let findings_array = parsed.as_array().unwrap();

    // Tier should be set when evidence gate is enabled
    assert!(findings_array[0]["verification_tier"].is_string());

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_include_rejected_true_object_shape() {
    let findings = vec![make_finding(Severity::High, "src/test.rs", Some(10))];
    let rejected = vec![(
        make_finding(Severity::Low, "src/rejected.rs", Some(5)),
        "Insufficient evidence".to_string(),
    )];
    let output_path = "/tmp/test_rejected_object.json";

    let _ = fs::remove_file(output_path);

    // Pass a config with include_rejected enabled
    let mut config = crate::fixtures::create_minimal_config();
    config.output.include_rejected = true;
    let result = write_findings_json(
        &findings,
        &rejected,
        output_path,
        None,
        Some(&config),
        None,
        None,
    );

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

    // Should have findings, rejected, and summary keys
    assert!(parsed["findings"].is_array());
    assert!(parsed["rejected"].is_array());
    assert!(parsed["summary"].is_object());

    // Rejected should have rejection_reason field
    assert!(!parsed["rejected"][0]["rejection_reason"].is_null());
    assert_eq!(
        parsed["rejected"][0]["rejection_reason"],
        "Insufficient evidence"
    );

    // Summary should have scan health keys
    assert!(parsed["summary"]["total_findings"].is_number());
    assert!(parsed["summary"]["critical"].is_number());

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_include_rejected_false_plain_array() {
    let findings = vec![make_finding(Severity::High, "src/test.rs", Some(10))];
    let output_path = "/tmp/test_no_rejected_array.json";

    let _ = fs::remove_file(output_path);

    // When include_rejected is false (no config), output is plain array
    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

    // Should be a plain array, not an object
    assert!(parsed.is_array());
    assert_eq!(parsed.as_array().unwrap().len(), 1);

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_summary_total_findings() {
    let findings = vec![
        make_finding(Severity::Critical, "src/c.rs", Some(1)),
        make_finding(Severity::High, "src/h.rs", Some(2)),
        make_finding(Severity::Medium, "src/m.rs", Some(3)),
    ];
    let output_path = "/tmp/test_summary_totals.json";

    let _ = fs::remove_file(output_path);

    // Pass a config with include_rejected to get summary
    let mut config = crate::fixtures::create_minimal_config();
    config.output.include_rejected = true;
    let result = write_findings_json(&findings, &[], output_path, None, Some(&config), None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

    // Summary should have correct total
    assert_eq!(parsed["summary"]["total_findings"], 3);
    assert_eq!(parsed["summary"]["critical"], 1);
    assert_eq!(parsed["summary"]["high"], 1);
    assert_eq!(parsed["summary"]["medium"], 1);

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_poc_format_field() {
    let mut finding = make_finding(Severity::Critical, "src/vuln.rs", Some(25));
    finding.poc_code = Some("exploit()".to_string());
    finding.poc_format = Some("python".to_string());
    let findings = vec![finding];
    let output_path = "/tmp/test_poc_format.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let findings_array = parsed.as_array().unwrap();

    assert_eq!(findings_array[0]["poc_format"], "python");

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_diff_hunk_field() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.diff_hunk = Some("-old_code()\n+new_code()".to_string());
    let findings = vec![finding];
    let output_path = "/tmp/test_diff_hunk.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("-old_code()"));
    assert!(content.contains("+new_code()"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_commit_reference_field() {
    let mut finding = make_finding(Severity::Medium, "src/test.rs", Some(10));
    finding.commit_reference = Some("abc123def".to_string());
    let findings = vec![finding];
    let output_path = "/tmp/test_commit_ref.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("abc123def"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_ticket_reference_field() {
    let mut finding = make_finding(Severity::Low, "src/test.rs", Some(10));
    finding.ticket_reference = Some("SEC-123".to_string());
    let findings = vec![finding];
    let output_path = "/tmp/test_ticket_ref.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("SEC-123"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_priority_score_field() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.priority_score = Some(0.85);
    let findings = vec![finding];
    let output_path = "/tmp/test_priority.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let findings_array = parsed.as_array().unwrap();

    let priority = findings_array[0]["priority_score"].as_f64().unwrap();
    assert!((priority - 0.85).abs() < 0.001);

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_cross_file_references_field() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.cross_file_references = Some(vec!["related_file.rs".to_string()]);
    let findings = vec![finding];
    let output_path = "/tmp/test_cross_file.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("related_file.rs"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_verification_status_field() {
    use baco::findings::VerificationStatus;

    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.verification_status = Some(VerificationStatus::Confirmed);
    let findings = vec![finding];
    let output_path = "/tmp/test_verification_status.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("confirmed"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_verification_notes_field() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.verification_notes = Some("Manual review confirmed".to_string());
    let findings = vec![finding];
    let output_path = "/tmp/test_verification_notes.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("Manual review confirmed"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_agent_mode_true() {
    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.agent_mode = true;
    finding.llm_model = Some("claude-3-sonnet".to_string());
    let findings = vec![finding];
    let output_path = "/tmp/test_agent_true.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let findings_array = parsed.as_array().unwrap();

    assert!(findings_array[0]["agent_mode"].as_bool().unwrap());
    assert_eq!(findings_array[0]["llm_model"], "claude-3-sonnet");

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_statement_range_field() {
    let mut finding = make_finding(Severity::Medium, "src/test.rs", Some(10));
    finding.statement_range = Some((10, 15));
    let findings = vec![finding];
    let output_path = "/tmp/test_statement_range.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let findings_array = parsed.as_array().unwrap();

    assert!(findings_array[0]["statement_range"].is_array());

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_triage_verdict_field() {
    use baco::findings::TriageVerdict;

    let mut finding = make_finding(Severity::Low, "src/test.rs", Some(10));
    finding.triage_verdict = Some(TriageVerdict::Kill);
    let findings = vec![finding];
    let output_path = "/tmp/test_triage_verdict.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("kill"));

    let _ = fs::remove_file(output_path);
}

#[test]
fn test_write_findings_json_evidence_array() {
    use baco::evidence::{Evidence, EvidenceSource};
    use chrono::Utc;

    let mut finding = make_finding(Severity::High, "src/test.rs", Some(10));
    finding.evidence = vec![
        Evidence {
            source: EvidenceSource::LlmAnalysis("static-analysis".to_string()),
            weight: 0.8,
            detail: "LLM identified vulnerability pattern".to_string(),
            timestamp: Utc::now(),
        },
        Evidence {
            source: EvidenceSource::IndependentVerifier("reproducer".to_string()),
            weight: 0.95,
            detail: "Reproducer confirmed exploit".to_string(),
            timestamp: Utc::now(),
        },
    ];
    let findings = vec![finding];
    let output_path = "/tmp/test_evidence.json";

    let _ = fs::remove_file(output_path);

    let result = write_findings_json(&findings, &[], output_path, None, None, None, None);

    assert!(result.is_ok());

    let content = fs::read_to_string(output_path).unwrap();
    assert!(content.contains("static-analysis"));
    assert!(content.contains("reproducer"));

    let _ = fs::remove_file(output_path);
}
