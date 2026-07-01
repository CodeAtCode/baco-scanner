//! Tests for SARIF report generation

use baco::findings::{Severity, VulnerabilityFinding};
use baco::report::sarif::generate_sarif_report;

fn make_finding(id: &str, severity: Severity, file: &str, line: Option<u32>) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: format!("Test {}", id),
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
        sources: vec!["semgrep".to_string()],
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
fn test_sarif_schema_version() {
    let findings = vec![make_finding("test-1", Severity::High, "test.c", Some(42))];
    let result = generate_sarif_report(&findings).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["$schema"], "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json");
    assert_eq!(parsed["version"], "2.1.0");
}

#[test]
fn test_sarif_tool_driver() {
    let findings = vec![make_finding("test-1", Severity::Critical, "test.c", Some(42))];
    let result = generate_sarif_report(&findings).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let driver = &parsed["runs"][0]["tool"]["driver"];
    assert_eq!(driver["name"], "BACO Security Scanner");
    assert_eq!(driver["informationUri"], "https://github.com/mte90/baco");
}

#[test]
fn test_sarif_severity_mapping_critical() {
    let findings = vec![make_finding("crit-1", Severity::Critical, "test.c", Some(42))];
    let result = generate_sarif_report(&findings).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["runs"][0]["results"][0]["level"], "error");
}

#[test]
fn test_sarif_severity_mapping_high() {
    let findings = vec![make_finding("high-1", Severity::High, "test.c", Some(42))];
    let result = generate_sarif_report(&findings).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["runs"][0]["results"][0]["level"], "error");
}

#[test]
fn test_sarif_severity_mapping_medium() {
    let findings = vec![make_finding("med-1", Severity::Medium, "test.c", Some(42))];
    let result = generate_sarif_report(&findings).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["runs"][0]["results"][0]["level"], "warning");
}

#[test]
fn test_sarif_severity_mapping_low() {
    let findings = vec![make_finding("low-1", Severity::Low, "test.c", Some(42))];
    let result = generate_sarif_report(&findings).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["runs"][0]["results"][0]["level"], "note");
}

#[test]
fn test_sarif_severity_mapping_info() {
    let findings = vec![make_finding("info-1", Severity::Info, "test.c", Some(42))];
    let result = generate_sarif_report(&findings).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["runs"][0]["results"][0]["level"], "note");
}

#[test]
fn test_sarif_rule_definition() {
    let findings = vec![make_finding("test-1", Severity::High, "test.c", Some(42))];
    let result = generate_sarif_report(&findings).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let rules = parsed["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();

    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["id"], "test-1");
    assert!(rules[0]["shortDescription"]["text"].is_string());
    assert!(rules[0]["fullDescription"]["text"].is_string());
}

#[test]
fn test_sarif_physical_location() {
    let findings = vec![make_finding("test-1", Severity::High, "test.c", Some(42))];
    let result = generate_sarif_report(&findings).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let location = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"];

    assert!(location["artifactLocation"].is_object());
    assert!(location["region"].is_object());
}

#[test]
fn test_sarif_empty_findings() {
    let findings: Vec<VulnerabilityFinding> = vec![];
    let result = generate_sarif_report(&findings).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let results = parsed["runs"][0]["results"].as_array().unwrap();
    assert!(results.is_empty());
}

#[test]
fn test_sarif_multiple_findings() {
    let findings = vec![
        make_finding("test-1", Severity::Critical, "test.c", Some(42)),
        make_finding("test-2", Severity::High, "test.c", Some(43)),
        make_finding("test-3", Severity::Medium, "test.c", Some(44)),
    ];
    let result = generate_sarif_report(&findings).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let results = parsed["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
}

#[test]
fn test_sarif_cwe_help_uri() {
    let mut finding = make_finding("test-1", Severity::High, "test.c", Some(42));
    finding.cwe_id = Some("CWE-79".to_string());
    let findings = vec![finding];

    let result = generate_sarif_report(&findings).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let rule = &parsed["runs"][0]["tool"]["driver"]["rules"][0];

    assert!(rule["helpUri"].as_str().unwrap().contains("79.html"));
}

#[test]
fn test_sarif_without_line_number() {
    let findings = vec![make_finding("test-1", Severity::High, "test.c", None)];
    let result = generate_sarif_report(&findings).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let region = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];

    assert!(region.is_object());
}

#[test]
fn test_sarif_poc_related_locations() {
    let mut finding = make_finding("test-1", Severity::High, "test.c", Some(42));
    finding.poc_code = Some("cursor.execute(f'SELECT * FROM users WHERE id = {user_input})')".to_string());
    finding.mitigation_code = Some("cursor.execute('SELECT * FROM users WHERE id = %s', (user_input,))".to_string());
    finding.poc_format = Some("python".to_string());

    let findings = vec![finding];
    let result = generate_sarif_report(&findings).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

    let related = &parsed["runs"][0]["results"][0]["relatedLocations"];
    assert!(related.is_array());
    let arr = related.as_array().unwrap();
    assert_eq!(arr.len(), 2);

    assert!(arr[0]["location"]["message"]["text"].as_str().unwrap().contains("Proof of Concept"));
    assert!(arr[1]["location"]["message"]["text"].as_str().unwrap().contains("Mitigation"));
}

#[test]
fn test_sarif_empty_file_path() {
    let mut finding = make_finding("test-1", Severity::High, "test.c", Some(42));
    finding.file_path = String::new();
    let findings = vec![finding];

    let result = generate_sarif_report(&findings).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

    // Should handle empty file path gracefully
    assert!(parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"].is_object());
}

#[test]
fn test_sarif_version_field() {
    let findings = vec![make_finding("test-1", Severity::High, "test.c", Some(42))];
    let result = generate_sarif_report(&findings).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

    let version = parsed["runs"][0]["tool"]["driver"]["version"].as_str().unwrap();
    assert!(!version.is_empty());
}
