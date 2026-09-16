use baco::findings::{Severity, VulnerabilityFinding};
use baco::report::sarif::generate_sarif_report;

fn make_finding(severity: Severity, id: &str) -> VulnerabilityFinding {
    VulnerabilityFinding {
        id: id.to_string(),
        title: format!("Test {}", id),
        description: "Test description".to_string(),
        severity,
        confidence_score: 0.8,
        cwe_id: Some("CWE-79".to_string()),
        file_path: "test.c".to_string(),
        line_number: Some(42),
        code_snippet: Some("printf(x)".to_string()),
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
        statement_range: None,
        triage_verdict: None,
        evidence: vec![],
        verification_tier: None,
    }
}

#[test]
fn test_sarif_schema_version() {
    let findings = vec![make_finding(Severity::High, "test-1")];
    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["$schema"], "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json");
    assert_eq!(parsed["version"], "2.1.0");
}

#[test]
fn test_sarif_tool_driver() {
    let findings = vec![make_finding(Severity::Critical, "test-1")];
    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let driver = &parsed["runs"][0]["tool"]["driver"];
    assert_eq!(driver["name"], "BACO Security Scanner");
    assert_eq!(driver["informationUri"], "https://github.com/mte90/baco");
}

#[test]
fn test_sarif_severity_mapping() {
    let findings = vec![
        make_finding(Severity::Critical, "crit-1"),
        make_finding(Severity::High, "high-1"),
        make_finding(Severity::Medium, "med-1"),
        make_finding(Severity::Low, "low-1"),
        make_finding(Severity::Info, "info-1"),
    ];
    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let results = parsed["runs"][0]["results"].as_array().unwrap();

    assert_eq!(results[0]["level"], "error");
    assert_eq!(results[1]["level"], "error");
    assert_eq!(results[2]["level"], "warning");
    assert_eq!(results[3]["level"], "note");
    assert_eq!(results[4]["level"], "note");
}

#[test]
fn test_sarif_rule_definition() {
    let findings = vec![make_finding(Severity::High, "test-1")];
    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();

    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["id"], "test-1");
    assert!(rules[0]["shortDescription"]["text"].is_string());
    assert!(rules[0]["fullDescription"]["text"].is_string());
}

#[test]
fn test_sarif_physical_location() {
    let findings = vec![make_finding(Severity::High, "test-1")];
    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let location = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"];

    assert!(location["artifactLocation"].is_object());
    assert!(location["region"].is_object());
}

#[test]
fn test_sarif_empty_findings() {
    let findings: Vec<VulnerabilityFinding> = vec![];
    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let results = parsed["runs"][0]["results"].as_array().unwrap();
    assert!(results.is_empty());
}

#[test]
fn test_sarif_multiple_findings() {
    let findings = vec![
        make_finding(Severity::Critical, "test-1"),
        make_finding(Severity::High, "test-2"),
        make_finding(Severity::Medium, "test-3"),
    ];
    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let results = parsed["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
}

#[test]
fn test_sarif_cwe_help_uri() {
    let mut finding = make_finding(Severity::High, "test-1");
    finding.cwe_id = Some("CWE-79".to_string());
    let findings = vec![finding];

    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let rule = &parsed["runs"][0]["tool"]["driver"]["rules"][0];

    assert!(rule["helpUri"].as_str().unwrap().contains("79.html"));
}

#[test]
fn test_sarif_without_line_number() {
    let mut finding = make_finding(Severity::High, "test-1");
    finding.line_number = None;
    let findings = vec![finding];

    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let region = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];

    assert!(region.is_object());
}

#[test]
fn test_sarif_poc_related_locations() {
    let mut finding = make_finding(Severity::High, "test-1");
    finding.poc_code =
        Some("cursor.execute(f'SELECT * FROM users WHERE id = {user_input})')".to_string());
    finding.mitigation_code =
        Some("cursor.execute('SELECT * FROM users WHERE id = %s', (user_input,))".to_string());
    finding.poc_format = Some("python".to_string());

    let findings = vec![finding];
    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

    let related = &parsed["runs"][0]["results"][0]["relatedLocations"];
    assert!(related.is_array());
    let arr = related.as_array().unwrap();
    assert_eq!(arr.len(), 2);

    assert!(arr[0]["location"]["message"]["text"]
        .as_str()
        .unwrap()
        .contains("Proof of Concept"));
    assert!(arr[1]["location"]["message"]["text"]
        .as_str()
        .unwrap()
        .contains("Mitigation"));
}

#[test]
fn test_sarif_cwe_in_properties() {
    let mut finding = make_finding(Severity::High, "test-1");
    finding.cwe_id = Some("CWE-89".to_string());
    let findings = vec![finding];

    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let rule = &parsed["runs"][0]["tool"]["driver"]["rules"][0];

    // CWE should be in properties or helpUri
    assert!(
        rule["helpUri"].as_str().unwrap().contains("89.html"),
        "CWE should appear in helpUri"
    );
}

#[test]
fn test_sarif_rule_id_stability() {
    let finding1 = make_finding(Severity::High, "stable-id-1");
    let finding2 = make_finding(Severity::Medium, "stable-id-2");
    let findings = vec![finding1, finding2];

    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();

    // Rule IDs should match finding IDs exactly
    assert_eq!(rules[0]["id"], "stable-id-1");
    assert_eq!(rules[1]["id"], "stable-id-2");
}

#[test]
fn test_sarif_severity_critical_to_error() {
    let finding = make_finding(Severity::Critical, "crit-test");
    let findings = vec![finding];

    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let result_obj = &parsed["runs"][0]["results"][0];

    assert_eq!(result_obj["level"], "error");
}

#[test]
fn test_sarif_severity_high_to_error() {
    let finding = make_finding(Severity::High, "high-test");
    let findings = vec![finding];

    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let result_obj = &parsed["runs"][0]["results"][0];

    assert_eq!(result_obj["level"], "error");
}

#[test]
fn test_sarif_severity_medium_to_warning() {
    let finding = make_finding(Severity::Medium, "med-test");
    let findings = vec![finding];

    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let result_obj = &parsed["runs"][0]["results"][0];

    assert_eq!(result_obj["level"], "warning");
}

#[test]
fn test_sarif_severity_low_to_note() {
    let finding = make_finding(Severity::Low, "low-test");
    let findings = vec![finding];

    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let result_obj = &parsed["runs"][0]["results"][0];

    assert_eq!(result_obj["level"], "note");
}

#[test]
fn test_sarif_severity_info_to_note() {
    let finding = make_finding(Severity::Info, "info-test");
    let findings = vec![finding];

    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let result_obj = &parsed["runs"][0]["results"][0];

    assert_eq!(result_obj["level"], "note");
}

#[test]
fn test_sarif_tool_version_present() {
    let findings = vec![make_finding(Severity::High, "test-1")];
    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let driver = &parsed["runs"][0]["tool"]["driver"];

    assert!(driver["version"].is_string());
    assert!(!driver["version"].as_str().unwrap().is_empty());
}

#[test]
fn test_sarif_uri_base_id() {
    let finding = make_finding(Severity::High, "test-1");
    let findings = vec![finding];

    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

    // Structure: locations[0].physicalLocation.artifactLocation.uriBaseId
    assert_eq!(
        parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
            ["uriBaseId"],
        "file://"
    );
}

#[test]
fn test_sarif_empty_file_path_handling() {
    let mut finding = make_finding(Severity::High, "test-1");
    finding.file_path = String::new();
    let findings = vec![finding];

    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let location = &parsed["runs"][0]["results"][0]["locations"][0];

    // Empty file path should result in empty location object
    assert!(location["physicalLocation"].is_object());
    assert!(location["physicalLocation"]["artifactLocation"].is_null());
}

#[test]
fn test_sarif_description_in_short_description() {
    let mut finding = make_finding(Severity::High, "test-1");
    finding.description = "Detailed vulnerability description".to_string();
    let findings = vec![finding];

    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let rule = &parsed["runs"][0]["tool"]["driver"]["rules"][0];

    assert_eq!(
        rule["shortDescription"]["text"],
        "Detailed vulnerability description"
    );
    assert_eq!(
        rule["fullDescription"]["text"],
        "Detailed vulnerability description"
    );
}

#[test]
fn test_sarif_properties_severity_field() {
    let finding = make_finding(Severity::High, "test-1");
    let findings = vec![finding];

    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let rule = &parsed["runs"][0]["tool"]["driver"]["rules"][0];

    // Severity should be preserved as-is (capitalized)
    assert_eq!(rule["properties"]["severity"], "High");
}

#[test]
fn test_sarif_region_with_line_number() {
    let finding = make_finding(Severity::High, "test-1");
    let findings = vec![finding];

    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let region = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];

    assert_eq!(region["startLine"], 42);
}

#[test]
fn test_sarif_region_without_line_number() {
    let mut finding = make_finding(Severity::High, "test-1");
    finding.line_number = None;
    let findings = vec![finding];

    let result = generate_sarif_report(&findings, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    let region = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];

    // Should be empty object when no line number
    assert!(region.as_object().unwrap().is_empty());
}
