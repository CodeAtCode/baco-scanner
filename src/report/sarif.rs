use crate::config::ScannerConfig;
use crate::evidence::{classify_finding, VerificationTier};
use crate::findings::{Severity, VulnerabilityFinding};

pub fn generate_sarif_report(
    findings: &[VulnerabilityFinding],
    config: Option<&ScannerConfig>,
) -> Result<String, String> {
    // Filter findings if evidence gate is enabled
    let filtered_findings = if let Some(cfg) = config {
        if cfg.output.evidence_gate {
            findings
                .iter()
                .filter(|f| {
                    let tier = classify_finding(&f.evidence, f.confidence_score);
                    matches!(
                        tier,
                        VerificationTier::Verified | VerificationTier::Supported
                    )
                })
                .cloned()
                .collect::<Vec<_>>()
        } else {
            findings.to_vec()
        }
    } else {
        findings.to_vec()
    };

    let mut results = Vec::new();
    for finding in &filtered_findings {
        let driver_location = if finding.file_path.is_empty() {
            serde_json::json!({})
        } else {
            serde_json::json!({
                "artifactLocation": {"uri": finding.file_path.clone(), "uriBaseId": "file://"},
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path.clone(), "uriBaseId": "file://"}
                }
            })
        };
        let line = finding.line_number.map(|l| l as u64).unwrap_or(0);
        let region = if line > 0 {
            serde_json::json!({"startLine": line})
        } else {
            serde_json::json!({})
        };
        let mut result_obj = serde_json::json!({
            "ruleId": finding.id,
            "message": {"text": finding.description},
            "locations": [
                serde_json::json!({
                    "physicalLocation": {
                        "artifactLocation": driver_location,
                        "region": region
                    }
                })
            ],
            "level": match finding.severity {
                Severity::Critical => "error",
                Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low => "note",
                Severity::Info => "note",
            }
        });

        // Add PoC and mitigation as related locations/annotations
        let mut related_locations = Vec::new();

        if let Some(ref poc) = finding.poc_code {
            let format = finding.poc_format.as_deref().unwrap_or("text");
            related_locations.push(serde_json::json!({
                "location": {
                    "message": {
                        "text": format!("Proof of Concept ({})", format)
                    },
                    "physicalLocation": {
                        "artifactLocation": {
                            "description": {
                                "text": "PoC Code"
                            }
                        },
                        "region": {
                            "byteOffset": 0,
                            "byteLength": poc.len()
                        }
                    }
                },
                "annotations": [
                    {
                        "startLine": 1,
                        "endLine": poc.lines().count() as u64,
                        "message": {
                            "text": poc
                        }
                    }
                ]
            }));
        }

        if let Some(ref mitigation) = finding.mitigation_code {
            related_locations.push(serde_json::json!({
                "location": {
                    "message": {
                        "text": "Mitigation Example"
                    },
                    "physicalLocation": {
                        "artifactLocation": {
                            "description": {
                                "text": "Mitigation Code"
                            }
                        }
                    }
                },
                "annotations": [
                    {
                        "startLine": 1,
                        "endLine": mitigation.lines().count() as u64,
                        "message": {
                            "text": mitigation
                        }
                    }
                ]
            }));
        }

        if !related_locations.is_empty() {
            result_obj["relatedLocations"] = serde_json::json!(related_locations);
        }

        let result = result_obj;
        results.push(result);
    }

    let sarif = serde_json::json!({
              "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
              "version": "2.1.0",
              "runs": [
                  serde_json::json!({
                      "tool": {
                          "driver": {
                              "name": "BACO Security Scanner",
                              "informationUri": "https://github.com/mte90/baco",
                              "version": env!("CARGO_PKG_VERSION"),
                              "rules": filtered_findings.iter().map(|f| serde_json::json!({
                            "id": f.id,
                            "name": f.title,
                            "shortDescription": {"text": f.description},
                            "fullDescription": {"text": f.description},
                            "helpUri": format!("https://cwe.mitre.org/data/definitions/{}.html",
                                f.cwe_id.as_deref().map(|id| id.replace("CWE-", "").parse::<u32>().unwrap_or(0)).unwrap_or(0)),
                            "properties": {"severity": f.severity.to_string()}
                        })).collect::<Vec<_>>(),
                    }
                },
                "results": results
            })
        ]
    });
    serde_json::to_string_pretty(&sarif)
        .map_err(|e| format!("Failed to serialize SARIF report: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Severity, VulnerabilityFinding};

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
}
