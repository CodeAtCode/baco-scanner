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
