use crate::config::ScannerConfig;
use crate::evidence::{classify_finding, VerificationTier};
use crate::findings::{Severity, VulnerabilityFinding};
use crate::llm_metrics::LlmMetrics;
use serde::Serialize;
use std::fs;

#[derive(Serialize)]
pub struct ReportSummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,

    /// Metriche LLM (se disponibili)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_metrics: Option<LlmMetricsSummary>,
}

#[derive(Serialize)]
pub struct LlmMetricsSummary {
    pub total_requests: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub cached_requests: usize,
    pub total_tokens: usize,
    pub avg_latency_ms: f64,

    /// Metriche per modello
    pub models: Vec<ModelMetricsSummary>,

    /// Metriche per operazione
    pub operations: Vec<OperationMetricsSummary>,
}

#[derive(Serialize)]
pub struct ModelMetricsSummary {
    pub model_name: String,
    pub total_requests: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub cached_requests: usize,
    pub total_tokens: usize,
}

#[derive(Serialize)]
pub struct OperationMetricsSummary {
    pub operation: String,
    pub phase: String,
    pub requests: usize,
    pub successful: usize,
    pub failed: usize,
}

pub fn write_findings_json(
    findings: &[VulnerabilityFinding],
    output_path: &str,
    llm_metrics: Option<LlmMetrics>,
    config: Option<&ScannerConfig>,
) -> Result<(), String> {
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

    // Compute verification_tier for each finding
    let mut findings_with_tier = filtered_findings;
    for finding in &mut findings_with_tier {
        if finding.verification_tier.is_none() {
            finding.verification_tier = Some(classify_finding(
                &finding.evidence,
                finding.confidence_score,
            ));
        }
    }

    let _summary = ReportSummary {
        total_findings: findings.len(),
        critical: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical))
            .count(),
        high: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::High))
            .count(),
        medium: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Medium))
            .count(),
        low: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Low))
            .count(),
        info: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Info))
            .count(),
        llm_metrics: llm_metrics.map(|metrics| {
            let models: Vec<ModelMetricsSummary> = metrics
                .by_model
                .values()
                .map(|m| ModelMetricsSummary {
                    model_name: m.model_name.clone(),
                    total_requests: m.total_requests as usize,
                    successful_requests: m.successful_requests as usize,
                    failed_requests: m.failed_requests as usize,
                    cached_requests: m.cached_requests as usize,
                    total_tokens: m.total_tokens as usize,
                })
                .collect();

            let operations: Vec<OperationMetricsSummary> = metrics
                .by_operation
                .into_values()
                .map(|op| OperationMetricsSummary {
                    operation: op.operation.clone(),
                    phase: op.phase.clone(),
                    requests: op.requests as usize,
                    successful: op.successful as usize,
                    failed: op.failed as usize,
                })
                .collect();

            LlmMetricsSummary {
                total_requests: metrics.total_requests as usize,
                successful_requests: metrics.total_success as usize,
                failed_requests: metrics.total_failed as usize,
                cached_requests: metrics.total_cached as usize,
                total_tokens: metrics.total_tokens as usize,
                avg_latency_ms: metrics.avg_latency_ms,
                models,
                operations,
            }
        }),
    };

    let json = serde_json::to_string_pretty(&findings_with_tier)
        .map_err(|e| format!("Failed to serialize findings: {}", e))?;

    // Create parent directory if it doesn't exist
    if let Some(parent) = std::path::Path::new(output_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create output directory: {}", e))?;
    }

    fs::write(output_path, json).map_err(|e| format!("Failed to write findings.json: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;
    use crate::llm_metrics::{LlmMetrics, ModelMetrics, OperationMetrics};
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

        let result = write_findings_json(&findings, output_path, None, None);

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

        let result = write_findings_json(&findings, output_path, None, None);

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

        let result = write_findings_json(&findings, output_path, None, None);

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

        let result = write_findings_json(&findings, output_path, None, None);

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

        let result = write_findings_json(&findings, output_path, None, None);

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

        let result = write_findings_json(&findings, output_path.to_str().unwrap(), None, None);

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

        let result = write_findings_json(&findings, output_path, None, None);

        assert!(result.is_ok());

        let content = fs::read_to_string(output_path).unwrap();
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&content);
        assert!(parsed.is_ok(), "Output should be valid JSON");

        let _ = fs::remove_file(output_path);
    }

    #[test]
    fn test_write_findings_json_with_llm_metrics() {
        let findings = vec![make_finding(Severity::High, "src/test.rs", Some(10))];
        let llm_metrics = LlmMetrics {
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
                },
            )]),
        };
        let output_path = "/tmp/test_with_metrics.json";

        let _ = fs::remove_file(output_path);

        let result = write_findings_json(&findings, output_path, Some(llm_metrics), None);

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

        let result = write_findings_json(&findings, output_path, None, None);

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

        let result = write_findings_json(&findings, output_path, None, None);

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

        let result = write_findings_json(&findings, output_path, None, None);

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

        let result = write_findings_json(&findings, output_path, None, None);

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

        let result = write_findings_json(&findings, output_path, None, None);

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

        let result = write_findings_json(&findings, output_path, None, None);

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

        let result = write_findings_json(&findings, output_path, None, None);

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

        let result = write_findings_json(&findings, output_path, None, None);

        assert!(result.is_ok());

        let content = fs::read_to_string(output_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        let findings_array = parsed.as_array().unwrap();

        assert!(findings_array[0]["agent_mode"].as_bool().unwrap());
        assert_eq!(findings_array[0]["llm_model"].as_str().unwrap(), "claude-3");

        let _ = fs::remove_file(output_path);
    }
}
