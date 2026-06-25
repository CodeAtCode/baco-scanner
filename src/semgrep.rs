use crate::findings::{Severity, VulnerabilityFinding};
use hex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

struct RawFinding {
    path: String,
    line: u32,
    severity: Severity,
    cwe_id: Option<String>,
    message: Option<String>,
}

#[derive(Clone)]
pub struct SemgrepRunner {
    pub config_path: Option<String>,
    pub exclude_rules: Vec<String>,
}

/// Read a file and extract lines around the target line for code snippet
fn extract_code_snippet(file_path: &str, target_line: u32, context_lines: usize) -> String {
    let path = PathBuf::from(file_path);
    if !path.exists() {
        return format!("Line {}: [file not found]", target_line);
    }
    
    match fs::read_to_string(&path) {
        Ok(content) => {
            let lines: Vec<&str> = content.lines().collect();
            let start = if target_line > context_lines as u32 {
                (target_line - context_lines as u32) as usize
            } else {
                0
            };
            let end = std::cmp::min(target_line as usize + context_lines, lines.len());
            
            let mut snippet = String::new();
            for (idx, line) in lines.iter().enumerate().skip(start).take(end - start) {
                let line_num = (idx + 1) as u32;
                let marker = if line_num == target_line { " >> " } else { "    " };
                snippet.push_str(&format!("{}{:4} | {}\n", marker, line_num, line));
            }
            snippet
        }
        Err(_) => format!("Line {}: [unable to read file]", target_line),
    }
}

impl SemgrepRunner {
    pub fn new(config_path: Option<String>, exclude_rules: Vec<String>) -> Self {
        Self {
            config_path,
            exclude_rules,
        }
    }

    /// Check if a rule check_id should be excluded based on exclude_rules patterns.
    /// Supports exact match and prefix match (e.g., "python.lang" excludes all "python.lang.*" rules).
    fn should_exclude_rule(&self, check_id: &str) -> bool {
        self.exclude_rules.iter().any(|pattern| {
            // Exact match
            if check_id == pattern {
                return true;
            }
            // Prefix match (e.g., "python.lang" matches "python.lang.security")
            if check_id.starts_with(pattern) {
                return true;
            }
            false
        })
    }

    pub async fn run(
        &self,
        target_path: &str,
        _output_path: &str,
    ) -> Result<Vec<VulnerabilityFinding>, String> {
        // Use spawn_blocking to avoid blocking the async runtime
        let self_clone = self.clone();
        let target_path_clone = target_path.to_string();

        tokio::task::spawn_blocking(move || {
            // Note: cache functionality removed for Semgrep v2+ compatibility
            // The --cache-path and --no-cache flags are no longer supported

            let mut cmd = Command::new("semgrep");
            cmd.arg("scan")
                .arg("--json")
                .arg("--quiet")
                .arg(&target_path_clone);

            if let Some(config) = &self_clone.config_path {
                cmd.arg("--config").arg(config);
            }

            let output = cmd
                .output()
                .map_err(|e| format!("Failed to run semgrep: {}", e))?;

            if !output.status.success() {
                return Err(format!(
                    "Semgrep failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }

            self_clone.parse_json_output(&output.stdout)
        })
        .await
        .map_err(|e| format!("Semgrep task panicked: {}", e))?
    }

    fn parse_json_output(&self, json: &[u8]) -> Result<Vec<VulnerabilityFinding>, String> {
        let results: serde_json::Value = serde_json::from_slice(json)
            .map_err(|e| format!("Failed to parse semgrep JSON: {}", e))?;

        let mut grouped: HashMap<String, Vec<RawFinding>> = HashMap::new();

        for result in results
            .get("results")
            .and_then(|r| r.as_array())
            .unwrap_or(&vec![])
            .iter()
        {
            let check_id = match result.get("check_id").and_then(|v| v.as_str()) {
                Some(id) => id,
                None => continue,
            };

            if self.should_exclude_rule(check_id) {
                tracing::debug!(
                    "Excluding semgrep finding: {} (matched rule: {:?})",
                    check_id,
                    self.exclude_rules
                );
                continue;
            }

            let path = match result.get("path").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => continue,
            };

            let start = match result
                .get("start")
                .and_then(|v| v.get("line"))
                .and_then(|v| v.as_u64())
            {
                Some(s) => s,
                None => continue,
            };

            let severity = match check_id.to_lowercase().as_str() {
                s if s.contains("critical") => Severity::Critical,
                s if s.contains("high") => Severity::High,
                s if s.contains("medium") => Severity::Medium,
                s if s.contains("low") => Severity::Low,
                _ => Severity::Info,
            };

            let cwe_id = result
                .get("extra")
                .and_then(|e| e.get("metadata"))
                .and_then(|m| m.get("cwe"))
                .and_then(|c| c.as_array())
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let message = result
                .get("extra")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .map(|s| s.to_string());

            let raw_finding = RawFinding {
                path: path.to_string(),
                line: start as u32,
                severity,
                cwe_id,
                message,
            };

            grouped
                .entry(check_id.to_string())
                .or_default()
                .push(raw_finding);
        }

        let mut findings = Vec::new();

        for (check_id, raw_findings) in grouped {
            if raw_findings.len() == 1 {
                let rf = &raw_findings[0];
                // Generate description from Semgrep message or use title as fallback
                let description = rf.message.clone()
                    .unwrap_or_else(|| format!("{} detected by Semgrep", check_id));
                
                findings.push(VulnerabilityFinding {
                    id: VulnerabilityFinding::generate_id(
                        &rf.path,
                        Some(rf.line),
                        &rf.cwe_id.clone().unwrap_or_else(|| "unknown".to_string()),
                    ),
                    title: check_id.clone(),
                    description: description.clone(),
                    severity: rf.severity,
                    confidence_score: 0.7,
                    cwe_id: rf.cwe_id.clone(),
                    file_path: rf.path.clone(),
                    line_number: Some(rf.line),
                    code_snippet: Some(extract_code_snippet(&rf.path, rf.line, 2)),
                    diff_hunk: None,
                    recommendation: Some("Review and fix this issue".to_string()),
                    code_location: Some(format!("{}:{}", rf.path, rf.line)),
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
                    llm_model: Some("semgrep".to_string()),
                    agent_mode: false,
                });
            } else {
                let first = &raw_findings[0];
                let count = raw_findings.len();

                let locations: Vec<String> = raw_findings
                    .iter()
                    .map(|rf| format!("{}:{}", rf.path, rf.line))
                    .collect();

                let other_count = count - 1;
                let base_message = first.message.as_deref().unwrap_or("");
                // Generate description from Semgrep message or use title as fallback
                let description = if base_message.is_empty() {
                    if other_count > 0 {
                        format!("{} detected in {} locations", check_id, count)
                    } else {
                        format!("{} detected by Semgrep", check_id)
                    }
                } else if other_count > 0 {
                    format!(
                        "{} (and {} other location{})",
                        base_message,
                        other_count,
                        if other_count == 1 { "" } else { "s" }
                    )
                } else {
                    base_message.to_string()
                };

                let code_snippet = format!(
                    "Found in {} file{}:\n{}",
                    count,
                    if count == 1 { "" } else { "s" },
                    locations.join("\n")
                );

                let mut hasher = Sha256::new();
                hasher.update(check_id.as_bytes());
                hasher.update(b"aggregated");
                let id = hex::encode(hasher.finalize());

                findings.push(VulnerabilityFinding {
                    id,
                    title: check_id.clone(),
                    description: description.clone(),
                    severity: first.severity,
                    confidence_score: 0.7,
                    cwe_id: first.cwe_id.clone(),
                    file_path: "multiple_files".to_string(),
                    line_number: None,
                    code_snippet: Some(code_snippet),
                    diff_hunk: None,
                    recommendation: Some("Review and fix this issue".to_string()),
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
                    llm_model: Some("semgrep".to_string()),
                    agent_mode: false,
                });
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_semgrep_output() {
        let mock_json = r#"{
            "results": [
                {
                    "check_id": "python.security.high.injection",
                    "path": "test.py",
                    "start": {"line": 42, "col": 10},
                    "extra": {
                        "message": "Potential SQL injection",
                        "metadata": {"cwe": ["CWE-89"]},
                        "severity": "High"
                    }
                }
            ]
        }"#;

        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file_path, "test.py");
        assert_eq!(findings[0].line_number, Some(42));
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_parse_semgrep_output_empty_results() {
        let mock_json = r#"{"results": []}"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_parse_semgrep_output_empty_array() {
        let mock_json = r#"[]"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let result = runner.parse_json_output(mock_json.as_bytes());
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_semgrep_output_no_results_key() {
        let mock_json = r#"{"data": []}"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_parse_semgrep_output_multiple_findings() {
        let mock_json = r#"{
            "results": [
                {"check_id": "cve.2024.1", "path": "file1.py", "start": {"line": 1}, "extra": {"message": "Issue 1", "metadata": {"cwe": ["CWE-1"]}}},
                {"check_id": "cve.2024.2", "path": "file2.py", "start": {"line": 2}, "extra": {"message": "Issue 2", "metadata": {"cwe": ["CWE-2"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_parse_semgrep_output_critical_severity() {
        let mock_json = r#"{
            "results": [
                {"check_id": "critical.issue", "path": "test.py", "start": {"line": 1}, "extra": {"message": "Critical", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_parse_semgrep_output_medium_severity() {
        let mock_json = r#"{
            "results": [
                {"check_id": "medium.issue", "path": "test.py", "start": {"line": 1}, "extra": {"message": "Medium", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_parse_semgrep_output_missing_cwe() {
        let mock_json = r#"{
            "results": [
                {"check_id": "test.issue", "path": "test.py", "start": {"line": 1}, "extra": {"message": "No CWE"}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert_eq!(findings[0].cwe_id, None);
    }

    #[test]
    fn test_parse_semgrep_output_missing_snippet() {
        let mock_json = r#"{
            "results": [
                {"check_id": "test.issue", "path": "test.py", "start": {"line": 1}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert!(findings[0].code_snippet.is_some());
    }

    #[test]
    fn test_parse_semgrep_output_json_parse_error() {
        let mock_json = r#"{"invalid json}"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let result = runner.parse_json_output(mock_json.as_bytes());
        assert!(result.unwrap_err().contains("Failed to parse"));
    }

    #[test]
    fn test_parse_semgrep_output_no_start_line() {
        let mock_json = r#"{
            "results": [
                {"check_id": "test.issue", "path": "test.py"}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let result = runner.parse_json_output(mock_json.as_bytes());
        let findings = result.unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_parse_semgrep_output_no_path() {
        let mock_json = r#"{
            "results": [
                {"check_id": "test.issue", "start": {"line": 1}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let result = runner.parse_json_output(mock_json.as_bytes());
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_run_stubbed() {
        let runner = SemgrepRunner::new(None, vec![]);
        assert!(runner.config_path.is_none());
    }

    #[test]
    fn test_run_with_config() {
        let runner = SemgrepRunner::new(Some("/path/to/config.yml".to_string()), vec![]);
        assert_eq!(runner.config_path, Some("/path/to/config.yml".to_string()));
    }

    #[test]
    fn test_run_invalid_json() {
        let mock_json = b"not valid json";
        let runner = SemgrepRunner::new(None, vec![]);
        let result = runner.parse_json_output(mock_json);
        assert!(result.is_err());
    }
}
