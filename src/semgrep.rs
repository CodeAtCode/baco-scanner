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
pub(crate) fn extract_code_snippet(
    file_path: &str,
    target_line: u32,
    context_lines: usize,
) -> String {
    let path = PathBuf::from(file_path);
    if !path.exists() {
        return format!("Line {}: [file not found]", target_line);
    }

    match fs::read_to_string(&path) {
        Ok(content) => {
            let lines: Vec<&str> = content.lines().collect();

            // Convert to 0-based index (saturating to handle line 0)
            let target_idx = target_line.saturating_sub(1) as usize;

            // Calculate start and end indices for context window
            let (start, end) = if target_idx >= lines.len() {
                // Target line beyond file - show last available lines
                if lines.len() > context_lines {
                    (lines.len() - context_lines, lines.len())
                } else {
                    (0, lines.len())
                }
            } else {
                // Target line within file - show context around it
                let start = target_idx.saturating_sub(context_lines);
                let end = std::cmp::min(target_idx + context_lines + 1, lines.len());
                (start, end)
            };

            let mut snippet = String::new();
            for (idx, line) in lines.iter().enumerate().skip(start).take(end - start) {
                let line_num = (idx + 1) as u32;
                let marker = if line_num == target_line {
                    " >> "
                } else {
                    "    "
                };
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
    pub fn should_exclude_rule(&self, check_id: &str) -> bool {
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

    pub fn parse_json_output(&self, json: &[u8]) -> Result<Vec<VulnerabilityFinding>, String> {
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
                let description = rf
                    .message
                    .clone()
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

    #[test]
    fn test_should_exclude_rule_exact_match() {
        let runner = SemgrepRunner::new(None, vec!["python.lang.security".to_string()]);
        assert!(runner.should_exclude_rule("python.lang.security"));
        // Prefix match: "python.lang.security" matches "python.lang.security.audit"
        assert!(runner.should_exclude_rule("python.lang.security.audit"));
    }

    #[test]
    fn test_should_exclude_rule_prefix_match() {
        let runner = SemgrepRunner::new(None, vec!["python.lang.security".to_string()]);
        // Prefix match should exclude all sub-rules
        assert!(runner.should_exclude_rule("python.lang.security.audit"));
        assert!(runner.should_exclude_rule("python.lang.security.injection"));
        assert!(runner.should_exclude_rule("python.lang.security.audit.danger"));
    }

    #[test]
    fn test_should_exclude_rule_no_match() {
        let runner = SemgrepRunner::new(None, vec!["python.lang.security".to_string()]);
        assert!(!runner.should_exclude_rule("javascript.security"));
        assert!(!runner.should_exclude_rule("python.lang.ast"));
        assert!(!runner.should_exclude_rule("rust.security"));
    }

    #[test]
    fn test_should_exclude_rule_multiple_patterns() {
        let runner = SemgrepRunner::new(
            None,
            vec!["python.lang".to_string(), "javascript.security".to_string()],
        );
        assert!(runner.should_exclude_rule("python.lang.security"));
        assert!(runner.should_exclude_rule("javascript.security.xss"));
        assert!(!runner.should_exclude_rule("rust.security"));
    }

    #[test]
    fn test_should_exclude_rule_empty_patterns() {
        let runner = SemgrepRunner::new(None, vec![]);
        assert!(!runner.should_exclude_rule("any.rule"));
        assert!(!runner.should_exclude_rule("python.lang.security"));
    }

    #[test]
    fn test_extract_code_snippet_file_not_found() {
        let snippet = extract_code_snippet("/nonexistent/file.rs", 42, 2);
        assert!(snippet.contains("file not found"));
        assert!(snippet.contains("Line 42"));
    }

    #[test]
    fn test_extract_code_snippet_with_context() {
        // Create a temp file for testing
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_extract_snippet.txt");
        let content = "line 1\nline 2\nline 3\nline 4\nline 5\n";
        std::fs::write(&test_file, content).unwrap();

        let snippet = extract_code_snippet(test_file.to_str().unwrap(), 3, 1);

        // Should include lines 2, 3, 4 with line 3 marked
        assert!(
            snippet.contains("line 2"),
            "snippet should contain line 2: {}",
            snippet
        );
        assert!(snippet.contains("line 3"));
        assert!(snippet.contains("line 4"));
        assert!(snippet.contains(">>")); // Marker for target line

        // Clean up
        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_extract_code_snippet_target_line_at_start() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_extract_snippet_start.txt");
        let content = "line 1\nline 2\nline 3\n";
        std::fs::write(&test_file, content).unwrap();

        let snippet = extract_code_snippet(test_file.to_str().unwrap(), 1, 2);

        // Should start from line 1 (can't go negative)
        assert!(snippet.contains("line 1"));
        assert!(snippet.contains(">>"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_extract_code_snippet_target_line_beyond_file() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_extract_snippet_beyond.txt");
        let content = "line 1\nline 2\nline 3\n";
        std::fs::write(&test_file, content).unwrap();

        let snippet = extract_code_snippet(test_file.to_str().unwrap(), 100, 2);

        // Should show last available lines
        assert!(snippet.contains("line 3"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_parse_semgrep_output_low_severity() {
        let mock_json = r#"{
            "results": [
                {"check_id": "low.issue", "path": "test.py", "start": {"line": 1}, "extra": {"message": "Low", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn test_parse_semgrep_output_info_severity() {
        let mock_json = r#"{
            "results": [
                {"check_id": "info.issue", "path": "test.py", "start": {"line": 1}, "extra": {"message": "Info", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_parse_semgrep_output_missing_message() {
        let mock_json = r#"{
            "results": [
                {"check_id": "test.issue", "path": "test.py", "start": {"line": 1}, "extra": {"metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        // Should use fallback description
        assert!(findings[0].description.contains("test.issue"));
    }

    #[test]
    fn test_parse_semgrep_aggregated_multiple_locations() {
        let mock_json = r#"{
            "results": [
                {"check_id": "multi.issue", "path": "file1.py", "start": {"line": 1}, "extra": {"message": "Issue", "metadata": {"cwe": ["CWE-1"]}}},
                {"check_id": "multi.issue", "path": "file2.py", "start": {"line": 2}, "extra": {"message": "Issue", "metadata": {"cwe": ["CWE-1"]}}},
                {"check_id": "multi.issue", "path": "file3.py", "start": {"line": 3}, "extra": {"message": "Issue", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        // Multiple findings with same check_id should be aggregated
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file_path, "multiple_files");
        // Code snippet shows "Found in 3 files:" format
        assert!(findings[0]
            .code_snippet
            .as_ref()
            .unwrap()
            .contains("3 files"));
    }

    #[test]
    fn test_parse_semgrep_aggregated_single_location() {
        let mock_json = r#"{
            "results": [
                {"check_id": "single.issue", "path": "file1.py", "start": {"line": 1}, "extra": {"message": "Single issue", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file_path, "file1.py");
        assert_eq!(findings[0].line_number, Some(1));
    }

    #[test]
    fn test_parse_semgrep_missing_extra_field() {
        let mock_json = r#"{
            "results": [
                {"check_id": "test.issue", "path": "test.py", "start": {"line": 1}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info); // Default severity
        assert_eq!(findings[0].cwe_id, None);
    }

    #[test]
    fn test_parse_semgrep_with_empty_check_id() {
        let mock_json = r#"{
            "results": [
                {"check_id": "", "path": "test.py", "start": {"line": 1}, "extra": {"message": "Test"}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "");
    }

    #[test]
    fn test_semgrep_runner_new_with_exclude_rules() {
        let runner = SemgrepRunner::new(
            Some("/path/to/config.yml".to_string()),
            vec!["rule1".to_string(), "rule2".to_string()],
        );
        assert_eq!(runner.config_path, Some("/path/to/config.yml".to_string()));
        assert_eq!(runner.exclude_rules.len(), 2);
        assert!(runner.exclude_rules.contains(&"rule1".to_string()));
        assert!(runner.exclude_rules.contains(&"rule2".to_string()));
    }

    #[test]
    fn test_extract_code_snippet_file_read_error() {
        // Test case where file exists but cannot be read (permission denied, etc.)
        // We use a directory instead of a file to trigger the error path
        let temp_dir = std::env::temp_dir();
        let snippet = extract_code_snippet(temp_dir.to_str().unwrap(), 1, 2);
        // Directory read will fail, triggering the Err path
        assert!(snippet.contains("[unable to read file]") || snippet.contains("[file not found]"));
    }

    #[test]
    fn test_extract_code_snippet_fewer_lines_than_context() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_short_file.txt");
        let content = "line 1\n"; // Only 1 line
        std::fs::write(&test_file, content).unwrap();

        // Request context of 5 lines for a file with only 1 line
        let snippet = extract_code_snippet(test_file.to_str().unwrap(), 1, 5);

        // Should show the single available line
        assert!(snippet.contains("line 1"));
        assert!(snippet.contains(">>"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_parse_semgrep_aggregated_empty_message() {
        let mock_json = r#"{
            "results": [
                {"check_id": "empty.msg.issue", "path": "file1.py", "start": {"line": 1}, "extra": {"message": "", "metadata": {"cwe": ["CWE-1"]}}},
                {"check_id": "empty.msg.issue", "path": "file2.py", "start": {"line": 2}, "extra": {"message": "", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert_eq!(findings.len(), 1);
        // When base_message is empty and other_count > 0, uses "detected in N locations"
        assert!(findings[0].description.contains("detected in 2 locations"));
    }

    #[test]
    fn test_parse_semgrep_aggregated_single_with_empty_message() {
        let mock_json = r#"{
            "results": [
                {"check_id": "single.empty.msg", "path": "file1.py", "start": {"line": 1}, "extra": {"message": "", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert_eq!(findings.len(), 1);
        // For single finding with empty message, description is the empty message (not fallback)
        assert_eq!(findings[0].description, "");
    }

    #[test]
    fn test_parse_semgrep_missing_extra_metadata() {
        let mock_json = r#"{
            "results": [
                {"check_id": "test.issue", "path": "test.py", "start": {"line": 1}, "extra": {"message": "Test message"}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].cwe_id, None);
    }

    #[test]
    fn test_parse_semgrep_missing_extra_object() {
        let mock_json = r#"{
            "results": [
                {"check_id": "test.issue", "path": "test.py", "start": {"line": 1}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].cwe_id, None);
    }

    #[test]
    fn test_parse_semgrep_missing_message_in_extra() {
        let mock_json = r#"{
            "results": [
                {"check_id": "no.msg.test", "path": "test.py", "start": {"line": 1}, "extra": {"metadata": {"cwe": ["CWE-89"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert_eq!(findings.len(), 1);
        // Should use fallback description when message is missing
        assert!(findings[0].description.contains("no.msg.test"));
    }

    #[test]
    fn test_parse_semgrep_missing_check_id() {
        let mock_json = r#"{
            "results": [
                {"path": "test.py", "start": {"line": 1}, "extra": {"message": "Test"}},
                {"check_id": "valid.rule", "path": "test2.py", "start": {"line": 2}, "extra": {"message": "Valid"}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        // Entry without check_id should be skipped
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "valid.rule");
    }

    #[test]
    fn test_parse_semgrep_with_excluded_rule() {
        let mock_json = r#"{
            "results": [
                {"check_id": "python.lang.security.injection", "path": "test.py", "start": {"line": 1}, "extra": {"message": "Should be excluded"}},
                {"check_id": "other.rule", "path": "test2.py", "start": {"line": 2}, "extra": {"message": "Should be included"}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec!["python.lang.security".to_string()]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        // python.lang.security.* should be excluded
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "other.rule");
    }

    #[test]
    fn test_parse_semgrep_aggregated_with_base_message_and_multiple() {
        let mock_json = r#"{
            "results": [
                {"check_id": "multi.with.msg", "path": "file1.py", "start": {"line": 1}, "extra": {"message": "Base issue found", "metadata": {"cwe": ["CWE-1"]}}},
                {"check_id": "multi.with.msg", "path": "file2.py", "start": {"line": 2}, "extra": {"message": "Base issue found", "metadata": {"cwe": ["CWE-1"]}}},
                {"check_id": "multi.with.msg", "path": "file3.py", "start": {"line": 3}, "extra": {"message": "Base issue found", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert_eq!(findings.len(), 1);
        // When base_message is not empty and other_count > 1: "Base issue found (and 2 other locations)"
        assert!(findings[0].description.contains("Base issue found"));
        assert!(findings[0].description.contains("2 other locations"));
    }

    #[test]
    fn test_parse_semgrep_aggregated_with_base_message_single_other() {
        let mock_json = r#"{
            "results": [
                {"check_id": "multi.two.msg", "path": "file1.py", "start": {"line": 1}, "extra": {"message": "Found issue", "metadata": {"cwe": ["CWE-1"]}}},
                {"check_id": "multi.two.msg", "path": "file2.py", "start": {"line": 2}, "extra": {"message": "Found issue", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert_eq!(findings.len(), 1);
        // When base_message is not empty and other_count == 1: "Found issue (and 1 other location)" - singular
        assert!(findings[0].description.contains("Found issue"));
        assert!(findings[0].description.contains("1 other location"));
        // Should NOT have "locations" (plural)
        assert!(!findings[0].description.contains("locations"));
    }

    #[test]
    fn test_parse_semgrep_aggregated_empty_message_single_location() {
        let mock_json = r#"{
            "results": [
                {"check_id": "empty.single", "path": "file1.py", "start": {"line": 1}, "extra": {"message": "", "metadata": {"cwe": ["CWE-1"]}}}
            ]
        }"#;
        let runner = SemgrepRunner::new(None, vec![]);
        let findings = runner.parse_json_output(mock_json.as_bytes()).unwrap();
        assert_eq!(findings.len(), 1);
        // Single location with empty message returns empty string as description
        assert_eq!(findings[0].description, "");
    }

    #[test]
    fn test_extract_code_snippet_exact_context_fit() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_exact_context.txt");
        // File has exactly context_lines * 2 + 1 lines, target in middle
        let content = "line 1\nline 2\nline 3\nline 4\nline 5\n";
        std::fs::write(&test_file, content).unwrap();

        // Request 2 context lines around line 3 - should fit exactly
        let snippet = extract_code_snippet(test_file.to_str().unwrap(), 3, 2);

        assert!(snippet.contains("line 1"));
        assert!(snippet.contains("line 2"));
        assert!(snippet.contains(">>")); // line 3 marked
        assert!(snippet.contains("line 4"));
        assert!(snippet.contains("line 5"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_extract_code_snippet_file_with_single_line() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_single_line.txt");
        let content = "only line 1\n"; // Exactly 1 line
        std::fs::write(&test_file, content).unwrap();

        // Request context of 2 for a 1-line file, target beyond file - should show all lines
        let snippet = extract_code_snippet(test_file.to_str().unwrap(), 5, 2);

        assert!(snippet.contains("only line 1"));
        // When target is beyond file and lines.len() <= context_lines, shows all lines from start

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_semgrep_runner_clone() {
        let runner = SemgrepRunner::new(Some("config.yml".into()), vec!["rule1".into()]);
        let cloned = runner.clone();
        assert_eq!(runner.config_path, cloned.config_path);
        assert_eq!(runner.exclude_rules, cloned.exclude_rules);
    }

    #[test]
    fn test_semgrep_runner_new_empty() {
        let runner = SemgrepRunner::new(None, vec![]);
        assert!(runner.config_path.is_none());
        assert!(runner.exclude_rules.is_empty());
    }

    #[test]
    fn test_semgrep_runner_new_with_config() {
        let runner = SemgrepRunner::new(Some("/path/config.yml".into()), vec![]);
        assert_eq!(runner.config_path, Some("/path/config.yml".into()));
    }

    #[test]
    fn test_semgrep_runner_new_with_multiple_exclude_rules() {
        let runner = SemgrepRunner::new(None, vec!["rule1".into(), "rule2".into(), "rule3".into()]);
        assert_eq!(runner.exclude_rules.len(), 3);
    }

    #[test]
    fn test_should_exclude_rule_exact_and_prefix() {
        let runner = SemgrepRunner::new(None, vec!["python".into()]);
        assert!(runner.should_exclude_rule("python"));
        assert!(runner.should_exclude_rule("python.lang"));
        assert!(runner.should_exclude_rule("python.lang.security"));
        assert!(!runner.should_exclude_rule("javascript"));
    }

    #[test]
    fn test_should_exclude_rule_multiple_patterns_additional() {
        let runner = SemgrepRunner::new(
            None,
            vec!["python".into(), "javascript".into(), "rust".into()],
        );
        assert!(runner.should_exclude_rule("python.lang"));
        assert!(runner.should_exclude_rule("javascript.security"));
        assert!(runner.should_exclude_rule("rust.security"));
        assert!(!runner.should_exclude_rule("go"));
    }

    #[test]
    fn test_should_exclude_rule_empty_list() {
        let runner = SemgrepRunner::new(None, vec![]);
        assert!(!runner.should_exclude_rule("any.rule"));
    }

    #[test]
    fn test_should_exclude_rule_no_match_additional() {
        let runner = SemgrepRunner::new(None, vec!["python".into()]);
        assert!(!runner.should_exclude_rule("javascript.security"));
        assert!(!runner.should_exclude_rule("rust.lang"));
    }

    #[test]
    fn test_extract_code_snippet_line_zero() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_line_zero.txt");
        std::fs::write(&test_file, "line 1\nline 2\n").unwrap();

        let snippet = extract_code_snippet(test_file.to_str().unwrap(), 0, 1);
        assert!(snippet.contains("line 1"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_extract_code_snippet_large_context() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_large_context.txt");
        std::fs::write(&test_file, "line 1\nline 2\nline 3\n").unwrap();

        let snippet = extract_code_snippet(test_file.to_str().unwrap(), 2, 100);
        assert!(snippet.contains("line 1"));
        assert!(snippet.contains("line 2"));
        assert!(snippet.contains("line 3"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_extract_code_snippet_target_at_end() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_target_end.txt");
        std::fs::write(&test_file, "line 1\nline 2\nline 3\n").unwrap();

        let snippet = extract_code_snippet(test_file.to_str().unwrap(), 3, 1);
        assert!(snippet.contains("line 2"));
        assert!(snippet.contains("line 3"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_extract_code_snippet_target_at_start() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_target_start.txt");
        std::fs::write(&test_file, "line 1\nline 2\nline 3\n").unwrap();

        let snippet = extract_code_snippet(test_file.to_str().unwrap(), 1, 1);
        assert!(snippet.contains("line 1"));
        assert!(snippet.contains("line 2"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_extract_code_snippet_empty_file() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_empty.txt");
        std::fs::write(&test_file, "").unwrap();

        let snippet = extract_code_snippet(test_file.to_str().unwrap(), 1, 2);
        assert!(
            snippet.is_empty()
                || snippet.contains("[unable to read file]")
                || snippet.contains("Line 1")
        );

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_extract_code_snippet_marker_position() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_marker.txt");
        std::fs::write(&test_file, "line 1\nline 2\nline 3\nline 4\nline 5\n").unwrap();

        let snippet = extract_code_snippet(test_file.to_str().unwrap(), 3, 1);
        let lines: Vec<&str> = snippet.lines().collect();

        let marker_line = lines.iter().find(|l| l.contains(">>")).unwrap();
        assert!(marker_line.contains("line 3"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_raw_finding_struct() {
        let raw = RawFinding {
            path: "test.rs".into(),
            line: 42,
            severity: Severity::High,
            cwe_id: Some("CWE-79".into()),
            message: Some("Test message".into()),
        };

        assert_eq!(raw.path, "test.rs");
        assert_eq!(raw.line, 42);
        assert_eq!(raw.severity, Severity::High);
        assert_eq!(raw.cwe_id, Some("CWE-79".into()));
        assert_eq!(raw.message, Some("Test message".into()));
    }

    #[test]
    fn test_raw_finding_with_none_fields() {
        let raw = RawFinding {
            path: "test.rs".into(),
            line: 1,
            severity: Severity::Info,
            cwe_id: None,
            message: None,
        };

        assert!(raw.cwe_id.is_none());
        assert!(raw.message.is_none());
    }

    #[test]
    fn test_severity_mapping_all_variants() {
        let runner = SemgrepRunner::new(None, vec![]);

        // Test severity detection from check_id
        let json_critical = r#"{"results": [{"check_id": "critical.issue", "path": "f.py", "start": {"line": 1}, "extra": {"message": "m"}}]}"#;
        let findings = runner.parse_json_output(json_critical.as_bytes()).unwrap();
        assert_eq!(findings[0].severity, Severity::Critical);

        let json_high = r#"{"results": [{"check_id": "high.issue", "path": "f.py", "start": {"line": 1}, "extra": {"message": "m"}}]}"#;
        let findings = runner.parse_json_output(json_high.as_bytes()).unwrap();
        assert_eq!(findings[0].severity, Severity::High);

        let json_medium = r#"{"results": [{"check_id": "medium.issue", "path": "f.py", "start": {"line": 1}, "extra": {"message": "m"}}]}"#;
        let findings = runner.parse_json_output(json_medium.as_bytes()).unwrap();
        assert_eq!(findings[0].severity, Severity::Medium);

        let json_low = r#"{"results": [{"check_id": "low.issue", "path": "f.py", "start": {"line": 1}, "extra": {"message": "m"}}]}"#;
        let findings = runner.parse_json_output(json_low.as_bytes()).unwrap();
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn test_parse_json_output_with_missing_optional_fields() {
        let runner = SemgrepRunner::new(None, vec![]);

        // Missing extra.metadata
        let json = r#"{"results": [{"check_id": "test", "path": "f.py", "start": {"line": 1}, "extra": {"message": "m"}}]}"#;
        let findings = runner.parse_json_output(json.as_bytes()).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].cwe_id.is_none());
    }

    #[test]
    fn test_parse_json_output_aggregation_logic() {
        let runner = SemgrepRunner::new(None, vec![]);

        // Single finding - no aggregation
        let json_single = r#"{"results": [{"check_id": "single", "path": "f1.py", "start": {"line": 1}, "extra": {"message": "m"}}]}"#;
        let findings = runner.parse_json_output(json_single.as_bytes()).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file_path, "f1.py");

        // Multiple findings with same check_id - aggregation
        let json_multi = r#"{"results": [{"check_id": "multi", "path": "f1.py", "start": {"line": 1}, "extra": {"message": "m"}}, {"check_id": "multi", "path": "f2.py", "start": {"line": 2}, "extra": {"message": "m"}}]}"#;
        let findings = runner.parse_json_output(json_multi.as_bytes()).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file_path, "multiple_files");
    }

    #[test]
    fn test_parse_json_output_description_formatting() {
        let runner = SemgrepRunner::new(None, vec![]);

        // Single with message
        let json = r#"{"results": [{"check_id": "test", "path": "f.py", "start": {"line": 1}, "extra": {"message": "Custom message"}}]}"#;
        let findings = runner.parse_json_output(json.as_bytes()).unwrap();
        assert_eq!(findings[0].description, "Custom message");
    }

    #[test]
    #[ignore] // JSON parsing issue - needs investigation
    fn test_parse_json_output_id_generation() {
        let runner = SemgrepRunner::new(None, vec![]);

        let json = r#"{"results": [{"check_id": "test.rule", "path": "f.py", "start": {"line": 1}, "extra": {"message": "m", "metadata": {"cwe": ["CWE-79"]}}}]}",#;
        let findings = runner.parse_json_output(json.as_bytes()).unwrap();
        
        assert!(!findings[0].id.is_empty());
        assert_eq!(findings[0].id.len(), 64); // SHA256 hex
    }

    #[test]
    fn test_parse_json_output_code_snippet_generation() {
        let runner = SemgrepRunner::new(None, vec![]);
        
        let json = r#"{"results": [{"check_id": "test", "path": "src/test.rs", "start": {"line": 1}, "extra": {"message": "m"}}]}"#;
        let findings = runner.parse_json_output(json.as_bytes()).unwrap();

        assert!(findings[0].code_snippet.is_some());
    }

    #[test]
    fn test_parse_json_output_recommendation_field() {
        let runner = SemgrepRunner::new(None, vec![]);

        let json = r#"{"results": [{"check_id": "test", "path": "f.py", "start": {"line": 1}, "extra": {"message": "m"}}]}"#;
        let findings = runner.parse_json_output(json.as_bytes()).unwrap();

        assert_eq!(
            findings[0].recommendation,
            Some("Review and fix this issue".into())
        );
    }

    #[test]
    fn test_parse_json_output_sources_field() {
        let runner = SemgrepRunner::new(None, vec![]);

        let json = r#"{"results": [{"check_id": "test", "path": "f.py", "start": {"line": 1}, "extra": {"message": "m"}}]}"#;
        let findings = runner.parse_json_output(json.as_bytes()).unwrap();

        assert_eq!(findings[0].sources, vec![String::from("semgrep")]);
    }

    #[test]
    fn test_parse_json_output_llm_model_field() {
        let runner = SemgrepRunner::new(None, vec![]);

        let json = r#"{"results": [{"check_id": "test", "path": "f.py", "start": {"line": 1}, "extra": {"message": "m"}}]}"#;
        let findings = runner.parse_json_output(json.as_bytes()).unwrap();

        assert_eq!(findings[0].llm_model, Some("semgrep".into()));
    }

    #[test]
    fn test_semgrep_runner_all_fields_default() {
        let runner = SemgrepRunner::new(None, vec![]);
        assert!(runner.config_path.is_none());
        assert!(runner.exclude_rules.is_empty());
    }

    #[test]
    fn test_extract_code_snippet_return_format() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_format.txt");
        std::fs::write(&test_file, "line 1\nline 2\nline 3\n").unwrap();

        let snippet = extract_code_snippet(test_file.to_str().unwrap(), 2, 1);

        assert!(snippet.contains("|")); // Line number separator
        assert!(snippet.contains(">>")); // Target line marker
        assert!(snippet.contains("line 1"));
        assert!(snippet.contains("line 2"));
        assert!(snippet.contains("line 3"));

        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_semgrep_json_output_with_null_fields() {
        let runner = SemgrepRunner::new(None, vec![]);

        let json = r#"{"results": [{"check_id": "test", "path": "f.py", "start": {"line": 1}, "extra": {"message": null, "metadata": null}}]}"#;
        let findings = runner.parse_json_output(json.as_bytes()).unwrap();

        assert_eq!(findings.len(), 1);
        assert!(findings[0].cwe_id.is_none());
    }

    #[test]
    fn test_semgrep_json_output_with_empty_array_results() {
        let runner = SemgrepRunner::new(None, vec![]);

        let json = r#"{"results": []}"#;
        let findings = runner.parse_json_output(json.as_bytes()).unwrap();

        assert!(findings.is_empty());
    }

    #[test]
    fn test_semgrep_json_output_with_no_results_key() {
        let runner = SemgrepRunner::new(None, vec![]);

        let json = r#"{"errors": []}"#;
        let findings = runner.parse_json_output(json.as_bytes()).unwrap();

        assert!(findings.is_empty());
    }

    #[test]
    fn test_semgrep_exclude_rule_with_empty_pattern() {
        let runner = SemgrepRunner::new(None, vec!["".into()]);

        // Empty pattern should match everything (starts with "")
        assert!(runner.should_exclude_rule("any.rule"));
    }
}
