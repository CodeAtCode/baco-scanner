use crate::findings::VulnerabilityFinding;
use hex;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

use super::rules::{parse_severity, RawFinding};

/// Read a file and extract lines around the target line for code snippet
pub fn extract_code_snippet(file_path: &str, target_line: u32, context_lines: usize) -> String {
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

pub fn parse_json_output(
    json: &[u8],
    exclude_rules: &[String],
) -> Result<Vec<VulnerabilityFinding>, String> {
    let results: serde_json::Value =
        serde_json::from_slice(json).map_err(|e| format!("Failed to parse semgrep JSON: {}", e))?;

    let mut grouped: std::collections::HashMap<String, Vec<RawFinding>> =
        std::collections::HashMap::new();

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

        // Check if rule should be excluded
        let should_exclude = exclude_rules.iter().any(|pattern| {
            // Exact match
            if check_id == pattern {
                return true;
            }
            // Prefix match (e.g., "python.lang" matches "python.lang.security")
            if check_id.starts_with(pattern) {
                return true;
            }
            false
        });

        if should_exclude {
            tracing::debug!(
                "Excluding semgrep finding: {} (matched exclude rules)",
                check_id
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

        let severity = parse_severity(check_id);

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

        // Extract end line for statement range
        let end = result
            .get("end")
            .and_then(|v| v.get("line"))
            .and_then(|v| v.as_u64())
            .unwrap_or(start);

        let raw_finding = RawFinding {
            path: path.to_string(),
            line: start as u32,
            end_line: end as u32,
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
                statement_range: Some((rf.line, rf.end_line)),
                triage_verdict: None,
                evidence: vec![crate::evidence::Evidence {
                    source: crate::evidence::EvidenceSource::Semgrep(check_id.clone()),
                    weight: 0.7,
                    detail: format!("Detected by Semgrep rule {}", check_id),
                    timestamp: chrono::Utc::now(),
                }],
                verification_tier: None,
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
                statement_range: None,
                triage_verdict: None,
                evidence: vec![crate::evidence::Evidence {
                    source: crate::evidence::EvidenceSource::Semgrep(check_id.clone()),
                    weight: 0.7,
                    detail: format!("Detected by Semgrep rule {}", check_id),
                    timestamp: chrono::Utc::now(),
                }],
                verification_tier: None,
            });
        }
    }

    Ok(findings)
}
