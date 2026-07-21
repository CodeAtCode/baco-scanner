//! IndependentVerify phase: fresh LLM call with no prior context

use crate::findings::VulnerabilityFinding;
use crate::llm::LlmClient;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct PhaseError(pub String);

impl std::fmt::Display for PhaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Phase error: {}", self.0)
    }
}

impl std::error::Error for PhaseError {}

#[derive(Debug, Clone, Default)]
pub struct OrchestrationConfig {
    pub enabled: bool,
    pub hunt_classes: Vec<String>,
    pub validate_batch_size: usize,
    pub independent_verify: bool,
}

pub struct IndependentVerifyPhase {
    llm: LlmClient,
    config: OrchestrationConfig,
}

impl IndependentVerifyPhase {
    pub fn new(llm: LlmClient, config: OrchestrationConfig) -> Self {
        Self { llm, config }
    }

    pub async fn run(&self, file: &Path, source: &str) -> Result<Vec<VulnerabilityFinding>, PhaseError> {
        if !self.config.enabled {
            return Ok(Vec::new());
        }

        let prompt = Self::independent_verify_prompt(source);
        let messages = vec![
            crate::llm::ChatMessage::system(
                "You are a security expert. Analyze this code independently. Return ONLY valid JSON array."
            ),
            crate::llm::ChatMessage::user(&prompt),
        ];

        match self.llm.chat(&messages).await {
            Ok(response) => {
                let findings = parse_findings(&response.content, file.to_string_lossy().as_ref());
                Ok(findings)
            }
            Err(e) => {
                tracing::warn!("Independent verify phase failed: {}", e);
                Ok(Vec::new())
            }
        }
    }

    fn independent_verify_prompt(source: &str) -> String {
        format!(
            r#"Analyze this code for security vulnerabilities. Report each with location, CWE, severity, and description.

Return JSON array with format:
[
  {{
    "severity": "critical|high|medium|low",
    "title": "short vulnerability title",
    "description": "detailed explanation",
    "line": line_number,
    "cwe_id": "CWE-XXX"
  }}
]

Code:
```
{}
```"#,
            source
        )
    }
}

/// Boost confidence for findings that match prior findings (called by orchestrator)
pub fn boost_independent_confidence(
    independent_findings: &mut [VulnerabilityFinding],
    prior_findings: &[VulnerabilityFinding],
) {
    for ind_finding in independent_findings.iter_mut() {
        let key = (
            ind_finding.line_number.unwrap_or(0),
            ind_finding.cwe_id.clone().unwrap_or_default(),
        );

        // Check if this finding appeared in prior phases
        let matched = prior_findings.iter().any(|prior| {
            let prior_key = (
                prior.line_number.unwrap_or(0),
                prior.cwe_id.clone().unwrap_or_default(),
            );
            prior_key == key
        });

        if matched {
            // Independent confirmation - boost confidence by +0.2
            ind_finding.confidence_score = (ind_finding.confidence_score + 0.2).min(1.0);
            ind_finding
                .verification_notes
                .get_or_insert_with(String::new)
                .push_str("Independent verification confirmed; ");
        }
    }
}

fn parse_findings(json: &str, file_path: &str) -> Vec<VulnerabilityFinding> {
    use crate::findings::Severity;

    let cleaned = json
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    let mut findings = Vec::new();

    if let Ok(parsed) = serde_json::from_str::<Vec<serde_json::Value>>(cleaned) {
        for item in parsed {
            let severity_str = item.get("severity").and_then(|v| v.as_str());
            let title = item.get("title").and_then(|v| v.as_str());
            let description = item.get("description").and_then(|v| v.as_str());
            let line = item.get("line").and_then(|v| v.as_i64());
            let cwe_id = item.get("cwe_id").and_then(|v| v.as_str());

            if let (Some(severity_str), Some(title), Some(line)) = (severity_str, title, line) {
                let severity = match severity_str.to_lowercase().as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    _ => Severity::Low,
                };

                findings.push(VulnerabilityFinding {
                    id: VulnerabilityFinding::generate_id(
                        file_path,
                        Some(line as u32),
                        cwe_id.unwrap_or("CWE-000"),
                    ),
                    title: title.to_string(),
                    description: description.map(|s| s.to_string()).unwrap_or_default(),
                    severity,
                    confidence_score: 0.7,
                    cwe_id: cwe_id.map(|s| s.to_string()),
                    file_path: file_path.to_string(),
                    line_number: Some(line as u32),
                    code_snippet: None,
                    diff_hunk: None,
                    recommendation: None,
                    code_location: None,
                    already_reported: false,
                    sources: vec!["independent_verify".to_string()],
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
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_independent_verify_disabled() {
        let config = OrchestrationConfig {
            enabled: false,
            ..Default::default()
        };
        let client = crate::llm::LlmClient::new(crate::llm::LlmConfig::default());
        let phase = IndependentVerifyPhase::new(client, config);

        let temp_file = std::fs::File::create("/tmp/test_verify.rs").unwrap();
        drop(temp_file);
        let path = Path::new("/tmp/test_verify.rs");

        let result = phase.run(path, "test code").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_boost_confidence() {
        let mut ind_finding = VulnerabilityFinding {
            id: "ind-1".to_string(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            severity: crate::findings::Severity::High,
            confidence_score: 0.7,
            cwe_id: Some("CWE-89".to_string()),
            file_path: "test.rs".to_string(),
            line_number: Some(42),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["ind".to_string()],
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
        };

        let prior_finding = VulnerabilityFinding {
            id: "prior-1".to_string(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            severity: crate::findings::Severity::High,
            confidence_score: 0.7,
            cwe_id: Some("CWE-89".to_string()),
            file_path: "test.rs".to_string(),
            line_number: Some(42),
            code_snippet: None,
            diff_hunk: None,
            recommendation: None,
            code_location: None,
            already_reported: false,
            sources: vec!["prior".to_string()],
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
        };

        boost_independent_confidence(&mut [ind_finding.clone()], &[prior_finding]);
        // Confidence should be boosted by 0.2
        assert!((ind_finding.confidence_score - 0.9).abs() < 0.01);
    }
}