//! Hunt phase: 7 parallel attack-class prompts (Cloudflare pattern)

use crate::findings::VulnerabilityFinding;
use crate::llm::LlmClient;
use crate::prompt::templates::{
    auth_hunt_prompt, crypto_hunt_prompt, deserialization_hunt_prompt, injection_hunt_prompt,
    path_traversal_hunt_prompt, resource_hunt_prompt, xss_hunt_prompt,
};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct PhaseError(pub String);

impl std::fmt::Display for PhaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Phase error: {}", self.0)
    }
}

impl std::error::Error for PhaseError {}

pub struct HuntPhase {
    llm: LlmClient,
    config: OrchestrationConfig,
}

#[derive(Debug, Clone, Default)]
pub struct OrchestrationConfig {
    pub enabled: bool,
    pub hunt_classes: Vec<String>,
    pub validate_batch_size: usize,
    pub independent_verify: bool,
}

impl HuntPhase {
    pub fn new(llm: LlmClient, config: OrchestrationConfig) -> Self {
        Self { llm, config }
    }

    pub async fn run(&self, file: &Path, source: &str) -> Result<Vec<VulnerabilityFinding>, PhaseError> {
        if !self.config.enabled {
            return Ok(Vec::new());
        }

        let hunt_classes = &self.config.hunt_classes;

        // Create prompts for each attack class
        let prompts = vec![
            ("injection", injection_hunt_prompt(source)),
            ("auth", auth_hunt_prompt(source)),
            ("xss", xss_hunt_prompt(source)),
            ("path_traversal", path_traversal_hunt_prompt(source)),
            ("crypto", crypto_hunt_prompt(source)),
            ("resource", resource_hunt_prompt(source)),
            ("deserialization", deserialization_hunt_prompt(source)),
        ]
        .into_iter()
        .filter(|(cls, _)| hunt_classes.is_empty() || hunt_classes.contains(&cls.to_string()))
        .collect::<Vec<_>>();

        // Run all prompts in parallel
        let tasks: Vec<_> = prompts
            .iter()
            .map(|(class, prompt)| {
                let client = self.llm.clone();
                let prompt = prompt.clone();
                let class = class.to_string();
                tokio::spawn(async move {
                    let messages = vec![
                        crate::llm::ChatMessage::system(
                            "You are a security expert. Return ONLY valid JSON array.",
                        ),
                        crate::llm::ChatMessage::user(&prompt),
                    ];

                    match client.chat(&messages).await {
                        Ok(response) => {
                            let findings = parse_findings(&response.content, file.to_string_lossy().as_ref());
                            (class, findings)
                        }
                        Err(e) => {
                            tracing::warn!("Hunt phase failed for {}: {}", class, e);
                            (class, Vec::new())
                        }
                    }
                })
            })
            .collect();

        let results = futures::future::join_all(tasks).await;

        // Deduplicate findings by (line, rule_id) and boost confidence for duplicates
        let mut finding_map: std::collections::HashMap<(u32, String), (VulnerabilityFinding, usize)> =
            std::collections::HashMap::new();

        for (_class, class_findings) in results.into_iter().flat_map(|r| r.unwrap_or_default()) {
            for finding in class_findings {
                let key = (
                    finding.line_number.unwrap_or(0),
                    finding.cwe_id.clone().unwrap_or_default(),
                );
                let entry = finding_map.entry(key).or_insert_with(|| (finding.clone(), 0));
                entry.1 += 1;
            }
        }

        let mut final_findings = Vec::new();
        for (mut finding, count) in finding_map.into_values() {
            // Boost confidence by +0.15 for each additional class that found it
            if count > 1 {
                finding.confidence_score = (finding.confidence_score + 0.15 * (count - 1) as f32).min(1.0);
            }
            final_findings.push(finding);
        }

        Ok(final_findings)
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
                    sources: vec!["hunt".to_string()],
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
    async fn test_hunt_phase_disabled() {
        let config = OrchestrationConfig {
            enabled: false,
            ..Default::default()
        };
        let client = crate::llm::LlmClient::new(crate::llm::LlmConfig::default());
        let phase = HuntPhase::new(client, config);

        let temp_file = std::fs::File::create("/tmp/test_hunt.rs").unwrap();
        drop(temp_file);
        let path = Path::new("/tmp/test_hunt.rs");

        let result = phase.run(path, "test code").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}