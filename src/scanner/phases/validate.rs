//! Validate phase: adversarial self-check

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

pub struct ValidatePhase {
    llm: LlmClient,
    config: OrchestrationConfig,
}

impl ValidatePhase {
    pub fn new(llm: LlmClient, config: OrchestrationConfig) -> Self {
        Self { llm, config }
    }

    pub async fn run(&self, findings: &[VulnerabilityFinding], source: &str) -> Result<Vec<VulnerabilityFinding>, PhaseError> {
        if !self.config.enabled || findings.is_empty() {
            return Ok(findings.to_vec());
        }

        let batch_size = self.config.validate_batch_size.max(1);
        let mut results = Vec::new();

        // Batch findings and validate each batch
        for chunk in findings.chunks(batch_size) {
            let batch_prompt = self.build_batch_prompt(chunk, source);
            let messages = vec![
                crate::llm::ChatMessage::system(
                    "You are a security adversarial tester. Answer YES if you can invalidate the finding, NO if it's valid. Return JSON: {\"invalid\": true/false, \"reason\": \"...\"}"
                ),
                crate::llm::ChatMessage::user(&batch_prompt),
            ];

            match self.llm.chat(&messages).await {
                Ok(response) => {
                    let invalidation = self.parse_invalidation(&response.content);
                    self.apply_findings(chunk, &mut results, invalidation);
                }
                Err(e) => {
                    tracing::warn!("Validate phase failed: {}", e);
                    // On error, keep original findings
                    results.extend(chunk.iter().cloned());
                }
            }
        }

        Ok(results)
    }

    fn build_batch_prompt(&self, findings: &[VulnerabilityFinding], source: &str) -> String {
        let mut prompt = String::from("Given this code and these findings, can you construct an adversarial case that INVALIDATES each finding? Answer YES (invalid) or NO (valid) with reasoning.\n\n");
        prompt.push_str("Code:\n```\n");
        prompt.push_str(source);
        prompt.push_str("\n```\n\nFindings:\n");

        for (i, finding) in findings.iter().enumerate() {
            prompt.push_str(&format!(
                "{}. {} at line {} (CWE: {:?}): {}\n",
                i + 1,
                finding.title,
                finding.line_number.unwrap_or(0),
                finding.cwe_id,
                finding.description
            ));
        }

        prompt.push_str("\nReturn JSON array: [{\"finding_index\": 0, \"invalid\": true/false, \"reason\": \"...\"}]\n");
        prompt
    }

    fn parse_invalidation(&self, json: &str) -> Vec<(usize, bool, String)> {
        let cleaned = json
            .trim()
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim();

        if let Ok(parsed) = serde_json::from_str::<Vec<serde_json::Value>>(cleaned) {
            parsed
                .iter()
                .filter_map(|item| {
                    let idx = item.get("finding_index").and_then(|v| v.as_u64())? as usize;
                    let invalid = item.get("invalid").and_then(|v| v.as_bool()).unwrap_or(false);
                    let reason = item.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    Some((idx, invalid, reason))
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    fn apply_findings(
        &self,
        batch: &[VulnerabilityFinding],
        results: &mut Vec<VulnerabilityFinding>,
        invalidations: Vec<(usize, bool, String)>,
    ) {
        for (i, finding) in batch.iter().enumerate() {
            let mut updated = finding.clone();
            
            // Check if this finding was invalidated
            if let Some((_idx, invalid, reason)) = invalidations.iter().find(|(idx, _, _)| *idx == i) {
                if *invalid {
                    // Adversarial invalidated - multiply confidence by 0.3
                    updated.confidence_score *= 0.3;
                    updated.verification_notes = Some(format!("Adversarial validation invalidated: {}", reason));
                } else {
                    // Validated - multiply confidence by 1.1
                    updated.confidence_score = (updated.confidence_score * 1.1).min(1.0);
                    updated.verification_notes = Some(format!("Adversarial validation passed: {}", reason));
                }
            } else {
                // No invalidation result - keep original confidence
                updated.verification_notes = Some("Adversarial validation skipped".to_string());
            }

            results.push(updated);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_validate_phase_disabled() {
        let config = OrchestrationConfig {
            enabled: false,
            ..Default::default()
        };
        let client = crate::llm::LlmClient::new(crate::llm::LlmConfig::default());
        let phase = ValidatePhase::new(client, config);

        let findings = vec![create_test_finding()];
        let result = phase.run(&findings, "test code").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    fn create_test_finding() -> VulnerabilityFinding {
        VulnerabilityFinding {
            id: "test-finding".to_string(),
            title: "Test vulnerability".to_string(),
            description: "Test description".to_string(),
            severity: crate::findings::Severity::High,
            confidence_score: 0.8,
            cwe_id: Some("CWE-89".to_string()),
            file_path: "test.rs".to_string(),
            line_number: Some(42),
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
        }
    }
}