//! Validate phase: adversarial self-check

use crate::findings::VulnerabilityFinding;
use crate::llm::LlmClient;

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

/// Answer to a single gate question
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateAnswer {
    Yes,
    No,
    Unknown,
}

impl std::fmt::Display for GateAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateAnswer::Yes => write!(f, "YES"),
            GateAnswer::No => write!(f, "NO"),
            GateAnswer::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Concrete impact proof (B2 requirement)
#[derive(Debug, Clone)]
struct ConcreteImpactProof {
    attack_vector: String,
    consequence: String,
    is_theoretical: bool,
}

/// Result of the 7-question gate analysis
#[derive(Debug, Clone)]
struct GateResult {
    reachability: GateAnswer,
    controllability: GateAnswer,
    preconditions: GateAnswer,
    impact: GateAnswer,
    context: GateAnswer,
    evidence: GateAnswer,
    confidence: GateAnswer,
    concrete_impact_proof: Option<ConcreteImpactProof>,
    triage_verdict: crate::findings::TriageVerdict,
    verification_notes: String,
    verification_status: Option<crate::findings::VerificationStatus>,
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
                    "You are a security adversarial tester. Apply the 7-question gate triage and provide concrete impact proof. Return JSON as specified in the prompt."
                ),
                crate::llm::ChatMessage::user(&batch_prompt),
            ];

            match self.llm.chat(&messages).await {
                Ok(response) => {
                    let gate_results = self.parse_7question_gate(&response.content);
                    self.apply_gate_results(chunk, &mut results, gate_results);
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
        let mut prompt = String::from(include_str!("../../../prompts/phases/llm_verification.md"));
        prompt.push_str("\n\nCode:\n```\n");
        prompt.push_str(source);
        prompt.push_str("\n```\n\nFindings to analyze:\n");

        for (i, finding) in findings.iter().enumerate() {
            prompt.push_str(&format!(
                "\n--- Finding {} ---\n",
                i + 1
            ));
            prompt.push_str(&format!("Title: {}\n", finding.title));
            prompt.push_str(&format!("Location: {}:{}\n", finding.file_path, finding.line_number.unwrap_or(0)));
            prompt.push_str(&format!("Description: {}\n", finding.description));
            if let Some(ref cwe) = finding.cwe_id {
                prompt.push_str(&format!("CWE: {}\n", cwe));
            }
            if let Some(ref snippet) = finding.code_snippet {
                prompt.push_str(&format!("Code snippet: {}\n", snippet));
            }
        }

        prompt
    }

    fn parse_7question_gate(&self, json: &str) -> Vec<(usize, GateResult)> {
        let cleaned = json
            .trim()
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim();

        let mut results = Vec::new();

        // Try to parse as array first (batch mode)
        if let Ok(parsed) = serde_json::from_str::<Vec<serde_json::Value>>(cleaned) {
            for (idx, item) in parsed.iter().enumerate() {
                if let Some(gate) = self.extract_gate_result(item) {
                    results.push((idx, gate));
                }
            }
        } else {
            // Try single object mode
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(cleaned) {
                if let Some(gate) = self.extract_gate_result(&parsed) {
                    results.push((0, gate));
                }
            }
        }

        results
    }

    fn extract_gate_result(&self, item: &serde_json::Value) -> Option<GateResult> {
        let gate_obj = item.get("seven_question_gate")?;
        
        let reachability = self.parse_gate_answer(gate_obj.get("reachability")?);
        let controllability = self.parse_gate_answer(gate_obj.get("controllability")?);
        let preconditions = self.parse_gate_answer(gate_obj.get("preconditions")?);
        let impact = self.parse_gate_answer(gate_obj.get("impact")?);
        let context = self.parse_gate_answer(gate_obj.get("context")?);
        let evidence = self.parse_gate_answer(gate_obj.get("evidence")?);
        let confidence = self.parse_gate_answer(gate_obj.get("confidence")?);

        let concrete_proof = item.get("concrete_impact_proof").and_then(|p| {
            let attack_vector = p.get("attack_vector").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let consequence = p.get("consequence").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let is_theoretical = p.get("is_theoretical").and_then(|v| v.as_bool()).unwrap_or(false);
            
            if attack_vector.is_empty() && consequence.is_empty() {
                None
            } else {
                Some(ConcreteImpactProof {
                    attack_vector,
                    consequence,
                    is_theoretical,
                })
            }
        });

        // Apply gate logic
        let triage_verdict = self.apply_gate_logic(reachability, controllability, preconditions, 
                                                   impact, context, evidence, confidence, 
                                                   concrete_proof.as_ref());

        Some(GateResult {
            reachability,
            controllability,
            preconditions,
            impact,
            context,
            evidence,
            confidence,
            concrete_impact_proof: concrete_proof,
            triage_verdict,
            verification_notes: item.get("verification_notes")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            verification_status: item.get("verification_status")
                .and_then(|v| v.as_str())
                .and_then(|s| match s {
                    "confirmed" => Some(crate::findings::VerificationStatus::Confirmed),
                    "false_positive" => Some(crate::findings::VerificationStatus::FalsePositive),
                    "needs_review" => Some(crate::findings::VerificationStatus::NeedsReview),
                    _ => None,
                }),
        })
    }

    fn parse_gate_answer(&self, value: &serde_json::Value) -> GateAnswer {
        value.as_str().map(|s| {
            match s.to_lowercase().as_str() {
                "yes" => GateAnswer::Yes,
                "no" => GateAnswer::No,
                "unknown" => GateAnswer::Unknown,
                _ => GateAnswer::Unknown,
            }
        }).unwrap_or(GateAnswer::Unknown)
    }

    fn apply_gate_logic(&self, 
                        reachability: GateAnswer,
                        controllability: GateAnswer,
                        preconditions: GateAnswer,
                        impact: GateAnswer,
                        context: GateAnswer,
                        evidence: GateAnswer,
                        confidence: GateAnswer,
                        concrete_proof: Option<&ConcreteImpactProof>) -> crate::findings::TriageVerdict {
        use crate::findings::TriageVerdict;

        // Kill conditions (Q1-Q3)
        if reachability == GateAnswer::No {
            return TriageVerdict::Kill;
        }
        if controllability == GateAnswer::No {
            return TriageVerdict::Kill;
        }
        if preconditions == GateAnswer::Yes {
            return TriageVerdict::Kill;
        }

        // Downgrade if impact is theoretical or missing concrete proof
        if concrete_proof.map(|p| p.is_theoretical).unwrap_or(true) || impact == GateAnswer::No {
            return TriageVerdict::Downgrade {
                adjusted_severity: crate::findings::Severity::Low,
            };
        }

        // Pass if Q4-Q7 all YES/CONFIRMED
        if impact == GateAnswer::Yes 
            && context == GateAnswer::Yes 
            && evidence == GateAnswer::Yes 
            && confidence == GateAnswer::Yes {
            return TriageVerdict::Pass;
        }

        // Everything else needs review
        TriageVerdict::Downgrade {
            adjusted_severity: crate::findings::Severity::Medium,
        }
    }

    fn apply_gate_results(
        &self,
        batch: &[VulnerabilityFinding],
        results: &mut Vec<VulnerabilityFinding>,
        gate_results: Vec<(usize, GateResult)>,
    ) {
        for (i, finding) in batch.iter().enumerate() {
            let mut updated = finding.clone();
            
            // Check if this finding has a gate result
            if let Some((_idx, gate)) = gate_results.iter().find(|(idx, _)| *idx == i) {
                // Apply triage verdict
                updated.triage_verdict = Some(gate.triage_verdict.clone());
                
                // Build verification notes
                let mut notes = format!("7-question gate: R={} C={} P={} I={} Ct={} E={} Conf={}",
                    gate.reachability, gate.controllability, gate.preconditions,
                    gate.impact, gate.context, gate.evidence, gate.confidence);
                
                if let Some(ref proof) = gate.concrete_impact_proof {
                    if proof.is_theoretical {
                        notes.push_str(" | Impact: THEORETICAL - downgraded");
                    } else {
                        notes.push_str(&format!(" | Impact proof: {}", proof.attack_vector));
                    }
                }
                
                if !gate.verification_notes.is_empty() {
                    notes.push_str(&format!(" | Reasoning: {}", gate.verification_notes));
                }
                
                updated.verification_notes = Some(notes);
                updated.verification_status = gate.verification_status;

                // Adjust confidence based on verdict
                match gate.triage_verdict {
                    crate::findings::TriageVerdict::Pass => {
                        updated.confidence_score = (updated.confidence_score * 1.15).min(1.0);
                    }
                    crate::findings::TriageVerdict::Kill => {
                        updated.confidence_score = 0.0;
                    }
                    crate::findings::TriageVerdict::Downgrade { .. } => {
                        updated.confidence_score *= 0.5;
                    }
                    crate::findings::TriageVerdict::ChainRequired { .. } => {
                        // No confidence adjustment for chain required
                    }
                }
            } else {
                // No gate result - keep original findings but mark as needs review
                updated.verification_notes = Some("7-question gate skipped - parsing failed".to_string());
                updated.verification_status = Some(crate::findings::VerificationStatus::NeedsReview);
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
            triage_verdict: None,
        }
    }
}