use super::{PhaseContext, PhaseError, ScanPhase};
use crate::findings::VulnerabilityFinding;
use crate::llm::ChatMessage;
use async_trait::async_trait;

pub struct LlmDiscoveryPhase;

#[async_trait]
impl ScanPhase for LlmDiscoveryPhase {
    fn name(&self) -> &'static str {
        "LlmDiscovery"
    }

    fn order(&self) -> u8 {
        4
    }

    async fn execute(
        &self,
        ctx: &mut PhaseContext,
    ) -> Result<Vec<VulnerabilityFinding>, PhaseError> {
        tracing::info!("Running LLM discovery phase...");

        // Get findings from scanner state
        let findings = {
            let state = ctx.scanner.state.clone();
            let reader = state.borrow();
            reader.findings.clone()
        };

        let Some(client) = crate::llm::create_llm_client_with_metrics(&ctx.scanner, "discovery") else {
            tracing::debug!("No API key for discovery, skipping LLM enrichment");
            return Ok(findings);
        };

        let total_findings = findings.len();
        let use_agent_mode = ctx.scanner.config.agent.enabled;
        let target_path = ctx.scanner.target_path.clone();

        let mut enriched_findings = Vec::with_capacity(findings.len());

        for (i, mut finding) in findings.into_iter().enumerate() {
            tracing::debug!(
                "Enriching finding [{}/{}]: {}",
                i + 1,
                total_findings,
                finding.title
            );

            if use_agent_mode {
                let models = client.get_all_models();
                tracing::debug!("Agent mode: analyzing with {} models: {:?}", models.len(), models);
                
                let source_path = target_path.join(&finding.file_path);
                let source_code = std::fs::read_to_string(&source_path)
                    .unwrap_or_else(|_| "Unable to read source file".to_string());
                
                let mut all_descriptions: Vec<String> = Vec::new();
                let mut all_fixes: Vec<String> = Vec::new();
                
                for model in &models {
                    tracing::debug!("  Agent mode with model: {}", model);
                    
                    let prompt = format!(
                        r#"Analyze this vulnerability and provide enriched details.

FILE: {}:{}
VULNERABILITY: {}
CURRENT DESCRIPTION: {}
MODEL: {}

SOURCE CODE:
```
{}
```

Respond with ONLY a JSON object (no other text):
{{
  "description": "Enriched technical description with attack scenarios and CWEs",
  "fix_code": "The SECURE version of the vulnerable code - how the code SHOULD be written"
}}"#,
                        finding.file_path,
                        finding.line_number.unwrap_or(0),
                        finding.title,
                        finding.description,
                        model,
                        &source_code[..source_code.len().min(8000)]
                    );

                    let messages = vec![
                        ChatMessage::system(
                            "You are a security vulnerability analyst. Output valid JSON only.",
                        ),
                        ChatMessage::user(&prompt),
                    ];

                    if let Ok(response_with_model) = client.chat(&messages).await {
                        parse_llm_response(&response_with_model.content, &mut all_descriptions, &mut all_fixes, &model);
                    } else {
                        tracing::warn!("  Agent mode model {} failed", model);
                    }
                }
                
                // Aggregate: use the longest/most detailed description
                if let Some(best_desc) = all_descriptions.into_iter().max_by_key(|d| d.len()) {
                    finding.description = best_desc;
                }
                
                if let Some(best_fix) = all_fixes.into_iter().next() {
                    finding.diff_hunk = Some(best_fix);
                }
            } else {
                // Multi-model mode: analyze with ALL configured models and aggregate results
                let models = client.get_all_models();
                tracing::debug!("Analyzing finding with {} models: {:?}", models.len(), models);
                
                let mut all_descriptions: Vec<String> = Vec::new();
                let mut all_fixes: Vec<String> = Vec::new();
                
                for model in &models {
                    tracing::debug!("  Analyzing with model: {}", model);
                    
                    let messages = vec![
                        ChatMessage::system(
                            "You are a security vulnerability analyzer. Output valid JSON only.",
                        ),
                        ChatMessage::user(&format!(
                            r#"Vulnerability: {}
Location: {}:{}
Current description: {}
Model: {}

Respond with ONLY JSON:
{{
  "description": "Enriched description",
  "fix_code": "The secure version of the code"
}}"#,
                            finding.title,
                            finding.file_path,
                            finding.line_number.unwrap_or(0),
                            finding.description,
                            model
                        )),
                    ];

                    if let Ok(response_with_model) = client.chat(&messages).await {
                        parse_llm_response(&response_with_model.content, &mut all_descriptions, &mut all_fixes, &model);
                    } else {
                        tracing::warn!("  Model {} failed to analyze this finding", model);
                    }
                }
                
                // Aggregate: use the longest/most detailed description
                if let Some(best_desc) = all_descriptions.into_iter().max_by_key(|d| d.len()) {
                    finding.description = best_desc;
                }
                
                // Use the first fix available
                if let Some(best_fix) = all_fixes.into_iter().next() {
                    finding.diff_hunk = Some(best_fix);
                }
            }

            enriched_findings.push(finding);
        }

        tracing::info!(
            "LLM discovery complete - enriched {} findings",
            total_findings
        );

        Ok(enriched_findings)
    }

    fn is_enabled(&self, ctx: &PhaseContext) -> bool {
        ctx.scanner.config.llm.phases.discovery.api_key.is_some()
    }
}

/// Helper to parse LLM JSON response and extract description/fix
fn parse_llm_response(
    content: &str,
    descriptions: &mut Vec<String>,
    fixes: &mut Vec<String>,
    model: &str,
) {
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(content) {
        if let Some(desc) = parsed.get("description").and_then(|v| v.as_str()) {
            descriptions.push(desc.to_string());
        }
        if let Some(fix) = parsed.get("fix_code").and_then(|v| v.as_str()) {
            fixes.push(fix.to_string());
        }
    } else {
        tracing::warn!("  Failed to parse JSON response from model {}", model);
    }
}
