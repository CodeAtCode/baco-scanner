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

        let Some(client) = crate::llm::create_llm_client_with_metrics(ctx.scanner, "discovery")
        else {
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
                tracing::debug!(
                    "Agent mode: analyzing with {} models: {:?}",
                    models.len(),
                    models
                );

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
                        parse_llm_response(
                            &response_with_model.content,
                            &mut all_descriptions,
                            &mut all_fixes,
                            model,
                        );
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
                tracing::debug!(
                    "Analyzing finding with {} models: {:?}",
                    models.len(),
                    models
                );

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
                        parse_llm_response(
                            &response_with_model.content,
                            &mut all_descriptions,
                            &mut all_fixes,
                            model,
                        );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LlmConfig, LlmPhaseConfig, LlmPhasesConfig, ScannerConfig};
    use crate::findings::{Severity, VulnerabilityFinding};
    use crate::scanner::Scanner;
    use tempfile::TempDir;

    fn create_test_scanner() -> (Scanner, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = ScannerConfig::default();
        let scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);
        (scanner, temp_dir)
    }

    fn create_test_scanner_with_llm() -> (Scanner, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let mut config = ScannerConfig::default();
        config.llm = LlmConfig {
            timeout_secs: 30,
            max_retries: 3,
            retry_backoff_ms: 2000,
            max_concurrent: 4,
            phases: LlmPhasesConfig {
                discovery: LlmPhaseConfig {
                    base_url: "http://test.local".to_string(),
                    api_key: Some("test-key".to_string()),
                    model: "test-model".to_string(),
                    models: vec![],
                    timeout_secs: None,
                },
                ..Default::default()
            },
            tgi: Default::default(),
        };
        let scanner = Scanner::new(config, temp_dir.path().to_path_buf(), false);
        (scanner, temp_dir)
    }

    #[test]
    fn test_llm_discovery_phase_creation() {
        let phase = LlmDiscoveryPhase;
        assert_eq!(phase.name(), "LlmDiscovery");
        assert_eq!(phase.order(), 4);
    }

    #[test]
    fn test_is_enabled_with_api_key() {
        let (scanner, _temp) = create_test_scanner_with_llm();
        let analyzed_files = Vec::new();
        let ctx = PhaseContext {
            scanner: Box::leak(Box::new(scanner)),
            analyzed_files: Box::leak(Box::new(analyzed_files)),
        };
        let phase = LlmDiscoveryPhase;
        assert!(phase.is_enabled(&ctx));
    }

    #[test]
    fn test_is_disabled_without_api_key() {
        let (scanner, _temp) = create_test_scanner();
        let analyzed_files = Vec::new();
        let ctx = PhaseContext {
            scanner: Box::leak(Box::new(scanner)),
            analyzed_files: Box::leak(Box::new(analyzed_files)),
        };
        let phase = LlmDiscoveryPhase;
        assert!(!phase.is_enabled(&ctx));
    }

    #[tokio::test]
    async fn test_execute_with_empty_findings() {
        let (scanner, _temp) = create_test_scanner_with_llm();
        let analyzed_files = Vec::new();
        let mut ctx = PhaseContext {
            scanner: Box::leak(Box::new(scanner)),
            analyzed_files: Box::leak(Box::new(analyzed_files)),
        };
        let phase = LlmDiscoveryPhase;
        let result = phase.execute(&mut ctx).await;
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_execute_without_api_key_returns_original() {
        let (scanner, _temp) = create_test_scanner();
        scanner.state.send_modify(|s| {
            s.findings.push(VulnerabilityFinding {
                id: "test-1".to_string(),
                title: "Test vulnerability".to_string(),
                description: "Test description".to_string(),
                severity: Severity::High,
                confidence_score: 0.5,
                cwe_id: Some("CWE-79".to_string()),
                file_path: "test.c".to_string(),
                line_number: Some(10),
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
            });
        });
        let analyzed_files = Vec::new();
        let mut ctx = PhaseContext {
            scanner: Box::leak(Box::new(scanner)),
            analyzed_files: Box::leak(Box::new(analyzed_files)),
        };
        let phase = LlmDiscoveryPhase;
        let result = phase.execute(&mut ctx).await;
        assert!(result.is_ok());
        let findings = result.unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_parse_llm_response_valid_json() {
        let content = r#"{"description": "Test desc", "fix_code": "test fix"}"#;
        let mut descriptions = Vec::new();
        let mut fixes = Vec::new();
        parse_llm_response(content, &mut descriptions, &mut fixes, "test-model");
        assert_eq!(descriptions.len(), 1);
        assert_eq!(descriptions[0], "Test desc");
        assert_eq!(fixes.len(), 1);
        assert_eq!(fixes[0], "test fix");
    }

    #[test]
    fn test_parse_llm_response_invalid_json() {
        let content = "not valid json";
        let mut descriptions = Vec::new();
        let mut fixes = Vec::new();
        parse_llm_response(content, &mut descriptions, &mut fixes, "test-model");
        assert!(descriptions.is_empty());
        assert!(fixes.is_empty());
    }

    #[test]
    fn test_parse_llm_response_partial_json() {
        let content = r#"{"description": "Only desc"}"#;
        let mut descriptions = Vec::new();
        let mut fixes = Vec::new();
        parse_llm_response(content, &mut descriptions, &mut fixes, "test-model");
        assert_eq!(descriptions.len(), 1);
        assert!(fixes.is_empty());
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
