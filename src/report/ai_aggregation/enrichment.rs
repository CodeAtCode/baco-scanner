//! LLM enrichment functions for findings

use crate::findings::VulnerabilityFinding;
use crate::llm::{ChatMessage, LlmClient, LlmConfig};
use regex;

/// Enrichment service for adding LLM-generated descriptions and recommendations
pub struct EnrichmentService {
    llm_client: Option<LlmClient>,
}

impl EnrichmentService {
    /// Create a new enrichment service
    pub fn new(config: &LlmConfig) -> Self {
        let llm_client = if !config.api_key.is_empty() && !config.base_url.is_empty() {
            Some(LlmClient::new(config.clone()))
        } else {
            None
        };
        Self { llm_client }
    }

    /// Enrich findings with LLM-generated description and recommendation
    pub async fn enrich_findings(&self, findings: &[VulnerabilityFinding]) -> (Vec<VulnerabilityFinding>, bool) {
        let client = match &self.llm_client {
            Some(c) => c,
            None => {
                tracing::warn!("LLM client is None, returning unenriched findings");
                return (findings.to_vec(), false);
            }
        };

        let mut enriched_findings = Vec::new();
        let mut llm_success_count = 0;
        let mut llm_failure_count = 0;

        for finding in findings {
            let prompt = format!(
                "Analyze this security finding and provide:\n\
                 1. A detailed description of the vulnerability\n\
                 2. A specific recommendation for fixing it\n\n\
                 Finding: {} ({})\n\
                 Location: {}:{}\n\
                 CWE: {:?}\n\
                 Current description: {}\n\
                 Current recommendation: {:?}\n\n\
                 Respond with JSON format:\n\
                 {{\n\
                   \"description\": \"detailed explanation of the vulnerability\",\n\
                   \"recommendation\": \"specific steps to fix this issue\"\n\
                 }}",
                finding.title,
                finding.severity,
                finding.file_path,
                finding.line_number.unwrap_or(0),
                finding.cwe_id,
                finding.description,
                finding.recommendation
            );

            let messages = vec![ChatMessage {
                role: "user".to_string(),
                content: prompt,
            }];

            match client.chat(&messages).await {
                Ok(response) => {
                    llm_success_count += 1;
                    let mut enriched = finding.clone();
                    
                    let desc = Self::extract_json_field(&response.content, "description");
                    let rec = Self::extract_json_field(&response.content, "recommendation");
                    
                    let (final_desc, final_rec) = if (desc.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) 
                                                      && finding.description.is_empty())
                        || (rec.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) 
                            && finding.recommendation.is_none()) {
                        let retry_prompt = format!(
                            "Describe this security issue in one sentence and provide one sentence recommendation.\n\
                             Issue: {} at {}:{}\n\
                             Respond with: description|recommendation",
                            finding.title,
                            finding.file_path,
                            finding.line_number.unwrap_or(0)
                        );
                        
                        let retry_messages = vec![ChatMessage {
                            role: "user".to_string(),
                            content: retry_prompt,
                        }];
                        
                        match client.chat(&retry_messages).await {
                            Ok(retry_response) => {
                                let parts: Vec<&str> = retry_response.content.split('|').collect();
                                let retry_desc = if !parts.is_empty() { parts[0].trim().to_string() } else { String::new() };
                                let retry_rec = if parts.len() > 1 { parts[1].trim().to_string() } else { String::new() };
                                
                                (
                                    if !retry_desc.is_empty() { retry_desc } else { desc.clone().unwrap_or_default() },
                                    if !retry_rec.is_empty() { Some(retry_rec) } else { rec.clone() }
                                )
                            }
                            Err(_e) => {
                                (desc.clone().unwrap_or_default(), rec.clone())
                            }
                        }
                    } else {
                        (desc.clone().unwrap_or_default(), rec.clone())
                    };
                    
                    let llm_failed = final_desc.is_empty() && final_rec.is_none() && desc.is_none();
                    
                    enriched.description = if !final_desc.is_empty() {
                        final_desc
                    } else if !finding.description.is_empty() {
                        finding.description.clone()
                    } else if llm_failed {
                        format!(
                            "Security issue: {} at {}:{} (CWE: {:?}). LLM enrichment unavailable.",
                            finding.title,
                            finding.file_path,
                            finding.line_number.unwrap_or(0),
                            finding.cwe_id
                        )
                    } else {
                        format!(
                            "Security issue: {} at {}:{} (CWE: {:?})",
                            finding.title,
                            finding.file_path,
                            finding.line_number.unwrap_or(0),
                            finding.cwe_id
                        )
                    };
                    
                    enriched.recommendation = if let Some(r) = final_rec {
                        if !r.trim().is_empty() {
                            Some(r)
                        } else if let Some(existing_rec) = &finding.recommendation {
                            Some(existing_rec.clone())
                        } else {
                            Some("Review and fix the identified security issue.".to_string())
                        }
                    } else if let Some(existing_rec) = &finding.recommendation {
                        Some(existing_rec.clone())
                    } else {
                        Some("Review and fix the identified security issue.".to_string())
                    };

                    enriched_findings.push(enriched);
                }
                Err(e) => {
                    llm_failure_count += 1;
                    tracing::debug!("LLM enrichment failed for finding {}: {}", finding.title, e);
                    let mut enriched = finding.clone();
                    if enriched.description.is_empty() {
                        enriched.description = format!(
                            "Security issue: {} at {}:{} (CWE: {:?}). LLM enrichment unavailable (client error).",
                            finding.title,
                            finding.file_path,
                            finding.line_number.unwrap_or(0),
                            finding.cwe_id
                        );
                    }
                    if enriched.recommendation.is_none() {
                        enriched.recommendation = Some("Investigate and remediate the security finding.".to_string());
                    }
                    enriched_findings.push(enriched);
                }
            }
        }

        let llm_completely_failed = llm_success_count == 0 && llm_failure_count > 0;
        
        if llm_completely_failed {
            tracing::warn!("LLM enrichment completely failed: 0 successes, {} failures", llm_failure_count);
        } else if llm_failure_count > 0 {
            tracing::info!("LLM enrichment partial: {} successes, {} failures", llm_success_count, llm_failure_count);
        }

        (enriched_findings, llm_completely_failed)
    }

    /// Extract a field value from JSON response (public for deduplication module)
    pub fn extract_json_field(json: &str, field: &str) -> Option<String> {
        let pattern = format!("\"{}\":\\s*\"([^\"]+)\"", field);
        if let Some(caps) = regex::Regex::new(&pattern).ok()?.captures(json) {
            if let Some(m) = caps.get(1) {
                return Some(m.as_str().to_string());
            }
        }
        None
    }
}
