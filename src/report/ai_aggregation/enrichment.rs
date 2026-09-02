//! LLM enrichment functions for findings

use crate::findings::VulnerabilityFinding;
use crate::llm::{ChatMessage, LlmChatClient, LlmClient, LlmConfig};
use regex;
use serde::Deserialize;

/// Enrichment service for adding LLM-generated descriptions and recommendations
pub struct EnrichmentService {
    llm_client: Option<LlmClient>,
}

/// Batch enrichment item (index + description + recommendation)
#[derive(Deserialize, Debug)]
struct BatchEnrichmentItem {
    index: usize,
    description: Option<String>,
    recommendation: Option<String>,
}

/// Build stable prefix for enrichment prompt (byte-stable across findings)
/// Returns the prefix that should be cached by LLM providers.
pub fn build_stable_enrichment_prefix(_findings: &[VulnerabilityFinding]) -> String {
    String::from(
        "Analyze the following security findings and provide descriptions and recommendations.\n\
         Return a JSON array with ONE object per finding.\n\
         Each object MUST have: index (0-based within this batch), description, recommendation.\n\
         STRICT OUTPUT FORMAT: Return ONLY valid JSON array, no prose outside the JSON.\n\n\
         JSON schema:\n\
         [\n\
           {\n\
             \"index\": <number>,\n\
             \"description\": \"detailed explanation of the vulnerability\",\n\
             \"recommendation\": \"specific steps to fix this issue\"\n\
           }\n\
         ]\n\n",
    )
}

/// Build volatile tail for enrichment prompt (finding-specific content)
pub fn build_volatile_enrichment_tail(findings: &[VulnerabilityFinding]) -> String {
    let mut tail = String::new();

    for (i, finding) in findings.iter().enumerate() {
        tail.push_str(&format!(
            "Finding #{}: {} ({})\n\
             Location: {}:{}\n\
             CWE: {:?}\n\
             Current description: {}\n\
             Current recommendation: {:?}\n\n",
            i,
            finding.title,
            finding.severity,
            finding.file_path,
            finding.line_number.unwrap_or(0),
            finding.cwe_id,
            finding.description,
            finding.recommendation
        ));
        tail.push_str("---\n\n");
    }

    tail.push_str("Return JSON array now.\n");
    tail
}

/// Build a batch enrichment prompt for multiple findings
fn build_batch_enrichment_prompt(findings: &[VulnerabilityFinding]) -> String {
    let stable_prefix = build_stable_enrichment_prefix(findings);
    let volatile_tail = build_volatile_enrichment_tail(findings);
    format!("{}{}", stable_prefix, volatile_tail)
}

/// Parse batch enrichment response from LLM output.
/// Returns Vec of (description, recommendation) per finding index.
/// Failed items get None for both fields.
fn parse_batch_enrichment_verdict(
    content: &str,
    expected_count: usize,
) -> Vec<(Option<String>, Option<String>)> {
    let cleaned = content
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim_start_matches("json")
        .trim();

    match serde_json::from_str::<Vec<BatchEnrichmentItem>>(cleaned) {
        Ok(items) => {
            let mut results = vec![(None, None); expected_count];

            for item in items {
                if item.index < expected_count {
                    results[item.index] = (item.description, item.recommendation);
                }
            }

            results
        }
        Err(_) => {
            // Entire batch failed - return all None
            vec![(None, None); expected_count]
        }
    }
}

/// Enrich findings in batches to reduce LLM API calls.
/// Returns Vec of enriched findings.
pub async fn enrich_findings_batched<C: LlmChatClient>(
    client: &C,
    findings: &[VulnerabilityFinding],
    batch_size: usize,
) -> Vec<VulnerabilityFinding> {
    if batch_size <= 1 || findings.is_empty() {
        // Signal fallback needed
        return Vec::new();
    }

    let mut enriched_findings = Vec::with_capacity(findings.len());
    let mut batch_start = 0;
    let mut success_count = 0;
    let mut failure_count = 0;

    while batch_start < findings.len() {
        let batch_end = (batch_start + batch_size).min(findings.len());
        let batch = &findings[batch_start..batch_end];

        let prompt_text = build_batch_enrichment_prompt(batch);
        let messages = vec![ChatMessage {
            role: "user".to_string(),
            content: prompt_text,
        }];

        match client.chat(&messages).await {
            Ok(response) => {
                let results = parse_batch_enrichment_verdict(&response.content, batch.len());

                for (i, finding) in batch.iter().enumerate() {
                    let mut enriched = finding.clone();
                    let (desc, rec) = &results[i];

                    let llm_failed = desc.is_none() && rec.is_none();

                    // Handle description
                    enriched.description = match desc {
                        Some(d) if !d.is_empty() => {
                            success_count += 1;
                            d.clone()
                        }
                        _ => {
                            if llm_failed && finding.description.is_empty() {
                                format!(
                                    "Security issue: {} at {}:{} (CWE: {:?}). LLM enrichment unavailable.",
                                    finding.title,
                                    finding.file_path,
                                    finding.line_number.unwrap_or(0),
                                    finding.cwe_id
                                )
                            } else if !finding.description.is_empty() {
                                finding.description.clone()
                            } else {
                                format!(
                                    "Security issue: {} at {}:{} (CWE: {:?})",
                                    finding.title,
                                    finding.file_path,
                                    finding.line_number.unwrap_or(0),
                                    finding.cwe_id
                                )
                            }
                        }
                    };

                    // Handle recommendation
                    enriched.recommendation = match rec {
                        Some(r) if !r.trim().is_empty() => {
                            success_count += 1;
                            Some(r.clone())
                        }
                        _ => finding.recommendation.clone().or_else(|| {
                            Some("Review and fix the identified security issue.".to_string())
                        }),
                    };

                    enriched_findings.push(enriched);
                }
            }
            Err(e) => {
                failure_count += batch.len();
                tracing::warn!("Batch enrichment failed: {}", e);
                for finding in batch {
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
                        enriched.recommendation =
                            Some("Investigate and remediate the security finding.".to_string());
                    }
                    enriched_findings.push(enriched);
                }
            }
        }

        batch_start = batch_end;
    }

    if success_count == 0 && failure_count > 0 {
        tracing::warn!(
            "LLM enrichment completely failed: 0 successes, {} failures",
            failure_count
        );
    } else if failure_count > 0 {
        tracing::info!(
            "LLM enrichment partial: {} successes, {} failures",
            success_count,
            failure_count
        );
    }

    enriched_findings
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
    pub async fn enrich_findings(
        &self,
        findings: &[VulnerabilityFinding],
    ) -> (Vec<VulnerabilityFinding>, bool) {
        let client = match &self.llm_client {
            Some(c) => c,
            None => {
                tracing::warn!("LLM client is None, returning unenriched findings");
                return (findings.to_vec(), false);
            }
        };

        // Use batched enrichment (batch_size=8 by default)
        let batch_size = 8;

        if batch_size > 1 && !findings.is_empty() {
            // Batched path
            let enriched = enrich_findings_batched(client, findings, batch_size).await;
            let llm_completely_failed = enriched
                .iter()
                .all(|f| f.description.contains("LLM enrichment unavailable"));
            (enriched, llm_completely_failed)
        } else {
            // Per-finding fallback (original path)
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

                        let (final_desc, final_rec) =
                            if (desc.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true)
                                && finding.description.is_empty())
                                || (rec.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true)
                                    && finding.recommendation.is_none())
                            {
                                // Removed second retry-prompt call per T14 spec
                                // Instead, keep empty fields and count in warning summary
                                (desc.clone(), rec.clone())
                            } else {
                                (desc.clone(), rec.clone())
                            };

                        let llm_failed =
                            final_desc.is_none() && final_rec.is_none() && desc.is_none();

                        enriched.description = if let Some(d) = final_desc {
                            if !d.is_empty() {
                                d
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
                            }
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
                        tracing::debug!(
                            "LLM enrichment failed for finding {}: {}",
                            finding.title,
                            e
                        );
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
                            enriched.recommendation =
                                Some("Investigate and remediate the security finding.".to_string());
                        }
                        enriched_findings.push(enriched);
                    }
                }
            }

            let llm_completely_failed = llm_success_count == 0 && llm_failure_count > 0;

            if llm_completely_failed {
                tracing::warn!(
                    "LLM enrichment completely failed: 0 successes, {} failures",
                    llm_failure_count
                );
            } else if llm_failure_count > 0 {
                tracing::info!(
                    "LLM enrichment partial: {} successes, {} failures",
                    llm_success_count,
                    llm_failure_count
                );
            }

            (enriched_findings, llm_completely_failed)
        }
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
