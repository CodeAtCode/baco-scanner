//! Semantic deduplication logic for findings

use super::enrichment::EnrichmentService;
use crate::findings::{Severity, VerificationStatus, VulnerabilityFinding};
use crate::llm::ChatMessage;
use std::collections::HashSet;

/// Semantic deduplication service
pub struct DeduplicationService {
    llm_config: crate::llm::LlmConfig,
}

impl DeduplicationService {
    /// Create a new deduplication service
    pub fn new(config: &crate::llm::LlmConfig) -> Self {
        Self {
            llm_config: config.clone(),
        }
    }

    /// Semantic deduplication: uses LLM to identify and merge duplicate findings
    pub async fn deduplicate(
        &self,
        findings: &[VulnerabilityFinding],
    ) -> Vec<VulnerabilityFinding> {
        if findings.is_empty() {
            return Vec::new();
        }

        let mut deduplicated: Vec<VulnerabilityFinding> = Vec::new();
        let mut skipped_indices = HashSet::new();

        for (i, finding) in findings.iter().enumerate() {
            if skipped_indices.contains(&i) {
                continue;
            }

            let mut duplicates = Vec::new();

            for (j, other) in findings.iter().enumerate().skip(i + 1) {
                if skipped_indices.contains(&j) {
                    continue;
                }

                if finding.file_path != other.file_path {
                    continue;
                }

                let same_location = match (finding.line_number, other.line_number) {
                    (Some(a), Some(b)) => (a as i32 - b as i32).abs() <= 3,
                    _ => false,
                };

                if !same_location {
                    continue;
                }

                if !self.llm_config.api_key.is_empty() && !self.llm_config.base_url.is_empty() {
                    let client = crate::llm::LlmClient::new(self.llm_config.clone());
                    let prompt = format!(
                        "Determine if these two security findings describe the SAME vulnerability:\n\n\
                         Finding 1: {} at {}:{} - {}\n\
                         Finding 2: {} at {}:{} - {}\n\n\
                         Respond with JSON: {{\"same_issue\": true/false, \"reason\": \"explanation\"}}",
                        finding.title,
                        finding.file_path,
                        finding.line_number.unwrap_or(0),
                        finding.description,
                        other.title,
                        other.file_path,
                        other.line_number.unwrap_or(0),
                        other.description
                    );

                    let messages = vec![ChatMessage {
                        role: "user".to_string(),
                        content: prompt,
                    }];

                    if let Ok(response) = client.chat(&messages).await {
                        if let Some(same) =
                            EnrichmentService::extract_json_field(&response.content, "same_issue")
                        {
                            if same.to_lowercase() == "true"
                                || same.to_lowercase() == "yes"
                                || same == "1"
                            {
                                duplicates.push(j);
                            }
                        }
                    }
                }
            }

            let mut candidates: Vec<VulnerabilityFinding> = vec![finding.clone()];
            for &dup_idx in &duplicates {
                candidates.push(findings[dup_idx].clone());
            }

            // Use the merge comparator to select the best candidate
            let best = candidates.into_iter().max_by(dedup_merge_comparator);

            if let Some(best_finding) = best {
                deduplicated.push(best_finding);
            }

            for &dup_idx in &duplicates {
                skipped_indices.insert(dup_idx);
            }
        }

        tracing::info!(
            "Semantic deduplication: {} findings reduced to {} unique findings",
            findings.len(),
            deduplicated.len()
        );
        deduplicated
    }
}

/// Merge comparator for selecting the best candidate when merging duplicate findings.
///
/// Priority order:
/// 1. Verification status: Confirmed beats FalsePositive regardless of severity/confidence
/// 2. Severity: Higher severity wins
/// 3. Confidence: Higher confidence wins as tiebreaker
pub fn dedup_merge_comparator(
    a: &VulnerabilityFinding,
    b: &VulnerabilityFinding,
) -> std::cmp::Ordering {
    // Verification status takes absolute priority: Confirmed beats FalsePositive
    let status_a = a.verification_status;
    let status_b = b.verification_status;

    // If one is Confirmed and the other is FalsePositive, Confirmed wins
    if status_a == Some(VerificationStatus::Confirmed)
        && status_b == Some(VerificationStatus::FalsePositive)
    {
        return std::cmp::Ordering::Greater;
    }
    if status_b == Some(VerificationStatus::Confirmed)
        && status_a == Some(VerificationStatus::FalsePositive)
    {
        return std::cmp::Ordering::Less;
    }

    // Otherwise, fall back to severity-then-confidence ordering
    let severity_cmp = match (a.severity, b.severity) {
        (Severity::Critical, Severity::Critical) => std::cmp::Ordering::Equal,
        (Severity::Critical, _) => std::cmp::Ordering::Greater,
        (_, Severity::Critical) => std::cmp::Ordering::Less,
        (Severity::High, Severity::High) => std::cmp::Ordering::Equal,
        (Severity::High, Severity::Medium | Severity::Low | Severity::Info) => {
            std::cmp::Ordering::Greater
        }
        (Severity::Medium | Severity::Low | Severity::Info, Severity::High) => {
            std::cmp::Ordering::Less
        }
        (Severity::Medium, Severity::Medium) => std::cmp::Ordering::Equal,
        (Severity::Medium, Severity::Low | Severity::Info) => std::cmp::Ordering::Greater,
        (Severity::Low | Severity::Info, Severity::Medium) => std::cmp::Ordering::Less,
        (Severity::Low, Severity::Low) => std::cmp::Ordering::Equal,
        (Severity::Low, Severity::Info) => std::cmp::Ordering::Greater,
        (Severity::Info, Severity::Low) => std::cmp::Ordering::Less,
        (Severity::Info, Severity::Info) => std::cmp::Ordering::Equal,
    };

    severity_cmp.then_with(|| {
        // Higher confidence wins. This used to be b.partial_cmp(&a), which is
        // reversed: under max_by a Greater result means "this element is the
        // maximum", so the old form selected the LOWER confidence of two
        // findings of equal severity.
        a.confidence_score
            .partial_cmp(&b.confidence_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    })
}
