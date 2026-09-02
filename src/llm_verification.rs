//! Extended LLM Verification Phase
//!
//! Verifies findings from previous phases using LLM with:
//! - Cross-references to security best practices
//! - Finding accuracy validation and false positive reduction
//! - Detailed verification reports
//! - Confidence scoring refinement
//! - Integration with AnalysisContext

use crate::findings::{VerificationStatus, VulnerabilityFinding};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Verification result for a single finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub finding_id: String,
    pub status: VerificationStatus,
    pub confidence: f32,
    pub notes: String,
    pub mitigating_factors: Vec<String>,
    pub related_patterns: Vec<String>,
    pub false_positive_reason: Option<String>,
}

/// Detailed verification report for all findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub total_findings: usize,
    pub confirmed: usize,
    pub false_positives: usize,
    pub needs_review: usize,
    pub failed: usize,
    pub results: Vec<VerificationResult>,
    pub average_confidence: f32,
    pub high_confidence_findings: Vec<String>,
}

/// Render template with variable substitution
pub fn render_template(template: &str, variables: &HashMap<String, String>) -> String {
    let mut result = template.to_string();

    for (key, value) in variables {
        result = result.replace(&format!("%%{}%%", key), value);
        result = result.replace(&format!("{{{{{}}}}}", key), value);
    }

    result
}

/// Triage verdict from LLM analysis
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageVerdict {
    TruePositive,
    FalsePositive,
}

impl std::fmt::Display for TriageVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            TriageVerdict::TruePositive => write!(f, "true_positive"),
            TriageVerdict::FalsePositive => write!(f, "false_positive"),
        }
    }
}

/// Result of LLM-based triage for false positive detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    pub verdict: TriageVerdict,
    pub confidence: f32,
    pub reasoning: String,
}

/// Verdict from LLM-as-judge rationale validation (paper CORRECT arxiv:2504.13474)
/// Evaluates the soundness of reasoning behind a vulnerability finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RationaleVerdict {
    /// Whether the reasoning is sound
    pub is_sound: bool,
    /// List of logical errors or issues found (if any)
    pub issues: Vec<String>,
    /// Confidence adjustment to apply: +0.10 for sound, -0.20 for flawed, 0.0 for neutral
    pub confidence_adjustment: f32,
}

/// Rationale check prompt template for LLM-as-judge evaluation
const RATIONALE_CHECK_PROMPT_TEMPLATE: &str = concat!(
    "Evaluate the reasoning behind this vulnerability finding. Is the reasoning sound?\n\n",
    "Finding: %%FINDING_TITLE%%\n",
    "Location: %%FILE_PATH%%:%%LINE_NUMBER%%\n",
    "CWE: %%CWE_ID%%\n",
    "Description: %%VULNERABILITY_DESCRIPTION%%\n",
    "Code Snippet:\n%%CODE_SNIPPET%%\n\n",
    "Task: Analyze the logical reasoning that led to this vulnerability finding.\n",
    "- Is the reasoning sound and logically valid?\n",
    "- Are there any logical errors, gaps, or assumptions?\n",
    "- Does the evidence actually support the conclusion?\n\n",
    "Return JSON with format:\n",
    "{\n",
    "  \"is_sound\": true|false,\n",
    "  \"issues\": [\"issue 1\", \"issue 2\"],\n",
    "  \"confidence_adjustment\": 0.10|-0.20|0.0\n",
    "}\n\n",
    "Rules:\n",
    "- Set is_sound to true if the reasoning is logically valid with no gaps\n",
    "- Set is_sound to false if there are logical errors or unsupported assumptions\n",
    "- Set confidence_adjustment to 0.10 if is_sound is true (boost confidence)\n",
    "- Set confidence_adjustment to -0.20 if is_sound is false (penalize confidence)\n",
    "- List specific issues if reasoning is flawed\n",
    "- Return empty issues array if reasoning is sound\n"
);

/// Perform rationale check on a finding using LLM-as-judge.
///
/// This implements the CORRECT paper approach (arxiv:2504.13474) where an LLM
/// evaluates the reasoning behind a vulnerability finding to reduce false positives.
///
/// # Arguments
/// * `llm` - LLM client for evaluation
/// * `finding` - The vulnerability finding to evaluate
///
/// # Returns
/// * `Ok(RationaleVerdict)` - The verdict with confidence adjustment
/// * `Err` - If LLM call fails (returns neutral verdict with 0.0 adjustment)
pub async fn rationale_check<C>(
    llm: &C,
    finding: &VulnerabilityFinding,
) -> Result<RationaleVerdict, Box<dyn std::error::Error + Send + Sync>>
where
    C: AsyncLlmClient + Send + Sync,
{
    // Build prompt variables
    let mut variables = HashMap::new();
    variables.insert("FINDING_TITLE".to_string(), finding.title.clone());
    variables.insert("FILE_PATH".to_string(), finding.file_path.clone());
    variables.insert(
        "LINE_NUMBER".to_string(),
        finding
            .line_number
            .map(|l| l.to_string())
            .unwrap_or_default(),
    );
    variables.insert(
        "CWE_ID".to_string(),
        finding.cwe_id.clone().unwrap_or_default(),
    );
    variables.insert(
        "VULNERABILITY_DESCRIPTION".to_string(),
        finding.description.clone(),
    );
    variables.insert(
        "CODE_SNIPPET".to_string(),
        finding.code_snippet.clone().unwrap_or_default(),
    );

    let prompt = render_template(RATIONALE_CHECK_PROMPT_TEMPLATE, &variables);
    let messages = vec![
        crate::llm::ChatMessage::system(
            "You are a security expert evaluating vulnerability reasoning. Return JSON only.",
        ),
        crate::llm::ChatMessage::user(&prompt),
    ];

    let response = llm.chat(&messages).await.map_err(|e| {
        tracing::warn!("Rationale check LLM call failed: {}", e);
        e
    })?;

    // Parse JSON response
    let cleaned = response
        .content
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    match serde_json::from_str::<RationaleVerdict>(cleaned) {
        Ok(verdict) => Ok(verdict),
        Err(e) => {
            tracing::warn!(
                "Failed to parse rationale verdict JSON: {}, returning neutral",
                e
            );
            // Return neutral verdict on parse failure
            Ok(RationaleVerdict {
                is_sound: true,
                issues: vec![],
                confidence_adjustment: 0.0,
            })
        }
    }
}

/// Trait for LLM clients used in triage
#[async_trait::async_trait]
pub trait AsyncLlmClient: Send + Sync {
    async fn chat(
        &self,
        messages: &[crate::llm::ChatMessage],
    ) -> Result<crate::llm::ChatResponseWithModel, crate::error::ScanError>;
}

#[async_trait::async_trait]
impl AsyncLlmClient for crate::llm::LlmClient {
    async fn chat(
        &self,
        messages: &[crate::llm::ChatMessage],
    ) -> Result<crate::llm::ChatResponseWithModel, crate::error::ScanError> {
        crate::llm::LlmClient::chat(self, messages).await
    }
}
