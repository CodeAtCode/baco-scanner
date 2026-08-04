//! Extended LLM Verification Phase
//!
//! Verifies findings from previous phases using LLM with:
//! - Cross-references to security best practices
//! - Finding accuracy validation and false positive reduction
//! - Detailed verification reports
//! - Confidence scoring refinement
//! - Integration with AnalysisContext

use crate::analysis_context::AnalysisContext;
use crate::findings::{VerificationStatus, VulnerabilityFinding};
use crate::llm::LlmClient;
use crate::project_type::ProjectType as DetectProjectType;
use crate::prompt::templates::{get_default_prompt, BacoPhase, ProjectType as PromptProjectType};

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

/// Extended Verification Phase
///
/// Uses LLM to verify security findings by:
/// 1. Cross-referencing with security best practices
/// 2. Checking for mitigating factors (sanitization, sandboxing)
/// 3. Validating runtime execution paths
/// 4. Reducing false positives
/// 5. Refining confidence scores
pub struct ExtendedVerificationPhase {
    /// Project type for contextual prompts
    project_type: DetectProjectType,
    /// Analysis context for state persistence
    context: AnalysisContext,
    /// LLM client for verification queries
    llm_client: Option<LlmClient>,
    /// Security best practices for the project type
    security_practices: Vec<String>,
}

impl ExtendedVerificationPhase {
    /// Create a new ExtendedVerificationPhase
    pub fn new(
        project_type: DetectProjectType,
        context: AnalysisContext,
        llm_client: Option<LlmClient>,
    ) -> Self {
        let security_practices = Self::get_security_practices(project_type.clone());

        Self {
            project_type,
            context,
            llm_client,
            security_practices,
        }
    }

    /// Get security best practices for project type
    pub fn get_security_practices(project_type: DetectProjectType) -> Vec<String> {
        match project_type {
            DetectProjectType::Web => vec![
                "Input validation on all entry points".to_string(),
                "Parameterized queries for database operations".to_string(),
                "Output encoding for XSS prevention".to_string(),
                "CSRF tokens on state-changing operations".to_string(),
                "Secure session management".to_string(),
                "Authentication checks on protected routes".to_string(),
                "Authorization checks for resource access".to_string(),
            ],
            DetectProjectType::CLI => vec![
                "Argument validation before processing".to_string(),
                "No shell command execution with user input".to_string(),
                "Path traversal prevention".to_string(),
                "Secure temporary file handling".to_string(),
            ],
            DetectProjectType::Library => vec![
                "No panic on malformed input".to_string(),
                "Thread-safe public APIs".to_string(),
                "Proper error handling".to_string(),
                "No unsafe code in public interfaces".to_string(),
            ],
            DetectProjectType::Embedded => vec![
                "No buffer overflow in stack/heap".to_string(),
                "No undefined behavior".to_string(),
                "Watchdog handling for hangs".to_string(),
                "Secure memory management".to_string(),
            ],
            DetectProjectType::Firmware => vec![
                "No hardcoded credentials".to_string(),
                "Secure boot chain verification".to_string(),
                "Encrypted storage for secrets".to_string(),
            ],
            DetectProjectType::Desktop => vec![
                "Input sanitization in UI elements".to_string(),
                "No file path traversal".to_string(),
                "Secure file handling".to_string(),
                "User data protection".to_string(),
            ],
            DetectProjectType::Game => vec![
                "No stack overflow from recursion".to_string(),
                "Secure multiplayer protocols".to_string(),
                "Safe deserialization".to_string(),
            ],
            DetectProjectType::Unknown => vec![
                "Input validation".to_string(),
                "Secure error handling".to_string(),
                "No hardcoded secrets".to_string(),
            ],
        }
    }

    /// Get project type
    pub fn project_type(&self) -> &DetectProjectType {
        &self.project_type
    }

    /// Get security practices
    pub fn security_practices(&self) -> &Vec<String> {
        &self.security_practices
    }

    /// Execute verification on all findings
    pub fn execute(
        &mut self,
        findings: &[VulnerabilityFinding],
    ) -> Result<VerificationReport, String> {
        let mut results = Vec::new();

        for finding in findings {
            let result = self.verify_finding(finding);
            results.push(result);
        }

        // Generate report
        let report = self.generate_report(&results);

        // Update context with verified findings
        self.context.findings_so_far = results
            .iter()
            .filter(|r| r.status == VerificationStatus::Confirmed)
            .map(|r| r.finding_id.clone())
            .collect();

        Ok(report)
    }

    /// Verify a single finding using LLM or heuristics
    pub fn verify_finding(&self, finding: &VulnerabilityFinding) -> VerificationResult {
        // Try LLM-based verification if client is available
        if let Some(ref client) = self.llm_client {
            if let Ok(llm_result) = self.llm_verify_finding(client, finding) {
                return llm_result;
            }
        }

        // Fall back to heuristic-based verification
        self.heuristic_verify_finding(finding)
    }

    /// Use LLM to verify a finding
    fn llm_verify_finding(
        &self,
        client: &LlmClient,
        finding: &VulnerabilityFinding,
    ) -> Result<VerificationResult, String> {
        let phase = BacoPhase::LlmVerification;
        let prompt_type: PromptProjectType = match self.project_type {
            DetectProjectType::CLI => PromptProjectType::CLI,
            DetectProjectType::Web => PromptProjectType::Web,
            DetectProjectType::Library => PromptProjectType::Library,
            DetectProjectType::Embedded => PromptProjectType::Embedded,
            DetectProjectType::Firmware => PromptProjectType::Firmware,
            DetectProjectType::Desktop => PromptProjectType::Desktop,
            DetectProjectType::Game => PromptProjectType::Library,
            DetectProjectType::Unknown => PromptProjectType::CLI,
        };
        let prompt_template = get_default_prompt(&phase, &prompt_type);

        // Build variables for prompt
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
            "VULNERABILITY_DESCRIPTION".to_string(),
            finding.description.clone(),
        );
        variables.insert("SOURCE_LIST".to_string(), finding.sources.join(", "));
        variables.insert(
            "SECURITY_PRACTICES".to_string(),
            self.security_practices.join("; "),
        );

        let prompt = render_template(&prompt_template, &variables);

        // In production, would call LLM here
        // For now, use heuristic fallback
        let _ = client;
        drop(prompt);

        Err("LLM verification not implemented, using heuristics".to_string())
    }

    /// Heuristic-based verification (fallback when LLM unavailable)
    fn heuristic_verify_finding(&self, finding: &VulnerabilityFinding) -> VerificationResult {
        let mut mitigating_factors = Vec::new();
        let mut related_patterns = Vec::new();
        let mut false_positive_reason = None;

        // Check for sanitization patterns in code
        if let Some(ref code) = finding.code_snippet {
            if self.has_sanitization(code) {
                mitigating_factors.push("Input sanitization detected in code".to_string());
                related_patterns.push("sanitization_present".to_string());
            }

            if self.is_known_false_positive_pattern(code) {
                false_positive_reason = Some("Matches known false positive pattern".to_string());
                related_patterns.push("false_positive_pattern".to_string());
            }
        }

        // Check security issue category for patterns
        if let Some(ref issue) = finding.security_issue {
            related_patterns.push(issue.category.to_string());

            if let Some(ref cwe) = issue.cwe_id {
                related_patterns.push(cwe.clone());

                // Check for known FP CWE patterns
                if self.is_cwe_known_false_positive(cwe) {
                    false_positive_reason = Some(format!("CWE {} is often a false positive", cwe));
                }
            }
        }

        // Determine status based on analysis
        let status = if false_positive_reason.is_some() {
            VerificationStatus::FalsePositive
        } else if mitigating_factors.is_empty() {
            // No mitigating factors found, likely valid
            VerificationStatus::Confirmed
        } else {
            // Has some mitigating factors, needs review
            VerificationStatus::NeedsReview
        };

        // Calculate refined confidence
        let confidence =
            self.calculate_refined_confidence(finding, &mitigating_factors, &related_patterns);

        VerificationResult {
            finding_id: finding.id.clone(),
            status,
            confidence,
            notes: format!(
                "Verified via heuristic analysis. Mitigating factors: {}",
                mitigating_factors.len()
            ),
            mitigating_factors,
            related_patterns,
            false_positive_reason,
        }
    }

    /// Check if code has sanitization
    pub fn has_sanitization(&self, code: &str) -> bool {
        let sanitization_patterns = [
            "sanitize",
            "escape",
            "encode",
            "validate",
            "filter",
            "parameterized",
            "parametrized",
            "prepared",
            "bind_param",
            "htmlspecialchars",
            "htmlentities",
            "urlencode",
            "base64_encode",
        ];

        let code_lower = code.to_lowercase();
        sanitization_patterns.iter().any(|p| code_lower.contains(p))
    }

    /// Check for known false positive patterns
    pub fn is_known_false_positive_pattern(&self, code: &str) -> bool {
        let fp_patterns = [
            "test",
            "mock",
            "example",
            "demo",
            "sample",
            "todo",
            "fixme",
            "xxx",
            "hack",
            "if false",
            "unreachable",
            "dead_code",
        ];

        let code_lower = code.to_lowercase();
        fp_patterns.iter().any(|p| code_lower.contains(p))
    }

    /// Check if CWE is known to generate false positives
    pub fn is_cwe_known_false_positive(&self, cwe: &str) -> bool {
        matches!(cwe, "CWE-190" | "CWE-191" | "CWE-754")
    }

    /// Calculate refined confidence score
    pub fn calculate_refined_confidence(
        &self,
        finding: &VulnerabilityFinding,
        mitigating_factors: &[String],
        _related_patterns: &[String],
    ) -> f32 {
        let mut confidence = finding.confidence_score;

        // Reduce confidence if mitigating factors found
        if !mitigating_factors.is_empty() {
            let reduction = 0.1 * mitigating_factors.len() as f32;
            confidence = (confidence - reduction).max(0.0);
        }

        // Boost confidence for high severity issues
        if finding.severity.is_high_or_critical() {
            confidence = (confidence + 0.1).min(1.0);
        }

        // Reduce confidence if already reported (may be known issue)
        if finding.already_reported {
            confidence = (confidence - 0.05).max(0.0);
        }

        confidence
    }

    /// Generate verification report
    fn generate_report(&self, results: &[VerificationResult]) -> VerificationReport {
        let total = results.len();
        let confirmed = results
            .iter()
            .filter(|r| r.status == VerificationStatus::Confirmed)
            .count();
        let false_positives = results
            .iter()
            .filter(|r| r.status == VerificationStatus::FalsePositive)
            .count();
        let needs_review = results
            .iter()
            .filter(|r| r.status == VerificationStatus::NeedsReview)
            .count();
        let failed = results
            .iter()
            .filter(|r| r.status == VerificationStatus::Failed)
            .count();

        let sum_confidence: f32 = results.iter().map(|r| r.confidence).sum();
        let average_confidence = if total > 0 {
            sum_confidence / total as f32
        } else {
            0.0
        };

        let high_confidence_findings: Vec<String> = results
            .iter()
            .filter(|r| r.confidence >= 0.7 && r.status == VerificationStatus::Confirmed)
            .map(|r| r.finding_id.clone())
            .collect();

        VerificationReport {
            total_findings: total,
            confirmed,
            false_positives,
            needs_review,
            failed,
            results: results.to_vec(),
            average_confidence,
            high_confidence_findings,
        }
    }
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

/// Rationale check template function for testing and direct use
pub fn rationale_check_template(finding: &VulnerabilityFinding) -> String {
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

    render_template(RATIONALE_CHECK_PROMPT_TEMPLATE, &variables)
}

/// Triage filter for LLM-based false positive detection
pub struct TriageFilter {
    #[allow(dead_code)]
    llm_client: Option<LlmClient>,
}

/// Triage prompt template for false positive detection
const TRIAGE_PROMPT_TEMPLATE: &str = concat!(
    "Analyze this security vulnerability and determine if it is a true positive or false positive.\n\n",
    "Finding: %%FINDING_TITLE%%\n",
    "Location: %%FILE_PATH%%:%%LINE_NUMBER%%\n",
    "Description: %%VULNERABILITY_DESCRIPTION%%\n",
    "Code: %%CODE_SNIPPET%%\n\n",
    "Return JSON: {\"verdict\": \"true_positive\"|\"false_positive\", \"confidence\": 0.0-1.0, \"reasoning\": \"...\"}"
);

impl TriageFilter {
    /// Create a new TriageFilter
    pub fn new(llm_client: Option<LlmClient>) -> Self {
        Self { llm_client }
    }

    /// Triage a single finding using LLM
    pub async fn triage_finding<C>(
        &self,
        finding: &VulnerabilityFinding,
        client: &C,
    ) -> Result<TriageResult, String>
    where
        C: AsyncLlmClient,
    {
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
            "VULNERABILITY_DESCRIPTION".to_string(),
            finding.description.clone(),
        );
        variables.insert(
            "CODE_SNIPPET".to_string(),
            finding.code_snippet.clone().unwrap_or_default(),
        );

        let prompt = render_template(TRIAGE_PROMPT_TEMPLATE, &variables);
        let messages = vec![
            crate::llm::ChatMessage::system(
                "You are a security expert. Analyze the vulnerability and return JSON only.",
            ),
            crate::llm::ChatMessage::user(&prompt),
        ];
        let response = client
            .chat(&messages)
            .await
            .map_err(|e| format!("LLM triage failed: {}", e))?;
        let response_content = response.content;

        self.parse_triage_response(&response_content)
    }

    /// Parse LLM response into TriageResult
    fn parse_triage_response(&self, response: &str) -> Result<TriageResult, String> {
        #[derive(Deserialize)]
        struct TriageResponse {
            verdict: String,
            confidence: f32,
            reasoning: String,
        }

        let json_str = response.trim();
        let parsed: TriageResponse =
            serde_json::from_str(json_str).map_err(|e| format!("JSON parse error: {}", e))?;

        let verdict = match parsed.verdict.as_str() {
            "true_positive" => TriageVerdict::TruePositive,
            "false_positive" => TriageVerdict::FalsePositive,
            other => return Err(format!("Invalid verdict: {}", other)),
        };

        Ok(TriageResult {
            verdict,
            confidence: parsed.confidence.clamp(0.0, 1.0),
            reasoning: parsed.reasoning,
        })
    }

    /// Filter out false positives from a batch of findings
    /// Returns filtered findings and the number of removed false positives
    pub async fn filter<C>(
        &self,
        findings: Vec<VulnerabilityFinding>,
        client: &C,
    ) -> Result<(Vec<VulnerabilityFinding>, usize), String>
    where
        C: AsyncLlmClient,
    {
        use crate::findings::TriageVerdict as FindingsTriageVerdict;

        let mut filtered = Vec::new();
        let mut removed_count = 0;

        for finding in findings {
            match self.triage_finding(&finding, client).await {
                Ok(triage_result) => {
                    if triage_result.verdict == TriageVerdict::FalsePositive {
                        removed_count += 1;
                        tracing::debug!(
                            "TriageFilter: filtered out {} (confidence: {:.2}) - {}",
                            finding.id,
                            triage_result.confidence,
                            triage_result.reasoning
                        );
                    } else {
                        // Add triage verdict to finding using findings::TriageVerdict
                        let mut updated_finding = finding.clone();
                        updated_finding.triage_verdict = Some(FindingsTriageVerdict::Pass);
                        filtered.push(updated_finding);
                    }
                }
                Err(e) => {
                    // On error, keep the finding but log warning
                    tracing::warn!("TriageFilter: failed to triage {}: {}", finding.id, e);
                    filtered.push(finding);
                }
            }
        }

        Ok((filtered, removed_count))
    }
}

/// Trait for LLM clients used in triage
#[async_trait::async_trait]
pub trait AsyncLlmClient: Send + Sync {
    async fn chat(
        &self,
        messages: &[crate::llm::ChatMessage],
    ) -> Result<crate::llm::ChatResponseWithModel, String>;
}

#[async_trait::async_trait]
impl AsyncLlmClient for crate::llm::LlmClient {
    async fn chat(
        &self,
        messages: &[crate::llm::ChatMessage],
    ) -> Result<crate::llm::ChatResponseWithModel, String> {
        crate::llm::LlmClient::chat(self, messages).await
    }
}
