//! Confidence Refinement Phase
//!
//! Refines confidence scores based on:
//! - Verification results from LLM verification
//! - Machine learning heuristics for false positive detection
//! - Historical data cross-references
//! - Code context analysis
//! - Generates confidence explanations
//! - Integrates with AnalysisContext (T5)

use crate::analysis_context::AnalysisContext;
use crate::findings::{VerificationStatus, VulnerabilityFinding};
use std::collections::HashMap;

/// Result of confidence refinement for a single finding.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RefinedConfidence {
    /// Original confidence score.
    pub original_score: f32,
    /// Refined confidence score.
    pub refined_score: f32,
    /// Explanation of confidence adjustment.
    pub explanation: Vec<String>,
    /// Factors that influenced the refinement.
    pub factors: Vec<ConfidenceFactor>,
}

/// A factor that influenced confidence score adjustment.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum ConfidenceFactor {
    /// Verified by LLM - higher confidence
    VerifiedByLlm,
    /// Identified as false positive - lower confidence
    FalsePositiveDetected,
    /// Multiple sources confirm the finding
    MultiSourceConfirmation,
    /// Cross-file reachability confirmed
    CrossFileReachability,
    /// Code context supports vulnerability
    SupportsVulnerability,
    /// Code context contradicts vulnerability
    ContradictsVulnerability,
    /// Historical pattern match
    HistoricalPatternMatch,
    /// New pattern - no historical data
    NoHistoricalData,
    /// High severity findings get boost
    SeverityBoost,
    /// Low confidence source
    LowConfidenceSource,
    /// Code is test/assertion related
    TestCodeRelated,
    /// Code is in dependency/vendor
    ThirdPartyCode,
    /// Triage confirmed true positive
    TriageTruePositive,
    /// Triage identified false positive
    TriageFalsePositive,
    /// Rationale validated by LLM-as-judge
    RationaleValidated,
    /// Never-submit pattern matched - finding should not be reported
    NeverSubmitMatch { pattern: String },
}

/// Confidence refinement phase - adjusts confidence scores based on multiple factors.
#[derive(Debug)]
pub struct ConfidenceRefinementPhase {
    historical_data: crate::historical_patterns::HistoricalData,
}

impl ConfidenceRefinementPhase {
    /// Create a new ConfidenceRefinementPhase.
    pub fn new() -> Self {
        Self {
            historical_data: crate::historical_patterns::HistoricalData::new(),
        }
    }

    /// Create a phase seeded with config-provided FP patterns (literal substrings).
    pub fn with_config_knowledge(knowledge: &crate::config::KnowledgeConfig) -> Self {
        let mut phase = Self::new();
        for (cwe, patterns) in &knowledge.fp_patterns {
            phase
                .historical_data
                .add_literal_false_positive_patterns(cwe, patterns);
        }
        phase
    }

    /// Refine confidence scores for all findings.
    ///
    /// # Arguments
    /// * `findings` - Findings to refine
    /// * `context` - AnalysisContext for historical data and context
    /// * `never_submit_enabled` - Whether the never-submit filter is enabled
    /// * `never_submit_multiplier` - Multiplier applied when pattern matches
    ///
    /// # Returns
    /// Map of finding ID to refined confidence
    pub fn run(
        &self,
        findings: Vec<VulnerabilityFinding>,
        context: &AnalysisContext,
        never_submit_enabled: bool,
        never_submit_multiplier: f32,
    ) -> HashMap<String, RefinedConfidence> {
        let mut results = HashMap::new();

        for finding in findings {
            let refined = self.refine_confidence(
                &finding,
                context,
                never_submit_enabled,
                never_submit_multiplier,
            );
            results.insert(finding.id.clone(), refined);
        }

        results
    }

    /// Refine confidence score for a single finding.
    pub fn refine_confidence(
        &self,
        finding: &VulnerabilityFinding,
        _context: &AnalysisContext,
        never_submit_enabled: bool,
        never_submit_multiplier: f32,
    ) -> RefinedConfidence {
        let original_score = finding.confidence_score;
        let mut refined_score = original_score;
        let mut factors = Vec::new();
        let mut explanations = Vec::new();

        // Factor 1: Verification status influence
        if let Some(verification_status) = &finding.verification_status {
            match verification_status {
                VerificationStatus::Confirmed => {
                    refined_score = (refined_score + 0.15).min(1.0);
                    factors.push(ConfidenceFactor::VerifiedByLlm);
                    explanations.push("LLM verification confirmed the finding".to_string());
                }
                VerificationStatus::FalsePositive => {
                    refined_score = (refined_score - 0.3).max(0.0);
                    factors.push(ConfidenceFactor::FalsePositiveDetected);
                    explanations.push("LLM verification identified as false positive".to_string());
                }
                VerificationStatus::NeedsReview => {
                    // No change - still needs review
                    explanations.push("Verification pending - confidence unchanged".to_string());
                }
                VerificationStatus::Failed => {
                    refined_score = (refined_score - 0.1).max(0.0);
                    explanations
                        .push("Verification failed - slight confidence reduction".to_string());
                }
            }
        }

        // Factor 2: Multi-source confirmation
        if finding.sources.len() > 1 {
            refined_score = (refined_score + 0.1).min(1.0);
            factors.push(ConfidenceFactor::MultiSourceConfirmation);
            explanations.push(format!(
                "Confirmed by {} independent sources",
                finding.sources.len()
            ));
        }

        // Factor 3: Cross-file reachability
        if finding.cross_file_references.is_some() {
            refined_score = (refined_score + 0.08).min(1.0);
            factors.push(ConfidenceFactor::CrossFileReachability);
            explanations.push("Cross-file reachability confirmed".to_string());
        }

        // Factor 4: Historical data patterns (false positive detection)
        if let Some(code_snippet) = &finding.code_snippet {
            if let Some(cwe_id) = &finding.cwe_id {
                if self
                    .historical_data
                    .matches_false_positive_pattern(cwe_id, code_snippet)
                {
                    refined_score = (refined_score - 0.2).max(0.0);
                    factors.push(ConfidenceFactor::FalsePositiveDetected);
                    explanations.push("Matches known false positive pattern".to_string());
                } else if self
                    .historical_data
                    .matches_high_confidence_pattern(cwe_id, code_snippet)
                {
                    refined_score = (refined_score + 0.1).min(1.0);
                    factors.push(ConfidenceFactor::HistoricalPatternMatch);
                    explanations
                        .push("Matches known high-confidence vulnerability pattern".to_string());
                }
            }
        }

        // Factor 5: Code context analysis
        if let Some(code_snippet) = &finding.code_snippet {
            let context_analysis = self.analyze_code_context(code_snippet);
            if context_analysis.supports {
                refined_score = (refined_score + 0.05).min(1.0);
                factors.push(ConfidenceFactor::SupportsVulnerability);
                explanations.push(context_analysis.explanation);
            } else if context_analysis.contradicts {
                refined_score = (refined_score - 0.15).max(0.0);
                factors.push(ConfidenceFactor::ContradictsVulnerability);
                explanations.push(context_analysis.explanation);
            }
        }

        // Factor 6: Severity-based adjustment
        if finding.severity.is_high_or_critical() && original_score > 0.7 {
            refined_score = (refined_score + 0.05).min(1.0);
            factors.push(ConfidenceFactor::SeverityBoost);
            explanations.push("High severity findings with high confidence get boost".to_string());
        }

        // Factor 7: Check if in test/third-party code
        let file_path_lower = finding.file_path.to_lowercase();
        if file_path_lower.contains("test")
            || file_path_lower.contains("mock")
            || file_path_lower.contains("_test.")
        {
            refined_score = (refined_score - 0.1).max(0.0);
            factors.push(ConfidenceFactor::TestCodeRelated);
            explanations.push("Finding is in test code - reduced confidence".to_string());
        }

        if file_path_lower.contains("vendor")
            || file_path_lower.contains("node_modules")
            || file_path_lower.contains("third_party")
        {
            refined_score = (refined_score - 0.15).max(0.0);
            factors.push(ConfidenceFactor::ThirdPartyCode);
            explanations.push("Finding is in third-party code - reduced confidence".to_string());
        }

        // Factor 8: Low confidence source penalty
        let low_confidence_sources = ["bandit", "gosec"];
        for source in &finding.sources {
            if low_confidence_sources.contains(&source.as_str()) {
                refined_score = (refined_score - 0.05).max(0.0);
                factors.push(ConfidenceFactor::LowConfidenceSource);
                explanations.push(format!(
                    "Source '{}' typically has lower confidence",
                    source
                ));
                break;
            }
        }

        // Factor 9: Triage-based adjustments
        if let Some(ref notes) = finding.verification_notes {
            if notes.contains("triage") || notes.contains("Triage") {
                if notes.contains("false_positive") || notes.contains("False positive") {
                    refined_score = (refined_score - 0.25).max(0.0);
                    factors.push(ConfidenceFactor::TriageFalsePositive);
                    explanations.push("Triage identified as false positive".to_string());
                } else if notes.contains("true_positive") || notes.contains("True positive") {
                    refined_score = (refined_score + 0.10).min(1.0);
                    factors.push(ConfidenceFactor::TriageTruePositive);
                    explanations.push("Triage confirmed as true positive".to_string());
                }
            }
        }

        // Factor 10: Rationale validation via LLM-as-judge
        // This applies when a finding has been through the rationale_check step
        // The verification_notes may contain rationale validation results
        if let Some(ref notes) = finding.verification_notes {
            if notes.contains("rationale") || notes.contains("Rationale") {
                if notes.contains("sound") || notes.contains("validated") {
                    // Sound rationale - boost confidence
                    refined_score = (refined_score + 0.10).min(1.0);
                    factors.push(ConfidenceFactor::RationaleValidated);
                    explanations.push("Rationale validated as sound by LLM judge".to_string());
                } else if notes.contains("flawed") || notes.contains("invalid") {
                    // Flawed rationale - penalize confidence
                    refined_score = (refined_score - 0.20).max(0.0);
                    factors.push(ConfidenceFactor::RationaleValidated);
                    explanations.push("Rationale identified as flawed by LLM judge".to_string());
                }
            }
        }

        // Factor 11: Never-submit pattern filter
        // Findings matching these patterns are heavily penalized as they should never be reported
        if never_submit_enabled {
            let title = finding.title.as_str();
            let description = finding.description.as_str();
            let cwe_id = finding.cwe_id.as_ref();

            if let Some(match_desc) =
                self.historical_data
                    .check_never_submit_pattern(title, description, cwe_id)
            {
                refined_score = (refined_score * never_submit_multiplier).max(0.0);
                factors.push(ConfidenceFactor::NeverSubmitMatch {
                    pattern: match_desc.clone(),
                });
                explanations
                    .push("Never-submit pattern matched - finding heavily penalized".to_string());
                tracing::warn!(
                    "Never-submit pattern matched: pattern='{}', finding_title='{}'",
                    match_desc,
                    finding.title
                );
            }
        }

        // Clamp final score
        refined_score = refined_score.clamp(0.0, 1.0);

        RefinedConfidence {
            original_score,
            refined_score,
            explanation: explanations,
            factors,
        }
    }

    /// Analyze code context for vulnerability support/contradiction.
    pub fn analyze_code_context(&self, code: &str) -> ContextAnalysis {
        let code_lower = code.to_lowercase();

        // Patterns that support the vulnerability
        let support_patterns = [
            (
                "user_input",
                vec!["request", "param", "query", "input", "body"],
            ),
            ("unsafe_sinks", vec![".exec(", "eval", "system", "shell"]),
            (
                "direct_access",
                vec!["readFile", "read_file", "open(", ".read()"],
            ),
        ];

        // Patterns that contradict the vulnerability
        let contradict_patterns = [
            (
                "validation",
                vec!["validate", "sanitize", "escape", "check", "verify"],
            ),
            (
                "safe_api",
                vec![
                    "preparedStatement",
                    "parameterized",
                    "bindParam",
                    "placeholder",
                ],
            ),
            (
                "auth_check",
                vec!["requireAuth", "isAuthenticated", "checkAuth", "authorized"],
            ),
        ];

        let mut support_count = 0;
        let mut contradict_count = 0;

        for (_, keywords) in &support_patterns {
            for keyword in keywords {
                if code_lower.contains(&keyword.to_lowercase()) {
                    support_count += 1;
                }
            }
        }

        for (_, keywords) in &contradict_patterns {
            for keyword in keywords {
                if code_lower.contains(&keyword.to_lowercase()) {
                    contradict_count += 1;
                }
            }
        }

        if support_count > contradict_count && support_count > 0 {
            let explanation = format!(
                "Code context supports vulnerability ({} supporting, {} contradicting patterns)",
                support_count, contradict_count
            );
            ContextAnalysis {
                supports: true,
                contradicts: false,
                explanation,
            }
        } else if contradict_count > support_count && contradict_count > 0 {
            let explanation = format!(
                "Code context contradicts vulnerability ({} supporting, {} contradicting patterns)",
                support_count, contradict_count
            );
            ContextAnalysis {
                supports: false,
                contradicts: true,
                explanation,
            }
        } else {
            let explanation = "Code context is neutral".to_string();
            ContextAnalysis {
                supports: false,
                contradicts: false,
                explanation,
            }
        }
    }

    /// Apply refined confidence scores to findings.
    pub fn apply_refinements(
        &self,
        findings: &mut [VulnerabilityFinding],
        refinements: &HashMap<String, RefinedConfidence>,
    ) {
        for finding in findings.iter_mut() {
            if let Some(refinement) = refinements.get(&finding.id) {
                finding.confidence_score = refinement.refined_score;
            }
        }
    }

    /// Get the historical data for external use.
    pub fn historical_data(&self) -> &crate::historical_patterns::HistoricalData {
        &self.historical_data
    }

    /// Update historical data with new verification results.
    pub fn record_verification_result(&mut self, cwe_id: &str, is_false_positive: bool) {
        self.historical_data
            .record_verification(cwe_id, is_false_positive);
    }
}

impl Default for ConfidenceRefinementPhase {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper struct for code context analysis.
pub struct ContextAnalysis {
    pub supports: bool,
    pub contradicts: bool,
    pub explanation: String,
}
