//! Confidence Refinement Phase
//!
//! Refines confidence scores based on:
//! - Verification results from LLM verification
//! - Machine learning heuristics for false positive detection
//! - Historical data cross-references
//! - Code context analysis
//! - Generates confidence explanations
//! - Integrates with AnalysisContext (T5)

use crate::context::AnalysisContext;
use crate::findings::{VerificationStatus, VulnerabilityFinding};
use std::collections::HashMap;

#[cfg(test)]
use crate::findings::Severity;

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
}

/// Historical data for confidence refinement.
#[derive(Debug, Clone, Default)]
pub struct HistoricalData {
    /// Known false positive patterns by CWE.
    false_positive_patterns: HashMap<String, Vec<String>>,
    /// Known high confidence patterns by CWE.
    high_confidence_patterns: HashMap<String, Vec<String>>,
    /// Verification history statistics.
    verification_stats: HashMap<String, VerificationStats>,
}

/// Statistics for a specific CWE verification history.
#[derive(Debug, Clone, Default)]
pub struct VerificationStats {
    /// Total verifications performed.
    pub total: usize,
    /// Confirmed findings count.
    pub confirmed: usize,
    /// False positive count.
    pub false_positives: usize,
}

/// Check if a code snippet matches patterns in the given collection.
fn matches_pattern_collection(
    patterns: &HashMap<String, Vec<String>>,
    cwe_id: &str,
    code: &str,
) -> bool {
    if let Some(patterns) = patterns.get(cwe_id) {
        for pattern in patterns {
            if regex::Regex::new(pattern)
                .map(|re| re.is_match(code))
                .unwrap_or(false)
            {
                return true;
            }
        }
    }
    false
}

impl HistoricalData {
    /// Create new historical data with default patterns.
    pub fn new() -> Self {
        let mut data = Self::default();

        // Common false positive patterns for various CWEs
        data.false_positive_patterns.insert(
            "CWE-79".to_string(),
            vec![
                r"html_escape".to_string(),
                r"escape_html".to_string(),
                r"sanitize.*html".to_string(),
                r"textContent".to_string(),
                r"innerText".to_string(),
            ],
        );

        data.false_positive_patterns.insert(
            "CWE-89".to_string(),
            vec![
                r"ORM".to_string(),
                r"ActiveRecord".to_string(),
                r"prepare.*statement".to_string(),
                r"parameterized".to_string(),
                r"find_by".to_string(),
            ],
        );

        data.false_positive_patterns.insert(
            "CWE-22".to_string(),
            vec![
                r"basename.*path".to_string(),
                r"normalize.*path".to_string(),
                r"realpath".to_string(),
            ],
        );

        // High confidence patterns
        data.high_confidence_patterns.insert(
            "CWE-79".to_string(),
            vec![
                r"innerHTML".to_string(),
                r"dangerouslySetInnerHTML".to_string(),
                r"document\.write".to_string(),
            ],
        );

        data.high_confidence_patterns.insert(
            "CWE-89".to_string(),
            vec![
                r"execute.*\(.*\+".to_string(),
                r"query.*\+.*param".to_string(),
                r"raw.*sql".to_string(),
            ],
        );

        data
    }

    /// Check if a code snippet matches false positive patterns.
    pub fn matches_false_positive_pattern(&self, cwe_id: &str, code: &str) -> bool {
        matches_pattern_collection(&self.false_positive_patterns, cwe_id, code)
    }

    /// Check if a code snippet matches high confidence patterns.
    pub fn matches_high_confidence_pattern(&self, cwe_id: &str, code: &str) -> bool {
        matches_pattern_collection(&self.high_confidence_patterns, cwe_id, code)
    }

    /// Get verification statistics for a CWE.
    pub fn get_stats(&self, cwe_id: &str) -> VerificationStats {
        self.verification_stats
            .get(cwe_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Record a verification result.
    pub fn record_verification(&mut self, cwe_id: &str, is_false_positive: bool) {
        let stats = self
            .verification_stats
            .entry(cwe_id.to_string())
            .or_default();
        stats.total += 1;
        if is_false_positive {
            stats.false_positives += 1;
        } else {
            stats.confirmed += 1;
        }
    }
}

/// Confidence refinement phase - adjusts confidence scores based on multiple factors.
#[derive(Debug)]
pub struct ConfidenceRefinementPhase {
    historical_data: HistoricalData,
}

impl ConfidenceRefinementPhase {
    /// Create a new ConfidenceRefinementPhase.
    pub fn new() -> Self {
        Self {
            historical_data: HistoricalData::new(),
        }
    }

    /// Refine confidence scores for all findings.
    ///
    /// # Arguments
    /// * `findings` - Findings to refine
    /// * `context` - AnalysisContext for historical data and context
    ///
    /// # Returns
    /// Map of finding ID to refined confidence
    pub fn run(
        &self,
        findings: Vec<VulnerabilityFinding>,
        context: &AnalysisContext,
    ) -> HashMap<String, RefinedConfidence> {
        let mut results = HashMap::new();

        for finding in findings {
            let refined = self.refine_confidence(&finding, context);
            results.insert(finding.id.clone(), refined);
        }

        results
    }

    /// Refine confidence score for a single finding.
    fn refine_confidence(
        &self,
        finding: &VulnerabilityFinding,
        _context: &AnalysisContext,
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
    fn analyze_code_context(&self, code: &str) -> ContextAnalysis {
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
    pub fn historical_data(&self) -> &HistoricalData {
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
struct ContextAnalysis {
    supports: bool,
    contradicts: bool,
    explanation: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::VerificationStatus;
    use crate::phase::helpers::create_finding_with_params;

    #[test]
    fn test_refine_confidence_verified() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();
        
        // Create a finding with verified status
        let mut finding = create_finding_with_params("f1", "Test finding", Severity::High);
        finding.verification_status = Some(VerificationStatus::Confirmed);

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!(refined.refined_score > refined.original_score);
        assert!(refined.factors.contains(&ConfidenceFactor::VerifiedByLlm));
    }

    #[test]
    fn test_refine_confidence_false_positive() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::High);
        finding.verification_status = Some(VerificationStatus::FalsePositive);

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!(refined.refined_score < refined.original_score);
        assert!(refined
            .factors
            .contains(&ConfidenceFactor::FalsePositiveDetected));
    }

    #[test]
    fn test_refine_confidence_multi_source() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::Medium);
        finding.sources = vec!["semgrep".to_string(), "llm".to_string()];

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!(refined
            .factors
            .contains(&ConfidenceFactor::MultiSourceConfirmation));
    }

    #[test]
    fn test_refine_confidence_test_code() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let finding = create_finding_with_params("f1", "Test finding", Severity::High);

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!(refined.factors.contains(&ConfidenceFactor::TestCodeRelated));
    }

    #[test]
    fn test_refine_confidence_vendor_code() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::High);
        finding.file_path = "vendor/some-lib/lib.rs".to_string();

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!(refined.factors.contains(&ConfidenceFactor::ThirdPartyCode));
    }

    #[test]
    fn test_refine_confidence_cross_file() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut finding = create_finding_with_params("f1", "Test finding", Severity::High);
        finding.cross_file_references = Some(vec!["src/util.rs".to_string()]);

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!(refined
            .factors
            .contains(&ConfidenceFactor::CrossFileReachability));
    }

    #[test]
    fn test_historical_false_positive_patterns() {
        let data = HistoricalData::new();

        // Should match known false positive pattern
        assert!(data.matches_false_positive_pattern("CWE-79", "some_function(html_escape(x))"));
        assert!(data.matches_false_positive_pattern("CWE-89", "User.find_by(name: name)"));
    }

    #[test]
    fn test_historical_high_confidence_patterns() {
        let data = HistoricalData::new();

        // Should match known high confidence pattern
        assert!(data.matches_high_confidence_pattern("CWE-79", "element.innerHTML = userInput"));
    }

    #[test]
    fn test_confidence_clamped_to_range() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        // Test upper bound
        let finding = create_finding_with_params("f1", "Test finding", Severity::Critical);

        let refinements = phase.run(vec![finding], &context);
        let refined = refinements.get("f1").unwrap();

        assert!(refined.refined_score <= 1.0);

        // Test lower bound with false positive
        let finding2 = create_finding_with_params("f2", "Test finding", Severity::Low);

        let refinements2 = phase.run(vec![finding2], &context);
        let refined2 = refinements2.get("f2").unwrap();

        assert!(refined2.refined_score >= 0.0);
    }

    #[test]
    fn test_apply_refinements() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let finding = create_finding_with_params("f1", "Test finding", Severity::High);

        let mut findings = vec![finding];
        let refinements = phase.run(findings.clone(), &context);

        phase.apply_refinements(&mut findings, &refinements);

        assert_eq!(
            findings[0].confidence_score,
            refinements["f1"].refined_score
        );
    }

    #[test]
    fn test_context_analysis_supports() {
        let phase = ConfidenceRefinementPhase::new();
        let code = "user_input = request.params.input; eval(user_input)";

        let analysis = phase.analyze_code_context(code);

        assert!(analysis.supports);
        assert!(!analysis.contradicts);
    }

    #[test]
    fn test_context_analysis_contradicts() {
        let phase = ConfidenceRefinementPhase::new();
        let code = "user_input = sanitize(input); preparedStatement.execute(user_input)";

        let analysis = phase.analyze_code_context(code);

        assert!(!analysis.supports);
        assert!(analysis.contradicts);
    }

    #[test]
    fn test_record_verification() {
        let mut phase = ConfidenceRefinementPhase::new();

        phase.record_verification_result("CWE-79", false);
        phase.record_verification_result("CWE-79", false);
        phase.record_verification_result("CWE-79", true);

        let stats = phase.historical_data().get_stats("CWE-79");
        assert_eq!(stats.total, 3);
        assert_eq!(stats.confirmed, 2);
        assert_eq!(stats.false_positives, 1);
    }

    #[test]
    fn test_multiple_findings_refinement() {
        let phase = ConfidenceRefinementPhase::new();
        let context = AnalysisContext::default();

        let mut f3 = create_finding_with_params("f3", "Test finding", Severity::Critical);
        f3.file_path = "src/main.rs".to_string();

        let findings = vec![
            create_finding_with_params("f1", "Test finding", Severity::High),
            create_finding_with_params("f2", "Test finding", Severity::Medium),
            f3,
        ];

        let refinements = phase.run(findings, &context);

        assert_eq!(refinements.len(), 3);
        assert!(refinements["f3"].refined_score > refinements["f3"].original_score);
    }
}
