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
use crate::config::{NormalizationConfig, NormalizationTier};
use crate::findings::{Severity, TriageVerdict, VerificationStatus, VulnerabilityFinding};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

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
    /// Pre-severity downgrade gate - theoretical impact rather than demonstrated
    SeverityDowngrade {
        original_severity: Severity,
        reason: String,
    },
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
    /// Never-submit patterns: (CWE-or-keyword, regex-pattern) for findings that should never be reported.
    never_submit_patterns: Vec<(String, String)>,
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

        // Never-submit patterns: findings matching these should be heavily penalized
        data.never_submit_patterns = vec![
            (
                "CWE-693".to_string(),
                r"missing.*header|content\.security\.policy|X-Frame-Options|HSTS".to_string(),
            ),
            ("CWE-601".to_string(), r"open.redirect".to_string()),
            (
                "self-xss".to_string(),
                r"self.xss|reflected.*same.origin".to_string(),
            ),
            (
                "CWE-918".to_string(),
                r"ssrf.*dns.*callback|ssrf.*without.*oob".to_string(),
            ),
        ];

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

    /// Check if a finding matches a never-submit pattern.
    /// Returns Some(description) if matched, None otherwise.
    pub fn check_never_submit_pattern(
        &self,
        title: &str,
        description: &str,
        cwe_id: Option<&String>,
    ) -> Option<String> {
        let text = format!(
            "{} {} {}",
            title,
            description,
            cwe_id.map_or("", |s| s.as_str())
        )
        .to_lowercase();

        for (cwe_or_keyword, pattern) in &self.never_submit_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(&text) {
                    return Some(format!("Never-submit pattern matched: {}", cwe_or_keyword));
                }
            }
        }
        None
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
        // Note: config is not available in AnalysisContext, so we always enable this filter
        let never_submit_config_enabled = true;

        if never_submit_config_enabled {
            let title = finding.title.as_str();
            let description = finding.description.as_str();
            let cwe_id = finding.cwe_id.as_ref();

            if let Some(match_desc) =
                self.historical_data
                    .check_never_submit_pattern(title, description, cwe_id)
            {
                refined_score = (refined_score * 0.1).max(0.0);
                factors.push(ConfidenceFactor::NeverSubmitMatch {
                    pattern: match_desc,
                });
                explanations
                    .push("Never-submit pattern matched - finding heavily penalized".to_string());
            }
        }

        // Factor 12: Pre-severity downgrade gate
        // Lower confidence when concrete impact proof is theoretical rather than demonstrated
        if let Some(triage_verdict) = &finding.triage_verdict {
            if matches!(triage_verdict, TriageVerdict::Downgrade { .. }) {
                refined_score = (refined_score - 0.15).max(0.0);
                factors.push(ConfidenceFactor::SeverityDowngrade {
                    original_severity: finding.severity,
                    reason: "Impact assessment is theoretical rather than demonstrated".to_string(),
                });
                explanations
                    .push("Pre-severity downgrade gate applied - theoretical impact".to_string());
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
pub struct ContextAnalysis {
    pub supports: bool,
    pub contradicts: bool,
    pub explanation: String,
}

/// Project baseline for confidence normalization.
///
/// Stores historical triage outcomes to enable per-project confidence calibration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ProjectBaseline {
    /// Total number of findings analyzed.
    pub total_findings: usize,
    /// Number of true positives confirmed.
    pub true_positives: usize,
    /// Number of false positives identified.
    pub false_positives: usize,
    /// Mean confidence score of all findings.
    pub mean_confidence: f32,
    /// Sum of squared deviations for std dev calculation.
    #[serde(default)]
    pub sum_sq_dev: f32,
}

impl ProjectBaseline {
    /// Create an empty baseline.
    pub fn empty() -> Self {
        Self {
            total_findings: 0,
            true_positives: 0,
            false_positives: 0,
            mean_confidence: 0.0,
            sum_sq_dev: 0.0,
        }
    }

    /// Load baseline from a file path.
    ///
    /// Returns empty baseline if file doesn't exist or is invalid.
    pub fn load(path: &PathBuf) -> Self {
        if !path.exists() {
            return Self::empty();
        }

        match fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(baseline) => baseline,
                Err(e) => {
                    tracing::warn!("Failed to parse baseline at {:?}: {}", path, e);
                    Self::empty()
                }
            },
            Err(e) => {
                tracing::warn!("Failed to read baseline at {:?}: {}", path, e);
                Self::empty()
            }
        }
    }

    /// Save baseline to a file path.
    pub fn save(&self, path: &PathBuf) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(path, json)
    }

    /// Get false positive rate.
    pub fn false_positive_rate(&self) -> f32 {
        if self.total_findings == 0 {
            return 0.0;
        }
        self.false_positives as f32 / self.total_findings as f32
    }

    /// Get standard deviation of confidence scores.
    pub fn std_dev(&self) -> f32 {
        if self.total_findings <= 1 {
            return 0.0;
        }
        (self.sum_sq_dev / self.total_findings as f32).sqrt()
    }

    /// Update baseline with a new finding's confidence score.
    pub fn update(&mut self, confidence: f32, is_true_positive: bool) {
        let old_mean = self.mean_confidence;
        self.total_findings += 1;

        // Update mean using Welford's online algorithm
        self.mean_confidence = old_mean + (confidence - old_mean) / self.total_findings as f32;

        // Update sum of squared deviations
        self.sum_sq_dev += (confidence - old_mean) * (confidence - self.mean_confidence);

        // Update TP/FP counts
        if is_true_positive {
            self.true_positives += 1;
        } else {
            self.false_positives += 1;
        }
    }
}

/// Normalize confidence score based on project baseline.
///
/// # Arguments
/// * `raw_confidence` - Original confidence score
/// * `config` - Normalization configuration
/// * `baseline` - Project baseline with historical data
///
/// # Returns
/// Normalized confidence score
pub fn normalize_confidence(
    raw_confidence: f32,
    config: &NormalizationConfig,
    baseline: &ProjectBaseline,
) -> f32 {
    if !config.enabled {
        return raw_confidence;
    }

    match config.normalization_tier {
        NormalizationTier::None => raw_confidence,

        NormalizationTier::ProjectRelative => {
            let fp_rate = baseline.false_positive_rate();

            if fp_rate > 0.30 {
                // High FP rate: scale down
                let scale = 1.0 - fp_rate * 0.5;
                raw_confidence * scale
            } else if fp_rate < 0.10 {
                // Low FP rate: scale up (capped at 1.0)
                let scale = 1.0 + (0.10 - fp_rate) * 2.0;
                (raw_confidence * scale).min(1.0)
            } else {
                // Medium FP rate: no adjustment
                raw_confidence
            }
        }

        NormalizationTier::Isotonic => {
            // Apply simple linear calibration
            let std_dev = baseline.std_dev();

            // Fallback to raw if std_dev is 0 or baseline has <10 findings
            if std_dev == 0.0 || baseline.total_findings < 10 {
                return raw_confidence;
            }

            let calibrated = (raw_confidence - baseline.mean_confidence) / std_dev * 0.5 + 0.5;
            calibrated.clamp(0.0, 1.0)
        }
    }
}
