//! Historical pattern matching for confidence refinement.
//!
//! Provides pattern-based false positive detection and high-confidence
//! vulnerability matching using regex patterns organized by CWE.

use std::collections::HashMap;

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
            match regex::Regex::new(pattern) {
                Ok(re) => {
                    if re.is_match(code) {
                        return true;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Pattern compilation failed for CWE='{}', pattern='{}': {}",
                        cwe_id,
                        pattern,
                        e
                    );
                }
            }
        }
    }
    false
}

/// Historical data for confidence refinement.
#[derive(Debug, Clone, Default)]
pub struct HistoricalData {
    /// Known false positive patterns by CWE.
    pub false_positive_patterns: HashMap<String, Vec<String>>,
    /// Known high confidence patterns by CWE.
    pub high_confidence_patterns: HashMap<String, Vec<String>>,
    /// Verification history statistics.
    verification_stats: HashMap<String, VerificationStats>,
    /// Never-submit patterns: (CWE-or-keyword, regex-pattern) for findings that should never be reported.
    never_submit_patterns: Vec<(String, String)>,
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
                r"(?i)missing.*header|content\.security\.policy|x-frame-options|hsts".to_string(),
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

    /// Add literal (non-regex) false-positive patterns for a CWE; regex-escaped on insert
    /// because the matcher compiles patterns as regexes.
    pub fn add_literal_false_positive_patterns(&mut self, cwe_id: &str, patterns: &[String]) {
        let escaped: Vec<String> = patterns.iter().map(|p| regex::escape(p)).collect();
        self.false_positive_patterns
            .entry(cwe_id.to_string())
            .or_default()
            .extend(escaped);
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
            match regex::Regex::new(pattern) {
                Ok(re) => {
                    if re.is_match(&text) {
                        return Some(format!("Never-submit pattern matched: {}", cwe_or_keyword));
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Never-submit pattern compilation failed for pattern='{}' (CWE/keyword='{}'): {}",
                        pattern,
                        cwe_or_keyword,
                        e
                    );
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
