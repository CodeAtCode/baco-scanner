//! Confidence normalization based on project baselines.
//!
//! Provides per-project confidence calibration using historical triage data.
//!
//! Paper: Closing the Gap — arxiv:2412.14306

use crate::config::{NormalizationConfig, NormalizationTier};
use std::fs;
use std::path::PathBuf;

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
