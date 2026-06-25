//! Data structures for AI aggregation

use crate::findings::VulnerabilityFinding;
use serde::{Deserialize, Serialize};

/// Source of a finding (which LLM phase produced it)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum FindingSource {
    Semgrep,
    LlmDiscovery,
    LlmVerification,
    LlmMultiPass,
    ChainOfThought,
    CrossFile,
}

/// Conflict between different AI analyses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingConflict {
    /// The conflicting findings
    pub findings: Vec<VulnerabilityFinding>,
    /// Type of conflict
    pub conflict_type: ConflictType,
    /// Resolution decision
    pub resolution: ConflictResolution,
    /// Explanation of the resolution
    pub resolution_reason: String,
}

/// Types of conflicts that can occur between findings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConflictType {
    /// Same location but different severity assessments
    SeverityMismatch,
    /// Same location different CWE IDs
    CweMismatch,
    /// One says vulnerable, other says false positive
    VerificationConflict,
    /// Duplicate findings from different sources
    Duplicate,
    /// Conflicting confidence scores
    ConfidenceConflict,
}

/// How conflicts were resolved
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConflictResolution {
    /// Kept the finding with highest confidence
    HighestConfidence,
    /// Kept the finding with highest severity
    HighestSeverity,
    /// Kept verified findings over unverified
    PreferVerified,
    /// Merged similar findings
    Merged,
    /// Marked as false positive
    MarkedFalsePositive,
    /// Kept one and discarded others
    KeptOne,
}

/// Consensus result for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusResult {
    /// The finding being evaluated
    pub finding: VulnerabilityFinding,
    /// Number of sources that agree
    pub agreement_count: usize,
    /// Total number of sources
    pub total_sources: usize,
    /// Consensus score (0.0 - 1.0)
    pub consensus_score: f32,
    /// Sources that confirmed this finding
    pub confirming_sources: Vec<FindingSource>,
    /// Sources that contradicted this finding (if any)
    pub contradicting_sources: Vec<FindingSource>,
    /// Whether this is likely a false positive
    pub likely_false_positive: bool,
    /// Recommended action
    pub recommendation: ConsensusRecommendation,
}

/// Recommendation based on consensus analysis
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConsensusRecommendation {
    /// Include with high confidence
    IncludeHighConfidence,
    /// Include but mark for review
    IncludeNeedsReview,
    /// Exclude as false positive
    ExcludeFalsePositive,
    /// Requires manual investigation
    ManualReview,
}

/// AI-generated confidence score breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfidenceScore {
    /// Overall confidence (0.0 - 1.0)
    pub overall: f32,
    /// Semantic analysis confidence
    pub semantic: f32,
    /// Verification confidence
    pub verification: f32,
    /// Context analysis confidence
    pub context: f32,
    /// Consensus-based confidence
    pub consensus: f32,
    /// Factors that increased confidence
    pub positive_factors: Vec<String>,
    /// Factors that decreased confidence
    pub negative_factors: Vec<String>,
}

/// Unified finding report combining all analyses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedFindingReport {
    /// The consolidated finding
    pub finding: VulnerabilityFinding,
    /// AI confidence score
    pub ai_confidence: AiConfidenceScore,
    /// Consensus result
    pub consensus: ConsensusResult,
    /// Whether conflicts were resolved
    pub conflicts_resolved: bool,
    /// Original findings before resolution
    pub original_findings: Vec<VulnerabilityFinding>,
}

/// Result of the AI Aggregation phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAggregationResult {
    /// Unified finding reports
    pub unified_reports: Vec<UnifiedFindingReport>,
    /// All conflicts that were found and resolved
    pub conflicts: Vec<FindingConflict>,
    /// Statistics about the aggregation
    pub statistics: AiAggregationStatistics,
    /// Executive summary
    pub executive_summary: String,
    /// Enriched findings with LLM description and recommendation
    pub enriched_findings: Vec<VulnerabilityFinding>,
}

/// Statistics from AI aggregation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AiAggregationStatistics {
    /// Total unique findings after aggregation
    pub total_unique_findings: usize,
    /// Number of conflicts resolved
    pub conflicts_resolved: usize,
    /// Number of false positives detected
    pub false_positives_detected: usize,
    /// Findings marked for manual review
    pub needs_manual_review: usize,
    /// High confidence findings
    pub high_confidence_count: usize,
    /// Average AI confidence score
    pub average_confidence: f32,
}
